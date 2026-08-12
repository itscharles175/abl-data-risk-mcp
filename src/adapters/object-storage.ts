import { createHash } from "node:crypto";

import type { Sha256Hash } from "../contracts/canonical.js";
import {
  AdapterValidationError,
  boundedPositiveInteger,
  type AdapterColumnV1,
  type BoundedTabularAdapter,
  type ConformedDatasetV1
} from "./conformance.js";
import {
  PARQUET_MEDIA_TYPE,
  type ParquetIngestionInputV1,
  type ParquetPartitionExpectationV1,
  type ParquetPartitionValueV1
} from "./parquet.js";
import {
  XLSX_MEDIA_TYPE,
  type XlsxIngestionInputV1
} from "./xlsx.js";

export interface ObjectStorageBucketAllowlistV1 {
  readonly bucket: string;
  readonly keyPrefixes: readonly string[];
  readonly mediaTypes: readonly (typeof XLSX_MEDIA_TYPE | typeof PARQUET_MEDIA_TYPE)[];
}

export interface ObjectStorageConnectorAllowlistV1 {
  readonly connectorId: string;
  /** Exact trusted origin. Paths, credentials, query strings and fragments are forbidden. */
  readonly endpointOrigin: string;
  readonly buckets: readonly Readonly<ObjectStorageBucketAllowlistV1>[];
}

export interface ImmutableObjectReferenceV1 {
  readonly connectorId: string;
  readonly endpointOrigin: string;
  readonly bucket: string;
  readonly key: string;
  readonly versionId: string;
  readonly expectedContentHash: Sha256Hash;
  readonly mediaType: typeof XLSX_MEDIA_TYPE | typeof PARQUET_MEDIA_TYPE;
}

export interface ImmutableObjectRequestV1 extends ImmutableObjectReferenceV1 {
  readonly signal: AbortSignal | undefined;
}

export type ObjectImmutabilityEvidenceV1 =
  | { readonly mode: "version_id"; readonly versionId: string }
  | { readonly mode: "compliance_lock"; readonly versionId: string; readonly retainUntil: string };

export interface ImmutableObjectHeadV1 {
  readonly connectorId: string;
  readonly endpointOrigin: string;
  readonly bucket: string;
  readonly key: string;
  readonly versionId: string;
  readonly contentLength: number;
  readonly contentType: string;
  readonly contentHash?: Sha256Hash;
  readonly immutability: ObjectImmutabilityEvidenceV1;
}

export interface ImmutableObjectBodyV1 {
  readonly versionId: string;
  readonly body: AsyncIterable<Uint8Array>;
}

/**
 * Provider SDKs live behind this port. Credentials are resolved by the port
 * from connectorId; they are never accepted in plans, object references, or
 * adapter configuration.
 */
export interface ImmutableObjectClientPortV1 {
  headImmutableObject(request: ImmutableObjectRequestV1): Promise<ImmutableObjectHeadV1>;
  readImmutableObject(request: ImmutableObjectRequestV1): Promise<ImmutableObjectBodyV1>;
}

export interface ObjectDeliveryEvidenceV1 {
  readonly connectorId: string;
  readonly endpointOrigin: string;
  readonly bucket: string;
  readonly key: string;
  readonly versionId: string;
  readonly mediaType: string;
  readonly byteLength: number;
  readonly contentHash: Sha256Hash;
  readonly immutability: ObjectImmutabilityEvidenceV1;
}

export interface LoadedImmutableObjectV1 {
  readonly bytes: Uint8Array;
  readonly evidence: ObjectDeliveryEvidenceV1;
}

export class ImmutableObjectDeliveryLoaderV1 {
  readonly #client: ImmutableObjectClientPortV1;
  readonly #allowlist: ReadonlyMap<string, Readonly<ObjectStorageConnectorAllowlistV1>>;
  readonly #maximumObjectBytes: number;
  readonly #maximumChunks: number;

  constructor(input: {
    readonly client: ImmutableObjectClientPortV1;
    readonly allowlist: readonly Readonly<ObjectStorageConnectorAllowlistV1>[];
    readonly maximumObjectBytes?: number;
    readonly maximumChunks?: number;
  }) {
    this.#client = input.client;
    this.#maximumObjectBytes = boundedPositiveInteger(
      input.maximumObjectBytes ?? 512 * 1024 * 1024,
      "maximumObjectBytes",
      2_000_000_000
    );
    this.#maximumChunks = boundedPositiveInteger(
      input.maximumChunks ?? 100_000,
      "maximumChunks",
      1_000_000
    );
    this.#allowlist = validateAllowlist(input.allowlist);
  }

  async load(reference: ImmutableObjectReferenceV1, signal?: AbortSignal): Promise<LoadedImmutableObjectV1> {
    if (signalWasAborted(signal)) {
      throw new AdapterValidationError("INVALID_INPUT", "Object retrieval was cancelled");
    }
    validateStrictKeys(reference, [
      "connectorId",
      "endpointOrigin",
      "bucket",
      "key",
      "versionId",
      "expectedContentHash",
      "mediaType"
    ], "object reference");
    const selected = authorizeReference(reference, this.#allowlist);
    const request: ImmutableObjectRequestV1 = Object.freeze({ ...selected, signal });
    const head = await this.#client.headImmutableObject(request);
    validateHead(head, selected, this.#maximumObjectBytes);
    const body = await this.#client.readImmutableObject(request);
    validateStrictKeys(body, ["versionId", "body"], "object body response");
    if (body.versionId !== selected.versionId || !isAsyncIterable(body.body)) {
      throw new AdapterValidationError(
        "INTEGRITY_FAILURE",
        "Object body response did not preserve the requested immutable version"
      );
    }

    const chunks: Buffer[] = [];
    const digest = createHash("sha256");
    let byteLength = 0;
    let chunkCount = 0;
    for await (const rawChunk of body.body) {
      chunkCount += 1;
      if (chunkCount > this.#maximumChunks) {
        throw new AdapterValidationError("LIMIT_EXCEEDED", "Object body emitted too many chunks");
      }
      if (signalWasAborted(signal)) {
        throw new AdapterValidationError("INVALID_INPUT", "Object retrieval was cancelled");
      }
      if (!(rawChunk instanceof Uint8Array)) {
        throw new AdapterValidationError("DECODER_CONTRACT_VIOLATION", "Object client emitted a non-binary chunk");
      }
      const chunk = Buffer.from(rawChunk);
      if (chunk.byteLength === 0) {
        throw new AdapterValidationError("DECODER_CONTRACT_VIOLATION", "Object client emitted an empty chunk");
      }
      byteLength += chunk.byteLength;
      if (byteLength > this.#maximumObjectBytes || byteLength > head.contentLength) {
        throw new AdapterValidationError("LIMIT_EXCEEDED", "Object body exceeded its declared or configured byte limit");
      }
      digest.update(chunk);
      chunks.push(Buffer.from(chunk));
    }
    if (byteLength !== head.contentLength) {
      throw new AdapterValidationError("INTEGRITY_FAILURE", "Object body length did not match immutable metadata");
    }
    const contentHash = `sha256:${digest.digest("hex")}` as Sha256Hash;
    if (contentHash !== selected.expectedContentHash || (head.contentHash !== undefined && head.contentHash !== contentHash)) {
      throw new AdapterValidationError("INTEGRITY_FAILURE", "Object body content hash did not match immutable metadata");
    }
    const bytes = new Uint8Array(Buffer.concat(chunks, byteLength));
    return Object.freeze({
      bytes,
      evidence: Object.freeze({
        connectorId: selected.connectorId,
        endpointOrigin: selected.endpointOrigin,
        bucket: selected.bucket,
        key: selected.key,
        versionId: selected.versionId,
        mediaType: selected.mediaType,
        byteLength,
        contentHash,
        immutability: Object.freeze({ ...head.immutability })
      })
    });
  }
}

export interface ObjectStorageXlsxIngestionInputV1 {
  readonly object: ImmutableObjectReferenceV1;
  readonly sheetName: string;
  readonly headerRow: number;
  readonly columns: readonly Readonly<AdapterColumnV1>[];
  readonly signal?: AbortSignal;
}

export class ObjectStorageXlsxIngestionAdapterV1
implements BoundedTabularAdapter<ObjectStorageXlsxIngestionInputV1> {
  readonly adapterKind = "xlsx" as const;
  readonly #loader: ImmutableObjectDeliveryLoaderV1;
  readonly #xlsx: BoundedTabularAdapter<XlsxIngestionInputV1>;

  constructor(loader: ImmutableObjectDeliveryLoaderV1, xlsx: BoundedTabularAdapter<XlsxIngestionInputV1>) {
    this.#loader = loader;
    this.#xlsx = xlsx;
  }

  async ingest(input: ObjectStorageXlsxIngestionInputV1): Promise<ConformedDatasetV1> {
    if (input.object.mediaType !== XLSX_MEDIA_TYPE) {
      throw new AdapterValidationError("SCHEMA_MISMATCH", "Object delivery is not declared as XLSX");
    }
    const loaded = await this.#loader.load(input.object, input.signal);
    return this.#xlsx.ingest({
      bytes: loaded.bytes,
      sheetName: input.sheetName,
      headerRow: input.headerRow,
      columns: input.columns,
      expectedSourceContentHash: loaded.evidence.contentHash
    });
  }
}

export interface ObjectStorageParquetIngestionInputV1 {
  readonly object: ImmutableObjectReferenceV1;
  readonly columns: readonly Readonly<AdapterColumnV1>[];
  readonly partitions: readonly Readonly<ParquetPartitionValueV1>[];
  readonly partitionExpectations: readonly Readonly<ParquetPartitionExpectationV1>[];
  readonly signal?: AbortSignal;
}

export class ObjectStorageParquetIngestionAdapterV1
implements BoundedTabularAdapter<ObjectStorageParquetIngestionInputV1> {
  readonly adapterKind = "parquet" as const;
  readonly #loader: ImmutableObjectDeliveryLoaderV1;
  readonly #parquet: BoundedTabularAdapter<ParquetIngestionInputV1>;

  constructor(
    loader: ImmutableObjectDeliveryLoaderV1,
    parquet: BoundedTabularAdapter<ParquetIngestionInputV1>
  ) {
    this.#loader = loader;
    this.#parquet = parquet;
  }

  async ingest(input: ObjectStorageParquetIngestionInputV1): Promise<ConformedDatasetV1> {
    if (input.object.mediaType !== PARQUET_MEDIA_TYPE) {
      throw new AdapterValidationError("SCHEMA_MISMATCH", "Object delivery is not declared as Parquet");
    }
    const loaded = await this.#loader.load(input.object, input.signal);
    return this.#parquet.ingest({
      bytes: loaded.bytes,
      columns: input.columns,
      partitions: input.partitions,
      partitionExpectations: input.partitionExpectations,
      expectedSourceContentHash: loaded.evidence.contentHash
    });
  }
}

function authorizeReference(
  reference: ImmutableObjectReferenceV1,
  allowlist: ReadonlyMap<string, Readonly<ObjectStorageConnectorAllowlistV1>>
): ImmutableObjectReferenceV1 {
  validateConnectorId(reference.connectorId);
  const endpointOrigin = canonicalEndpointOrigin(reference.endpointOrigin);
  const connector = allowlist.get(reference.connectorId);
  if (connector === undefined || connector.endpointOrigin !== endpointOrigin) {
    throw new AdapterValidationError("DELIVERY_NOT_ALLOWED", "Object-storage connector or endpoint is not allowlisted");
  }
  validateBucket(reference.bucket);
  const bucket = connector.buckets.find((candidate) => candidate.bucket === reference.bucket);
  if (bucket === undefined || !bucket.mediaTypes.includes(reference.mediaType)) {
    throw new AdapterValidationError("DELIVERY_NOT_ALLOWED", "Object-storage bucket or media type is not allowlisted");
  }
  const key = validateObjectKey(reference.key);
  if (!bucket.keyPrefixes.some((prefix) => key.startsWith(prefix))) {
    throw new AdapterValidationError("DELIVERY_NOT_ALLOWED", "Object key is outside all governed prefixes");
  }
  const versionId = validateVersionId(reference.versionId);
  validateHash(reference.expectedContentHash, "expectedContentHash");
  if (reference.mediaType !== XLSX_MEDIA_TYPE && reference.mediaType !== PARQUET_MEDIA_TYPE) {
    throw new AdapterValidationError("DELIVERY_NOT_ALLOWED", "Object media type is unsupported");
  }
  return Object.freeze({ ...reference, endpointOrigin, key, versionId });
}

function validateHead(
  head: ImmutableObjectHeadV1,
  reference: ImmutableObjectReferenceV1,
  maximumObjectBytes: number
): void {
  validateStrictKeys(head, [
    "connectorId",
    "endpointOrigin",
    "bucket",
    "key",
    "versionId",
    "contentLength",
    "contentType",
    "contentHash",
    "immutability"
  ], "object head response", ["contentHash"]);
  if (
    head.connectorId !== reference.connectorId ||
    head.endpointOrigin !== reference.endpointOrigin ||
    head.bucket !== reference.bucket ||
    head.key !== reference.key ||
    head.versionId !== reference.versionId ||
    head.contentType !== reference.mediaType
  ) {
    throw new AdapterValidationError("INTEGRITY_FAILURE", "Object metadata did not match the exact requested version");
  }
  if (!Number.isSafeInteger(head.contentLength) || head.contentLength < 1 || head.contentLength > maximumObjectBytes) {
    throw new AdapterValidationError("LIMIT_EXCEEDED", "Object content length is outside policy");
  }
  if (head.contentHash !== undefined) validateHash(head.contentHash, "head.contentHash");
  assertPlainObject(head.immutability, "object immutability evidence");
  if (head.immutability.versionId !== reference.versionId) {
    throw new AdapterValidationError("INTEGRITY_FAILURE", "Object immutability evidence has a different version ID");
  }
  if (head.immutability.mode === "version_id") {
    validateStrictKeys(head.immutability, ["mode", "versionId"], "version immutability evidence");
  } else if (head.immutability.mode === "compliance_lock") {
    validateStrictKeys(head.immutability, ["mode", "versionId", "retainUntil"], "lock immutability evidence");
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(head.immutability.retainUntil)) {
      throw new AdapterValidationError("INTEGRITY_FAILURE", "Object retention lock timestamp is not canonical UTC");
    }
  } else {
    throw new AdapterValidationError("INTEGRITY_FAILURE", "Object version lacks immutable delivery evidence");
  }
}

function validateAllowlist(
  input: readonly Readonly<ObjectStorageConnectorAllowlistV1>[]
): ReadonlyMap<string, Readonly<ObjectStorageConnectorAllowlistV1>> {
  if (!Array.isArray(input) || input.length < 1 || input.length > 1_000) {
    throw new AdapterValidationError("INVALID_INPUT", "Object-storage allowlist is empty or unbounded");
  }
  const output = new Map<string, Readonly<ObjectStorageConnectorAllowlistV1>>();
  for (const connector of input) {
    validateStrictKeys(connector, ["connectorId", "endpointOrigin", "buckets"], "connector allowlist entry");
    validateConnectorId(connector.connectorId);
    if (output.has(connector.connectorId)) {
      throw new AdapterValidationError("INVALID_INPUT", `Duplicate connector '${connector.connectorId}'`);
    }
    const endpointOrigin = canonicalEndpointOrigin(connector.endpointOrigin);
    if (!Array.isArray(connector.buckets) || connector.buckets.length < 1 || connector.buckets.length > 1_000) {
      throw new AdapterValidationError("INVALID_INPUT", `Connector '${connector.connectorId}' has invalid buckets`);
    }
    const bucketNames = new Set<string>();
    const buckets = connector.buckets.map((bucket: Readonly<ObjectStorageBucketAllowlistV1>) => {
      validateStrictKeys(bucket, ["bucket", "keyPrefixes", "mediaTypes"], "bucket allowlist entry");
      validateBucket(bucket.bucket);
      if (bucketNames.has(bucket.bucket)) throw new AdapterValidationError("INVALID_INPUT", `Duplicate bucket '${bucket.bucket}'`);
      bucketNames.add(bucket.bucket);
      if (!Array.isArray(bucket.keyPrefixes) || bucket.keyPrefixes.length < 1 || bucket.keyPrefixes.length > 256) {
        throw new AdapterValidationError("INVALID_INPUT", `Bucket '${bucket.bucket}' has invalid key prefixes`);
      }
      const keyPrefixes = bucket.keyPrefixes.map(validateKeyPrefix);
      if (new Set(keyPrefixes).size !== keyPrefixes.length) {
        throw new AdapterValidationError("INVALID_INPUT", `Bucket '${bucket.bucket}' has duplicate key prefixes`);
      }
      if (!Array.isArray(bucket.mediaTypes) || bucket.mediaTypes.length < 1 ||
        bucket.mediaTypes.some((type: string) => type !== XLSX_MEDIA_TYPE && type !== PARQUET_MEDIA_TYPE)) {
        throw new AdapterValidationError("INVALID_INPUT", `Bucket '${bucket.bucket}' has invalid media types`);
      }
      return Object.freeze({
        bucket: bucket.bucket,
        keyPrefixes: Object.freeze(keyPrefixes),
        mediaTypes: Object.freeze([...new Set(bucket.mediaTypes)])
      });
    });
    output.set(connector.connectorId, Object.freeze({ connectorId: connector.connectorId, endpointOrigin, buckets: Object.freeze(buckets) }));
  }
  return output;
}

function canonicalEndpointOrigin(value: string): string {
  if (typeof value !== "string" || value.length > 512) {
    throw new AdapterValidationError("INVALID_INPUT", "Object-storage endpoint is invalid");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new AdapterValidationError("INVALID_INPUT", "Object-storage endpoint is not an absolute URL");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.pathname !== "/" ||
    value !== parsed.origin
  ) {
    throw new AdapterValidationError(
      "INVALID_INPUT",
      "Object-storage endpoint must be an exact credential-free HTTPS origin"
    );
  }
  return parsed.origin;
}

function validateObjectKey(value: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 1_024 ||
    value.startsWith("/") ||
    value.endsWith("/") ||
    value.includes("//") ||
    !/^[A-Za-z0-9!_.*'()=+\/-]+$/.test(value) ||
    value.split("/").some((segment) => segment === "." || segment === ".." || segment.length === 0)
  ) {
    throw new AdapterValidationError("INVALID_INPUT", "Object key is not a portable governed key");
  }
  return value;
}

function validateKeyPrefix(value: string): string {
  if (typeof value !== "string" || !value.endsWith("/")) {
    throw new AdapterValidationError("INVALID_INPUT", "Object key prefix must end with '/'");
  }
  const testKey = `${value}object`;
  validateObjectKey(testKey);
  return value;
}

function validateBucket(value: string): void {
  if (
    typeof value !== "string" ||
    value.length < 3 ||
    value.length > 63 ||
    !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/.test(value) ||
    value.includes("..") ||
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)
  ) {
    throw new AdapterValidationError("INVALID_INPUT", "Object-storage bucket name is not DNS-safe");
  }
}

function validateVersionId(value: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 512 ||
    /[ -]/u.test(value) ||
    value === "null" ||
    value.toLowerCase() === "latest"
  ) {
    throw new AdapterValidationError("INVALID_INPUT", "An immutable non-null object version ID is required");
  }
  return value;
}

function validateConnectorId(value: string): void {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) {
    throw new AdapterValidationError("INVALID_INPUT", "Object-storage connector ID is not portable");
  }
}

function validateHash(value: string, label: string): asserts value is Sha256Hash {
  if (!/^sha256:[a-f0-9]{64}$/.test(value)) {
    throw new AdapterValidationError("INVALID_INPUT", `${label} must be a lowercase sha256: hash`);
  }
}

function validateStrictKeys(
  value: unknown,
  allowedKeys: readonly string[],
  label: string,
  optionalKeys: readonly string[] = []
): void {
  assertPlainObject(value, label);
  const actual = Object.keys(value as object);
  const allowed = new Set(allowedKeys);
  const optional = new Set(optionalKeys);
  if (actual.some((key) => !allowed.has(key)) || allowedKeys.some((key) => !optional.has(key) && !actual.includes(key))) {
    throw new AdapterValidationError("INVALID_INPUT", `${label} contains missing or unapproved fields`);
  }
}

function assertPlainObject(value: unknown, label: string): void {
  if (value === null || typeof value !== "object") {
    throw new AdapterValidationError("DECODER_CONTRACT_VIOLATION", `${label} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value) as object | null;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new AdapterValidationError("DECODER_CONTRACT_VIOLATION", `${label} must be a plain object`);
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new AdapterValidationError("DECODER_CONTRACT_VIOLATION", `${label} contains symbol keys`);
  }
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (descriptor.get !== undefined || descriptor.set !== undefined) {
      throw new AdapterValidationError("DECODER_CONTRACT_VIOLATION", `${label} contains accessors`);
    }
  }
}

function isAsyncIterable(value: unknown): value is AsyncIterable<Uint8Array> {
  return value !== null && typeof value === "object" &&
    typeof (value as { readonly [Symbol.asyncIterator]?: unknown })[Symbol.asyncIterator] === "function";
}

function signalWasAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted ?? false;
}
