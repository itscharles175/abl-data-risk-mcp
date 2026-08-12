import assert from "node:assert/strict";
import { test } from "node:test";

import { canonicalHash } from "../src/contracts/canonical.js";
import {
  AdapterValidationError,
  ImmutableObjectDeliveryLoaderV1,
  ObjectStorageXlsxIngestionAdapterV1,
  XLSX_MEDIA_TYPE,
  createConformedDataset,
  sha256Bytes,
  type BoundedTabularAdapter,
  type ImmutableObjectClientPortV1,
  type ImmutableObjectHeadV1,
  type ImmutableObjectReferenceV1,
  type ImmutableObjectRequestV1,
  type XlsxIngestionInputV1
} from "../src/adapters/index.js";

const BYTES = Buffer.from("immutable object payload", "utf8");
const HASH = sha256Bytes(BYTES);

test("object-storage delivery uses an exact allowlist, immutable version and streamed content hash", async () => {
  const requests: ImmutableObjectRequestV1[] = [];
  const client = clientPort({ requests });
  const loader = loaderFor(client);
  const controller = new AbortController();
  const loaded = await loader.load(reference(), controller.signal);

  assert.deepEqual(Buffer.from(loaded.bytes), BYTES);
  assert.equal(loaded.evidence.contentHash, HASH);
  assert.equal(loaded.evidence.versionId, "v1+opaque=");
  assert.equal(loaded.evidence.byteLength, BYTES.byteLength);
  assert.equal(Object.isFrozen(loaded.evidence), true);
  assert.equal(requests.length, 2);
  assert.deepEqual(Object.keys(requests[0]!).sort(), [
    "bucket", "connectorId", "endpointOrigin", "expectedContentHash", "key", "mediaType", "signal", "versionId"
  ]);
  assert.equal(requests[0]!.signal, controller.signal);
  assert.equal(JSON.stringify(requests).includes("credential"), false);
});

test("object-storage delivery denies arbitrary endpoints, buckets, keys, versions and credential fields", async () => {
  let calls = 0;
  const client = clientPort({ onCall: () => { calls += 1; } });
  const loader = loaderFor(client);
  const rejected: readonly [Partial<ImmutableObjectReferenceV1>, AdapterValidationError["code"]][] = [
    [{ endpointOrigin: "https://evil.example.test" }, "DELIVERY_NOT_ALLOWED"],
    [{ bucket: "other-bucket" }, "DELIVERY_NOT_ALLOWED"],
    [{ key: "tenants/other/tape.xlsx" }, "DELIVERY_NOT_ALLOWED"],
    [{ key: "tenants/acme/../other/tape.xlsx" }, "INVALID_INPUT"],
    [{ versionId: "null" }, "INVALID_INPUT"]
  ];
  for (const [override, code] of rejected) {
    await assert.rejects(
      loader.load({ ...reference(), ...override }),
      (error: unknown) => {
        assert.ok(error instanceof AdapterValidationError);
        assert.equal(error.code, code);
        return true;
      }
    );
  }
  const withCredential = { ...reference(), credentialRef: "secret://must-not-pass" };
  await assert.rejects(
    loader.load(withCredential as ImmutableObjectReferenceV1),
    (error: unknown) => adapterError(error, "INVALID_INPUT", /unapproved fields/)
  );
  assert.equal(calls, 0);
});

test("object-storage delivery rejects metadata races, truncation and digest mismatches", async () => {
  const wrongVersion = loaderFor(clientPort({
    head: { ...head(), versionId: "different", immutability: { mode: "version_id", versionId: "different" } }
  }));
  await assert.rejects(
    wrongVersion.load(reference()),
    (error: unknown) => adapterError(error, "INTEGRITY_FAILURE", /exact requested version/)
  );

  const truncated = loaderFor(clientPort({
    head: { ...head(), contentLength: BYTES.byteLength + 1 }
  }));
  await assert.rejects(
    truncated.load(reference()),
    (error: unknown) => adapterError(error, "INTEGRITY_FAILURE", /length did not match/)
  );

  const badDigestReference = { ...reference(), expectedContentHash: `sha256:${"0".repeat(64)}` as const };
  await assert.rejects(
    loaderFor(clientPort()).load(badDigestReference),
    (error: unknown) => adapterError(error, "INTEGRITY_FAILURE", /content hash/)
  );

  const overrun = loaderFor(clientPort({
    head: { ...head(), contentLength: 4 }
  }));
  await assert.rejects(
    overrun.load(reference()),
    (error: unknown) => adapterError(error, "LIMIT_EXCEEDED", /declared or configured byte limit/)
  );
});

test("object-storage wrapper binds the verified hash into the format adapter", async () => {
  let delegated: XlsxIngestionInputV1 | undefined;
  const xlsx: BoundedTabularAdapter<XlsxIngestionInputV1> = {
    adapterKind: "xlsx",
    async ingest(input) {
      delegated = input;
      return createConformedDataset({
        adapterKind: "xlsx",
        sourceMediaType: XLSX_MEDIA_TYPE,
        sourceContentHash: input.expectedSourceContentHash!,
        parser: {
          parserId: "fixture",
          parserVersion: "1",
          optionsHash: canonicalHash({ fixture: true })
        },
        columns: input.columns,
        records: [{ loan_id: "LN-001" }],
        limits: { maximumRows: 10, maximumColumns: 10, maximumCellCharacters: 100 }
      });
    }
  };
  const adapter = new ObjectStorageXlsxIngestionAdapterV1(
    loaderFor(clientPort()),
    xlsx
  );
  const result = await adapter.ingest({
    object: reference(),
    sheetName: "Loan Tape",
    headerRow: 1,
    columns: [{ name: "loan_id", logicalType: "text", nullable: false }]
  });

  assert.equal(delegated?.expectedSourceContentHash, HASH);
  assert.deepEqual(Buffer.from(delegated!.bytes), BYTES);
  assert.equal(result.sourceContentHash, HASH);
});

function loaderFor(client: ImmutableObjectClientPortV1): ImmutableObjectDeliveryLoaderV1 {
  return new ImmutableObjectDeliveryLoaderV1({
    client,
    maximumObjectBytes: 1_000,
    allowlist: [{
      connectorId: "s3-client-vpc",
      endpointOrigin: "https://objects.example.test",
      buckets: [{
        bucket: "client-risk-data",
        keyPrefixes: ["tenants/acme/"],
        mediaTypes: [XLSX_MEDIA_TYPE]
      }]
    }]
  });
}

function reference(): ImmutableObjectReferenceV1 {
  return {
    connectorId: "s3-client-vpc",
    endpointOrigin: "https://objects.example.test",
    bucket: "client-risk-data",
    key: "tenants/acme/tape.xlsx",
    versionId: "v1+opaque=",
    expectedContentHash: HASH,
    mediaType: XLSX_MEDIA_TYPE
  };
}

function head(): ImmutableObjectHeadV1 {
  const ref = reference();
  return {
    connectorId: ref.connectorId,
    endpointOrigin: ref.endpointOrigin,
    bucket: ref.bucket,
    key: ref.key,
    versionId: ref.versionId,
    contentLength: BYTES.byteLength,
    contentType: XLSX_MEDIA_TYPE,
    contentHash: HASH,
    immutability: { mode: "version_id", versionId: ref.versionId }
  };
}

function clientPort(overrides: {
  readonly head?: ImmutableObjectHeadV1;
  readonly requests?: ImmutableObjectRequestV1[];
  readonly onCall?: () => void;
} = {}): ImmutableObjectClientPortV1 {
  return {
    async headImmutableObject(request) {
      overrides.requests?.push(request);
      overrides.onCall?.();
      return overrides.head ?? head();
    },
    async readImmutableObject(request) {
      overrides.requests?.push(request);
      overrides.onCall?.();
      return {
        versionId: request.versionId,
        body: (async function* () {
          yield BYTES.subarray(0, 7);
          yield BYTES.subarray(7);
        })()
      };
    }
  };
}

function adapterError(
  error: unknown,
  code: AdapterValidationError["code"],
  message: RegExp
): boolean {
  assert.ok(error instanceof AdapterValidationError);
  assert.equal(error.code, code);
  assert.match(error.message, message);
  return true;
}
