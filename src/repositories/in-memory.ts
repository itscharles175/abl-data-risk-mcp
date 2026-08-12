import { createHash } from "node:crypto";

import {
  canonicalHash,
  canonicalJson,
  deepFreeze,
  parseBlockedInputPopulationV1,
  parseCertifiedInputPopulationV1,
  parseDatasetSnapshotV2,
  parseMappingApplicationV1,
  parseMappingSpecV2,
  parseSourceContractV1,
  type DatasetSnapshotV2,
  type InputPopulationV1,
  type MappingApplicationV1,
  type MappingSpecV2,
  type SourceContractV1,
  type Sha256Hash
} from "../contracts/index.js";
import type {
  AlertRepositoryPort,
  AlertRepositoryRecordV1,
  AppendAuditEventCommandV1,
  ArtifactMetadataV1,
  ArtifactRepositoryPort,
  AuditEventRecordV1,
  AuditRepositoryPort,
  ControlRepositoryPort,
  DefinitionRepositoryPort,
  DefinitionRepositoryRecordV1,
  FoundationRepositoryPorts,
  ImmutableRepositoryPort,
  JobRepositoryPort,
  JobRepositoryRecordV1,
  MembershipRepositoryPort,
  MembershipRepositoryRecordV1,
  PutArtifactCommandV1,
  RepositoryPage,
  RepositoryPageRequest,
  RepositoryPutResult,
  RepositoryWriteContext,
  RevisionedTenantRecord,
  SecurityRepositoryPort,
  SecurityRepositoryRecordV1,
  TenantRecord,
  VersionedRepositoryPort
} from "./ports.js";
import { RepositoryError } from "./ports.js";

interface IdempotencyReceipt {
  readonly requestHash: Sha256Hash;
  readonly recordId: string;
  readonly revision?: number;
}

type RecordValidator<T> = (record: T) => void;

export class InMemoryImmutableRepository<T extends TenantRecord>
  implements ImmutableRepositoryPort<T>
{
  readonly #namespace: string;
  readonly #recordId: (record: T) => string;
  readonly #validate: RecordValidator<T>;
  readonly #records = new Map<string, T>();
  readonly #receipts = new Map<string, IdempotencyReceipt>();

  constructor(
    namespace: string,
    recordId: (record: T) => string,
    validate: RecordValidator<T> = () => undefined
  ) {
    this.#namespace = requiredText(namespace, "repository namespace");
    this.#recordId = recordId;
    this.#validate = validate;
  }

  async put(record: T, context: RepositoryWriteContext): Promise<RepositoryPutResult<T>> {
    validateContext(record, context);
    this.#validate(record);
    const frozen = cloneCanonical(record);
    const recordId = requiredText(this.#recordId(frozen), "record id");
    const requestHash = canonicalHash({ actorId: context.actorId, record: frozen });
    const receiptKey = scoped(context.tenantId, context.idempotencyKey);
    const receipt = this.#receipts.get(receiptKey);
    if (receipt) {
      if (receipt.requestHash !== requestHash || receipt.recordId !== recordId) {
        throw new RepositoryError("IDEMPOTENCY_CONFLICT", "Idempotency key was used for a different write");
      }
      const replay = this.#records.get(scoped(context.tenantId, recordId));
      if (!replay) throw new RepositoryError("INTEGRITY_FAILURE", "Idempotency receipt has no stored record");
      return Object.freeze({ record: cloneCanonical(replay), replayed: true });
    }
    const key = scoped(record.tenantId, recordId);
    if (this.#records.has(key)) {
      throw new RepositoryError("ALREADY_EXISTS", "Immutable record already exists");
    }
    this.#records.set(key, frozen);
    this.#receipts.set(receiptKey, Object.freeze({ requestHash, recordId }));
    return Object.freeze({ record: cloneCanonical(frozen), replayed: false });
  }

  async get(tenantId: string, recordId: string): Promise<T | undefined> {
    validateLookup(tenantId, recordId);
    const value = this.#records.get(scoped(tenantId, recordId));
    return value === undefined ? undefined : cloneCanonical(value);
  }

  async list(tenantId: string, page: RepositoryPageRequest = {}): Promise<RepositoryPage<T>> {
    requiredText(tenantId, "tenant id");
    const { limit, afterId } = decodePage(this.#namespace, page);
    const records = [...this.#records.entries()]
      .filter(([key]) => key.startsWith(`${tenantId}\u0000`))
      .map(([key, record]) => ({ id: key.slice(tenantId.length + 1), record }))
      .filter(({ id }) => afterId === undefined || id > afterId)
      .sort((left, right) => compare(left.id, right.id));
    const selected = records.slice(0, limit);
    const nextCursor =
      records.length > selected.length && selected.length > 0
        ? encodeCursor(this.#namespace, selected[selected.length - 1]!.id)
        : null;
    return Object.freeze({
      items: Object.freeze(selected.map(({ record }) => cloneCanonical(record))),
      nextCursor
    });
  }
}

export class InMemoryVersionedRepository<T extends RevisionedTenantRecord>
  implements VersionedRepositoryPort<T>
{
  readonly #namespace: string;
  readonly #recordId: (record: T) => string;
  readonly #validate: RecordValidator<T>;
  readonly #history = new Map<string, Map<number, T>>();
  readonly #receipts = new Map<string, IdempotencyReceipt>();

  constructor(
    namespace: string,
    recordId: (record: T) => string,
    validate: RecordValidator<T> = () => undefined
  ) {
    this.#namespace = requiredText(namespace, "repository namespace");
    this.#recordId = recordId;
    this.#validate = validate;
  }

  async put(record: T, context: RepositoryWriteContext): Promise<RepositoryPutResult<T>> {
    validateContext(record, context);
    if (!Number.isSafeInteger(record.revision) || record.revision < 1) {
      throw new RepositoryError("INVALID_ARGUMENT", "Record revision must be a positive safe integer");
    }
    this.#validate(record);
    const frozen = cloneCanonical(record);
    const recordId = requiredText(this.#recordId(frozen), "record id");
    const requestHash = canonicalHash({
      actorId: context.actorId,
      expectedRevision: context.expectedRevision ?? null,
      record: frozen
    });
    const receiptKey = scoped(context.tenantId, context.idempotencyKey);
    const receipt = this.#receipts.get(receiptKey);
    if (receipt) {
      if (
        receipt.requestHash !== requestHash ||
        receipt.recordId !== recordId ||
        receipt.revision !== record.revision
      ) {
        throw new RepositoryError("IDEMPOTENCY_CONFLICT", "Idempotency key was used for a different write");
      }
      const replay = this.#history.get(scoped(context.tenantId, recordId))?.get(record.revision);
      if (!replay) throw new RepositoryError("INTEGRITY_FAILURE", "Idempotency receipt has no stored revision");
      return Object.freeze({ record: cloneCanonical(replay), replayed: true });
    }

    const key = scoped(record.tenantId, recordId);
    const history = this.#history.get(key) ?? new Map<number, T>();
    const currentRevision = Math.max(0, ...history.keys());
    if (currentRevision === 0) {
      if (record.revision !== 1 || (context.expectedRevision !== undefined && context.expectedRevision !== 0)) {
        throw new RepositoryError("CONCURRENCY_CONFLICT", "Initial record must be revision 1 with expected revision 0");
      }
    } else if (
      context.expectedRevision !== currentRevision ||
      record.revision !== currentRevision + 1
    ) {
      throw new RepositoryError(
        "CONCURRENCY_CONFLICT",
        `Update must expect revision ${currentRevision} and write revision ${currentRevision + 1}`
      );
    }
    history.set(record.revision, frozen);
    this.#history.set(key, history);
    this.#receipts.set(
      receiptKey,
      Object.freeze({ requestHash, recordId, revision: record.revision })
    );
    return Object.freeze({ record: cloneCanonical(frozen), replayed: false });
  }

  async getCurrent(tenantId: string, recordId: string): Promise<T | undefined> {
    validateLookup(tenantId, recordId);
    const history = this.#history.get(scoped(tenantId, recordId));
    if (!history) return undefined;
    const revision = Math.max(...history.keys());
    return cloneCanonical(required(history.get(revision)));
  }

  async getRevision(tenantId: string, recordId: string, revision: number): Promise<T | undefined> {
    validateLookup(tenantId, recordId);
    if (!Number.isSafeInteger(revision) || revision < 1) {
      throw new RepositoryError("INVALID_ARGUMENT", "Revision must be a positive safe integer");
    }
    const value = this.#history.get(scoped(tenantId, recordId))?.get(revision);
    return value === undefined ? undefined : cloneCanonical(value);
  }

  async listCurrent(
    tenantId: string,
    page: RepositoryPageRequest = {}
  ): Promise<RepositoryPage<T>> {
    requiredText(tenantId, "tenant id");
    const { limit, afterId } = decodePage(this.#namespace, page);
    const records = [...this.#history.entries()]
      .filter(([key]) => key.startsWith(`${tenantId}\u0000`))
      .map(([key, history]) => ({
        id: key.slice(tenantId.length + 1),
        record: required(history.get(Math.max(...history.keys())))
      }))
      .filter(({ id }) => afterId === undefined || id > afterId)
      .sort((left, right) => compare(left.id, right.id));
    const selected = records.slice(0, limit);
    const nextCursor =
      records.length > selected.length && selected.length > 0
        ? encodeCursor(this.#namespace, selected[selected.length - 1]!.id)
        : null;
    return Object.freeze({
      items: Object.freeze(selected.map(({ record }) => cloneCanonical(record))),
      nextCursor
    });
  }

  async listHistory(tenantId: string, recordId: string): Promise<readonly T[]> {
    validateLookup(tenantId, recordId);
    const history = this.#history.get(scoped(tenantId, recordId));
    if (!history) return Object.freeze([]);
    return Object.freeze(
      [...history.entries()]
        .sort(([left], [right]) => left - right)
        .map(([, record]) => cloneCanonical(record))
    );
  }
}

export class InMemoryArtifactRepository implements ArtifactRepositoryPort {
  readonly #metadata = new InMemoryImmutableRepository<ArtifactMetadataV1>(
    "artifacts",
    (record) => record.artifactId
  );
  readonly #bytes = new Map<string, Uint8Array>();

  async put(
    command: PutArtifactCommandV1,
    context: RepositoryWriteContext
  ): Promise<RepositoryPutResult<ArtifactMetadataV1>> {
    if (!(command.bytes instanceof Uint8Array)) {
      throw new RepositoryError("INVALID_ARGUMENT", "Artifact bytes must be a Uint8Array");
    }
    const actualHash = `sha256:${createHash("sha256").update(command.bytes).digest("hex")}`;
    if (
      command.metadata.byteLength !== command.bytes.byteLength ||
      command.metadata.contentHash !== actualHash
    ) {
      throw new RepositoryError("INTEGRITY_FAILURE", "Artifact bytes do not match immutable metadata");
    }
    const result = await this.#metadata.put(command.metadata, context);
    const key = scoped(command.metadata.tenantId, command.metadata.artifactId);
    const existing = this.#bytes.get(key);
    if (existing && !equalBytes(existing, command.bytes)) {
      throw new RepositoryError("INTEGRITY_FAILURE", "Artifact replay bytes changed");
    }
    if (!existing) this.#bytes.set(key, Uint8Array.from(command.bytes));
    return result;
  }

  getMetadata(tenantId: string, artifactId: string): Promise<ArtifactMetadataV1 | undefined> {
    return this.#metadata.get(tenantId, artifactId);
  }

  async read(tenantId: string, artifactId: string): Promise<Uint8Array | undefined> {
    validateLookup(tenantId, artifactId);
    const bytes = this.#bytes.get(scoped(tenantId, artifactId));
    return bytes === undefined ? undefined : Uint8Array.from(bytes);
  }

  list(tenantId: string, page: RepositoryPageRequest = {}): Promise<RepositoryPage<ArtifactMetadataV1>> {
    return this.#metadata.list(tenantId, page);
  }
}

export class InMemoryAuditRepository implements AuditRepositoryPort {
  readonly #events = new Map<string, AuditEventRecordV1[]>();
  readonly #eventIds = new Set<string>();
  readonly #receipts = new Map<string, { readonly requestHash: Sha256Hash; readonly sequence: number }>();

  async append(
    command: AppendAuditEventCommandV1,
    context: RepositoryWriteContext
  ): Promise<RepositoryPutResult<AuditEventRecordV1>> {
    validateContext(command, context);
    if (command.actorId !== context.actorId) {
      throw new RepositoryError("INVALID_ARGUMENT", "Audit actor must match the write context actor");
    }
    const requestHash = canonicalHash(command);
    const receiptKey = scoped(context.tenantId, context.idempotencyKey);
    const existingReceipt = this.#receipts.get(receiptKey);
    const tenantEvents = this.#events.get(command.tenantId) ?? [];
    if (existingReceipt) {
      if (existingReceipt.requestHash !== requestHash) {
        throw new RepositoryError("IDEMPOTENCY_CONFLICT", "Idempotency key was used for a different audit event");
      }
      const replay = tenantEvents.find((event) => event.sequence === existingReceipt.sequence);
      if (!replay) throw new RepositoryError("INTEGRITY_FAILURE", "Audit receipt has no event");
      return Object.freeze({ record: cloneCanonical(replay), replayed: true });
    }
    const eventKey = scoped(command.tenantId, requiredText(command.eventId, "event id"));
    if (this.#eventIds.has(eventKey)) throw new RepositoryError("ALREADY_EXISTS", "Audit event id already exists");
    const previousEventHash = tenantEvents.at(-1)?.eventHash ?? null;
    const sequence = (tenantEvents.at(-1)?.sequence ?? 0) + 1;
    const body = { ...command, sequence, previousEventHash };
    const event = cloneCanonical({ ...body, eventHash: canonicalHash(body) }) as AuditEventRecordV1;
    tenantEvents.push(event);
    this.#events.set(command.tenantId, tenantEvents);
    this.#eventIds.add(eventKey);
    this.#receipts.set(receiptKey, Object.freeze({ requestHash, sequence }));
    return Object.freeze({ record: cloneCanonical(event), replayed: false });
  }

  async list(tenantId: string, afterSequence = 0, limit = 100): Promise<readonly AuditEventRecordV1[]> {
    requiredText(tenantId, "tenant id");
    if (!Number.isSafeInteger(afterSequence) || afterSequence < 0) {
      throw new RepositoryError("INVALID_ARGUMENT", "afterSequence must be a non-negative safe integer");
    }
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      throw new RepositoryError("INVALID_ARGUMENT", "Audit limit must be between 1 and 1000");
    }
    return Object.freeze(
      (this.#events.get(tenantId) ?? [])
        .filter((event) => event.sequence > afterSequence)
        .slice(0, limit)
        .map(cloneCanonical)
    );
  }
}

export class InMemoryFoundationRepositories implements FoundationRepositoryPorts {
  readonly control: ControlRepositoryPort;
  readonly definitions: DefinitionRepositoryPort;
  readonly memberships: MembershipRepositoryPort;
  readonly jobs: JobRepositoryPort;
  readonly alerts: AlertRepositoryPort;
  readonly security: SecurityRepositoryPort;
  readonly artifacts: ArtifactRepositoryPort;
  readonly audit: AuditRepositoryPort;

  constructor() {
    this.control = Object.freeze({
      sourceContracts: new InMemoryImmutableRepository<SourceContractV1>(
        "control.source-contracts",
        (record) => `${record.sourceContractId}@${record.revision}`,
        parseSourceContractV1
      ),
      datasetSnapshots: new InMemoryImmutableRepository<DatasetSnapshotV2>(
        "control.dataset-snapshots",
        (record) => record.snapshotId,
        parseDatasetSnapshotV2
      ),
      mappingSpecs: new InMemoryImmutableRepository<MappingSpecV2>(
        "control.mapping-specs",
        (record) => `${record.mappingSpecId}@${record.revision}`,
        parseMappingSpecV2
      ),
      mappingApplications: new InMemoryImmutableRepository<MappingApplicationV1>(
        "control.mapping-applications",
        (record) => record.mappingApplicationId,
        parseMappingApplicationV1
      ),
      inputPopulations: new InMemoryImmutableRepository<InputPopulationV1>(
        "control.input-populations",
        (record) => record.populationId,
        validatePopulation
      )
    });
    this.definitions = Object.freeze({
      records: new InMemoryVersionedRepository<DefinitionRepositoryRecordV1>(
        "definitions",
        (record) => record.definitionId,
        (record) => assertEmbeddedHash(record.document, record.documentHash, "definition document")
      )
    });
    this.memberships = Object.freeze({
      records: new InMemoryVersionedRepository<MembershipRepositoryRecordV1>(
        "memberships",
        (record) => record.membershipId
      )
    });
    this.jobs = Object.freeze({
      records: new InMemoryVersionedRepository<JobRepositoryRecordV1>(
        "jobs",
        (record) => record.jobId,
        (record) => assertEmbeddedHash(record.request, record.requestHash, "job request")
      )
    });
    this.alerts = Object.freeze({
      records: new InMemoryVersionedRepository<AlertRepositoryRecordV1>(
        "alerts",
        (record) => record.alertId,
        (record) => assertEmbeddedHash(record.evidence, record.evidenceHash, "alert evidence")
      )
    });
    this.security = Object.freeze({
      records: new InMemoryVersionedRepository<SecurityRepositoryRecordV1>(
        "security",
        (record) => record.securityRecordId
      )
    });
    this.artifacts = new InMemoryArtifactRepository();
    this.audit = new InMemoryAuditRepository();
  }
}

function validatePopulation(record: InputPopulationV1): void {
  if (record.certificationStatus === "certified") parseCertifiedInputPopulationV1(record);
  else parseBlockedInputPopulationV1(record);
}

function assertEmbeddedHash(value: unknown, expected: Sha256Hash, label: string): void {
  if (canonicalHash(value) !== expected) {
    throw new RepositoryError("INTEGRITY_FAILURE", `${label} hash did not match its content`);
  }
}

function validateContext(record: TenantRecord, context: RepositoryWriteContext): void {
  requiredText(record.tenantId, "record tenant id");
  requiredText(context.tenantId, "context tenant id");
  requiredText(context.actorId, "actor id");
  requiredText(context.idempotencyKey, "idempotency key");
  if (record.tenantId !== context.tenantId) {
    throw new RepositoryError("INVALID_ARGUMENT", "Record tenant must match write context tenant");
  }
}

function validateLookup(tenantId: string, recordId: string): void {
  requiredText(tenantId, "tenant id");
  requiredText(recordId, "record id");
}

function decodePage(
  namespace: string,
  page: RepositoryPageRequest
): { readonly limit: number; readonly afterId?: string } {
  const limit = page.limit ?? 100;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
    throw new RepositoryError("INVALID_ARGUMENT", "Page limit must be between 1 and 1000");
  }
  if (page.cursor === undefined) return { limit };
  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(page.cursor, "base64url").toString("utf8"));
  } catch {
    throw new RepositoryError("INVALID_ARGUMENT", "Repository cursor is invalid");
  }
  if (
    !decoded ||
    typeof decoded !== "object" ||
    Object.keys(decoded).length !== 2 ||
    (decoded as Record<string, unknown>).namespace !== namespace ||
    typeof (decoded as Record<string, unknown>).afterId !== "string"
  ) {
    throw new RepositoryError("INVALID_ARGUMENT", "Repository cursor is invalid for this collection");
  }
  return { limit, afterId: requiredText((decoded as { afterId: string }).afterId, "cursor record id") };
}

function encodeCursor(namespace: string, afterId: string): string {
  return Buffer.from(canonicalJson({ afterId, namespace }), "utf8").toString("base64url");
}

function cloneCanonical<T>(value: T): T {
  return deepFreeze(JSON.parse(canonicalJson(value)) as T);
}

function requiredText(value: string, label: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 1_024 || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new RepositoryError("INVALID_ARGUMENT", `${label} is invalid`);
  }
  return value;
}

function scoped(tenantId: string, value: string): string {
  return `${tenantId}\u0000${value}`;
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw new RepositoryError("INTEGRITY_FAILURE", "Required record is missing");
  return value;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}
