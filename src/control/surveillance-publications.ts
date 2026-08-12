import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  canonicalHash,
  canonicalJson,
  parseCertifiedSnapshotPublicationV1,
  parseWithSchema,
  type CanonicalJsonValue,
  type CertifiedSnapshotPublicationV1,
  type Sha256Hash
} from "../contracts/index.js";
import { migrateSqliteComponent } from "../infrastructure/sqlite-component-schema.js";

export const SURVEILLANCE_PUBLICATION_CATALOG_COMPONENT =
  "abl.surveillance-publication-catalog" as const;
export const SURVEILLANCE_PUBLICATION_CATALOG_SCHEMA_VERSION = 1 as const;

export interface RecordSurveillancePublicationInput {
  readonly publication: CertifiedSnapshotPublicationV1;
  /** Hash of the caller's IDs-only publication request. */
  readonly requestHash: Sha256Hash;
  readonly actor: string;
  readonly idempotencyKey: string;
}

export interface DisableSurveillancePublicationInput {
  readonly tenantId: string;
  readonly publicationId: string;
  readonly expectedPublicationHash: Sha256Hash;
  readonly reasonCode: string;
  readonly reason: string;
  readonly disabledBy: string;
  readonly idempotencyKey: string;
}

export interface SurveillancePublicationDisableEventV1 {
  readonly tenantId: string;
  readonly publicationId: string;
  readonly publicationHash: Sha256Hash;
  readonly reasonCode: string;
  readonly reason: string;
  readonly disabledBy: string;
  readonly disabledAt: string;
}

export interface SurveillancePublicationAuditEventV1 {
  readonly sequence: number;
  readonly tenantSequence: number;
  readonly tenantId: string;
  readonly eventId: string;
  readonly eventType: "surveillance_publication.recorded" | "surveillance_publication.disabled";
  readonly publicationId: string;
  readonly actor: string;
  readonly details: CanonicalJsonValue;
  readonly occurredAt: string;
  readonly previousEventHash: Sha256Hash | null;
  readonly eventHash: Sha256Hash;
}

export interface SurveillancePublicationCatalogOptions {
  readonly clock?: () => Date;
  readonly busyTimeoutMs?: number;
}

export type SurveillancePublicationCatalogErrorCode =
  | "INVALID_INPUT"
  | "NOT_FOUND"
  | "CONFLICT"
  | "IDEMPOTENCY_CONFLICT"
  | "INTEGRITY_FAILURE"
  | "STORE_CLOSED";

export class SurveillancePublicationCatalogError extends Error {
  constructor(readonly code: SurveillancePublicationCatalogErrorCode, message: string) {
    super(message);
    this.name = "SurveillancePublicationCatalogError";
  }
}

/**
 * @internal Immutable persistence primitive. Only a trusted publication
 * service may derive authoritative publication rows; callers cannot register
 * prebuilt certified material through this catalog.
 */
export class SurveillancePublicationCatalog {
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;
  #closed = false;

  constructor(databasePath: string, options: SurveillancePublicationCatalogOptions = {}) {
    if (!databasePath.trim()) invalid("Surveillance publication database path is required");
    const absolute = resolve(databasePath);
    if (databasePath !== ":memory:") mkdirSync(dirname(absolute), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(databasePath === ":memory:" ? databasePath : absolute);
    this.#clock = options.clock ?? (() => new Date());
    const busyTimeoutMs = integer(options.busyTimeoutMs ?? 5_000, "busyTimeoutMs", 0, 60_000);
    try {
      this.#database.exec(
        `PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${busyTimeoutMs};`
      );
      migrateSqliteComponent(this.#database, {
        componentName: SURVEILLANCE_PUBLICATION_CATALOG_COMPONENT,
        supportedVersion: SURVEILLANCE_PUBLICATION_CATALOG_SCHEMA_VERSION,
        migrations: [{ version: 1, sql: SURVEILLANCE_PUBLICATION_CATALOG_SCHEMA }],
        unsupportedVersionError: (current, supported) =>
          new SurveillancePublicationCatalogError(
            "CONFLICT",
            `Surveillance publication schema ${current} is newer than supported version ${supported}`
          )
      });
    } catch (error) {
      this.#database.close();
      throw error;
    }
  }

  record(inputValue: RecordSurveillancePublicationInput): CertifiedSnapshotPublicationV1 {
    this.#assertOpen();
    const input = validateRecord(inputValue);
    return this.#transaction(() => {
      const replay = this.#readReceipt(
        input.publication.tenantId,
        "surveillance_publication.record",
        input.actor,
        input.idempotencyKey,
        input.requestHash
      );
      if (replay) return this.#required(input.publication.tenantId, replay.publicationId);
      if (this.get(input.publication.tenantId, input.publication.publicationId)) {
        conflict("Surveillance publication id already exists in this tenant");
      }
      const publication = input.publication;
      try {
        this.#database
          .prepare(
            `INSERT INTO surveillance_publications (
               tenant_id, publication_id, certification_manifest_id, snapshot_id,
               publication_hash, published_by, published_at, publication_json
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .run(
            publication.tenantId,
            publication.publicationId,
            publication.certification.certificationManifestId,
            publication.snapshot.snapshotId,
            publication.publicationHash,
            publication.publishedBy,
            publication.publishedAt,
            canonicalJson(publication)
          );
      } catch (error) {
        if (isConstraint(error)) {
          conflict("Certification manifest or snapshot already has a surveillance publication");
        }
        throw error;
      }
      this.#appendAudit(
        publication.tenantId,
        publication.publicationId,
        "surveillance_publication.recorded",
        input.actor,
        {
          certificationManifestHash: publication.certification.certificationManifestHash,
          certificationManifestId: publication.certification.certificationManifestId,
          publicationHash: publication.publicationHash,
          snapshotHash: publication.snapshot.snapshotHash,
          snapshotId: publication.snapshot.snapshotId
        },
        publication.publishedAt
      );
      this.#recordReceipt(
        publication.tenantId,
        "surveillance_publication.record",
        input.actor,
        input.idempotencyKey,
        input.requestHash,
        publication.publicationId,
        publication.publishedAt
      );
      return this.#required(publication.tenantId, publication.publicationId);
    });
  }

  disable(inputValue: DisableSurveillancePublicationInput): SurveillancePublicationDisableEventV1 {
    this.#assertOpen();
    const input = validateDisable(inputValue);
    const requestHash = canonicalHash(input);
    return this.#transaction(() => {
      const replay = this.#readReceipt(
        input.tenantId,
        "surveillance_publication.disable",
        input.disabledBy,
        input.idempotencyKey,
        requestHash
      );
      if (replay) return this.#requiredDisable(input.tenantId, replay.publicationId);
      const publication = this.#required(input.tenantId, input.publicationId);
      if (publication.publicationHash !== input.expectedPublicationHash) {
        conflict("Disable request did not bind the immutable publication hash");
      }
      if (this.getDisable(input.tenantId, input.publicationId)) {
        conflict("Surveillance publication is already disabled");
      }
      const disabledAt = this.#now();
      this.#database
        .prepare(
          `INSERT INTO surveillance_publication_disables (
             tenant_id, publication_id, publication_hash, reason_code, reason,
             disabled_by, disabled_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          input.tenantId,
          input.publicationId,
          input.expectedPublicationHash,
          input.reasonCode,
          input.reason,
          input.disabledBy,
          disabledAt
        );
      this.#appendAudit(
        input.tenantId,
        input.publicationId,
        "surveillance_publication.disabled",
        input.disabledBy,
        {
          publicationHash: input.expectedPublicationHash,
          reason: input.reason,
          reasonCode: input.reasonCode
        },
        disabledAt
      );
      this.#recordReceipt(
        input.tenantId,
        "surveillance_publication.disable",
        input.disabledBy,
        input.idempotencyKey,
        requestHash,
        input.publicationId,
        disabledAt
      );
      return this.#requiredDisable(input.tenantId, input.publicationId);
    });
  }

  get(tenantIdValue: string, publicationIdValue: string): CertifiedSnapshotPublicationV1 | undefined {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenantId");
    const publicationId = identifier(publicationIdValue, "publicationId");
    const row = this.#database
      .prepare("SELECT * FROM surveillance_publications WHERE tenant_id = ? AND publication_id = ?")
      .get(tenantId, publicationId) as PublicationRow | undefined;
    return row ? publicationFromRow(row) : undefined;
  }

  getByCertificationManifest(
    tenantIdValue: string,
    certificationManifestIdValue: string
  ): CertifiedSnapshotPublicationV1 | undefined {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenantId");
    const certificationManifestId = identifier(
      certificationManifestIdValue,
      "certificationManifestId"
    );
    const row = this.#database
      .prepare(
        "SELECT * FROM surveillance_publications WHERE tenant_id = ? AND certification_manifest_id = ?"
      )
      .get(tenantId, certificationManifestId) as PublicationRow | undefined;
    return row ? publicationFromRow(row) : undefined;
  }

  getDisable(
    tenantIdValue: string,
    publicationIdValue: string
  ): SurveillancePublicationDisableEventV1 | undefined {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenantId");
    const publicationId = identifier(publicationIdValue, "publicationId");
    const row = this.#database
      .prepare(
        "SELECT * FROM surveillance_publication_disables WHERE tenant_id = ? AND publication_id = ?"
      )
      .get(tenantId, publicationId) as DisableRow | undefined;
    return row ? disableFromRow(row) : undefined;
  }

  list(tenantIdValue: string, limit = 100): readonly CertifiedSnapshotPublicationV1[] {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenantId");
    integer(limit, "limit", 1, 1_000);
    const rows = this.#database
      .prepare(
        "SELECT * FROM surveillance_publications WHERE tenant_id = ? ORDER BY published_at, publication_id LIMIT ?"
      )
      .all(tenantId, limit) as unknown as PublicationRow[];
    return rows.map(publicationFromRow);
  }

  listAuditEvents(
    tenantIdValue: string,
    afterTenantSequence = 0,
    limit = 100
  ): readonly SurveillancePublicationAuditEventV1[] {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenantId");
    integer(afterTenantSequence, "afterTenantSequence", 0, Number.MAX_SAFE_INTEGER);
    integer(limit, "limit", 1, 1_000);
    const all = this.#database
      .prepare(
        "SELECT * FROM surveillance_publication_audit_events WHERE tenant_id = ? ORDER BY tenant_sequence"
      )
      .all(tenantId) as unknown as AuditRow[];
    const verified = verifyAuditRows(all);
    return verified
      .filter((event) => event.tenantSequence > afterTenantSequence)
      .slice(0, limit);
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#database.close();
  }

  #required(tenantId: string, publicationId: string): CertifiedSnapshotPublicationV1 {
    const publication = this.get(tenantId, publicationId);
    if (!publication) notFound("Surveillance publication was not found");
    return publication;
  }

  #requiredDisable(tenantId: string, publicationId: string): SurveillancePublicationDisableEventV1 {
    const event = this.getDisable(tenantId, publicationId);
    if (!event) notFound("Surveillance publication disable event was not found");
    return event;
  }

  #readReceipt(
    tenantId: string,
    operation: string,
    actor: string,
    idempotencyKey: string,
    requestHash: Sha256Hash
  ): { readonly publicationId: string } | null {
    const row = this.#database
      .prepare(
        `SELECT request_hash, publication_id
           FROM surveillance_publication_idempotency
          WHERE tenant_id = ? AND operation = ? AND actor = ? AND idempotency_key = ?`
      )
      .get(tenantId, operation, actor, idempotencyKey) as ReceiptRow | undefined;
    if (!row) return null;
    if (row.request_hash !== requestHash) {
      throw new SurveillancePublicationCatalogError(
        "IDEMPOTENCY_CONFLICT",
        "Idempotency key was used for another surveillance publication request"
      );
    }
    return { publicationId: row.publication_id };
  }

  #recordReceipt(
    tenantId: string,
    operation: string,
    actor: string,
    idempotencyKey: string,
    requestHash: Sha256Hash,
    publicationId: string,
    createdAt: string
  ): void {
    this.#database
      .prepare(
        `INSERT INTO surveillance_publication_idempotency (
           tenant_id, operation, actor, idempotency_key, request_hash,
           publication_id, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(tenantId, operation, actor, idempotencyKey, requestHash, publicationId, createdAt);
  }

  #appendAudit(
    tenantId: string,
    publicationId: string,
    eventType: SurveillancePublicationAuditEventV1["eventType"],
    actor: string,
    details: CanonicalJsonValue,
    occurredAt: string
  ): void {
    const previous = this.#database
      .prepare(
        `SELECT tenant_sequence, event_hash, occurred_at
           FROM surveillance_publication_audit_events
          WHERE tenant_id = ? ORDER BY tenant_sequence DESC LIMIT 1`
      )
      .get(tenantId) as
      | { readonly tenant_sequence: number; readonly event_hash: string; readonly occurred_at: string }
      | undefined;
    if (previous && occurredAt < previous.occurred_at) {
      invalid("Surveillance publication audit time cannot move backward");
    }
    const eventId = randomUUID();
    const tenantSequence = (previous?.tenant_sequence ?? 0) + 1;
    const previousEventHash = (previous?.event_hash ?? null) as Sha256Hash | null;
    const body = {
      tenantId,
      eventId,
      tenantSequence,
      eventType,
      publicationId,
      actor,
      details,
      occurredAt,
      previousEventHash
    };
    const eventHash = canonicalHash(body);
    this.#database
      .prepare(
        `INSERT INTO surveillance_publication_audit_events (
           tenant_id, event_id, tenant_sequence, event_type, publication_id,
           actor, details_json, occurred_at, previous_event_hash, event_hash
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        tenantId,
        eventId,
        tenantSequence,
        eventType,
        publicationId,
        actor,
        canonicalJson(details),
        occurredAt,
        previousEventHash,
        eventHash
      );
  }

  #transaction<T>(operation: () => T): T {
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      try {
        this.#database.exec("ROLLBACK");
      } catch {
        // Preserve the original failure.
      }
      throw error;
    }
  }

  #now(): string {
    const value = this.#clock();
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) invalid("Catalog clock is invalid");
    return parseWithSchema(IsoTimestampSchema, value.toISOString(), "catalog time");
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw new SurveillancePublicationCatalogError("STORE_CLOSED", "Publication catalog is closed");
    }
  }
}

const SURVEILLANCE_PUBLICATION_CATALOG_SCHEMA = `
CREATE TABLE surveillance_publications (
  tenant_id TEXT NOT NULL,
  publication_id TEXT NOT NULL,
  certification_manifest_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  publication_hash TEXT NOT NULL CHECK (publication_hash GLOB 'sha256:[0-9a-f]*' AND length(publication_hash) = 71),
  published_by TEXT NOT NULL,
  published_at TEXT NOT NULL,
  publication_json TEXT NOT NULL CHECK (json_valid(publication_json)),
  PRIMARY KEY (tenant_id, publication_id),
  UNIQUE (tenant_id, certification_manifest_id),
  UNIQUE (tenant_id, snapshot_id)
) STRICT;
CREATE INDEX surveillance_publications_tenant_time
  ON surveillance_publications (tenant_id, published_at, publication_id);
CREATE TRIGGER surveillance_publications_no_update BEFORE UPDATE ON surveillance_publications
BEGIN SELECT RAISE(ABORT, 'surveillance publications are immutable'); END;
CREATE TRIGGER surveillance_publications_no_delete BEFORE DELETE ON surveillance_publications
BEGIN SELECT RAISE(ABORT, 'surveillance publications are immutable'); END;

CREATE TABLE surveillance_publication_disables (
  tenant_id TEXT NOT NULL,
  publication_id TEXT NOT NULL,
  publication_hash TEXT NOT NULL CHECK (publication_hash GLOB 'sha256:[0-9a-f]*' AND length(publication_hash) = 71),
  reason_code TEXT NOT NULL,
  reason TEXT NOT NULL,
  disabled_by TEXT NOT NULL,
  disabled_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, publication_id),
  FOREIGN KEY (tenant_id, publication_id)
    REFERENCES surveillance_publications (tenant_id, publication_id)
) STRICT;
CREATE TRIGGER surveillance_publication_disables_no_update BEFORE UPDATE ON surveillance_publication_disables
BEGIN SELECT RAISE(ABORT, 'surveillance publication disable events are immutable'); END;
CREATE TRIGGER surveillance_publication_disables_no_delete BEFORE DELETE ON surveillance_publication_disables
BEGIN SELECT RAISE(ABORT, 'surveillance publication disable events are immutable'); END;

CREATE TABLE surveillance_publication_audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  tenant_sequence INTEGER NOT NULL CHECK (tenant_sequence > 0),
  event_type TEXT NOT NULL CHECK (event_type IN ('surveillance_publication.recorded','surveillance_publication.disabled')),
  publication_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  details_json TEXT NOT NULL CHECK (json_valid(details_json)),
  occurred_at TEXT NOT NULL,
  previous_event_hash TEXT CHECK (previous_event_hash IS NULL OR (previous_event_hash GLOB 'sha256:[0-9a-f]*' AND length(previous_event_hash) = 71)),
  event_hash TEXT NOT NULL CHECK (event_hash GLOB 'sha256:[0-9a-f]*' AND length(event_hash) = 71),
  UNIQUE (tenant_id, event_id),
  UNIQUE (tenant_id, tenant_sequence),
  FOREIGN KEY (tenant_id, publication_id)
    REFERENCES surveillance_publications (tenant_id, publication_id)
) STRICT;
CREATE INDEX surveillance_publication_audit_tenant_sequence
  ON surveillance_publication_audit_events (tenant_id, tenant_sequence);
CREATE TRIGGER surveillance_publication_audit_no_update BEFORE UPDATE ON surveillance_publication_audit_events
BEGIN SELECT RAISE(ABORT, 'surveillance publication audit is append-only'); END;
CREATE TRIGGER surveillance_publication_audit_no_delete BEFORE DELETE ON surveillance_publication_audit_events
BEGIN SELECT RAISE(ABORT, 'surveillance publication audit is append-only'); END;

CREATE TABLE surveillance_publication_idempotency (
  tenant_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  actor TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL CHECK (request_hash GLOB 'sha256:[0-9a-f]*' AND length(request_hash) = 71),
  publication_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, operation, actor, idempotency_key),
  FOREIGN KEY (tenant_id, publication_id)
    REFERENCES surveillance_publications (tenant_id, publication_id)
) STRICT;
CREATE TRIGGER surveillance_publication_idempotency_no_update BEFORE UPDATE ON surveillance_publication_idempotency
BEGIN SELECT RAISE(ABORT, 'surveillance publication idempotency is immutable'); END;
CREATE TRIGGER surveillance_publication_idempotency_no_delete BEFORE DELETE ON surveillance_publication_idempotency
BEGIN SELECT RAISE(ABORT, 'surveillance publication idempotency is immutable'); END;
`;

interface PublicationRow {
  readonly tenant_id: string;
  readonly publication_id: string;
  readonly certification_manifest_id: string;
  readonly snapshot_id: string;
  readonly publication_hash: string;
  readonly published_by: string;
  readonly published_at: string;
  readonly publication_json: string;
}

interface DisableRow {
  readonly tenant_id: string;
  readonly publication_id: string;
  readonly publication_hash: string;
  readonly reason_code: string;
  readonly reason: string;
  readonly disabled_by: string;
  readonly disabled_at: string;
}

interface AuditRow {
  readonly sequence: number;
  readonly tenant_id: string;
  readonly event_id: string;
  readonly tenant_sequence: number;
  readonly event_type: SurveillancePublicationAuditEventV1["eventType"];
  readonly publication_id: string;
  readonly actor: string;
  readonly details_json: string;
  readonly occurred_at: string;
  readonly previous_event_hash: string | null;
  readonly event_hash: string;
}

interface ReceiptRow {
  readonly request_hash: string;
  readonly publication_id: string;
}

function publicationFromRow(row: PublicationRow): CertifiedSnapshotPublicationV1 {
  const publication = inputContract(() =>
    parseCertifiedSnapshotPublicationV1(parseJson(row.publication_json, "surveillance publication"))
  );
  if (
    publication.tenantId !== row.tenant_id ||
    publication.publicationId !== row.publication_id ||
    publication.certification.certificationManifestId !== row.certification_manifest_id ||
    publication.snapshot.snapshotId !== row.snapshot_id ||
    publication.publicationHash !== row.publication_hash ||
    publication.publishedBy !== row.published_by ||
    publication.publishedAt !== row.published_at
  ) {
    integrity("Surveillance publication columns do not match immutable JSON");
  }
  return publication;
}

function disableFromRow(row: DisableRow): SurveillancePublicationDisableEventV1 {
  return Object.freeze({
    tenantId: row.tenant_id,
    publicationId: row.publication_id,
    publicationHash: inputContract(() =>
      parseWithSchema(Sha256HashSchema, row.publication_hash, "disable publicationHash")
    ),
    reasonCode: row.reason_code,
    reason: row.reason,
    disabledBy: row.disabled_by,
    disabledAt: inputContract(() =>
      parseWithSchema(IsoTimestampSchema, row.disabled_at, "disabledAt")
    )
  });
}

function verifyAuditRows(rows: readonly AuditRow[]): readonly SurveillancePublicationAuditEventV1[] {
  let previousHash: Sha256Hash | null = null;
  let previousOccurredAt: string | null = null;
  return rows.map((row, index) => {
    const details = parseJson(row.details_json, "surveillance publication audit details") as CanonicalJsonValue;
    const event = {
      sequence: row.sequence,
      tenantSequence: row.tenant_sequence,
      tenantId: row.tenant_id,
      eventId: row.event_id,
      eventType: row.event_type,
      publicationId: row.publication_id,
      actor: row.actor,
      details,
      occurredAt: row.occurred_at,
      previousEventHash: row.previous_event_hash as Sha256Hash | null,
      eventHash: row.event_hash as Sha256Hash
    };
    if (
      event.tenantSequence !== index + 1 ||
      event.previousEventHash !== previousHash ||
      (previousOccurredAt !== null && event.occurredAt < previousOccurredAt)
    ) {
      integrity("Surveillance publication audit chain ordering is invalid");
    }
    const { sequence: _sequence, eventHash, ...body } = event;
    if (canonicalHash(body) !== eventHash) integrity("Surveillance publication audit hash chain failed");
    previousHash = eventHash;
    previousOccurredAt = event.occurredAt;
    return Object.freeze(event);
  });
}

function validateRecord(input: RecordSurveillancePublicationInput): RecordSurveillancePublicationInput {
  if (!input || typeof input !== "object" || Array.isArray(input)) invalid("Record request is invalid");
  const keys = Object.keys(input).sort();
  if (canonicalJson(keys) !== canonicalJson(["actor", "idempotencyKey", "publication", "requestHash"])) {
    invalid("Record request contains unsupported fields");
  }
  const publication = inputContract(() => parseCertifiedSnapshotPublicationV1(input.publication));
  const actor = identifier(input.actor, "actor");
  const idempotencyKey = identifier(input.idempotencyKey, "idempotencyKey");
  const requestHash = inputContract(() =>
    parseWithSchema(Sha256HashSchema, input.requestHash, "publication requestHash")
  );
  if (publication.publishedBy !== actor) invalid("Publication actor must match publishedBy");
  return Object.freeze({ publication, requestHash, actor, idempotencyKey });
}

function validateDisable(input: DisableSurveillancePublicationInput): DisableSurveillancePublicationInput {
  if (!input || typeof input !== "object" || Array.isArray(input)) invalid("Disable request is invalid");
  const keys = Object.keys(input).sort();
  const expected = [
    "disabledBy",
    "expectedPublicationHash",
    "idempotencyKey",
    "publicationId",
    "reason",
    "reasonCode",
    "tenantId"
  ];
  if (canonicalJson(keys) !== canonicalJson(expected)) invalid("Disable request contains unsupported fields");
  const reason = input.reason.trim();
  if (!reason || reason.length > 2_000 || /[\u0000-\u001f\u007f]/u.test(reason)) {
    invalid("Disable reason is invalid");
  }
  return Object.freeze({
    tenantId: identifier(input.tenantId, "tenantId"),
    publicationId: identifier(input.publicationId, "publicationId"),
    expectedPublicationHash: inputContract(() =>
      parseWithSchema(Sha256HashSchema, input.expectedPublicationHash, "expectedPublicationHash")
    ),
    reasonCode: identifier(input.reasonCode, "reasonCode"),
    reason,
    disabledBy: identifier(input.disabledBy, "disabledBy"),
    idempotencyKey: identifier(input.idempotencyKey, "idempotencyKey")
  });
}

function parseJson(value: string, label: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    integrity(`${label} is invalid JSON`);
  }
}

function identifier(value: string, label: string): string {
  return inputContract(() => parseWithSchema(IdentifierSchema, value, label));
}

function integer(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalid(`${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function inputContract<T>(operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    if (error instanceof SurveillancePublicationCatalogError) throw error;
    invalid(error instanceof Error ? error.message : "Publication catalog input is invalid");
  }
}

function isConstraint(error: unknown): boolean {
  return error instanceof Error && /constraint|unique/iu.test(error.message);
}

function invalid(message: string): never {
  throw new SurveillancePublicationCatalogError("INVALID_INPUT", message);
}

function notFound(message: string): never {
  throw new SurveillancePublicationCatalogError("NOT_FOUND", message);
}

function conflict(message: string): never {
  throw new SurveillancePublicationCatalogError("CONFLICT", message);
}

function integrity(message: string): never {
  throw new SurveillancePublicationCatalogError("INTEGRITY_FAILURE", message);
}
