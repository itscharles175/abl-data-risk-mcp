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
  parseWithSchema,
  type CanonicalJsonValue,
  type Sha256Hash
} from "../contracts/canonical.js";
import {
  parseGovernedCertifiedSnapshotPublicationLinkV2,
  type GovernedCertifiedSnapshotPublicationLinkV2
} from "../contracts/governed-certified-snapshot-publication-link-v2.js";
import { migrateSqliteComponent } from "../infrastructure/sqlite-component-schema.js";

/**
 * An isolated, additive sidecar for V2 certification-to-publication links.
 * It deliberately has no foreign keys to, or schema dependencies on, the
 * legacy publication catalog: a V2 read must prove its own lineage contract.
 */
export const GOVERNED_CERTIFIED_SNAPSHOT_PUBLICATION_LINK_CATALOG_V2_COMPONENT =
  "abl.governed-certified-snapshot-publication-link-catalog-v2" as const;
export const GOVERNED_CERTIFIED_SNAPSHOT_PUBLICATION_LINK_CATALOG_V2_SCHEMA_VERSION = 1 as const;

export interface GovernedCertifiedSnapshotPublicationLinkCatalogV2Options {
  readonly clock?: () => Date;
  readonly busyTimeoutMs?: number;
}

export interface RecordGovernedCertifiedSnapshotPublicationLinkV2Input {
  readonly link: GovernedCertifiedSnapshotPublicationLinkV2;
  /** Hash of the trusted caller's IDs-only link request. */
  readonly requestHash: Sha256Hash;
  readonly actor: string;
  readonly idempotencyKey: string;
}

export interface DisableGovernedCertifiedSnapshotPublicationLinkV2Input {
  readonly tenantId: string;
  readonly linkId: string;
  readonly expectedLinkHash: Sha256Hash;
  readonly reasonCode: string;
  readonly reason: string;
  readonly disabledBy: string;
  readonly idempotencyKey: string;
}

export interface GovernedCertifiedSnapshotPublicationLinkDisableEventV2 {
  readonly tenantId: string;
  readonly linkId: string;
  readonly linkHash: Sha256Hash;
  readonly reasonCode: string;
  readonly reason: string;
  readonly disabledBy: string;
  readonly disabledAt: string;
}

export interface GovernedCertifiedSnapshotPublicationLinkAuditEventV2 {
  readonly sequence: number;
  readonly tenantSequence: number;
  readonly tenantId: string;
  readonly eventId: string;
  readonly eventType:
    | "governed_certified_snapshot_publication_link_v2.recorded"
    | "governed_certified_snapshot_publication_link_v2.disabled";
  readonly linkId: string;
  readonly actor: string;
  readonly details: CanonicalJsonValue;
  readonly occurredAt: string;
  readonly previousEventHash: Sha256Hash | null;
  readonly eventHash: Sha256Hash;
}

export type GovernedCertifiedSnapshotPublicationLinkCatalogV2ErrorCode =
  | "INVALID_INPUT"
  | "NOT_FOUND"
  | "CONFLICT"
  | "IDEMPOTENCY_CONFLICT"
  | "INTEGRITY_FAILURE"
  | "STORE_CLOSED";

export class GovernedCertifiedSnapshotPublicationLinkCatalogV2Error extends Error {
  constructor(
    readonly code: GovernedCertifiedSnapshotPublicationLinkCatalogV2ErrorCode,
    message: string
  ) {
    super(message);
    this.name = "GovernedCertifiedSnapshotPublicationLinkCatalogV2Error";
  }
}

interface LinkRow {
  readonly tenant_id: string;
  readonly link_id: string;
  readonly link_hash: string;
  readonly publication_id: string;
  readonly publication_hash: string;
  readonly evidence_id: string;
  readonly evidence_hash: string;
  readonly snapshot_id: string;
  readonly snapshot_hash: string;
  readonly scope_binding_id: string;
  readonly scope_binding_hash: string;
  readonly mapping_application_id: string;
  readonly mapping_application_hash: string;
  readonly governance_hash: string;
  readonly linked_at: string;
  readonly link_json: string;
}

interface ReceiptRow {
  readonly request_hash: string;
  readonly link_id: string;
  readonly link_hash: string;
}

interface DisableRow {
  readonly tenant_id: string;
  readonly link_id: string;
  readonly link_hash: string;
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
  readonly event_type: GovernedCertifiedSnapshotPublicationLinkAuditEventV2["eventType"];
  readonly link_id: string;
  readonly actor: string;
  readonly details_json: string;
  readonly occurred_at: string;
  readonly previous_event_hash: string | null;
  readonly event_hash: string;
}

/**
 * Immutable V2 bridge persistence. A link can only be disabled, never
 * overwritten, and all replays are actor-bound and tenant-scoped.
 */
export class GovernedCertifiedSnapshotPublicationLinkCatalogV2 {
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;
  #closed = false;

  constructor(databasePath: string, options: GovernedCertifiedSnapshotPublicationLinkCatalogV2Options = {}) {
    if (typeof databasePath !== "string" || !databasePath.trim()) invalid("SQLite database path is required");
    const path = databasePath === ":memory:" ? databasePath : resolve(databasePath);
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(path, { enableForeignKeyConstraints: true });
    this.#clock = options.clock ?? (() => new Date());
    try {
      this.#database.exec(
        `PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${safeInteger(options.busyTimeoutMs ?? 5_000, "busyTimeoutMs", 0, 60_000)};`
      );
      migrateSqliteComponent(this.#database, {
        componentName: GOVERNED_CERTIFIED_SNAPSHOT_PUBLICATION_LINK_CATALOG_V2_COMPONENT,
        supportedVersion: GOVERNED_CERTIFIED_SNAPSHOT_PUBLICATION_LINK_CATALOG_V2_SCHEMA_VERSION,
        migrations: [{ version: 1, sql: SCHEMA_V1 }],
        unsupportedVersionError: (current, supported) =>
          new GovernedCertifiedSnapshotPublicationLinkCatalogV2Error(
            "CONFLICT",
            `Governed V2 publication-link schema ${current} is newer than supported version ${supported}`
          )
      });
    } catch (error) {
      this.#database.close();
      if (error instanceof GovernedCertifiedSnapshotPublicationLinkCatalogV2Error) throw error;
      integrity("Governed V2 publication-link schema initialization failed", error);
    }
  }

  record(inputValue: RecordGovernedCertifiedSnapshotPublicationLinkV2Input): GovernedCertifiedSnapshotPublicationLinkV2 {
    this.#assertOpen();
    const input = validateRecord(inputValue);
    return this.#transaction(() => {
      const receipt = this.#readReceipt(input.link.tenantId, "record", input.actor, input.idempotencyKey, input.requestHash);
      if (receipt) return this.#required(input.link.tenantId, receipt.link_id);
      if (this.get(input.link.tenantId, input.link.linkId)) conflict("Governed V2 publication link id already exists");
      try {
        this.#insert(input.link);
      } catch (error) {
        if (isConstraint(error)) conflict("V1 publication or V2 evidence is already linked in this tenant");
        throw error;
      }
      this.#appendAudit(input.link.tenantId, input.link.linkId, "governed_certified_snapshot_publication_link_v2.recorded", input.actor, {
        evidenceHash: input.link.evidence.evidenceHash,
        governanceHash: input.link.governance.governanceHash,
        linkHash: input.link.linkHash,
        publicationHash: input.link.publication.publicationHash
      }, input.link.linkedAt);
      this.#recordReceipt(input.link.tenantId, "record", input.actor, input.idempotencyKey, input.requestHash, input.link.linkId, input.link.linkHash, input.link.linkedAt);
      return this.#required(input.link.tenantId, input.link.linkId);
    });
  }

  disable(inputValue: DisableGovernedCertifiedSnapshotPublicationLinkV2Input): GovernedCertifiedSnapshotPublicationLinkDisableEventV2 {
    this.#assertOpen();
    const input = validateDisable(inputValue);
    const requestHash = canonicalHash(input);
    return this.#transaction(() => {
      const receipt = this.#readReceipt(input.tenantId, "disable", input.disabledBy, input.idempotencyKey, requestHash);
      if (receipt) return this.#requiredDisable(input.tenantId, receipt.link_id);
      const link = this.#required(input.tenantId, input.linkId);
      if (link.linkHash !== input.expectedLinkHash) conflict("Disable request did not bind immutable link hash");
      if (this.getDisable(input.tenantId, input.linkId)) conflict("Governed V2 publication link is already disabled");
      const disabledAt = this.#now();
      this.#database.prepare(
        `INSERT INTO governed_certified_snapshot_publication_link_v2_disables (
          tenant_id, link_id, link_hash, reason_code, reason, disabled_by, disabled_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(input.tenantId, input.linkId, input.expectedLinkHash, input.reasonCode, input.reason, input.disabledBy, disabledAt);
      this.#appendAudit(input.tenantId, input.linkId, "governed_certified_snapshot_publication_link_v2.disabled", input.disabledBy, {
        linkHash: input.expectedLinkHash,
        reason: input.reason,
        reasonCode: input.reasonCode
      }, disabledAt);
      this.#recordReceipt(input.tenantId, "disable", input.disabledBy, input.idempotencyKey, requestHash, input.linkId, input.expectedLinkHash, disabledAt);
      return this.#requiredDisable(input.tenantId, input.linkId);
    });
  }

  get(tenantIdValue: string, linkIdValue: string): GovernedCertifiedSnapshotPublicationLinkV2 | undefined {
    this.#assertOpen();
    const row = this.#database.prepare(
      "SELECT * FROM governed_certified_snapshot_publication_links_v2 WHERE tenant_id = ? AND link_id = ?"
    ).get(identifier(tenantIdValue, "tenantId"), identifier(linkIdValue, "linkId")) as LinkRow | undefined;
    return row ? linkFromRow(row) : undefined;
  }

  /** Returns undefined when this V2 bridge has been explicitly disabled. */
  getEnabled(tenantIdValue: string, linkIdValue: string): GovernedCertifiedSnapshotPublicationLinkV2 | undefined {
    const tenantId = identifier(tenantIdValue, "tenantId");
    const linkId = identifier(linkIdValue, "linkId");
    const link = this.get(tenantId, linkId);
    return link && !this.getDisable(tenantId, linkId) ? link : undefined;
  }

  getByEvidence(tenantIdValue: string, evidenceIdValue: string): GovernedCertifiedSnapshotPublicationLinkV2 | undefined {
    this.#assertOpen();
    const row = this.#database.prepare(
      "SELECT * FROM governed_certified_snapshot_publication_links_v2 WHERE tenant_id = ? AND evidence_id = ?"
    ).get(identifier(tenantIdValue, "tenantId"), identifier(evidenceIdValue, "evidenceId")) as LinkRow | undefined;
    return row ? linkFromRow(row) : undefined;
  }

  list(tenantIdValue: string, limit = 100): readonly GovernedCertifiedSnapshotPublicationLinkV2[] {
    this.#assertOpen();
    const rows = this.#database.prepare(
      `SELECT * FROM governed_certified_snapshot_publication_links_v2
        WHERE tenant_id = ? ORDER BY linked_at, link_id LIMIT ?`
    ).all(identifier(tenantIdValue, "tenantId"), safeInteger(limit, "limit", 1, 1_000)) as unknown as LinkRow[];
    return Object.freeze(rows.map(linkFromRow));
  }

  getDisable(tenantIdValue: string, linkIdValue: string): GovernedCertifiedSnapshotPublicationLinkDisableEventV2 | undefined {
    this.#assertOpen();
    const row = this.#database.prepare(
      "SELECT * FROM governed_certified_snapshot_publication_link_v2_disables WHERE tenant_id = ? AND link_id = ?"
    ).get(identifier(tenantIdValue, "tenantId"), identifier(linkIdValue, "linkId")) as DisableRow | undefined;
    return row ? disableFromRow(row) : undefined;
  }

  listAuditEvents(tenantIdValue: string, afterTenantSequence = 0, limit = 100): readonly GovernedCertifiedSnapshotPublicationLinkAuditEventV2[] {
    this.#assertOpen();
    const rows = this.#database.prepare(
      `SELECT * FROM governed_certified_snapshot_publication_link_v2_audit_events
        WHERE tenant_id = ? ORDER BY tenant_sequence`
    ).all(identifier(tenantIdValue, "tenantId")) as unknown as AuditRow[];
    return Object.freeze(verifyAuditRows(rows).filter((event) => event.tenantSequence > safeInteger(afterTenantSequence, "afterTenantSequence", 0, Number.MAX_SAFE_INTEGER)).slice(0, safeInteger(limit, "limit", 1, 1_000)));
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#database.close();
  }

  #insert(link: GovernedCertifiedSnapshotPublicationLinkV2): void {
    this.#database.prepare(
      `INSERT INTO governed_certified_snapshot_publication_links_v2 (
         tenant_id, link_id, link_hash, publication_id, publication_hash,
         evidence_id, evidence_hash, snapshot_id, snapshot_hash,
         scope_binding_id, scope_binding_hash, mapping_application_id,
         mapping_application_hash, governance_hash, linked_at, link_json
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      link.tenantId, link.linkId, link.linkHash, link.publication.publicationId,
      link.publication.publicationHash, link.evidence.evidenceId,
      link.evidence.evidenceHash, link.publication.snapshotId,
      link.publication.snapshotHash, link.governance.scopeBinding.bindingId,
      link.governance.scopeBinding.bindingHash,
      link.governance.mapping.mappingApplicationId,
      link.governance.mapping.mappingApplicationHash,
      link.governance.governanceHash, link.linkedAt, canonicalJson(link)
    );
  }

  #required(tenantId: string, linkId: string): GovernedCertifiedSnapshotPublicationLinkV2 {
    const link = this.get(tenantId, linkId);
    if (!link) notFound("Governed V2 publication link was not found");
    return link;
  }

  #requiredDisable(tenantId: string, linkId: string): GovernedCertifiedSnapshotPublicationLinkDisableEventV2 {
    const event = this.getDisable(tenantId, linkId);
    if (!event) notFound("Governed V2 publication link disable event was not found");
    return event;
  }

  #readReceipt(tenantId: string, operation: "record" | "disable", actor: string, idempotencyKey: string, requestHash: Sha256Hash): ReceiptRow | undefined {
    const receipt = this.#database.prepare(
      `SELECT request_hash, link_id, link_hash
         FROM governed_certified_snapshot_publication_link_v2_idempotency
        WHERE tenant_id = ? AND operation = ? AND actor = ? AND idempotency_key = ?`
    ).get(tenantId, operation, actor, idempotencyKey) as ReceiptRow | undefined;
    if (receipt && receipt.request_hash !== requestHash) {
      throw new GovernedCertifiedSnapshotPublicationLinkCatalogV2Error("IDEMPOTENCY_CONFLICT", "Idempotency key was used for a different governed V2 publication-link request");
    }
    return receipt;
  }

  #recordReceipt(tenantId: string, operation: "record" | "disable", actor: string, idempotencyKey: string, requestHash: Sha256Hash, linkId: string, linkHash: Sha256Hash, createdAt: string): void {
    this.#database.prepare(
      `INSERT INTO governed_certified_snapshot_publication_link_v2_idempotency (
         tenant_id, operation, actor, idempotency_key, request_hash,
         link_id, link_hash, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(tenantId, operation, actor, idempotencyKey, requestHash, linkId, linkHash, createdAt);
  }

  #appendAudit(tenantId: string, linkId: string, eventType: GovernedCertifiedSnapshotPublicationLinkAuditEventV2["eventType"], actor: string, details: CanonicalJsonValue, occurredAt: string): void {
    const previous = this.#database.prepare(
      `SELECT tenant_sequence, event_hash, occurred_at
         FROM governed_certified_snapshot_publication_link_v2_audit_events
        WHERE tenant_id = ? ORDER BY tenant_sequence DESC LIMIT 1`
    ).get(tenantId) as { readonly tenant_sequence: number; readonly event_hash: string; readonly occurred_at: string } | undefined;
    if (previous && occurredAt < previous.occurred_at) invalid("Governed V2 publication-link audit time cannot move backward");
    const eventId = randomUUID();
    const body = {
      tenantId, eventId, tenantSequence: (previous?.tenant_sequence ?? 0) + 1,
      eventType, linkId, actor, details, occurredAt,
      previousEventHash: (previous?.event_hash ?? null) as Sha256Hash | null
    };
    this.#database.prepare(
      `INSERT INTO governed_certified_snapshot_publication_link_v2_audit_events (
         tenant_id, event_id, tenant_sequence, event_type, link_id, actor,
         details_json, occurred_at, previous_event_hash, event_hash
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(tenantId, eventId, body.tenantSequence, eventType, linkId, actor, canonicalJson(details), occurredAt, body.previousEventHash, canonicalHash(body));
  }

  #transaction<T>(operation: () => T): T {
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      try { this.#database.exec("ROLLBACK"); } catch { /* preserve original */ }
      throw error;
    }
  }

  #now(): string {
    const value = this.#clock();
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) invalid("Catalog clock returned an invalid date");
    return value.toISOString();
  }

  #assertOpen(): void {
    if (this.#closed) throw new GovernedCertifiedSnapshotPublicationLinkCatalogV2Error("STORE_CLOSED", "Governed V2 publication-link catalog is closed");
  }
}

function linkFromRow(row: LinkRow): GovernedCertifiedSnapshotPublicationLinkV2 {
  try {
    const raw = JSON.parse(row.link_json) as unknown;
    if (canonicalJson(raw) !== row.link_json) integrity("Stored governed V2 publication link JSON is not canonical");
    const link = parseGovernedCertifiedSnapshotPublicationLinkV2(raw);
    const actual = {
      tenant_id: row.tenant_id, link_id: row.link_id, link_hash: row.link_hash,
      publication_id: row.publication_id, publication_hash: row.publication_hash,
      evidence_id: row.evidence_id, evidence_hash: row.evidence_hash,
      snapshot_id: row.snapshot_id, snapshot_hash: row.snapshot_hash,
      scope_binding_id: row.scope_binding_id, scope_binding_hash: row.scope_binding_hash,
      mapping_application_id: row.mapping_application_id,
      mapping_application_hash: row.mapping_application_hash,
      governance_hash: row.governance_hash, linked_at: row.linked_at
    };
    const expected = {
      tenant_id: link.tenantId, link_id: link.linkId, link_hash: link.linkHash,
      publication_id: link.publication.publicationId, publication_hash: link.publication.publicationHash,
      evidence_id: link.evidence.evidenceId, evidence_hash: link.evidence.evidenceHash,
      snapshot_id: link.publication.snapshotId, snapshot_hash: link.publication.snapshotHash,
      scope_binding_id: link.governance.scopeBinding.bindingId,
      scope_binding_hash: link.governance.scopeBinding.bindingHash,
      mapping_application_id: link.governance.mapping.mappingApplicationId,
      mapping_application_hash: link.governance.mapping.mappingApplicationHash,
      governance_hash: link.governance.governanceHash, linked_at: link.linkedAt
    };
    if (canonicalJson(actual) !== canonicalJson(expected)) integrity("Stored governed V2 publication-link indexes do not match canonical content");
    return link;
  } catch (error) {
    if (error instanceof GovernedCertifiedSnapshotPublicationLinkCatalogV2Error) throw error;
    integrity("Stored governed V2 publication link failed integrity verification", error);
  }
}

function disableFromRow(row: DisableRow): GovernedCertifiedSnapshotPublicationLinkDisableEventV2 {
  return Object.freeze({
    tenantId: row.tenant_id, linkId: row.link_id,
    linkHash: inputContract(() => parseWithSchema(Sha256HashSchema, row.link_hash, "disable linkHash")),
    reasonCode: identifier(row.reason_code, "disable reasonCode"), reason: validReason(row.reason),
    disabledBy: identifier(row.disabled_by, "disabledBy"),
    disabledAt: inputContract(() => parseWithSchema(IsoTimestampSchema, row.disabled_at, "disabledAt"))
  });
}

function verifyAuditRows(rows: readonly AuditRow[]): readonly GovernedCertifiedSnapshotPublicationLinkAuditEventV2[] {
  let previousHash: Sha256Hash | null = null;
  let previousOccurredAt: string | null = null;
  return rows.map((row, index) => {
    const event = {
      sequence: row.sequence, tenantSequence: row.tenant_sequence, tenantId: row.tenant_id,
      eventId: row.event_id, eventType: row.event_type, linkId: row.link_id,
      actor: row.actor, details: parseJson(row.details_json, "governed V2 publication-link audit details") as CanonicalJsonValue,
      occurredAt: row.occurred_at, previousEventHash: row.previous_event_hash as Sha256Hash | null,
      eventHash: row.event_hash as Sha256Hash
    };
    if (event.tenantSequence !== index + 1 || event.previousEventHash !== previousHash || (previousOccurredAt !== null && event.occurredAt < previousOccurredAt)) {
      integrity("Governed V2 publication-link audit chain ordering is invalid");
    }
    const { sequence: _sequence, eventHash, ...body } = event;
    if (canonicalHash(body) !== eventHash) integrity("Governed V2 publication-link audit hash chain failed");
    previousHash = eventHash;
    previousOccurredAt = event.occurredAt;
    return Object.freeze(event);
  });
}

function validateRecord(value: RecordGovernedCertifiedSnapshotPublicationLinkV2Input): RecordGovernedCertifiedSnapshotPublicationLinkV2Input {
  exactKeys(value, ["actor", "idempotencyKey", "link", "requestHash"], "Record request");
  return Object.freeze({
    link: inputContract(() => parseGovernedCertifiedSnapshotPublicationLinkV2(value.link)),
    requestHash: inputContract(() => parseWithSchema(Sha256HashSchema, value.requestHash, "requestHash")),
    actor: identifier(value.actor, "actor"), idempotencyKey: identifier(value.idempotencyKey, "idempotencyKey")
  });
}

function validateDisable(value: DisableGovernedCertifiedSnapshotPublicationLinkV2Input): DisableGovernedCertifiedSnapshotPublicationLinkV2Input {
  exactKeys(value, ["disabledBy", "expectedLinkHash", "idempotencyKey", "linkId", "reason", "reasonCode", "tenantId"], "Disable request");
  return Object.freeze({
    tenantId: identifier(value.tenantId, "tenantId"), linkId: identifier(value.linkId, "linkId"),
    expectedLinkHash: inputContract(() => parseWithSchema(Sha256HashSchema, value.expectedLinkHash, "expectedLinkHash")),
    reasonCode: identifier(value.reasonCode, "reasonCode"), reason: validReason(value.reason),
    disabledBy: identifier(value.disabledBy, "disabledBy"), idempotencyKey: identifier(value.idempotencyKey, "idempotencyKey")
  });
}

function exactKeys(value: unknown, expected: readonly string[], label: string): void {
  if (!value || typeof value !== "object" || Array.isArray(value) || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...expected].sort())) {
    invalid(`${label} contains missing or unsupported fields`);
  }
}

function validReason(value: string): string {
  if (typeof value !== "string") invalid("Disable reason is invalid");
  const reason = value.trim();
  if (!reason || reason.length > 2_000 || /[\u0000-\u001f\u007f]/u.test(reason)) invalid("Disable reason is invalid");
  return reason;
}

function identifier(value: string, label: string): string {
  return inputContract(() => parseWithSchema(IdentifierSchema, value, label));
}

function safeInteger(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalid(`${label} must be an integer from ${minimum} through ${maximum}`);
  return value;
}

function parseJson(value: string, label: string): unknown {
  try { return JSON.parse(value) as unknown; } catch { integrity(`${label} is invalid JSON`); }
}

function inputContract<T>(operation: () => T): T {
  try { return operation(); } catch (error) {
    if (error instanceof GovernedCertifiedSnapshotPublicationLinkCatalogV2Error) throw error;
    invalid(error instanceof Error ? error.message : "Catalog input is invalid");
  }
}

function isConstraint(error: unknown): boolean {
  return error instanceof Error && /constraint|unique/iu.test(error.message);
}

function invalid(message: string): never {
  throw new GovernedCertifiedSnapshotPublicationLinkCatalogV2Error("INVALID_INPUT", message);
}

function notFound(message: string): never {
  throw new GovernedCertifiedSnapshotPublicationLinkCatalogV2Error("NOT_FOUND", message);
}

function conflict(message: string): never {
  throw new GovernedCertifiedSnapshotPublicationLinkCatalogV2Error("CONFLICT", message);
}

function integrity(message: string, cause?: unknown): never {
  const detail = cause instanceof Error ? `: ${cause.message}` : "";
  throw new GovernedCertifiedSnapshotPublicationLinkCatalogV2Error("INTEGRITY_FAILURE", `${message}${detail}`);
}

const SCHEMA_V1 = `
CREATE TABLE governed_certified_snapshot_publication_links_v2 (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  link_id TEXT NOT NULL CHECK (length(link_id) BETWEEN 1 AND 128),
  link_hash TEXT NOT NULL CHECK (link_hash GLOB 'sha256:[0-9a-f]*' AND length(link_hash) = 71),
  publication_id TEXT NOT NULL CHECK (length(publication_id) BETWEEN 1 AND 128),
  publication_hash TEXT NOT NULL CHECK (publication_hash GLOB 'sha256:[0-9a-f]*' AND length(publication_hash) = 71),
  evidence_id TEXT NOT NULL CHECK (length(evidence_id) BETWEEN 1 AND 128),
  evidence_hash TEXT NOT NULL CHECK (evidence_hash GLOB 'sha256:[0-9a-f]*' AND length(evidence_hash) = 71),
  snapshot_id TEXT NOT NULL CHECK (length(snapshot_id) BETWEEN 1 AND 128),
  snapshot_hash TEXT NOT NULL CHECK (snapshot_hash GLOB 'sha256:[0-9a-f]*' AND length(snapshot_hash) = 71),
  scope_binding_id TEXT NOT NULL CHECK (length(scope_binding_id) BETWEEN 1 AND 128),
  scope_binding_hash TEXT NOT NULL CHECK (scope_binding_hash GLOB 'sha256:[0-9a-f]*' AND length(scope_binding_hash) = 71),
  mapping_application_id TEXT NOT NULL CHECK (length(mapping_application_id) BETWEEN 1 AND 128),
  mapping_application_hash TEXT NOT NULL CHECK (mapping_application_hash GLOB 'sha256:[0-9a-f]*' AND length(mapping_application_hash) = 71),
  governance_hash TEXT NOT NULL CHECK (governance_hash GLOB 'sha256:[0-9a-f]*' AND length(governance_hash) = 71),
  linked_at TEXT NOT NULL,
  link_json TEXT NOT NULL CHECK (json_valid(link_json)),
  PRIMARY KEY (tenant_id, link_id),
  UNIQUE (tenant_id, link_hash),
  UNIQUE (tenant_id, publication_id),
  UNIQUE (tenant_id, evidence_id)
) STRICT;
CREATE INDEX governed_certified_snapshot_publication_links_v2_tenant_time
  ON governed_certified_snapshot_publication_links_v2 (tenant_id, linked_at, link_id);
CREATE TRIGGER governed_certified_snapshot_publication_links_v2_no_update
BEFORE UPDATE ON governed_certified_snapshot_publication_links_v2
BEGIN SELECT RAISE(ABORT, 'governed V2 publication links are immutable'); END;
CREATE TRIGGER governed_certified_snapshot_publication_links_v2_no_delete
BEFORE DELETE ON governed_certified_snapshot_publication_links_v2
BEGIN SELECT RAISE(ABORT, 'governed V2 publication links are immutable'); END;

CREATE TABLE governed_certified_snapshot_publication_link_v2_disables (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  link_id TEXT NOT NULL CHECK (length(link_id) BETWEEN 1 AND 128),
  link_hash TEXT NOT NULL CHECK (link_hash GLOB 'sha256:[0-9a-f]*' AND length(link_hash) = 71),
  reason_code TEXT NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 128),
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 2000),
  disabled_by TEXT NOT NULL CHECK (length(disabled_by) BETWEEN 1 AND 128),
  disabled_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, link_id),
  FOREIGN KEY (tenant_id, link_id) REFERENCES governed_certified_snapshot_publication_links_v2 (tenant_id, link_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;
CREATE TRIGGER governed_certified_snapshot_publication_link_v2_disables_no_update
BEFORE UPDATE ON governed_certified_snapshot_publication_link_v2_disables
BEGIN SELECT RAISE(ABORT, 'governed V2 publication-link disable events are immutable'); END;
CREATE TRIGGER governed_certified_snapshot_publication_link_v2_disables_no_delete
BEFORE DELETE ON governed_certified_snapshot_publication_link_v2_disables
BEGIN SELECT RAISE(ABORT, 'governed V2 publication-link disable events are immutable'); END;

CREATE TABLE governed_certified_snapshot_publication_link_v2_audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  event_id TEXT NOT NULL CHECK (length(event_id) BETWEEN 1 AND 128),
  tenant_sequence INTEGER NOT NULL CHECK (tenant_sequence > 0),
  event_type TEXT NOT NULL CHECK (event_type IN (
    'governed_certified_snapshot_publication_link_v2.recorded',
    'governed_certified_snapshot_publication_link_v2.disabled'
  )),
  link_id TEXT NOT NULL CHECK (length(link_id) BETWEEN 1 AND 128),
  actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 128),
  details_json TEXT NOT NULL CHECK (json_valid(details_json)),
  occurred_at TEXT NOT NULL,
  previous_event_hash TEXT CHECK (previous_event_hash IS NULL OR (previous_event_hash GLOB 'sha256:[0-9a-f]*' AND length(previous_event_hash) = 71)),
  event_hash TEXT NOT NULL CHECK (event_hash GLOB 'sha256:[0-9a-f]*' AND length(event_hash) = 71),
  UNIQUE (tenant_id, event_id), UNIQUE (tenant_id, tenant_sequence),
  FOREIGN KEY (tenant_id, link_id) REFERENCES governed_certified_snapshot_publication_links_v2 (tenant_id, link_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;
CREATE INDEX governed_certified_snapshot_publication_link_v2_audit_tenant_sequence
  ON governed_certified_snapshot_publication_link_v2_audit_events (tenant_id, tenant_sequence);
CREATE TRIGGER governed_certified_snapshot_publication_link_v2_audit_no_update
BEFORE UPDATE ON governed_certified_snapshot_publication_link_v2_audit_events
BEGIN SELECT RAISE(ABORT, 'governed V2 publication-link audit is append-only'); END;
CREATE TRIGGER governed_certified_snapshot_publication_link_v2_audit_no_delete
BEFORE DELETE ON governed_certified_snapshot_publication_link_v2_audit_events
BEGIN SELECT RAISE(ABORT, 'governed V2 publication-link audit is append-only'); END;

CREATE TABLE governed_certified_snapshot_publication_link_v2_idempotency (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  operation TEXT NOT NULL CHECK (operation IN ('record', 'disable')),
  actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 128),
  idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  request_hash TEXT NOT NULL CHECK (request_hash GLOB 'sha256:[0-9a-f]*' AND length(request_hash) = 71),
  link_id TEXT NOT NULL CHECK (length(link_id) BETWEEN 1 AND 128),
  link_hash TEXT NOT NULL CHECK (link_hash GLOB 'sha256:[0-9a-f]*' AND length(link_hash) = 71),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, operation, actor, idempotency_key),
  FOREIGN KEY (tenant_id, link_id) REFERENCES governed_certified_snapshot_publication_links_v2 (tenant_id, link_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;
CREATE TRIGGER governed_certified_snapshot_publication_link_v2_idempotency_no_update
BEFORE UPDATE ON governed_certified_snapshot_publication_link_v2_idempotency
BEGIN SELECT RAISE(ABORT, 'governed V2 publication-link idempotency is immutable'); END;
CREATE TRIGGER governed_certified_snapshot_publication_link_v2_idempotency_no_delete
BEFORE DELETE ON governed_certified_snapshot_publication_link_v2_idempotency
BEGIN SELECT RAISE(ABORT, 'governed V2 publication-link idempotency is immutable'); END;
`;
