import { createHash, randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { migrateSqliteComponent } from "../infrastructure/sqlite-component-schema.js";

export const INVESTIGATION_STORE_COMPONENT = "abl.investigation-store" as const;
export const INVESTIGATION_STORE_SCHEMA_VERSION = 1 as const;

export type InvestigationStatus = "open" | "closed";
export type InvestigationReferenceKind = "snapshot" | "result";
export type InvestigationMask = "none" | "partial" | "tokenize" | "redact";

export interface InvestigationReference {
  readonly kind: InvestigationReferenceKind;
  readonly id: string;
}

export type InvestigationScalar = string | boolean | null;

export type InvestigationFilter =
  | {
      readonly type: "predicate";
      readonly field: string;
      readonly operator: "eq" | "ne" | "gt" | "gte" | "lt" | "lte" | "in" | "is_null";
      readonly value?: InvestigationScalar | readonly InvestigationScalar[];
    }
  | {
      readonly type: "and";
      readonly filters: readonly InvestigationFilter[];
    }
  | {
      readonly type: "or";
      readonly filters: readonly InvestigationFilter[];
    };

export interface CreateInvestigationRecord {
  readonly tenantId: string;
  readonly investigationId: string;
  readonly principalBinding: string;
  readonly reference: InvestigationReference;
  readonly certificationManifestId: string;
  readonly requestedFields: readonly string[];
  readonly filter: InvestigationFilter | null;
  readonly filterHash: string;
  readonly purpose: string;
  readonly reason: string;
  readonly masks: Readonly<Record<string, InvestigationMask>>;
  readonly populationHash: string;
  readonly rowBudget: number;
  readonly expiresAt: string;
  readonly createdBy: string;
  readonly reviewerPrincipalId?: string;
  readonly idempotencyKey: string;
}

export interface InvestigationRecord
  extends Omit<CreateInvestigationRecord, "idempotencyKey"> {
  readonly status: InvestigationStatus;
  readonly disclosedRows: number;
  readonly disclosureHistoryFingerprint: string;
  readonly createdAt: string;
  readonly closedAt: string | null;
  readonly closedBy: string | null;
  readonly closeReason: string | null;
}

export interface RecordInvestigationDisclosureInput {
  readonly tenantId: string;
  readonly investigationId: string;
  readonly principalBinding: string;
  readonly pageRowCount: number;
  readonly pageHash: string;
  readonly cursorHash: string;
  readonly disclosedFields: readonly string[];
  readonly appliedMasks: Readonly<Record<string, InvestigationMask>>;
  readonly fieldPolicyVersion: string;
  readonly actor: string;
  readonly idempotencyKey: string;
}

export interface InvestigationDisclosureRecord {
  readonly sequence: number;
  readonly tenantId: string;
  readonly investigationId: string;
  readonly disclosureId: string;
  readonly pageRowCount: number;
  readonly cumulativeRowCount: number;
  readonly pageHash: string;
  readonly cursorHash: string;
  readonly disclosedFields: readonly string[];
  readonly appliedMasks: Readonly<Record<string, InvestigationMask>>;
  readonly fieldPolicyVersion: string;
  readonly reference: InvestigationReference;
  readonly certificationManifestId: string;
  readonly populationHash: string;
  readonly purpose: string;
  readonly previousFingerprint: string;
  readonly disclosureFingerprint: string;
  readonly actor: string;
  readonly disclosedAt: string;
}

export interface CloseInvestigationInput {
  readonly tenantId: string;
  readonly investigationId: string;
  readonly principalBinding: string;
  readonly actor: string;
  readonly reason: string;
  readonly idempotencyKey: string;
}

export interface InvestigationStoreOptions {
  readonly clock?: () => Date;
  readonly busyTimeoutMs?: number;
}

export type InvestigationStoreErrorCode =
  | "INVALID_INPUT"
  | "NOT_FOUND"
  | "FORBIDDEN"
  | "EXPIRED"
  | "CLOSED"
  | "ROW_BUDGET_EXCEEDED"
  | "IDEMPOTENCY_CONFLICT";

export class InvestigationStoreError extends Error {
  constructor(readonly code: InvestigationStoreErrorCode, message: string) {
    super(message);
    this.name = "InvestigationStoreError";
  }
}

export interface InvestigationRepository {
  create(input: CreateInvestigationRecord): InvestigationRecord;
  get(tenantId: string, investigationId: string): InvestigationRecord | undefined;
  list(tenantId: string, principalBinding?: string): readonly InvestigationRecord[];
  recordDisclosure(input: RecordInvestigationDisclosureInput): InvestigationDisclosureRecord;
  listDisclosures(tenantId: string, investigationId: string): readonly InvestigationDisclosureRecord[];
  closeInvestigation(input: CloseInvestigationInput): InvestigationRecord;
}

/** Durable investigation lifecycle and disclosure ledger for a single-node deployment. */
export class InvestigationStore implements InvestigationRepository {
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;

  constructor(databasePath: string, options: InvestigationStoreOptions = {}) {
    if (!databasePath.trim()) invalid("Investigation database path is required");
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
        componentName: INVESTIGATION_STORE_COMPONENT,
        supportedVersion: INVESTIGATION_STORE_SCHEMA_VERSION,
        migrations: [{ version: 1, sql: INVESTIGATION_SCHEMA }],
        unsupportedVersionError: (current, supported) =>
          new InvestigationStoreError(
            "INVALID_INPUT",
            `Investigation schema ${current} is newer than supported version ${supported}`
          )
      });
    } catch (error) {
      this.#database.close();
      throw error;
    }
  }

  create(input: CreateInvestigationRecord): InvestigationRecord {
    validateCreate(input);
    return this.#idempotent(input.tenantId, "investigation.create", input.idempotencyKey, input, () => {
      const createdAt = this.#now();
      if (Date.parse(input.expiresAt) <= Date.parse(createdAt)) invalid("Investigation expiry must be in the future");
      this.#database
        .prepare(
          `INSERT INTO investigations (
             tenant_id, investigation_id, principal_binding, reference_kind, reference_id,
             certification_manifest_id, requested_fields_json, filter_json, filter_hash,
             purpose, reason, masks_json, population_hash, row_budget, disclosed_rows,
             status, expires_at, created_by, reviewer_principal_id,
             disclosure_history_fingerprint, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'open', ?, ?, ?, ?, ?)`
        )
        .run(
          input.tenantId,
          input.investigationId,
          input.principalBinding,
          input.reference.kind,
          input.reference.id,
          input.certificationManifestId,
          canonicalJson(input.requestedFields),
          input.filter === null ? null : canonicalJson(input.filter),
          input.filterHash,
          input.purpose,
          input.reason,
          canonicalJson(input.masks),
          input.populationHash,
          input.rowBudget,
          input.expiresAt,
          input.createdBy,
          input.reviewerPrincipalId ?? null,
          initialDisclosureFingerprint(input),
          createdAt
        );
      return required(this.get(input.tenantId, input.investigationId));
    });
  }

  get(tenantId: string, investigationId: string): InvestigationRecord | undefined {
    id(tenantId, "tenantId");
    id(investigationId, "investigationId");
    const row = this.#database
      .prepare("SELECT * FROM investigations WHERE tenant_id = ? AND investigation_id = ?")
      .get(tenantId, investigationId) as InvestigationRow | undefined;
    return row ? investigationFromRow(row) : undefined;
  }

  list(tenantId: string, principalBinding?: string): readonly InvestigationRecord[] {
    id(tenantId, "tenantId");
    if (principalBinding !== undefined) hash(principalBinding, "principalBinding");
    const rows = principalBinding === undefined
      ? this.#database
          .prepare("SELECT * FROM investigations WHERE tenant_id = ? ORDER BY created_at, investigation_id")
          .all(tenantId)
      : this.#database
          .prepare(
            "SELECT * FROM investigations WHERE tenant_id = ? AND principal_binding = ? ORDER BY created_at, investigation_id"
          )
          .all(tenantId, principalBinding);
    return (rows as unknown as InvestigationRow[]).map(investigationFromRow);
  }

  recordDisclosure(input: RecordInvestigationDisclosureInput): InvestigationDisclosureRecord {
    validateDisclosure(input);
    return this.#idempotent(input.tenantId, "investigation.disclose", input.idempotencyKey, input, () => {
      const investigation = this.#requireUsable(
        input.tenantId,
        input.investigationId,
        input.principalBinding
      );
      if (input.disclosedFields.join("\u0000") !== investigation.requestedFields.join("\u0000")) {
        throw new InvestigationStoreError("FORBIDDEN", "Disclosure fields are not authorized");
      }
      if (canonicalJson(input.appliedMasks) !== canonicalJson(investigation.masks)) {
        throw new InvestigationStoreError("FORBIDDEN", "Disclosure masks are not authorized");
      }
      const cumulativeRowCount = investigation.disclosedRows + input.pageRowCount;
      if (cumulativeRowCount > investigation.rowBudget) {
        throw new InvestigationStoreError("ROW_BUDGET_EXCEEDED", "Investigation row budget is exhausted");
      }
      const disclosedAt = this.#now();
      const disclosureId = randomUUID();
      const disclosureFingerprint = digest({
        actor: input.actor,
        appliedMasks: input.appliedMasks,
        certificationManifestId: investigation.certificationManifestId,
        cumulativeRowCount,
        cursorHash: input.cursorHash,
        disclosedAt,
        disclosedFields: input.disclosedFields,
        disclosureId,
        fieldPolicyVersion: input.fieldPolicyVersion,
        investigationId: input.investigationId,
        pageHash: input.pageHash,
        pageRowCount: input.pageRowCount,
        populationHash: investigation.populationHash,
        previousFingerprint: investigation.disclosureHistoryFingerprint,
        purpose: investigation.purpose,
        reference: investigation.reference,
        tenantId: input.tenantId
      });
      const result = this.#database
        .prepare(
          `UPDATE investigations
              SET disclosed_rows = ?, disclosure_history_fingerprint = ?
            WHERE tenant_id = ? AND investigation_id = ?
              AND disclosed_rows = ? AND disclosure_history_fingerprint = ?`
        )
        .run(
          cumulativeRowCount,
          disclosureFingerprint,
          input.tenantId,
          input.investigationId,
          investigation.disclosedRows,
          investigation.disclosureHistoryFingerprint
        );
      if (Number(result.changes) !== 1) {
        throw new InvestigationStoreError("IDEMPOTENCY_CONFLICT", "Investigation changed concurrently");
      }
      this.#database
        .prepare(
          `INSERT INTO investigation_disclosures (
             tenant_id, investigation_id, disclosure_id, page_row_count, cumulative_row_count,
             page_hash, cursor_hash, disclosed_fields_json, applied_masks_json,
             field_policy_version, reference_kind, reference_id, certification_manifest_id,
             population_hash, purpose, previous_fingerprint, disclosure_fingerprint, actor, disclosed_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          input.tenantId,
          input.investigationId,
          disclosureId,
          input.pageRowCount,
          cumulativeRowCount,
          input.pageHash,
          input.cursorHash,
          canonicalJson(input.disclosedFields),
          canonicalJson(input.appliedMasks),
          input.fieldPolicyVersion,
          investigation.reference.kind,
          investigation.reference.id,
          investigation.certificationManifestId,
          investigation.populationHash,
          investigation.purpose,
          investigation.disclosureHistoryFingerprint,
          disclosureFingerprint,
          input.actor,
          disclosedAt
        );
      const row = this.#database
        .prepare("SELECT * FROM investigation_disclosures WHERE disclosure_id = ?")
        .get(disclosureId) as DisclosureRow | undefined;
      return disclosureFromRow(required(row));
    });
  }

  listDisclosures(tenantId: string, investigationId: string): readonly InvestigationDisclosureRecord[] {
    id(tenantId, "tenantId");
    id(investigationId, "investigationId");
    return (this.#database
      .prepare(
        `SELECT * FROM investigation_disclosures
          WHERE tenant_id = ? AND investigation_id = ? ORDER BY sequence`
      )
      .all(tenantId, investigationId) as unknown as DisclosureRow[]).map(disclosureFromRow);
  }

  closeInvestigation(input: CloseInvestigationInput): InvestigationRecord {
    validateClose(input);
    return this.#idempotent(input.tenantId, "investigation.close", input.idempotencyKey, input, () => {
      const current = this.#requireOwned(input.tenantId, input.investigationId, input.principalBinding);
      if (current.status === "closed") return current;
      const closedAt = this.#now();
      this.#database
        .prepare(
          `UPDATE investigations
              SET status = 'closed', closed_at = ?, closed_by = ?, close_reason = ?
            WHERE tenant_id = ? AND investigation_id = ? AND status = 'open'`
        )
        .run(closedAt, input.actor, input.reason, input.tenantId, input.investigationId);
      return required(this.get(input.tenantId, input.investigationId));
    });
  }

  close(): void {
    this.#database.close();
  }

  #requireOwned(tenantId: string, investigationId: string, principalBinding: string): InvestigationRecord {
    hash(principalBinding, "principalBinding");
    const record = this.get(tenantId, investigationId);
    if (!record) throw new InvestigationStoreError("NOT_FOUND", "Investigation was not found");
    if (record.principalBinding !== principalBinding) {
      throw new InvestigationStoreError("NOT_FOUND", "Investigation was not found");
    }
    return record;
  }

  #requireUsable(tenantId: string, investigationId: string, principalBinding: string): InvestigationRecord {
    const record = this.#requireOwned(tenantId, investigationId, principalBinding);
    if (record.status !== "open") throw new InvestigationStoreError("CLOSED", "Investigation is closed");
    if (Date.parse(record.expiresAt) <= Date.parse(this.#now())) {
      throw new InvestigationStoreError("EXPIRED", "Investigation has expired");
    }
    return record;
  }

  #idempotent<T>(
    tenantId: string,
    operation: string,
    key: string,
    input: unknown,
    mutation: () => T
  ): T {
    id(tenantId, "tenantId");
    id(key, "idempotencyKey");
    const requestHash = digest(input);
    const existing = this.#database
      .prepare(
        "SELECT request_hash, response_json FROM investigation_idempotency WHERE tenant_id = ? AND operation = ? AND idempotency_key = ?"
      )
      .get(tenantId, operation, key) as IdempotencyRow | undefined;
    if (existing) {
      if (existing.request_hash !== requestHash) {
        throw new InvestigationStoreError("IDEMPOTENCY_CONFLICT", "Idempotency key conflicts with an earlier request");
      }
      return JSON.parse(existing.response_json) as T;
    }
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const response = mutation();
      this.#database
        .prepare(
          "INSERT INTO investigation_idempotency (tenant_id, operation, idempotency_key, request_hash, response_json) VALUES (?, ?, ?, ?, ?)"
        )
        .run(tenantId, operation, key, requestHash, canonicalJson(response));
      this.#database.exec("COMMIT");
      return response;
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
    if (!Number.isFinite(value.getTime())) invalid("Clock is invalid");
    return value.toISOString();
  }
}

interface InvestigationRow {
  readonly tenant_id: string;
  readonly investigation_id: string;
  readonly principal_binding: string;
  readonly reference_kind: InvestigationReferenceKind;
  readonly reference_id: string;
  readonly certification_manifest_id: string;
  readonly requested_fields_json: string;
  readonly filter_json: string | null;
  readonly filter_hash: string;
  readonly purpose: string;
  readonly reason: string;
  readonly masks_json: string;
  readonly population_hash: string;
  readonly row_budget: number;
  readonly disclosed_rows: number;
  readonly status: InvestigationStatus;
  readonly expires_at: string;
  readonly created_by: string;
  readonly reviewer_principal_id: string | null;
  readonly disclosure_history_fingerprint: string;
  readonly created_at: string;
  readonly closed_at: string | null;
  readonly closed_by: string | null;
  readonly close_reason: string | null;
}

interface DisclosureRow {
  readonly sequence: number;
  readonly tenant_id: string;
  readonly investigation_id: string;
  readonly disclosure_id: string;
  readonly page_row_count: number;
  readonly cumulative_row_count: number;
  readonly page_hash: string;
  readonly cursor_hash: string;
  readonly disclosed_fields_json: string;
  readonly applied_masks_json: string;
  readonly field_policy_version: string;
  readonly reference_kind: InvestigationReferenceKind;
  readonly reference_id: string;
  readonly certification_manifest_id: string;
  readonly population_hash: string;
  readonly purpose: string;
  readonly previous_fingerprint: string;
  readonly disclosure_fingerprint: string;
  readonly actor: string;
  readonly disclosed_at: string;
}

interface IdempotencyRow {
  readonly request_hash: string;
  readonly response_json: string;
}

function investigationFromRow(row: InvestigationRow): InvestigationRecord {
  return Object.freeze({
    tenantId: row.tenant_id,
    investigationId: row.investigation_id,
    principalBinding: row.principal_binding,
    reference: Object.freeze({ kind: row.reference_kind, id: row.reference_id }),
    certificationManifestId: row.certification_manifest_id,
    requestedFields: Object.freeze(parseStringArray(row.requested_fields_json)),
    filter: row.filter_json === null ? null : (JSON.parse(row.filter_json) as InvestigationFilter),
    filterHash: row.filter_hash,
    purpose: row.purpose,
    reason: row.reason,
    masks: Object.freeze(JSON.parse(row.masks_json) as Record<string, InvestigationMask>),
    populationHash: row.population_hash,
    rowBudget: row.row_budget,
    disclosedRows: row.disclosed_rows,
    status: row.status,
    expiresAt: row.expires_at,
    createdBy: row.created_by,
    ...(row.reviewer_principal_id === null ? {} : { reviewerPrincipalId: row.reviewer_principal_id }),
    disclosureHistoryFingerprint: row.disclosure_history_fingerprint,
    createdAt: row.created_at,
    closedAt: row.closed_at,
    closedBy: row.closed_by,
    closeReason: row.close_reason
  });
}

function disclosureFromRow(row: DisclosureRow): InvestigationDisclosureRecord {
  return Object.freeze({
    sequence: row.sequence,
    tenantId: row.tenant_id,
    investigationId: row.investigation_id,
    disclosureId: row.disclosure_id,
    pageRowCount: row.page_row_count,
    cumulativeRowCount: row.cumulative_row_count,
    pageHash: row.page_hash,
    cursorHash: row.cursor_hash,
    disclosedFields: Object.freeze(parseStringArray(row.disclosed_fields_json)),
    appliedMasks: Object.freeze(JSON.parse(row.applied_masks_json) as Record<string, InvestigationMask>),
    fieldPolicyVersion: row.field_policy_version,
    reference: Object.freeze({ kind: row.reference_kind, id: row.reference_id }),
    certificationManifestId: row.certification_manifest_id,
    populationHash: row.population_hash,
    purpose: row.purpose,
    previousFingerprint: row.previous_fingerprint,
    disclosureFingerprint: row.disclosure_fingerprint,
    actor: row.actor,
    disclosedAt: row.disclosed_at
  });
}

function validateCreate(input: CreateInvestigationRecord): void {
  id(input.tenantId, "tenantId");
  id(input.investigationId, "investigationId");
  hash(input.principalBinding, "principalBinding");
  if (input.reference.kind !== "snapshot" && input.reference.kind !== "result") invalid("Reference kind is invalid");
  id(input.reference.id, "reference.id");
  id(input.certificationManifestId, "certificationManifestId");
  stringSet(input.requestedFields, "requestedFields", 1, 20);
  hash(input.filterHash, "filterHash");
  text(input.purpose, "purpose", 256);
  text(input.reason, "reason", 2_048);
  maskMap(input.masks, input.requestedFields);
  hash(input.populationHash, "populationHash");
  integer(input.rowBudget, "rowBudget", 1, 1_000);
  iso(input.expiresAt, "expiresAt");
  id(input.createdBy, "createdBy");
  if (input.reviewerPrincipalId !== undefined) id(input.reviewerPrincipalId, "reviewerPrincipalId");
  id(input.idempotencyKey, "idempotencyKey");
}

function validateDisclosure(input: RecordInvestigationDisclosureInput): void {
  id(input.tenantId, "tenantId");
  id(input.investigationId, "investigationId");
  hash(input.principalBinding, "principalBinding");
  integer(input.pageRowCount, "pageRowCount", 0, 100);
  hash(input.pageHash, "pageHash");
  hash(input.cursorHash, "cursorHash");
  stringSet(input.disclosedFields, "disclosedFields", 1, 20);
  maskMap(input.appliedMasks, input.disclosedFields);
  id(input.fieldPolicyVersion, "fieldPolicyVersion");
  id(input.actor, "actor");
  id(input.idempotencyKey, "idempotencyKey");
}

function validateClose(input: CloseInvestigationInput): void {
  id(input.tenantId, "tenantId");
  id(input.investigationId, "investigationId");
  hash(input.principalBinding, "principalBinding");
  id(input.actor, "actor");
  text(input.reason, "reason", 2_048);
  id(input.idempotencyKey, "idempotencyKey");
}

function initialDisclosureFingerprint(input: CreateInvestigationRecord): string {
  return digest({
    certificationManifestId: input.certificationManifestId,
    filterHash: input.filterHash,
    investigationId: input.investigationId,
    masks: input.masks,
    populationHash: input.populationHash,
    principalBinding: input.principalBinding,
    requestedFields: input.requestedFields,
    rowBudget: input.rowBudget,
    tenantId: input.tenantId
  });
}

function maskMap(value: Readonly<Record<string, InvestigationMask>>, fields: readonly string[]): void {
  const keys = Object.keys(value).sort();
  if (keys.join("\u0000") !== [...fields].sort().join("\u0000")) invalid("Mask fields must match requested fields");
  for (const mask of Object.values(value)) {
    if (!(["none", "partial", "tokenize", "redact"] as const).includes(mask)) invalid("Mask is invalid");
  }
}

function stringSet(value: readonly string[], label: string, minimum: number, maximum: number): void {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) invalid(`${label} is invalid`);
  const seen = new Set<string>();
  for (const item of value) {
    id(item, label);
    if (seen.has(item)) invalid(`${label} contains duplicates`);
    seen.add(item);
  }
}

function parseStringArray(value: string): string[] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || !parsed.every((item) => typeof item === "string")) invalid("Stored string array is invalid");
  return parsed;
}

function id(value: string, label: string): string {
  if (!value || value.length > 256 || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(value)) invalid(`${label} is invalid`);
  return value;
}

function text(value: string, label: string, maximum: number): string {
  if (!value.trim() || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) invalid(`${label} is invalid`);
  return value;
}

function hash(value: string, label: string): string {
  if (!/^[a-f0-9]{64}$/.test(value)) invalid(`${label} must be a lowercase SHA-256 hash`);
  return value;
}

function iso(value: string, label: string): string {
  if (!value || value.length > 128 || !Number.isFinite(Date.parse(value))) invalid(`${label} is invalid`);
  return value;
}

function integer(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalid(`${label} is invalid`);
  return value;
}

function invalid(message: string): never {
  throw new InvestigationStoreError("INVALID_INPUT", message);
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw new InvestigationStoreError("NOT_FOUND", "Investigation record was not found");
  return value;
}

function digest(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, nested]) => nested !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalize(nested)])
    );
  }
  return value;
}

const INVESTIGATION_SCHEMA = `
CREATE TABLE investigations (
  tenant_id TEXT NOT NULL,
  investigation_id TEXT NOT NULL,
  principal_binding TEXT NOT NULL CHECK (length(principal_binding) = 64),
  reference_kind TEXT NOT NULL CHECK (reference_kind IN ('snapshot', 'result')),
  reference_id TEXT NOT NULL,
  certification_manifest_id TEXT NOT NULL,
  requested_fields_json TEXT NOT NULL,
  filter_json TEXT,
  filter_hash TEXT NOT NULL CHECK (length(filter_hash) = 64),
  purpose TEXT NOT NULL,
  reason TEXT NOT NULL,
  masks_json TEXT NOT NULL,
  population_hash TEXT NOT NULL CHECK (length(population_hash) = 64),
  row_budget INTEGER NOT NULL CHECK (row_budget BETWEEN 1 AND 1000),
  disclosed_rows INTEGER NOT NULL CHECK (disclosed_rows BETWEEN 0 AND row_budget),
  status TEXT NOT NULL CHECK (status IN ('open', 'closed')),
  expires_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  reviewer_principal_id TEXT,
  disclosure_history_fingerprint TEXT NOT NULL CHECK (length(disclosure_history_fingerprint) = 64),
  created_at TEXT NOT NULL,
  closed_at TEXT,
  closed_by TEXT,
  close_reason TEXT,
  PRIMARY KEY (tenant_id, investigation_id)
) STRICT;

CREATE INDEX investigations_principal_created
  ON investigations (tenant_id, principal_binding, created_at, investigation_id);

CREATE TABLE investigation_disclosures (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  investigation_id TEXT NOT NULL,
  disclosure_id TEXT NOT NULL UNIQUE,
  page_row_count INTEGER NOT NULL CHECK (page_row_count BETWEEN 0 AND 100),
  cumulative_row_count INTEGER NOT NULL CHECK (cumulative_row_count BETWEEN 0 AND 1000),
  page_hash TEXT NOT NULL CHECK (length(page_hash) = 64),
  cursor_hash TEXT NOT NULL CHECK (length(cursor_hash) = 64),
  disclosed_fields_json TEXT NOT NULL,
  applied_masks_json TEXT NOT NULL,
  field_policy_version TEXT NOT NULL,
  reference_kind TEXT NOT NULL CHECK (reference_kind IN ('snapshot', 'result')),
  reference_id TEXT NOT NULL,
  certification_manifest_id TEXT NOT NULL,
  population_hash TEXT NOT NULL CHECK (length(population_hash) = 64),
  purpose TEXT NOT NULL,
  previous_fingerprint TEXT NOT NULL CHECK (length(previous_fingerprint) = 64),
  disclosure_fingerprint TEXT NOT NULL CHECK (length(disclosure_fingerprint) = 64),
  actor TEXT NOT NULL,
  disclosed_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, investigation_id)
    REFERENCES investigations (tenant_id, investigation_id)
) STRICT;

CREATE INDEX investigation_disclosures_investigation_sequence
  ON investigation_disclosures (tenant_id, investigation_id, sequence);

CREATE TABLE investigation_idempotency (
  tenant_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
  response_json TEXT NOT NULL,
  PRIMARY KEY (tenant_id, operation, idempotency_key)
) STRICT;

CREATE TRIGGER investigations_no_delete
BEFORE DELETE ON investigations BEGIN SELECT RAISE(ABORT, 'investigations cannot be deleted'); END;
CREATE TRIGGER investigation_disclosures_no_update
BEFORE UPDATE ON investigation_disclosures BEGIN SELECT RAISE(ABORT, 'investigation disclosures are immutable'); END;
CREATE TRIGGER investigation_disclosures_no_delete
BEFORE DELETE ON investigation_disclosures BEGIN SELECT RAISE(ABORT, 'investigation disclosures are immutable'); END;
CREATE TRIGGER investigation_idempotency_no_update
BEFORE UPDATE ON investigation_idempotency BEGIN SELECT RAISE(ABORT, 'investigation idempotency is immutable'); END;
CREATE TRIGGER investigation_idempotency_no_delete
BEFORE DELETE ON investigation_idempotency BEGIN SELECT RAISE(ABORT, 'investigation idempotency is immutable'); END;
`;
