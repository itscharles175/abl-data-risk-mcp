import { createHash, randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { migrateSqliteComponent } from "../infrastructure/sqlite-component-schema.js";
import type { JsonValue } from "./store.js";

export const DEFINITION_STORE_COMPONENT = "abl.definition-store" as const;
export const DEFINITION_STORE_SCHEMA_VERSION = 1 as const;

export type DefinitionKind =
  | "data_quality_profile"
  | "stratification_recipe"
  | "vintage_recipe"
  | "borrowing_base_policy"
  | "monitor_definition";

export type DefinitionStatus = "proposed" | "validated" | "approved" | "active" | "superseded" | "retired";
export type DefinitionTransition = "validated" | "approved" | "active" | "retired";

export interface ProposeDefinitionInput {
  readonly tenantId: string;
  readonly definitionId: string;
  readonly definitionKey: string;
  readonly kind: DefinitionKind;
  readonly version: string;
  readonly effectiveFrom: string;
  readonly effectiveTo?: string;
  readonly document: JsonValue;
  readonly proposedBy: string;
  readonly idempotencyKey: string;
}

export interface TransitionDefinitionInput {
  readonly tenantId: string;
  readonly definitionId: string;
  readonly toStatus: DefinitionTransition;
  readonly actor: string;
  readonly evidence?: JsonValue;
  readonly idempotencyKey: string;
}

export interface GovernedDefinition {
  readonly tenantId: string;
  readonly definitionId: string;
  readonly definitionKey: string;
  readonly kind: DefinitionKind;
  readonly version: string;
  readonly effectiveFrom: string;
  readonly effectiveTo: string | null;
  readonly document: JsonValue;
  readonly documentHash: string;
  readonly status: DefinitionStatus;
  readonly proposedBy: string;
  readonly proposedAt: string;
  readonly validatedBy: string | null;
  readonly validatedAt: string | null;
  readonly approvedBy: string | null;
  readonly approvedAt: string | null;
  readonly activatedBy: string | null;
  readonly activatedAt: string | null;
  readonly terminalBy: string | null;
  readonly terminalAt: string | null;
}

export interface DefinitionAuditEvent {
  readonly sequence: number;
  readonly tenantId: string;
  readonly eventId: string;
  readonly definitionId: string;
  readonly eventType: string;
  readonly actor: string;
  readonly details: JsonValue;
  readonly occurredAt: string;
}

export interface DefinitionStoreOptions {
  readonly clock?: () => Date;
  readonly busyTimeoutMs?: number;
}

export class DefinitionStoreError extends Error {
  constructor(
    readonly code:
      | "INVALID_INPUT"
      | "NOT_FOUND"
      | "CONFLICT"
      | "IDEMPOTENCY_CONFLICT"
      | "ILLEGAL_TRANSITION"
      | "MAKER_CHECKER_VIOLATION",
    message: string
  ) {
    super(message);
    this.name = "DefinitionStoreError";
  }
}

/** Durable effective-dated policy and recipe governance; documents are never executable code. */
export class DefinitionStore {
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;

  constructor(databasePath: string, options: DefinitionStoreOptions = {}) {
    if (!databasePath.trim()) throw invalid("Definition database path is required");
    const absolute = resolve(databasePath);
    if (databasePath !== ":memory:") mkdirSync(dirname(absolute), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(databasePath === ":memory:" ? databasePath : absolute);
    this.#clock = options.clock ?? (() => new Date());
    const busyTimeout = boundedInteger(options.busyTimeoutMs ?? 5_000, "busyTimeoutMs", 0, 60_000);
    try {
      this.#database.exec(`PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${busyTimeout};`);
      migrateSqliteComponent(this.#database, {
        componentName: DEFINITION_STORE_COMPONENT,
        supportedVersion: DEFINITION_STORE_SCHEMA_VERSION,
        migrations: [{ version: 1, sql: DEFINITION_SCHEMA }],
        unsupportedVersionError: (current, supported) =>
          new DefinitionStoreError(
            "CONFLICT",
            `Definition-store schema ${current} is newer than supported version ${supported}`
          )
      });
    } catch (error) {
      this.#database.close();
      throw error;
    }
  }

  propose(input: ProposeDefinitionInput): GovernedDefinition {
    validateProposal(input);
    const requestJson = canonicalJson(input);
    const requestHash = sha256(requestJson);
    return this.#transaction(() => {
      const replay = this.#idempotentReplay(input.tenantId, "definition.propose", input.idempotencyKey, requestHash);
      if (replay) return this.#required(input.tenantId, replay);
      if (this.get(input.tenantId, input.definitionId)) {
        throw new DefinitionStoreError("CONFLICT", "Definition id already exists in this tenant");
      }
      const duplicate = this.#database
        .prepare(
          `SELECT definition_id FROM governed_definitions
            WHERE tenant_id = ? AND definition_key = ? AND kind = ? AND version = ?`
        )
        .get(input.tenantId, input.definitionKey, input.kind, input.version) as { definition_id: string } | undefined;
      if (duplicate) throw new DefinitionStoreError("CONFLICT", "Definition version already exists");
      const now = this.#now();
      const documentJson = canonicalJson(input.document);
      const documentHash = sha256(documentJson);
      this.#database
        .prepare(
          `INSERT INTO governed_definitions (
             tenant_id, definition_id, definition_key, kind, version,
             effective_from, effective_to, document_json, document_hash,
             status, proposed_by, proposed_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?, ?)`
        )
        .run(
          input.tenantId,
          input.definitionId,
          input.definitionKey,
          input.kind,
          input.version,
          input.effectiveFrom,
          input.effectiveTo ?? null,
          documentJson,
          documentHash,
          input.proposedBy,
          now
        );
      this.#audit(input.tenantId, input.definitionId, "definition.proposed", input.proposedBy, {
        definitionKey: input.definitionKey,
        documentHash,
        kind: input.kind,
        version: input.version
      }, now);
      this.#receipt(input.tenantId, "definition.propose", input.idempotencyKey, requestHash, input.definitionId, now);
      return this.#required(input.tenantId, input.definitionId);
    });
  }

  transition(input: TransitionDefinitionInput): GovernedDefinition {
    validateTransition(input);
    const requestHash = sha256(canonicalJson(input));
    return this.#transaction(() => {
      const replay = this.#idempotentReplay(input.tenantId, "definition.transition", input.idempotencyKey, requestHash);
      if (replay) return this.#required(input.tenantId, replay);
      const current = this.#required(input.tenantId, input.definitionId);
      if (input.actor === current.proposedBy) {
        throw new DefinitionStoreError("MAKER_CHECKER_VIOLATION", "The proposer cannot validate, approve, activate, or retire this definition");
      }
      const expected: Record<DefinitionTransition, readonly DefinitionStatus[]> = {
        validated: ["proposed"],
        approved: ["validated"],
        active: ["approved"],
        retired: ["active", "superseded"]
      };
      if (!expected[input.toStatus].includes(current.status)) {
        throw new DefinitionStoreError(
          "ILLEGAL_TRANSITION",
          `Cannot transition ${current.status} definition to ${input.toStatus}`
        );
      }
      const now = this.#now();
      if (input.toStatus === "validated") {
        this.#database
          .prepare(
            `UPDATE governed_definitions SET status = 'validated', validated_by = ?, validated_at = ?
              WHERE tenant_id = ? AND definition_id = ? AND status = 'proposed'`
          )
          .run(input.actor, now, input.tenantId, input.definitionId);
      } else if (input.toStatus === "approved") {
        this.#database
          .prepare(
            `UPDATE governed_definitions SET status = 'approved', approved_by = ?, approved_at = ?
              WHERE tenant_id = ? AND definition_id = ? AND status = 'validated'`
          )
          .run(input.actor, now, input.tenantId, input.definitionId);
      } else if (input.toStatus === "active") {
        const sameEffectiveDate = this.#database
          .prepare(
            `SELECT definition_id FROM governed_definitions
              WHERE tenant_id = ? AND definition_key = ? AND kind = ?
                AND effective_from = ? AND status IN ('active', 'superseded')`
          )
          .get(input.tenantId, current.definitionKey, current.kind, current.effectiveFrom) as
          | { definition_id: string }
          | undefined;
        if (sameEffectiveDate) {
          throw new DefinitionStoreError("CONFLICT", "An effective version already starts on this date");
        }
        const priorActive = this.#database
          .prepare(
            `SELECT definition_id, effective_from FROM governed_definitions
              WHERE tenant_id = ? AND definition_key = ? AND kind = ? AND status = 'active'`
          )
          .get(input.tenantId, current.definitionKey, current.kind) as
          | { definition_id: string; effective_from: string }
          | undefined;
        if (priorActive) {
          if (current.effectiveFrom <= priorActive.effective_from) {
            throw new DefinitionStoreError(
              "CONFLICT",
              "A replacement definition must start after the currently active version"
            );
          }
          this.#database
            .prepare(
              `UPDATE governed_definitions
                  SET status = 'superseded', terminal_by = ?, terminal_at = ?
                WHERE tenant_id = ? AND definition_id = ? AND status = 'active'`
            )
            .run(input.actor, now, input.tenantId, priorActive.definition_id);
          this.#audit(
            input.tenantId,
            priorActive.definition_id,
            "definition.superseded",
            input.actor,
            { replacementDefinitionId: input.definitionId },
            now
          );
        }
        this.#database
          .prepare(
            `UPDATE governed_definitions SET status = 'active', activated_by = ?, activated_at = ?
              WHERE tenant_id = ? AND definition_id = ? AND status = 'approved'`
          )
          .run(input.actor, now, input.tenantId, input.definitionId);
      } else {
        this.#database
          .prepare(
            `UPDATE governed_definitions SET status = 'retired', terminal_by = ?, terminal_at = ?
              WHERE tenant_id = ? AND definition_id = ? AND status IN ('active', 'superseded')`
          )
          .run(input.actor, now, input.tenantId, input.definitionId);
      }
      this.#audit(
        input.tenantId,
        input.definitionId,
        `definition.${input.toStatus}`,
        input.actor,
        input.evidence === undefined ? {} : { evidence: input.evidence },
        now
      );
      this.#receipt(input.tenantId, "definition.transition", input.idempotencyKey, requestHash, input.definitionId, now);
      return this.#required(input.tenantId, input.definitionId);
    });
  }

  get(tenantId: string, definitionId: string): GovernedDefinition | undefined {
    identifier(tenantId, "tenant id");
    identifier(definitionId, "definition id");
    const row = this.#database
      .prepare("SELECT * FROM governed_definitions WHERE tenant_id = ? AND definition_id = ?")
      .get(tenantId, definitionId) as DefinitionRow | undefined;
    return row ? definitionRow(row) : undefined;
  }

  list(tenantId: string, kind?: DefinitionKind, definitionKey?: string): readonly GovernedDefinition[] {
    identifier(tenantId, "tenant id");
    if (definitionKey !== undefined) identifier(definitionKey, "definition key");
    const conditions = ["tenant_id = ?"];
    const parameters: string[] = [tenantId];
    if (kind !== undefined) {
      definitionKind(kind);
      conditions.push("kind = ?");
      parameters.push(kind);
    }
    if (definitionKey !== undefined) {
      conditions.push("definition_key = ?");
      parameters.push(definitionKey);
    }
    const rows = this.#database
      .prepare(
        `SELECT * FROM governed_definitions WHERE ${conditions.join(" AND ")}
          ORDER BY kind, definition_key, effective_from, version`
      )
      .all(...parameters) as unknown as DefinitionRow[];
    return rows.map(definitionRow);
  }

  selectEffective(
    tenantId: string,
    kindInput: DefinitionKind,
    definitionKey: string,
    asOfDate: string
  ): GovernedDefinition {
    identifier(tenantId, "tenant id");
    const kind = definitionKind(kindInput);
    identifier(definitionKey, "definition key");
    isoDate(asOfDate, "as-of date");
    const rows = this.#database
      .prepare(
        `SELECT * FROM governed_definitions
          WHERE tenant_id = ? AND kind = ? AND definition_key = ?
            AND status IN ('active', 'superseded')
            AND effective_from <= ? AND (effective_to IS NULL OR effective_to > ?)
          ORDER BY effective_from DESC, activated_at DESC
          LIMIT 2`
      )
      .all(tenantId, kind, definitionKey, asOfDate, asOfDate) as unknown as DefinitionRow[];
    if (rows.length === 0) throw new DefinitionStoreError("NOT_FOUND", "No effective governed definition was found");
    const selected = rows[0]!;
    if (rows[1]?.effective_from === selected.effective_from) {
      throw new DefinitionStoreError("CONFLICT", "Multiple governed definitions are effective on the same date");
    }
    return definitionRow(selected);
  }

  listAuditEvents(tenantId: string, afterSequence = 0, limit = 100): readonly DefinitionAuditEvent[] {
    identifier(tenantId, "tenant id");
    boundedInteger(afterSequence, "afterSequence", 0, Number.MAX_SAFE_INTEGER);
    boundedInteger(limit, "limit", 1, 1_000);
    const rows = this.#database
      .prepare(
        `SELECT * FROM definition_audit_events
          WHERE tenant_id = ? AND sequence > ? ORDER BY sequence LIMIT ?`
      )
      .all(tenantId, afterSequence, limit) as unknown as AuditRow[];
    return rows.map((row) => ({
      sequence: row.sequence,
      tenantId: row.tenant_id,
      eventId: row.event_id,
      definitionId: row.definition_id,
      eventType: row.event_type,
      actor: row.actor,
      details: JSON.parse(row.details_json) as JsonValue,
      occurredAt: row.occurred_at
    }));
  }

  close(): void {
    this.#database.close();
  }

  #required(tenantId: string, definitionId: string): GovernedDefinition {
    const definition = this.get(tenantId, definitionId);
    if (!definition) throw new DefinitionStoreError("NOT_FOUND", "Governed definition was not found");
    return definition;
  }

  #idempotentReplay(tenantId: string, operation: string, key: string, requestHash: string): string | null {
    const row = this.#database
      .prepare(
        `SELECT request_hash, definition_id FROM definition_idempotency
          WHERE tenant_id = ? AND operation = ? AND idempotency_key = ?`
      )
      .get(tenantId, operation, key) as { request_hash: string; definition_id: string } | undefined;
    if (!row) return null;
    if (row.request_hash !== requestHash) {
      throw new DefinitionStoreError("IDEMPOTENCY_CONFLICT", "Idempotency key was used with another request");
    }
    return row.definition_id;
  }

  #receipt(
    tenantId: string,
    operation: string,
    key: string,
    requestHash: string,
    definitionId: string,
    now: string
  ): void {
    this.#database
      .prepare(
        `INSERT INTO definition_idempotency (
           tenant_id, operation, idempotency_key, request_hash, definition_id, created_at
         ) VALUES (?, ?, ?, ?, ?, ?)`
      )
      .run(tenantId, operation, key, requestHash, definitionId, now);
  }

  #audit(
    tenantId: string,
    definitionId: string,
    eventType: string,
    actor: string,
    details: JsonValue,
    now: string
  ): void {
    this.#database
      .prepare(
        `INSERT INTO definition_audit_events (
           tenant_id, event_id, definition_id, event_type, actor, details_json, occurred_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(tenantId, randomUUID(), definitionId, eventType, actor, canonicalJson(details), now);
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
        // Preserve the original error if SQLite already ended the transaction.
      }
      throw error;
    }
  }

  #now(): string {
    const time = this.#clock();
    if (Number.isNaN(time.getTime())) throw invalid("Clock returned an invalid date");
    return time.toISOString();
  }
}

interface DefinitionRow {
  readonly tenant_id: string;
  readonly definition_id: string;
  readonly definition_key: string;
  readonly kind: DefinitionKind;
  readonly version: string;
  readonly effective_from: string;
  readonly effective_to: string | null;
  readonly document_json: string;
  readonly document_hash: string;
  readonly status: DefinitionStatus;
  readonly proposed_by: string;
  readonly proposed_at: string;
  readonly validated_by: string | null;
  readonly validated_at: string | null;
  readonly approved_by: string | null;
  readonly approved_at: string | null;
  readonly activated_by: string | null;
  readonly activated_at: string | null;
  readonly terminal_by: string | null;
  readonly terminal_at: string | null;
}

interface AuditRow {
  readonly sequence: number;
  readonly tenant_id: string;
  readonly event_id: string;
  readonly definition_id: string;
  readonly event_type: string;
  readonly actor: string;
  readonly details_json: string;
  readonly occurred_at: string;
}

function definitionRow(row: DefinitionRow): GovernedDefinition {
  return Object.freeze({
    tenantId: row.tenant_id,
    definitionId: row.definition_id,
    definitionKey: row.definition_key,
    kind: row.kind,
    version: row.version,
    effectiveFrom: row.effective_from,
    effectiveTo: row.effective_to,
    document: JSON.parse(row.document_json) as JsonValue,
    documentHash: row.document_hash,
    status: row.status,
    proposedBy: row.proposed_by,
    proposedAt: row.proposed_at,
    validatedBy: row.validated_by,
    validatedAt: row.validated_at,
    approvedBy: row.approved_by,
    approvedAt: row.approved_at,
    activatedBy: row.activated_by,
    activatedAt: row.activated_at,
    terminalBy: row.terminal_by,
    terminalAt: row.terminal_at
  });
}

function validateProposal(input: ProposeDefinitionInput): void {
  identifier(input.tenantId, "tenant id");
  identifier(input.definitionId, "definition id");
  identifier(input.definitionKey, "definition key");
  definitionKind(input.kind);
  identifier(input.version, "version");
  isoDate(input.effectiveFrom, "effectiveFrom");
  if (input.effectiveTo !== undefined) {
    isoDate(input.effectiveTo, "effectiveTo");
    if (input.effectiveTo <= input.effectiveFrom) throw invalid("effectiveTo must follow effectiveFrom");
  }
  canonicalJson(input.document);
  identifier(input.proposedBy, "proposer");
  identifier(input.idempotencyKey, "idempotency key");
}

function validateTransition(input: TransitionDefinitionInput): void {
  identifier(input.tenantId, "tenant id");
  identifier(input.definitionId, "definition id");
  if (!["validated", "approved", "active", "retired"].includes(input.toStatus)) {
    throw invalid("Definition transition is invalid");
  }
  identifier(input.actor, "actor");
  identifier(input.idempotencyKey, "idempotency key");
  if (input.evidence !== undefined) canonicalJson(input.evidence);
}

function definitionKind(value: DefinitionKind): DefinitionKind {
  if (
    ![
      "data_quality_profile",
      "stratification_recipe",
      "vintage_recipe",
      "borrowing_base_policy",
      "monitor_definition"
    ].includes(value)
  ) {
    throw invalid("Definition kind is invalid");
  }
  return value;
}

function identifier(value: string, label: string): string {
  if (!value || value.length > 256 || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(value)) {
    throw invalid(`${label} is invalid`);
  }
  return value;
}

function isoDate(value: string, label: string): string {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) throw invalid(`${label} must be YYYY-MM-DD`);
  const date = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== value) {
    throw invalid(`${label} must be a real calendar date`);
  }
  return value;
}

function boundedInteger(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw invalid(`${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function canonicalJson(value: unknown): string {
  const result = JSON.stringify(canonicalize(value));
  if (result === undefined || Buffer.byteLength(result, "utf8") > 1_000_000) {
    throw invalid("Definition document must be bounded canonical JSON");
  }
  return result;
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
  if (typeof value === "bigint" || (typeof value === "number" && !Number.isFinite(value))) {
    throw invalid("Definition document contains a non-JSON value");
  }
  return value;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function invalid(message: string): DefinitionStoreError {
  return new DefinitionStoreError("INVALID_INPUT", message);
}

const DEFINITION_SCHEMA = `
CREATE TABLE IF NOT EXISTS governed_definitions (
  tenant_id TEXT NOT NULL,
  definition_id TEXT NOT NULL,
  definition_key TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN (
    'data_quality_profile', 'stratification_recipe', 'vintage_recipe',
    'borrowing_base_policy', 'monitor_definition'
  )),
  version TEXT NOT NULL,
  effective_from TEXT NOT NULL,
  effective_to TEXT,
  document_json TEXT NOT NULL CHECK (json_valid(document_json)),
  document_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('proposed', 'validated', 'approved', 'active', 'superseded', 'retired')),
  proposed_by TEXT NOT NULL,
  proposed_at TEXT NOT NULL,
  validated_by TEXT,
  validated_at TEXT,
  approved_by TEXT,
  approved_at TEXT,
  activated_by TEXT,
  activated_at TEXT,
  terminal_by TEXT,
  terminal_at TEXT,
  PRIMARY KEY (tenant_id, definition_id),
  UNIQUE (tenant_id, definition_key, kind, version)
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS governed_definitions_one_active
  ON governed_definitions (tenant_id, definition_key, kind)
  WHERE status = 'active';

CREATE INDEX IF NOT EXISTS governed_definitions_effective
  ON governed_definitions (tenant_id, kind, definition_key, effective_from, effective_to, status);

CREATE TABLE IF NOT EXISTS definition_idempotency (
  tenant_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  definition_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, operation, idempotency_key),
  FOREIGN KEY (tenant_id, definition_id) REFERENCES governed_definitions (tenant_id, definition_id)
) STRICT;

CREATE TABLE IF NOT EXISTS definition_audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL UNIQUE,
  definition_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  details_json TEXT NOT NULL CHECK (json_valid(details_json)),
  occurred_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id, definition_id) REFERENCES governed_definitions (tenant_id, definition_id)
) STRICT;

CREATE TRIGGER IF NOT EXISTS governed_definitions_immutable_identity
BEFORE UPDATE ON governed_definitions
WHEN OLD.tenant_id != NEW.tenant_id
  OR OLD.definition_id != NEW.definition_id
  OR OLD.definition_key != NEW.definition_key
  OR OLD.kind != NEW.kind
  OR OLD.version != NEW.version
  OR OLD.effective_from != NEW.effective_from
  OR COALESCE(OLD.effective_to, '') != COALESCE(NEW.effective_to, '')
  OR OLD.document_json != NEW.document_json
  OR OLD.document_hash != NEW.document_hash
  OR OLD.proposed_by != NEW.proposed_by
  OR OLD.proposed_at != NEW.proposed_at
BEGIN
  SELECT RAISE(ABORT, 'governed definition content is immutable');
END;

CREATE TRIGGER IF NOT EXISTS governed_definitions_no_delete
BEFORE DELETE ON governed_definitions
BEGIN
  SELECT RAISE(ABORT, 'governed definitions are retained');
END;

CREATE TRIGGER IF NOT EXISTS definition_idempotency_append_only_update
BEFORE UPDATE ON definition_idempotency BEGIN SELECT RAISE(ABORT, 'idempotency receipts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS definition_idempotency_append_only_delete
BEFORE DELETE ON definition_idempotency BEGIN SELECT RAISE(ABORT, 'idempotency receipts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS definition_audit_append_only_update
BEFORE UPDATE ON definition_audit_events BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;
CREATE TRIGGER IF NOT EXISTS definition_audit_append_only_delete
BEFORE DELETE ON definition_audit_events BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;
`;
