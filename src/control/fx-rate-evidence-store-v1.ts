import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  IdentifierSchema,
  IsoTimestampSchema,
  canonicalHash,
  canonicalJson,
  parseFxRateEvidenceV1,
  parseWithSchema,
  type FxRateEvidenceV1,
  type Sha256Hash
} from "../contracts/index.js";
import { migrateSqliteComponent, type SqliteComponentMigration } from "../infrastructure/sqlite-component-schema.js";
import { z } from "zod";

export const SQLITE_FX_RATE_EVIDENCE_COMPONENT = "abl.fx-rate-evidence-v1" as const;
export const SQLITE_FX_RATE_EVIDENCE_SCHEMA_VERSION = 1 as const;

const SCHEMA = `
CREATE TABLE fx_rate_evidence_v1 (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  rate_evidence_id TEXT NOT NULL CHECK (length(rate_evidence_id) BETWEEN 1 AND 128),
  definition_id TEXT NOT NULL CHECK (length(definition_id) BETWEEN 1 AND 128),
  definition_hash TEXT NOT NULL CHECK (length(definition_hash) = 71 AND definition_hash GLOB 'sha256:*'),
  base_currency TEXT NOT NULL CHECK (length(base_currency) = 3),
  quote_currency TEXT NOT NULL CHECK (length(quote_currency) = 3),
  rate_type TEXT NOT NULL CHECK (rate_type IN ('spot','closing','period_average','contractual')),
  effective_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  rate_evidence_hash TEXT NOT NULL CHECK (length(rate_evidence_hash) = 71 AND rate_evidence_hash GLOB 'sha256:*'),
  evidence_json TEXT NOT NULL CHECK (json_valid(evidence_json)),
  PRIMARY KEY (tenant_id, rate_evidence_id),
  UNIQUE (tenant_id, definition_hash, effective_at, received_at)
) STRICT;

CREATE INDEX fx_rate_evidence_v1_effective
  ON fx_rate_evidence_v1 (
    tenant_id, definition_id, base_currency, quote_currency, rate_type, effective_at DESC, received_at DESC
  );

CREATE TRIGGER fx_rate_evidence_v1_no_update
BEFORE UPDATE ON fx_rate_evidence_v1
BEGIN SELECT RAISE(ABORT, 'FX rate evidence is immutable'); END;
CREATE TRIGGER fx_rate_evidence_v1_no_delete
BEFORE DELETE ON fx_rate_evidence_v1
BEGIN SELECT RAISE(ABORT, 'FX rate evidence is immutable'); END;

CREATE TABLE fx_rate_evidence_v1_idempotency (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
  idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  request_hash TEXT NOT NULL CHECK (length(request_hash) = 71 AND request_hash GLOB 'sha256:*'),
  rate_evidence_id TEXT NOT NULL CHECK (length(rate_evidence_id) BETWEEN 1 AND 128),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, actor_id, idempotency_key),
  FOREIGN KEY (tenant_id, rate_evidence_id)
    REFERENCES fx_rate_evidence_v1 (tenant_id, rate_evidence_id)
) STRICT;

CREATE TRIGGER fx_rate_evidence_v1_idempotency_no_update
BEFORE UPDATE ON fx_rate_evidence_v1_idempotency
BEGIN SELECT RAISE(ABORT, 'FX rate evidence idempotency is immutable'); END;
CREATE TRIGGER fx_rate_evidence_v1_idempotency_no_delete
BEFORE DELETE ON fx_rate_evidence_v1_idempotency
BEGIN SELECT RAISE(ABORT, 'FX rate evidence idempotency is immutable'); END;
`;

export const SQLITE_FX_RATE_EVIDENCE_MIGRATIONS = Object.freeze([
  { version: 1, sql: SCHEMA }
] as const satisfies readonly SqliteComponentMigration[]);

const WriteContextSchema = z.object({
  tenantId: IdentifierSchema,
  actorId: IdentifierSchema,
  idempotencyKey: IdentifierSchema,
  recordedAt: IsoTimestampSchema
}).strict();

const SelectionSchema = z.object({
  tenantId: IdentifierSchema,
  fxDefinitionId: IdentifierSchema,
  definitionHash: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
  baseCurrency: z.string().regex(/^[A-Z]{3}$/u),
  quoteCurrency: z.string().regex(/^[A-Z]{3}$/u),
  rateType: z.enum(["spot", "closing", "period_average", "contractual"]),
  asOf: IsoTimestampSchema,
  knowledgeCutoff: IsoTimestampSchema
}).strict().superRefine((value, context) => {
  if (value.knowledgeCutoff < value.asOf) {
    context.addIssue({
      code: "custom",
      path: ["knowledgeCutoff"],
      message: "cannot precede asOf"
    });
  }
});

export interface FxRateEvidenceWriteContextV1 {
  readonly tenantId: string;
  readonly actorId: string;
  readonly idempotencyKey: string;
  readonly recordedAt: string;
}

export interface SelectGovernedFxRateV1Input {
  readonly tenantId: string;
  readonly fxDefinitionId: string;
  /** Exact frozen active definition document hash; logical IDs are not selection authority. */
  readonly definitionHash: Sha256Hash;
  readonly baseCurrency: string;
  readonly quoteCurrency: string;
  readonly rateType: "spot" | "closing" | "period_average" | "contractual";
  readonly asOf: string;
  /** Rates received after this timestamp are deliberately invisible to replay. */
  readonly knowledgeCutoff: string;
}

export type FxRateEvidenceStoreErrorCode =
  | "INVALID_ARGUMENT"
  | "NOT_FOUND"
  | "CONFLICT"
  | "IDEMPOTENCY_CONFLICT"
  | "INTEGRITY_FAILURE"
  | "STORE_CLOSED";

export class FxRateEvidenceStoreError extends Error {
  constructor(readonly code: FxRateEvidenceStoreErrorCode, message: string) {
    super(message);
    this.name = "FxRateEvidenceStoreError";
  }
}

interface EvidenceRow {
  readonly tenant_id: string;
  readonly rate_evidence_id: string;
  readonly definition_id: string;
  readonly definition_hash: Sha256Hash;
  readonly base_currency: string;
  readonly quote_currency: string;
  readonly rate_type: FxRateEvidenceV1["definition"]["rateType"];
  readonly effective_at: string;
  readonly received_at: string;
  readonly rate_evidence_hash: Sha256Hash;
  readonly evidence_json: string;
}

interface ReceiptRow {
  readonly tenant_id: string;
  readonly actor_id: string;
  readonly idempotency_key: string;
  readonly request_hash: Sha256Hash;
  readonly rate_evidence_id: string;
  readonly created_at: string;
}

/**
 * Internal persistence only. Callers must use a trusted capture authority to
 * construct evidence; this store never treats a stored row as source truth.
 */
export class SqliteFxRateEvidenceStoreV1 {
  readonly #database: DatabaseSync;
  #closed = false;

  constructor(databasePath: string, busyTimeoutMs = 5_000) {
    const path = requiredPath(databasePath);
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(path, { enableForeignKeyConstraints: true });
    try {
      this.#database.exec(
        `PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${integer(busyTimeoutMs, "busyTimeoutMs", 0, 60_000)};`
      );
      migrateSqliteComponent(this.#database, {
        componentName: SQLITE_FX_RATE_EVIDENCE_COMPONENT,
        supportedVersion: SQLITE_FX_RATE_EVIDENCE_SCHEMA_VERSION,
        migrations: SQLITE_FX_RATE_EVIDENCE_MIGRATIONS,
        unsupportedVersionError: (current, supported) =>
          integrity(`FX rate evidence schema ${current} is newer than supported ${supported}`)
      });
      this.#verifyIntegrity();
    } catch (error) {
      this.#database.close();
      if (error instanceof FxRateEvidenceStoreError) throw error;
      throw integrity("FX rate evidence store initialization failed");
    }
  }

  record(
    evidenceValue: FxRateEvidenceV1,
    contextValue: FxRateEvidenceWriteContextV1
  ): Readonly<{ evidence: FxRateEvidenceV1; replayed: boolean }> {
    this.#assertOpen();
    const evidence = parsedEvidence(evidenceValue);
    const context = parsed(WriteContextSchema, contextValue, "FX rate evidence write context");
    if (evidence.tenantId !== context.tenantId) {
      throw new FxRateEvidenceStoreError("INVALID_ARGUMENT", "FX evidence tenant does not match write context");
    }
    if (context.recordedAt < evidence.receivedAt) {
      throw new FxRateEvidenceStoreError("INVALID_ARGUMENT", "FX evidence cannot be recorded before receipt");
    }
    const requestHash = requestHashFor(evidence.rateEvidenceHash, context.tenantId, context.actorId);
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const receipt = this.#receipt(context.tenantId, context.actorId, context.idempotencyKey);
      if (receipt !== undefined) {
        if (receipt.request_hash !== requestHash) {
          throw new FxRateEvidenceStoreError("IDEMPOTENCY_CONFLICT", "FX evidence idempotency request changed");
        }
        const replay = this.#row(context.tenantId, receipt.rate_evidence_id);
        if (!replay) throw integrity("FX idempotency receipt references absent evidence");
        this.#database.exec("COMMIT");
        return Object.freeze({ evidence: rowEvidence(replay), replayed: true });
      }
      const existing = this.#row(context.tenantId, evidence.rateEvidenceId);
      if (existing !== undefined) {
        throw new FxRateEvidenceStoreError("CONFLICT", "FX rate evidence identity already exists");
      }
      this.#database.prepare(
        `INSERT INTO fx_rate_evidence_v1 (
          tenant_id, rate_evidence_id, definition_id, definition_hash,
          base_currency, quote_currency, rate_type, effective_at, received_at,
          rate_evidence_hash, evidence_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        evidence.tenantId,
        evidence.rateEvidenceId,
        evidence.definition.fxDefinitionId,
        evidence.definition.definitionHash,
        evidence.definition.pair.baseCurrency,
        evidence.definition.pair.quoteCurrency,
        evidence.definition.rateType,
        evidence.effectiveAt,
        evidence.receivedAt,
        evidence.rateEvidenceHash,
        canonicalJson(evidence)
      );
      this.#database.prepare(
        `INSERT INTO fx_rate_evidence_v1_idempotency (
          tenant_id, actor_id, idempotency_key, request_hash, rate_evidence_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)`
      ).run(
        context.tenantId,
        context.actorId,
        context.idempotencyKey,
        requestHash,
        evidence.rateEvidenceId,
        context.recordedAt
      );
      this.#database.exec("COMMIT");
      return Object.freeze({ evidence, replayed: false });
    } catch (error) {
      rollback(this.#database);
      if (error instanceof FxRateEvidenceStoreError) throw error;
      throw integrity("FX rate evidence transaction failed");
    }
  }

  get(tenantId: string, rateEvidenceId: string): FxRateEvidenceV1 | undefined {
    this.#assertOpen();
    const tenant = parsed(IdentifierSchema, tenantId, "tenantId");
    const id = parsed(IdentifierSchema, rateEvidenceId, "rateEvidenceId");
    const row = this.#row(tenant, id);
    return row ? rowEvidence(row) : undefined;
  }

  selectEffective(inputValue: SelectGovernedFxRateV1Input): FxRateEvidenceV1 {
    this.#assertOpen();
    const input = parsed(SelectionSchema, inputValue, "FX rate selection");
    const row = this.#database.prepare(
      `SELECT * FROM fx_rate_evidence_v1
        WHERE tenant_id = ?
          AND definition_id = ?
          AND definition_hash = ?
          AND base_currency = ?
          AND quote_currency = ?
          AND rate_type = ?
          AND effective_at <= ?
          AND received_at <= ?
        ORDER BY effective_at DESC, received_at DESC, rate_evidence_hash DESC
        LIMIT 1`
    ).get(
      input.tenantId,
      input.fxDefinitionId,
      input.definitionHash,
      input.baseCurrency,
      input.quoteCurrency,
      input.rateType,
      input.asOf,
      input.knowledgeCutoff
    ) as EvidenceRow | undefined;
    if (!row) {
      throw new FxRateEvidenceStoreError("NOT_FOUND", "No governed FX rate is effective at the requested time");
    }
    const evidence = rowEvidence(row);
    if (
      evidence.definition.fxDefinitionId !== input.fxDefinitionId ||
      evidence.definition.definitionHash !== input.definitionHash ||
      evidence.definition.pair.baseCurrency !== input.baseCurrency ||
      evidence.definition.pair.quoteCurrency !== input.quoteCurrency ||
      evidence.definition.rateType !== input.rateType ||
      evidence.effectiveAt > input.asOf ||
      evidence.receivedAt > input.knowledgeCutoff
    ) {
      throw integrity("Effective FX selection indexes do not match canonical evidence");
    }
    return evidence;
  }

  close(): void {
    if (!this.#closed) {
      this.#database.close();
      this.#closed = true;
    }
  }

  #row(tenantId: string, rateEvidenceId: string): EvidenceRow | undefined {
    return this.#database.prepare(
      "SELECT * FROM fx_rate_evidence_v1 WHERE tenant_id = ? AND rate_evidence_id = ?"
    ).get(tenantId, rateEvidenceId) as EvidenceRow | undefined;
  }

  #receipt(tenantId: string, actorId: string, idempotencyKey: string): ReceiptRow | undefined {
    return this.#database.prepare(
      `SELECT * FROM fx_rate_evidence_v1_idempotency
        WHERE tenant_id = ? AND actor_id = ? AND idempotency_key = ?`
    ).get(tenantId, actorId, idempotencyKey) as ReceiptRow | undefined;
  }

  #verifyIntegrity(): void {
    const evidenceRows = this.#database.prepare(
      "SELECT * FROM fx_rate_evidence_v1 ORDER BY tenant_id, rate_evidence_id"
    ).all() as unknown as EvidenceRow[];
    const evidenceByIdentity = new Map<string, FxRateEvidenceV1>();
    for (const row of evidenceRows) {
      const evidence = rowEvidence(row);
      evidenceByIdentity.set(`${evidence.tenantId}\u0000${evidence.rateEvidenceId}`, evidence);
    }
    const receipts = this.#database.prepare(
      "SELECT * FROM fx_rate_evidence_v1_idempotency ORDER BY tenant_id, actor_id, idempotency_key"
    ).all() as unknown as ReceiptRow[];
    for (const receipt of receipts) {
      const evidence = evidenceByIdentity.get(`${receipt.tenant_id}\u0000${receipt.rate_evidence_id}`);
      if (!evidence) throw integrity("FX idempotency receipt references absent evidence");
      const context = parsed(WriteContextSchema, {
        tenantId: receipt.tenant_id,
        actorId: receipt.actor_id,
        idempotencyKey: receipt.idempotency_key,
        recordedAt: receipt.created_at
      }, "stored FX idempotency context");
      const expected = requestHashFor(evidence.rateEvidenceHash, context.tenantId, context.actorId);
      if (receipt.request_hash !== expected) throw integrity("FX idempotency receipt failed canonical verification");
    }
  }

  #assertOpen(): void {
    if (this.#closed) throw new FxRateEvidenceStoreError("STORE_CLOSED", "FX rate evidence store is closed");
  }
}

function rowEvidence(row: EvidenceRow): FxRateEvidenceV1 {
  let evidence: FxRateEvidenceV1;
  try {
    const raw = JSON.parse(row.evidence_json) as unknown;
    if (canonicalJson(raw) !== row.evidence_json) throw new Error("noncanonical");
    evidence = parseFxRateEvidenceV1(raw);
  } catch {
    throw integrity("Stored FX evidence failed canonical validation");
  }
  if (
    evidence.tenantId !== row.tenant_id ||
    evidence.rateEvidenceId !== row.rate_evidence_id ||
    evidence.definition.fxDefinitionId !== row.definition_id ||
    evidence.definition.definitionHash !== row.definition_hash ||
    evidence.definition.pair.baseCurrency !== row.base_currency ||
    evidence.definition.pair.quoteCurrency !== row.quote_currency ||
    evidence.definition.rateType !== row.rate_type ||
    evidence.effectiveAt !== row.effective_at ||
    evidence.receivedAt !== row.received_at ||
    evidence.rateEvidenceHash !== row.rate_evidence_hash
  ) {
    throw integrity("Stored FX evidence indexes do not match canonical content");
  }
  return evidence;
}

function parsedEvidence(value: FxRateEvidenceV1): FxRateEvidenceV1 {
  try {
    return parseFxRateEvidenceV1(value);
  } catch {
    throw new FxRateEvidenceStoreError("INVALID_ARGUMENT", "FX rate evidence failed canonical validation");
  }
}

function parsed<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  try {
    return parseWithSchema(schema, value, label);
  } catch {
    throw new FxRateEvidenceStoreError("INVALID_ARGUMENT", `${label} failed strict validation`);
  }
}

function requiredPath(value: string): string {
  if (value === ":memory:") return value;
  if (!value.trim()) throw new FxRateEvidenceStoreError("INVALID_ARGUMENT", "FX evidence database path is required");
  return resolve(value);
}

function integer(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new FxRateEvidenceStoreError("INVALID_ARGUMENT", `${label} is outside allowed bounds`);
  }
  return value;
}

function rollback(database: DatabaseSync): void {
  try {
    database.exec("ROLLBACK");
  } catch {
    // Preserve the original transaction error.
  }
}

function integrity(message: string): FxRateEvidenceStoreError {
  return new FxRateEvidenceStoreError("INTEGRITY_FAILURE", message);
}

function requestHashFor(evidenceHash: Sha256Hash, tenantId: string, actorId: string): Sha256Hash {
  return canonicalHash({ evidenceHash, tenantId, actorId });
}
