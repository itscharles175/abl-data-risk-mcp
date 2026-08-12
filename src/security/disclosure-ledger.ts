import { createHash, timingSafeEqual } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { migrateSqliteComponent } from "../infrastructure/sqlite-component-schema.js";

export const DISCLOSURE_LEDGER_COMPONENT = "abl.disclosure-ledger" as const;
export const DISCLOSURE_LEDGER_SCHEMA_VERSION = 1 as const;

export interface AggregateDisclosureCellV1 {
  readonly cellKey: string;
  readonly populationHash: string;
  /** HMAC-SHA256 member tokens produced inside the trusted data plane; never raw record IDs. */
  readonly memberTokens: readonly string[];
}

export interface AssessAggregateDisclosureInputV1 {
  readonly tenantId: string;
  readonly audienceId: string;
  readonly purpose: string;
  readonly datasetId: string;
  readonly snapshotHash: string;
  readonly metricDefinitionHash: string;
  readonly queryFingerprint: string;
  readonly minimumCohortSize: number;
  readonly cells: readonly AggregateDisclosureCellV1[];
  readonly actor: string;
  readonly idempotencyKey: string;
}

export interface AggregateDisclosureDecisionV1 {
  readonly decisionId: string;
  readonly effect: "permit" | "deny";
  readonly reason: "cohort_allowed" | "small_cell" | "differencing_risk";
  readonly queryFingerprint: string;
  readonly comparedReleaseCount: number;
  readonly releasedCellCount: number;
  readonly decidedAt: string;
  readonly decisionHash: string;
}

export class DisclosureLedgerError extends Error {
  constructor(readonly code: "INVALID_INPUT" | "IDEMPOTENCY_CONFLICT", message: string) {
    super(message);
    this.name = "DisclosureLedgerError";
  }
}

/** Durable adaptive-query gate over keyed population membership, with no raw identifiers or cell values. */
export class DisclosureLedger {
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;

  constructor(databasePath: string, options: { readonly clock?: () => Date } = {}) {
    if (!databasePath.trim()) invalid("Disclosure ledger path is required");
    const absolute = resolve(databasePath);
    if (databasePath !== ":memory:") mkdirSync(dirname(absolute), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(databasePath === ":memory:" ? databasePath : absolute);
    this.#clock = options.clock ?? (() => new Date());
    try {
      this.#database.exec("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;");
      migrateSqliteComponent(this.#database, {
        componentName: DISCLOSURE_LEDGER_COMPONENT,
        supportedVersion: DISCLOSURE_LEDGER_SCHEMA_VERSION,
        migrations: [{ version: 1, sql: DISCLOSURE_SCHEMA }],
        unsupportedVersionError: (current, supported) =>
          new DisclosureLedgerError("INVALID_INPUT", `Disclosure schema ${current} is newer than supported ${supported}`)
      });
    } catch (error) {
      this.#database.close();
      throw error;
    }
  }

  assess(input: AssessAggregateDisclosureInputV1): AggregateDisclosureDecisionV1 {
    validateInput(input);
    const canonicalInput = canonicalJson(input);
    const requestHash = sha256(canonicalInput);
    const now = this.#now();
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const receipt = this.#database.prepare(
        `SELECT request_hash, decision_json FROM disclosure_idempotency
          WHERE tenant_id = ? AND audience_id = ? AND idempotency_key = ?`
      ).get(input.tenantId, input.audienceId, input.idempotencyKey) as
        | { request_hash: string; decision_json: string }
        | undefined;
      if (receipt) {
        if (!secureEqual(receipt.request_hash, requestHash)) {
          throw new DisclosureLedgerError("IDEMPOTENCY_CONFLICT", "Disclosure idempotency key was reused with different input");
        }
        const decision = JSON.parse(receipt.decision_json) as AggregateDisclosureDecisionV1;
        this.#database.exec("COMMIT");
        return Object.freeze(decision);
      }

      const previous = this.#database.prepare(
        `SELECT cells_json FROM aggregate_disclosure_releases
          WHERE tenant_id = ? AND audience_id = ? AND purpose = ? AND dataset_id = ?
            AND snapshot_hash = ? AND metric_definition_hash = ?
          ORDER BY sequence DESC LIMIT 500`
      ).all(
        input.tenantId,
        input.audienceId,
        input.purpose,
        input.datasetId,
        normalizeHash(input.snapshotHash),
        normalizeHash(input.metricDefinitionHash)
      ) as unknown as { cells_json: string }[];

      let effect: AggregateDisclosureDecisionV1["effect"] = "permit";
      let reason: AggregateDisclosureDecisionV1["reason"] = "cohort_allowed";
      if (input.cells.some((cell) => cell.memberTokens.length < input.minimumCohortSize)) {
        effect = "deny";
        reason = "small_cell";
      } else {
        const candidateCells = new Map(input.cells.map((cell) => [cell.cellKey, new Set(cell.memberTokens)]));
        outer: for (const release of previous) {
          const cells = JSON.parse(release.cells_json) as AggregateDisclosureCellV1[];
          for (const prior of cells) {
            const candidate = candidateCells.get(prior.cellKey);
            if (!candidate) continue;
            const priorTokens = new Set(prior.memberTokens);
            if (setsEqual(candidate, priorTokens)) continue;
            const removed = setDifferenceSize(priorTokens, candidate);
            const added = setDifferenceSize(candidate, priorTokens);
            if (
              (removed > 0 && removed < input.minimumCohortSize) ||
              (added > 0 && added < input.minimumCohortSize) ||
              (removed + added > 0 && removed + added < input.minimumCohortSize)
            ) {
              effect = "deny";
              reason = "differencing_risk";
              break outer;
            }
          }
        }
      }

      const decisionBody = {
        decisionId: `disclosure-${requestHash.slice(0, 32)}`,
        effect,
        reason,
        queryFingerprint: normalizeHash(input.queryFingerprint),
        comparedReleaseCount: previous.length,
        releasedCellCount: effect === "permit" ? input.cells.length : 0,
        decidedAt: now
      };
      const decision: AggregateDisclosureDecisionV1 = Object.freeze({
        ...decisionBody,
        decisionHash: sha256(canonicalJson(decisionBody))
      });
      if (effect === "permit") {
        this.#database.prepare(
          `INSERT INTO aggregate_disclosure_releases (
             tenant_id, audience_id, purpose, dataset_id, snapshot_hash,
             metric_definition_hash, query_fingerprint, cells_json, actor,
             decision_hash, released_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
          input.tenantId,
          input.audienceId,
          input.purpose,
          input.datasetId,
          normalizeHash(input.snapshotHash),
          normalizeHash(input.metricDefinitionHash),
          normalizeHash(input.queryFingerprint),
          canonicalJson(input.cells),
          input.actor,
          decision.decisionHash,
          now
        );
      }
      this.#database.prepare(
        `INSERT INTO disclosure_idempotency (
           tenant_id, audience_id, idempotency_key, request_hash, decision_json, created_at
         ) VALUES (?, ?, ?, ?, ?, ?)`
      ).run(input.tenantId, input.audienceId, input.idempotencyKey, requestHash, canonicalJson(decision), now);
      this.#database.exec("COMMIT");
      return decision;
    } catch (error) {
      rollback(this.#database);
      throw error;
    }
  }

  close(): void {
    this.#database.close();
  }

  #now(): string {
    const value = this.#clock();
    if (Number.isNaN(value.getTime())) invalid("Clock is invalid");
    return value.toISOString();
  }
}

const DISCLOSURE_SCHEMA = `
CREATE TABLE aggregate_disclosure_releases (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  audience_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  dataset_id TEXT NOT NULL,
  snapshot_hash TEXT NOT NULL CHECK (length(snapshot_hash) = 64),
  metric_definition_hash TEXT NOT NULL CHECK (length(metric_definition_hash) = 64),
  query_fingerprint TEXT NOT NULL CHECK (length(query_fingerprint) = 64),
  cells_json TEXT NOT NULL,
  actor TEXT NOT NULL,
  decision_hash TEXT NOT NULL CHECK (length(decision_hash) = 64),
  released_at TEXT NOT NULL
) STRICT;
CREATE INDEX aggregate_disclosure_history ON aggregate_disclosure_releases (
  tenant_id, audience_id, purpose, dataset_id, snapshot_hash, metric_definition_hash, sequence
);
CREATE TRIGGER aggregate_disclosure_releases_no_update BEFORE UPDATE ON aggregate_disclosure_releases BEGIN SELECT RAISE(ABORT, 'disclosure history is immutable'); END;
CREATE TRIGGER aggregate_disclosure_releases_no_delete BEFORE DELETE ON aggregate_disclosure_releases BEGIN SELECT RAISE(ABORT, 'disclosure history is immutable'); END;

CREATE TABLE disclosure_idempotency (
  tenant_id TEXT NOT NULL,
  audience_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
  decision_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, audience_id, idempotency_key)
) STRICT;
CREATE TRIGGER disclosure_idempotency_no_update BEFORE UPDATE ON disclosure_idempotency BEGIN SELECT RAISE(ABORT, 'disclosure receipts are immutable'); END;
CREATE TRIGGER disclosure_idempotency_no_delete BEFORE DELETE ON disclosure_idempotency BEGIN SELECT RAISE(ABORT, 'disclosure receipts are immutable'); END;
`;

function validateInput(input: AssessAggregateDisclosureInputV1): void {
  for (const [value, label] of [
    [input.tenantId, "tenant id"], [input.audienceId, "audience id"], [input.purpose, "purpose"],
    [input.datasetId, "dataset id"], [input.actor, "actor"], [input.idempotencyKey, "idempotency key"]
  ] as const) identifier(value, label);
  normalizeHash(input.snapshotHash);
  normalizeHash(input.metricDefinitionHash);
  normalizeHash(input.queryFingerprint);
  if (!Number.isSafeInteger(input.minimumCohortSize) || input.minimumCohortSize < 2 || input.minimumCohortSize > 10_000) invalid("minimumCohortSize is invalid");
  if (!Array.isArray(input.cells) || input.cells.length < 1 || input.cells.length > 1_000) invalid("Disclosure cells are invalid");
  const keys = new Set<string>();
  let members = 0;
  for (const cell of input.cells) {
    identifier(cell.cellKey, "cell key");
    if (keys.has(cell.cellKey)) invalid("Disclosure cell keys must be unique");
    keys.add(cell.cellKey);
    normalizeHash(cell.populationHash);
    if (!Array.isArray(cell.memberTokens) || cell.memberTokens.length > 100_000) invalid("Disclosure membership is invalid");
    const tokens = new Set(cell.memberTokens.map(normalizeHash));
    if (tokens.size !== cell.memberTokens.length) invalid("Disclosure membership contains duplicates");
    members += tokens.size;
    if (members > 1_000_000) invalid("Disclosure request exceeds the member-token bound");
    const computed = sha256(canonicalJson([...tokens].sort()));
    if (!secureEqual(computed, normalizeHash(cell.populationHash))) invalid("Disclosure population hash does not match member tokens");
  }
}

function setsEqual(left: ReadonlySet<string>, right: ReadonlySet<string>): boolean {
  return left.size === right.size && [...left].every((value) => right.has(value));
}

function setDifferenceSize(left: ReadonlySet<string>, right: ReadonlySet<string>): number {
  let count = 0;
  for (const value of left) if (!right.has(value)) count += 1;
  return count;
}

function identifier(value: string, label: string): void {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u.test(value)) invalid(`${label} is invalid`);
}

function normalizeHash(value: string): string {
  const normalized = value.startsWith("sha256:") ? value.slice(7) : value;
  if (!/^[0-9a-f]{64}$/u.test(normalized)) invalid("SHA-256 hash is invalid");
  return normalized;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonical(value));
}

function canonical(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) invalid("Canonical number is invalid");
    return value;
  }
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const nested = (value as Record<string, unknown>)[key];
      if (nested !== undefined) result[key] = canonical(nested);
    }
    return result;
  }
  invalid("Value is not canonical JSON");
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function secureEqual(left: string, right: string): boolean {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function rollback(database: DatabaseSync): void {
  try { database.exec("ROLLBACK"); } catch { /* preserve original */ }
}

function invalid(message: string): never {
  throw new DisclosureLedgerError("INVALID_INPUT", message);
}
