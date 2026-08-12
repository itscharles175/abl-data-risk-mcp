import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { migrateSqliteComponent } from "../infrastructure/sqlite-component-schema.js";
import type {
  OpaqueHandleKind,
  PrincipalBoundHandleRecord,
  ReplayDefense,
  ReplayRecord
} from "./signed-plan.js";

export const SECURITY_STATE_STORE_COMPONENT = "abl.security-state-store" as const;
export const SECURITY_STATE_STORE_SCHEMA_VERSION = 1 as const;

export interface SecurityStateStoreOptions {
  readonly clock?: () => Date;
  readonly busyTimeoutMs?: number;
}

export interface HandleBinding {
  readonly handleId: string;
  readonly kind: OpaqueHandleKind;
  readonly tenantId: string;
  readonly principalBinding: string;
  readonly resourceId: string;
  readonly issuedAtEpochSeconds: number;
  readonly expiresAtEpochSeconds: number;
}

export class SecurityStateStoreError extends Error {
  constructor(
    readonly code: "INVALID_INPUT" | "HANDLE_CONFLICT" | "HANDLE_NOT_FOUND" | "HANDLE_EXPIRED",
    message: string
  ) {
    super(message);
    this.name = "SecurityStateStoreError";
  }
}

/** Shared replay and opaque-handle state. SQLite is suitable for one-node deployments. */
export class SecurityStateStore implements ReplayDefense {
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;

  constructor(databasePath: string, options: SecurityStateStoreOptions = {}) {
    if (!databasePath.trim()) throw new SecurityStateStoreError("INVALID_INPUT", "Security state path is required");
    const absolute = resolve(databasePath);
    if (databasePath !== ":memory:") mkdirSync(dirname(absolute), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(databasePath === ":memory:" ? databasePath : absolute);
    this.#clock = options.clock ?? (() => new Date());
    const busyTimeoutMs = boundedInteger(options.busyTimeoutMs ?? 5_000, "busyTimeoutMs", 0, 60_000);
    try {
      this.#database.exec(`PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${busyTimeoutMs};`);
      migrateSqliteComponent(this.#database, {
        componentName: SECURITY_STATE_STORE_COMPONENT,
        supportedVersion: SECURITY_STATE_STORE_SCHEMA_VERSION,
        migrations: [{ version: 1, sql: SECURITY_STATE_SCHEMA }],
        unsupportedVersionError: (current, supported) =>
          new SecurityStateStoreError(
            "INVALID_INPUT",
            `Security-state schema ${current} is newer than supported version ${supported}`
          )
      });
    } catch (error) {
      this.#database.close();
      throw error;
    }
  }

  consumeOnce(record: ReplayRecord): boolean {
    validateReplay(record);
    const now = this.#nowEpochSeconds();
    if (record.expiresAtEpochSeconds <= now) return false;
    const result = this.#database
      .prepare(
        `INSERT OR IGNORE INTO consumed_plans (
           replay_key, plan_id, nonce, tenant_id, principal_binding,
           expires_at_epoch_seconds, consumed_at_epoch_seconds
         ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        record.replayKey,
        record.planId,
        record.nonce,
        record.tenantId,
        record.principalBinding,
        record.expiresAtEpochSeconds,
        now
      );
    return Number(result.changes) === 1;
  }

  bindHandle(record: PrincipalBoundHandleRecord, resourceIdInput: string): HandleBinding {
    validateHandle(record);
    const resourceId = identifier(resourceIdInput, "resource id");
    this.#database
      .prepare(
        `INSERT OR IGNORE INTO handle_bindings (
           handle_id, kind, tenant_id, principal_binding, resource_id,
           issued_at_epoch_seconds, expires_at_epoch_seconds
         ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        record.handleId,
        record.kind,
        record.tenantId,
        record.principalBinding,
        resourceId,
        record.issuedAtEpochSeconds,
        record.expiresAtEpochSeconds
      );
    const persisted = this.#database
      .prepare("SELECT * FROM handle_bindings WHERE handle_id = ?")
      .get(record.handleId) as HandleRow | undefined;
    if (!persisted) throw new SecurityStateStoreError("HANDLE_CONFLICT", "Opaque handle could not be bound");
    const binding = handleRow(persisted);
    if (!sameBinding(binding, record, resourceId)) {
      throw new SecurityStateStoreError("HANDLE_CONFLICT", "Opaque handle is already bound to another resource");
    }
    return binding;
  }

  resolveHandle(record: PrincipalBoundHandleRecord): HandleBinding {
    validateHandle(record);
    const row = this.#database
      .prepare("SELECT * FROM handle_bindings WHERE handle_id = ?")
      .get(record.handleId) as HandleRow | undefined;
    if (!row) throw new SecurityStateStoreError("HANDLE_NOT_FOUND", "Opaque handle was not found");
    const binding = handleRow(row);
    if (!sameBinding(binding, record, binding.resourceId)) {
      throw new SecurityStateStoreError("HANDLE_NOT_FOUND", "Opaque handle was not found");
    }
    if (binding.expiresAtEpochSeconds <= this.#nowEpochSeconds()) {
      throw new SecurityStateStoreError("HANDLE_EXPIRED", "Opaque handle has expired");
    }
    return binding;
  }

  pruneExpired(): { readonly replayRecords: number; readonly handleBindings: number } {
    const now = this.#nowEpochSeconds();
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const replayRecords = Number(
        this.#database
          .prepare("DELETE FROM consumed_plans WHERE expires_at_epoch_seconds <= ?")
          .run(now).changes
      );
      const handleBindings = Number(
        this.#database
          .prepare("DELETE FROM handle_bindings WHERE expires_at_epoch_seconds <= ?")
          .run(now).changes
      );
      this.#database.exec("COMMIT");
      return { replayRecords, handleBindings };
    } catch (error) {
      try {
        this.#database.exec("ROLLBACK");
      } catch {
        // Preserve the original SQLite error.
      }
      throw error;
    }
  }

  close(): void {
    this.#database.close();
  }

  #nowEpochSeconds(): number {
    const milliseconds = this.#clock().getTime();
    if (!Number.isFinite(milliseconds)) throw new SecurityStateStoreError("INVALID_INPUT", "Clock is invalid");
    return Math.floor(milliseconds / 1_000);
  }
}

interface HandleRow {
  readonly handle_id: string;
  readonly kind: OpaqueHandleKind;
  readonly tenant_id: string;
  readonly principal_binding: string;
  readonly resource_id: string;
  readonly issued_at_epoch_seconds: number;
  readonly expires_at_epoch_seconds: number;
}

function handleRow(row: HandleRow): HandleBinding {
  return Object.freeze({
    handleId: row.handle_id,
    kind: row.kind,
    tenantId: row.tenant_id,
    principalBinding: row.principal_binding,
    resourceId: row.resource_id,
    issuedAtEpochSeconds: row.issued_at_epoch_seconds,
    expiresAtEpochSeconds: row.expires_at_epoch_seconds
  });
}

function sameBinding(
  binding: HandleBinding,
  record: PrincipalBoundHandleRecord,
  resourceId: string
): boolean {
  return (
    binding.handleId === record.handleId &&
    binding.kind === record.kind &&
    binding.tenantId === record.tenantId &&
    binding.principalBinding === record.principalBinding &&
    binding.resourceId === resourceId &&
    binding.issuedAtEpochSeconds === record.issuedAtEpochSeconds &&
    binding.expiresAtEpochSeconds === record.expiresAtEpochSeconds
  );
}

function validateReplay(record: ReplayRecord): void {
  hash(record.replayKey, "replay key");
  hash(record.planId, "plan id");
  identifier(record.nonce, "nonce");
  identifier(record.tenantId, "tenant id");
  hash(record.principalBinding, "principal binding");
  epoch(record.expiresAtEpochSeconds, "replay expiry");
}

function validateHandle(record: PrincipalBoundHandleRecord): void {
  identifier(record.handleId, "handle id");
  if (record.kind !== "job" && record.kind !== "result") {
    throw new SecurityStateStoreError("INVALID_INPUT", "handle kind is invalid");
  }
  identifier(record.tenantId, "tenant id");
  hash(record.principalBinding, "principal binding");
  epoch(record.issuedAtEpochSeconds, "handle issue time");
  epoch(record.expiresAtEpochSeconds, "handle expiry");
  if (record.expiresAtEpochSeconds <= record.issuedAtEpochSeconds) {
    throw new SecurityStateStoreError("INVALID_INPUT", "handle validity window is invalid");
  }
}

function identifier(value: string, label: string): string {
  if (!value || value.length > 256 || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(value)) {
    throw new SecurityStateStoreError("INVALID_INPUT", `${label} is invalid`);
  }
  return value;
}

function hash(value: string, label: string): string {
  if (!/^[a-f0-9]{64}$/.test(value)) {
    throw new SecurityStateStoreError("INVALID_INPUT", `${label} must be lowercase SHA-256`);
  }
  return value;
}

function epoch(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new SecurityStateStoreError("INVALID_INPUT", `${label} must be non-negative epoch seconds`);
  }
  return value;
}

function boundedInteger(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new SecurityStateStoreError("INVALID_INPUT", `${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

const SECURITY_STATE_SCHEMA = `
CREATE TABLE IF NOT EXISTS consumed_plans (
  replay_key TEXT PRIMARY KEY,
  plan_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  principal_binding TEXT NOT NULL,
  expires_at_epoch_seconds INTEGER NOT NULL,
  consumed_at_epoch_seconds INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS consumed_plans_expiry
  ON consumed_plans (expires_at_epoch_seconds);

CREATE TABLE IF NOT EXISTS handle_bindings (
  handle_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('job', 'result')),
  tenant_id TEXT NOT NULL,
  principal_binding TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  issued_at_epoch_seconds INTEGER NOT NULL,
  expires_at_epoch_seconds INTEGER NOT NULL,
  CHECK (expires_at_epoch_seconds > issued_at_epoch_seconds)
) STRICT;

CREATE INDEX IF NOT EXISTS handle_bindings_expiry
  ON handle_bindings (expires_at_epoch_seconds);

CREATE TRIGGER IF NOT EXISTS consumed_plans_no_update
BEFORE UPDATE ON consumed_plans
BEGIN
  SELECT RAISE(ABORT, 'consumed plan records are immutable');
END;

CREATE TRIGGER IF NOT EXISTS handle_bindings_no_update
BEFORE UPDATE ON handle_bindings
BEGIN
  SELECT RAISE(ABORT, 'handle bindings are immutable');
END;
`;
