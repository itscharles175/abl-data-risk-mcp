import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";

import { migrateSqliteComponent } from "../infrastructure/sqlite-component-schema.js";

export const JOB_STORE_COMPONENT = "abl.job-store" as const;
export const JOB_STORE_SCHEMA_VERSION = 1 as const;

export type JobStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";

export interface SubmitJobInput {
  readonly tenantId: string;
  /** Optional trusted caller-generated id used to bind pre-submission audit evidence. */
  readonly jobId?: string;
  readonly requestedBy: string;
  readonly idempotencyKey: string;
  readonly toolName: string;
  readonly datasetId?: string;
  readonly request: Readonly<Record<string, unknown>>;
  readonly maxAttempts?: number;
  readonly availableAt?: string;
}

export interface ClaimJobInput {
  readonly tenantId: string;
  readonly workerId: string;
  readonly leaseSeconds: number;
}

export interface JobRecord {
  readonly tenantId: string;
  readonly jobId: string;
  readonly toolName: string;
  readonly datasetId: string | null;
  readonly requestHash: string;
  readonly request: Readonly<Record<string, unknown>>;
  readonly requestedBy: string;
  readonly status: JobStatus;
  readonly attemptCount: number;
  readonly maxAttempts: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly availableAt: string;
  readonly claimedBy: string | null;
  readonly leaseExpiresAt: string | null;
  readonly cancellationRequested: boolean;
  readonly resultHandle: string | null;
  readonly errorCode: string | null;
}

export interface ClaimedJob extends JobRecord {
  readonly status: "running";
  readonly claimToken: string;
  readonly claimedBy: string;
  readonly leaseExpiresAt: string;
  /** True only for an expired final attempt; callers may verify/adopt durable output but must not recompute. */
  readonly recoveryOnly: boolean;
}

export interface ReapedJobRecord {
  readonly tenantId: string;
  readonly jobId: string;
  readonly status: "failed" | "cancelled";
  readonly errorCode: "LEASE_EXPIRED" | "CANCELLED";
}

export interface JobStoreOptions {
  readonly clock?: () => Date;
}

export class JobStoreError extends Error {
  constructor(
    readonly code:
      | "INVALID_INPUT"
      | "IDEMPOTENCY_CONFLICT"
      | "JOB_NOT_FOUND"
      | "CLAIM_REJECTED"
      | "INVALID_TRANSITION",
    message: string
  ) {
    super(message);
    this.name = "JobStoreError";
  }
}

/**
 * A durable, tenant-partitioned queue for portable MCP start/status/result
 * workflows. Claim tokens are only returned once and are stored as hashes.
 */
export class JobStore {
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;

  constructor(databasePath: string, options: JobStoreOptions = {}) {
    if (!databasePath.trim()) throw new JobStoreError("INVALID_INPUT", "Job database path is required");
    const absolutePath = resolve(databasePath);
    if (databasePath !== ":memory:") mkdirSync(dirname(absolutePath), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(databasePath === ":memory:" ? databasePath : absolutePath);
    this.#clock = options.clock ?? (() => new Date());
    try {
      this.#database.exec("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;");
      migrateSqliteComponent(this.#database, {
        componentName: JOB_STORE_COMPONENT,
        supportedVersion: JOB_STORE_SCHEMA_VERSION,
        migrations: [{ version: 1, sql: JOB_SCHEMA }],
        unsupportedVersionError: (current, supported) =>
          new JobStoreError(
            "INVALID_INPUT",
            `Job-store schema ${current} is newer than supported version ${supported}`
          )
      });
    } catch (error) {
      this.#database.close();
      throw error;
    }
  }

  submit(input: SubmitJobInput): JobRecord {
    validateIdentifier(input.tenantId, "tenant id");
    if (input.jobId !== undefined) validateIdentifier(input.jobId, "job id");
    validateIdentifier(input.requestedBy, "requester binding");
    validateIdentifier(input.idempotencyKey, "idempotency key");
    validateIdentifier(input.toolName, "tool name");
    if (input.datasetId !== undefined) validateIdentifier(input.datasetId, "dataset id");
    const maxAttempts = input.maxAttempts ?? 3;
    if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 10) {
      throw new JobStoreError("INVALID_INPUT", "maxAttempts must be an integer from 1 through 10");
    }
    const requestJson = canonicalJson(input.request);
    if (Buffer.byteLength(requestJson, "utf8") > 256_000) {
      throw new JobStoreError("INVALID_INPUT", "Job request exceeds 256 KB");
    }
    const requestHash = sha256(requestJson);
    const now = this.#now();
    const availableAt = input.availableAt ? normalizeIsoTimestamp(input.availableAt, "availableAt") : now;

    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const receipt = this.#database
        .prepare(
          `SELECT request_hash, job_id
             FROM job_idempotency
            WHERE tenant_id = ? AND requested_by = ? AND idempotency_key = ?`
        )
        .get(input.tenantId, input.requestedBy, input.idempotencyKey) as
        | { request_hash: string; job_id: string }
        | undefined;
      if (receipt) {
        if (!safeEqual(receipt.request_hash, requestHash)) {
          throw new JobStoreError(
            "IDEMPOTENCY_CONFLICT",
            "The idempotency key was already used with a different request"
          );
        }
        const existing = this.#getWithinTransaction(input.tenantId, receipt.job_id);
        this.#database.exec("COMMIT");
        return existing;
      }

      const jobId = input.jobId ?? randomUUID();
      const duplicateJob = this.#database
        .prepare("SELECT job_id FROM jobs WHERE tenant_id = ? AND job_id = ?")
        .get(input.tenantId, jobId) as { job_id: string } | undefined;
      if (duplicateJob) {
        throw new JobStoreError("IDEMPOTENCY_CONFLICT", "Job id is already in use");
      }
      this.#database
        .prepare(
          `INSERT INTO jobs (
             tenant_id, job_id, tool_name, dataset_id, request_hash, request_json,
             requested_by, status, attempt_count, max_attempts, created_at,
             updated_at, available_at, cancellation_requested
           ) VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', 0, ?, ?, ?, ?, 0)`
        )
        .run(
          input.tenantId,
          jobId,
          input.toolName,
          input.datasetId ?? null,
          requestHash,
          requestJson,
          input.requestedBy,
          maxAttempts,
          now,
          now,
          availableAt
        );
      this.#database
        .prepare(
          `INSERT INTO job_idempotency (
             tenant_id, requested_by, idempotency_key, request_hash, job_id, created_at
           ) VALUES (?, ?, ?, ?, ?, ?)`
        )
        .run(input.tenantId, input.requestedBy, input.idempotencyKey, requestHash, jobId, now);
      const created = this.#getWithinTransaction(input.tenantId, jobId);
      this.#database.exec("COMMIT");
      return created;
    } catch (error) {
      rollback(this.#database);
      throw error;
    }
  }

  claimNext(input: ClaimJobInput): ClaimedJob | null {
    validateIdentifier(input.tenantId, "tenant id");
    validateIdentifier(input.workerId, "worker id");
    if (!Number.isSafeInteger(input.leaseSeconds) || input.leaseSeconds < 5 || input.leaseSeconds > 3_600) {
      throw new JobStoreError("INVALID_INPUT", "leaseSeconds must be an integer from 5 through 3600");
    }
    const now = this.#now();
    const leaseExpiresAt = new Date(Date.parse(now) + input.leaseSeconds * 1_000).toISOString();
    const claimToken = randomUUID();
    const claimTokenHash = sha256(claimToken);

    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const row = this.#database
        .prepare(
          `SELECT job_id,
                  CASE WHEN status = 'running' AND attempt_count >= max_attempts THEN 1 ELSE 0 END AS recovery_only
             FROM jobs
            WHERE tenant_id = ?
              AND cancellation_requested = 0
              AND (
                (status = 'queued' AND attempt_count < max_attempts AND available_at <= ?)
                OR (status = 'running' AND lease_expires_at <= ?)
              )
            ORDER BY created_at ASC, job_id ASC
            LIMIT 1`
        )
        .get(input.tenantId, now, now) as { job_id: string; recovery_only: number } | undefined;
      if (!row) {
        this.#database.exec("COMMIT");
        return null;
      }
      const updated = this.#database
        .prepare(
          `UPDATE jobs
              SET status = 'running',
                  attempt_count = CASE
                    WHEN status = 'running' AND attempt_count >= max_attempts THEN attempt_count
                    ELSE attempt_count + 1
                  END,
                  claimed_by = ?, claim_token_hash = ?, lease_expires_at = ?, updated_at = ?
            WHERE tenant_id = ? AND job_id = ?
              AND cancellation_requested = 0
              AND (
                (status = 'queued' AND attempt_count < max_attempts AND available_at <= ?)
                OR (status = 'running' AND lease_expires_at <= ?)
              )`
        )
        .run(
          input.workerId,
          claimTokenHash,
          leaseExpiresAt,
          now,
          input.tenantId,
          row.job_id,
          now,
          now
        );
      if (Number(updated.changes) !== 1) {
        this.#database.exec("COMMIT");
        return null;
      }
      const claimed = this.#getWithinTransaction(input.tenantId, row.job_id);
      this.#database.exec("COMMIT");
      if (claimed.status !== "running" || !claimed.claimedBy || !claimed.leaseExpiresAt) {
        throw new JobStoreError("INVALID_TRANSITION", "Claimed job was not persisted as running");
      }
      return {
        ...claimed,
        status: "running",
        claimToken,
        claimedBy: claimed.claimedBy,
        leaseExpiresAt: claimed.leaseExpiresAt,
        recoveryOnly: row.recovery_only === 1
      };
    } catch (error) {
      rollback(this.#database);
      throw error;
    }
  }

  heartbeat(
    tenantId: string,
    jobId: string,
    workerId: string,
    claimToken: string,
    leaseSeconds: number
  ): JobRecord {
    if (!Number.isSafeInteger(leaseSeconds) || leaseSeconds < 5 || leaseSeconds > 3_600) {
      throw new JobStoreError("INVALID_INPUT", "leaseSeconds must be an integer from 5 through 3600");
    }
    const now = this.#now();
    const expires = new Date(Date.parse(now) + leaseSeconds * 1_000).toISOString();
    const updated = this.#database
      .prepare(
        `UPDATE jobs
            SET lease_expires_at = ?, updated_at = ?
          WHERE tenant_id = ? AND job_id = ? AND status = 'running'
            AND claimed_by = ? AND claim_token_hash = ? AND lease_expires_at > ?`
      )
      .run(expires, now, tenantId, jobId, workerId, sha256(claimToken), now);
    if (Number(updated.changes) !== 1) throw new JobStoreError("CLAIM_REJECTED", "The active job lease was not found");
    return this.get(tenantId, jobId);
  }

  complete(
    tenantId: string,
    jobId: string,
    workerId: string,
    claimToken: string,
    resultHandle: string
  ): JobRecord {
    validateIdentifier(resultHandle, "result handle");
    return this.#finishClaim(tenantId, jobId, workerId, claimToken, {
      status: "succeeded",
      resultHandle,
      errorCode: null,
      requireCancellationClear: true
    });
  }

  fail(
    tenantId: string,
    jobId: string,
    workerId: string,
    claimToken: string,
    errorCode: string,
    retryable: boolean,
    retryAt?: string
  ): JobRecord {
    validateIdentifier(errorCode, "error code");
    const normalizedRetryAt = retryAt ? normalizeIsoTimestamp(retryAt, "retryAt") : undefined;
    const current = this.#assertClaim(tenantId, jobId, workerId, claimToken);
    if (retryable && current.attemptCount < current.maxAttempts && !current.cancellationRequested) {
      const now = this.#now();
      const updated = this.#database
        .prepare(
          `UPDATE jobs
              SET status = 'queued', available_at = ?, claimed_by = NULL,
                  claim_token_hash = NULL, lease_expires_at = NULL,
                  error_code = ?, updated_at = ?
            WHERE tenant_id = ? AND job_id = ? AND status = 'running'
              AND claimed_by = ? AND claim_token_hash = ? AND lease_expires_at > ?`
        )
        .run(
          normalizedRetryAt ?? now,
          errorCode,
          now,
          tenantId,
          jobId,
          workerId,
          sha256(claimToken),
          now
        );
      if (Number(updated.changes) !== 1) throw new JobStoreError("CLAIM_REJECTED", "The active job lease was not found");
      return this.get(tenantId, jobId);
    }
    return this.#finishClaim(tenantId, jobId, workerId, claimToken, {
      status: current.cancellationRequested ? "cancelled" : "failed",
      resultHandle: null,
      errorCode,
      requireCancellationClear: false
    });
  }

  requestCancellation(tenantId: string, jobId: string, requestedBy: string): JobRecord {
    validateIdentifier(requestedBy, "requester binding");
    const now = this.#now();
    const current = this.get(tenantId, jobId);
    if (current.requestedBy !== requestedBy) {
      throw new JobStoreError("JOB_NOT_FOUND", "Job was not found");
    }
    if (current.status === "succeeded" || current.status === "failed" || current.status === "cancelled") return current;
    if (current.status === "queued") {
      this.#database
        .prepare(
          `UPDATE jobs
              SET status = 'cancelled', cancellation_requested = 1, updated_at = ?
            WHERE tenant_id = ? AND job_id = ? AND status = 'queued'`
        )
        .run(now, tenantId, jobId);
    } else {
      this.#database
        .prepare(
          `UPDATE jobs
              SET cancellation_requested = 1, updated_at = ?
            WHERE tenant_id = ? AND job_id = ? AND status = 'running'`
        )
        .run(now, tenantId, jobId);
    }
    return this.get(tenantId, jobId);
  }

  get(tenantId: string, jobId: string, requestedBy?: string): JobRecord {
    validateIdentifier(tenantId, "tenant id");
    validateIdentifier(jobId, "job id");
    const record = this.#getWithinTransaction(tenantId, jobId);
    if (requestedBy !== undefined && record.requestedBy !== requestedBy) {
      throw new JobStoreError("JOB_NOT_FOUND", "Job was not found");
    }
    return record;
  }

  list(tenantId: string, requestedBy: string, limit: number = 100): readonly JobRecord[] {
    validateIdentifier(tenantId, "tenant id");
    validateIdentifier(requestedBy, "requester binding");
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) {
      throw new JobStoreError("INVALID_INPUT", "limit must be an integer from 1 through 500");
    }
    const rows = this.#database
      .prepare(
        `SELECT * FROM jobs
          WHERE tenant_id = ? AND requested_by = ?
          ORDER BY created_at DESC, job_id DESC
          LIMIT ?`
      )
      .all(tenantId, requestedBy, limit as SQLInputValue) as unknown as readonly JobRow[];
    return rows.map(rowToRecord);
  }

  /**
   * Returns only tenant partitions that currently contain claimable work.
   * This is an internal worker-discovery surface; tenant ids never come from
   * MCP job-processing arguments.
   */
  listRunnableTenantIds(limit: number = 100): readonly string[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      throw new JobStoreError("INVALID_INPUT", "limit must be an integer from 1 through 1000");
    }
    const now = this.#now();
    const rows = this.#database
      .prepare(
        `SELECT tenant_id, MIN(created_at) AS oldest_created_at
           FROM jobs
          WHERE cancellation_requested = 0
            AND (
              (status = 'queued' AND attempt_count < max_attempts AND available_at <= ?)
              OR (status = 'running' AND lease_expires_at <= ?)
            )
          GROUP BY tenant_id
          ORDER BY oldest_created_at ASC, tenant_id ASC
          LIMIT ?`
      )
      .all(now, now, limit as SQLInputValue) as unknown as readonly {
        readonly tenant_id: string;
      }[];
    return Object.freeze(rows.map((row) => row.tenant_id));
  }

  /**
   * Terminalizes cancelled expired claims. Exhausted non-cancelled claims stay
   * recoverable so the workflow can adopt a verified durable manifest without
   * granting another computation attempt.
   */
  reapExpiredJobs(limit: number = 100): readonly ReapedJobRecord[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      throw new JobStoreError("INVALID_INPUT", "limit must be an integer from 1 through 1000");
    }
    const now = this.#now();
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const rows = this.#database
        .prepare(
          `SELECT tenant_id, job_id, cancellation_requested
             FROM jobs
            WHERE status = 'running'
              AND lease_expires_at <= ?
              AND cancellation_requested = 1
            ORDER BY lease_expires_at ASC, tenant_id ASC, job_id ASC
            LIMIT ?`
        )
        .all(now, limit as SQLInputValue) as unknown as readonly {
          readonly tenant_id: string;
          readonly job_id: string;
          readonly cancellation_requested: number;
        }[];
      const reaped: ReapedJobRecord[] = [];
      for (const row of rows) {
        const status = "cancelled";
        const errorCode = "CANCELLED";
        const updated = this.#database
          .prepare(
            `UPDATE jobs
                SET status = ?, claimed_by = NULL, claim_token_hash = NULL,
                    lease_expires_at = NULL, error_code = ?, updated_at = ?
              WHERE tenant_id = ? AND job_id = ? AND status = 'running'
                AND lease_expires_at <= ?
                AND cancellation_requested = 1`
          )
          .run(status, errorCode, now, row.tenant_id, row.job_id, now);
        if (Number(updated.changes) === 1) {
          reaped.push(
            Object.freeze({
              tenantId: row.tenant_id,
              jobId: row.job_id,
              status,
              errorCode
            })
          );
        }
      }
      this.#database.exec("COMMIT");
      return Object.freeze(reaped);
    } catch (error) {
      rollback(this.#database);
      throw error;
    }
  }

  close(): void {
    this.#database.close();
  }

  #assertClaim(tenantId: string, jobId: string, workerId: string, claimToken: string): JobRecord {
    const now = this.#now();
    const current = this.get(tenantId, jobId);
    if (
      current.status !== "running" ||
      current.claimedBy !== workerId ||
      !current.leaseExpiresAt ||
      current.leaseExpiresAt <= now
    ) {
      throw new JobStoreError("CLAIM_REJECTED", "The active job lease was not found");
    }
    const row = this.#database
      .prepare("SELECT claim_token_hash FROM jobs WHERE tenant_id = ? AND job_id = ?")
      .get(tenantId, jobId) as { claim_token_hash: string | null } | undefined;
    if (!row?.claim_token_hash || !safeEqual(row.claim_token_hash, sha256(claimToken))) {
      throw new JobStoreError("CLAIM_REJECTED", "The active job lease was not found");
    }
    return current;
  }

  #finishClaim(
    tenantId: string,
    jobId: string,
    workerId: string,
    claimToken: string,
    outcome: {
      readonly status: "succeeded" | "failed" | "cancelled";
      readonly resultHandle: string | null;
      readonly errorCode: string | null;
      readonly requireCancellationClear: boolean;
    }
  ): JobRecord {
    this.#assertClaim(tenantId, jobId, workerId, claimToken);
    const now = this.#now();
    const updated = this.#database
      .prepare(
        `UPDATE jobs
            SET status = ?, result_handle = ?, error_code = ?,
                claimed_by = NULL, claim_token_hash = NULL,
                lease_expires_at = NULL, updated_at = ?
          WHERE tenant_id = ? AND job_id = ? AND status = 'running'
            AND claimed_by = ? AND claim_token_hash = ? AND lease_expires_at > ?
            AND (? = 0 OR cancellation_requested = 0)`
      )
      .run(
        outcome.status,
        outcome.resultHandle,
        outcome.errorCode,
        now,
        tenantId,
        jobId,
        workerId,
        sha256(claimToken),
        now,
        outcome.requireCancellationClear ? 1 : 0
      );
    if (Number(updated.changes) !== 1) throw new JobStoreError("CLAIM_REJECTED", "The active job lease was not found");
    return this.get(tenantId, jobId);
  }

  #getWithinTransaction(tenantId: string, jobId: string): JobRecord {
    const row = this.#database
      .prepare("SELECT * FROM jobs WHERE tenant_id = ? AND job_id = ?")
      .get(tenantId, jobId) as JobRow | undefined;
    if (!row) throw new JobStoreError("JOB_NOT_FOUND", "Job was not found");
    return rowToRecord(row);
  }

  #now(): string {
    const date = this.#clock();
    if (Number.isNaN(date.getTime())) throw new JobStoreError("INVALID_INPUT", "Clock returned an invalid date");
    return date.toISOString();
  }
}

interface JobRow {
  readonly tenant_id: string;
  readonly job_id: string;
  readonly tool_name: string;
  readonly dataset_id: string | null;
  readonly request_hash: string;
  readonly request_json: string;
  readonly requested_by: string;
  readonly status: JobStatus;
  readonly attempt_count: number;
  readonly max_attempts: number;
  readonly created_at: string;
  readonly updated_at: string;
  readonly available_at: string;
  readonly claimed_by: string | null;
  readonly lease_expires_at: string | null;
  readonly cancellation_requested: number;
  readonly result_handle: string | null;
  readonly error_code: string | null;
}

function rowToRecord(row: JobRow): JobRecord {
  return Object.freeze({
    tenantId: row.tenant_id,
    jobId: row.job_id,
    toolName: row.tool_name,
    datasetId: row.dataset_id,
    requestHash: row.request_hash,
    request: JSON.parse(row.request_json) as Readonly<Record<string, unknown>>,
    requestedBy: row.requested_by,
    status: row.status,
    attemptCount: row.attempt_count,
    maxAttempts: row.max_attempts,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    availableAt: row.available_at,
    claimedBy: row.claimed_by,
    leaseExpiresAt: row.lease_expires_at,
    cancellationRequested: row.cancellation_requested === 1,
    resultHandle: row.result_handle,
    errorCode: row.error_code
  });
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    if (value instanceof Date) return value.toISOString();
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, nested]) => nested !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalize(nested)])
    );
  }
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new JobStoreError("INVALID_INPUT", "Job requests cannot contain non-finite numbers");
  }
  return value;
}

function validateIdentifier(value: string, label: string): void {
  if (!value || value.length > 256 || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new JobStoreError("INVALID_INPUT", `${label} is invalid`);
  }
}

function normalizeIsoTimestamp(value: string, label: string): string {
  if (!/^\d{4}-\d{2}-\d{2}T/.test(value) || Number.isNaN(Date.parse(value))) {
    throw new JobStoreError("INVALID_INPUT", `${label} must be an ISO timestamp`);
  }
  return new Date(value).toISOString();
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function rollback(database: DatabaseSync): void {
  try {
    database.exec("ROLLBACK");
  } catch {
    // Preserve the original failure if SQLite already closed the transaction.
  }
}

const JOB_SCHEMA = `
CREATE TABLE IF NOT EXISTS jobs (
  tenant_id TEXT NOT NULL,
  job_id TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  dataset_id TEXT,
  request_hash TEXT NOT NULL,
  request_json TEXT NOT NULL CHECK (json_valid(request_json)),
  requested_by TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
  max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 10),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  available_at TEXT NOT NULL,
  claimed_by TEXT,
  claim_token_hash TEXT,
  lease_expires_at TEXT,
  cancellation_requested INTEGER NOT NULL CHECK (cancellation_requested IN (0, 1)),
  result_handle TEXT,
  error_code TEXT,
  PRIMARY KEY (tenant_id, job_id),
  CHECK (
    (status = 'running' AND claimed_by IS NOT NULL AND claim_token_hash IS NOT NULL AND lease_expires_at IS NOT NULL)
    OR (status != 'running' AND claimed_by IS NULL AND claim_token_hash IS NULL AND lease_expires_at IS NULL)
  ),
  CHECK ((status = 'succeeded' AND result_handle IS NOT NULL) OR status != 'succeeded')
) STRICT;

CREATE INDEX IF NOT EXISTS jobs_claimable
  ON jobs (tenant_id, status, available_at, lease_expires_at, created_at);

CREATE TABLE IF NOT EXISTS job_idempotency (
  tenant_id TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  job_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, requested_by, idempotency_key),
  FOREIGN KEY (tenant_id, job_id) REFERENCES jobs (tenant_id, job_id)
) STRICT;

CREATE TRIGGER IF NOT EXISTS jobs_no_delete
BEFORE DELETE ON jobs
BEGIN
  SELECT RAISE(ABORT, 'jobs are retained for audit');
END;

CREATE TRIGGER IF NOT EXISTS idempotency_no_update
BEFORE UPDATE ON job_idempotency
BEGIN
  SELECT RAISE(ABORT, 'idempotency receipts are immutable');
END;

CREATE TRIGGER IF NOT EXISTS idempotency_no_delete
BEFORE DELETE ON job_idempotency
BEGIN
  SELECT RAISE(ABORT, 'idempotency receipts are immutable');
END;
`;
