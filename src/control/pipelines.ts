import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { migrateSqliteComponent } from "../infrastructure/sqlite-component-schema.js";

export const PIPELINE_STORE_COMPONENT = "abl.pipeline-store" as const;
export const PIPELINE_STORE_SCHEMA_VERSION = 1 as const;

export const PIPELINE_STAGES = Object.freeze([
  "detect",
  "extract",
  "profile",
  "map",
  "dq",
  "reconcile",
  "certify",
  "analyze",
  "monitor",
  "report"
] as const);

export type PipelineStage = (typeof PIPELINE_STAGES)[number];
export type PipelineDeliveryMode = "full" | "delta" | "correction" | "backfill";
export type PipelineRunStatus = "queued" | "running" | "blocked" | "failed" | "cancelled" | "succeeded";
export type PipelineAttemptStatus = "running" | "failed" | "succeeded";
export type OutboxKind = "audit" | "notification";
export type OutboxStatus = "pending" | "claimed" | "delivered" | "dead_letter";

export interface CreatePipelineRunInput {
  readonly tenantId: string;
  readonly pipelineDefinitionId: string;
  readonly pipelineDefinitionVersion: string;
  readonly sourceContractId: string;
  readonly requestedBy: string;
  readonly idempotencyKey: string;
  readonly deliveryMode: PipelineDeliveryMode;
  readonly deliveryReference: string;
  readonly watermarkStart?: string;
  readonly watermarkEnd?: string;
  readonly supersedesRunId?: string;
  readonly maximumAttemptsPerStage?: number;
}

export interface PipelineRunV1 {
  readonly schemaVersion: 1;
  readonly tenantId: string;
  readonly runId: string;
  readonly pipelineDefinitionId: string;
  readonly pipelineDefinitionVersion: string;
  readonly sourceContractId: string;
  readonly requestedBy: string;
  readonly deliveryMode: PipelineDeliveryMode;
  readonly deliveryReferenceHash: string;
  readonly watermarkStart: string | null;
  readonly watermarkEnd: string | null;
  readonly supersedesRunId: string | null;
  readonly status: PipelineRunStatus;
  readonly currentStage: PipelineStage | null;
  readonly snapshotId: string | null;
  readonly certificationManifestId: string | null;
  readonly maximumAttemptsPerStage: number;
  readonly cancellationRequested: boolean;
  readonly errorCode: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface PipelineStageAttemptV1 {
  readonly schemaVersion: 1;
  readonly tenantId: string;
  readonly runId: string;
  readonly stage: PipelineStage;
  readonly attempt: number;
  readonly status: PipelineAttemptStatus;
  readonly workerId: string;
  readonly startedAt: string;
  readonly finishedAt: string | null;
  readonly evidenceHash: string | null;
  readonly errorCode: string | null;
}

export interface StartPipelineStageInput {
  readonly tenantId: string;
  readonly runId: string;
  readonly workerId: string;
  readonly idempotencyKey: string;
}

export interface OutboxMessageInput {
  readonly kind: OutboxKind;
  readonly eventType: string;
  readonly destinationRef?: string;
  readonly templateRef?: string;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly maximumAttempts?: number;
}

export interface CompletePipelineStageInput {
  readonly tenantId: string;
  readonly runId: string;
  readonly stage: PipelineStage;
  readonly attempt: number;
  readonly workerId: string;
  readonly idempotencyKey: string;
  readonly evidenceHash: string;
  readonly snapshotId?: string;
  readonly certificationManifestId?: string;
  readonly outbox?: readonly OutboxMessageInput[];
}

export interface FailPipelineStageInput {
  readonly tenantId: string;
  readonly runId: string;
  readonly stage: PipelineStage;
  readonly attempt: number;
  readonly workerId: string;
  readonly idempotencyKey: string;
  readonly errorCode: string;
  readonly retryable: boolean;
}

export interface OutboxMessageV1 {
  readonly schemaVersion: 1;
  readonly tenantId: string;
  readonly messageId: string;
  readonly runId: string;
  readonly stage: PipelineStage;
  readonly kind: OutboxKind;
  readonly eventType: string;
  readonly destinationRef: string | null;
  readonly templateRef: string | null;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly status: OutboxStatus;
  readonly attemptCount: number;
  readonly maximumAttempts: number;
  readonly availableAt: string;
  readonly claimedBy: string | null;
  readonly leaseExpiresAt: string | null;
  readonly deliveredAt: string | null;
  readonly receiptHash: string | null;
  readonly createdAt: string;
}

export interface ClaimedOutboxMessageV1 extends OutboxMessageV1 {
  readonly status: "claimed";
  readonly claimToken: string;
  readonly claimedBy: string;
  readonly leaseExpiresAt: string;
}

export interface PipelineStoreOptions {
  readonly clock?: () => Date;
}

export class PipelineStoreError extends Error {
  constructor(
    readonly code:
      | "INVALID_INPUT"
      | "NOT_FOUND"
      | "IDEMPOTENCY_CONFLICT"
      | "INVALID_TRANSITION"
      | "CLAIM_REJECTED",
    message: string
  ) {
    super(message);
    this.name = "PipelineStoreError";
  }
}

/**
 * Durable, tenant-partitioned pipeline and transactional outbox store.
 * It deliberately owns no scheduler, connector, notification destination, or
 * delivery client; those services operate only on typed, governed references.
 */
export class PipelineStore {
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;

  constructor(databasePath: string, options: PipelineStoreOptions = {}) {
    if (!databasePath.trim()) invalid("Pipeline database path is required");
    const absolutePath = resolve(databasePath);
    if (databasePath !== ":memory:") mkdirSync(dirname(absolutePath), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(databasePath === ":memory:" ? databasePath : absolutePath);
    this.#clock = options.clock ?? (() => new Date());
    try {
      this.#database.exec("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;");
      migrateSqliteComponent(this.#database, {
        componentName: PIPELINE_STORE_COMPONENT,
        supportedVersion: PIPELINE_STORE_SCHEMA_VERSION,
        migrations: [{ version: 1, sql: PIPELINE_SCHEMA }],
        unsupportedVersionError: (current, supported) =>
          new PipelineStoreError(
            "INVALID_INPUT",
            `Pipeline-store schema ${current} is newer than supported version ${supported}`
          )
      });
    } catch (error) {
      this.#database.close();
      throw error;
    }
  }

  createRun(input: CreatePipelineRunInput): PipelineRunV1 {
    validateCreateRun(input);
    const request = canonicalJson(input);
    const requestHash = sha256(request);
    const now = this.#now();
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const receipt = this.#database.prepare(
        `SELECT request_hash, response_json FROM pipeline_idempotency
          WHERE tenant_id = ? AND operation = 'create_run' AND actor_id = ? AND idempotency_key = ?`
      ).get(input.tenantId, input.requestedBy, input.idempotencyKey) as
        | { request_hash: string; response_json: string }
        | undefined;
      if (receipt) {
        assertReplay(receipt.request_hash, requestHash);
        const replay = JSON.parse(receipt.response_json) as { runId: string };
        const result = this.#getRun(input.tenantId, replay.runId);
        this.#database.exec("COMMIT");
        return result;
      }
      if (input.supersedesRunId) {
        const predecessor = this.#getRun(input.tenantId, input.supersedesRunId);
        if (predecessor.status !== "succeeded") {
          transition("A correction or backfill may supersede only a succeeded pipeline run");
        }
      }
      const runId = randomUUID();
      this.#database.prepare(
        `INSERT INTO pipeline_runs (
           tenant_id, run_id, pipeline_definition_id, pipeline_definition_version,
           source_contract_id, requested_by, delivery_mode, delivery_reference_hash,
           watermark_start, watermark_end, supersedes_run_id, status, current_stage,
           maximum_attempts_per_stage, cancellation_requested, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', 'detect', ?, 0, ?, ?)`
      ).run(
        input.tenantId,
        runId,
        input.pipelineDefinitionId,
        input.pipelineDefinitionVersion,
        input.sourceContractId,
        input.requestedBy,
        input.deliveryMode,
        sha256(input.deliveryReference),
        input.watermarkStart ?? null,
        input.watermarkEnd ?? null,
        input.supersedesRunId ?? null,
        input.maximumAttemptsPerStage ?? 3,
        now,
        now
      );
      this.#recordReceipt(input.tenantId, "create_run", input.requestedBy, input.idempotencyKey, requestHash, { runId }, now);
      const created = this.#getRun(input.tenantId, runId);
      this.#database.exec("COMMIT");
      return created;
    } catch (error) {
      rollback(this.#database);
      throw error;
    }
  }

  getRun(tenantId: string, runId: string): PipelineRunV1 {
    validateIdentifier(tenantId, "tenant id");
    validateIdentifier(runId, "run id");
    return this.#getRun(tenantId, runId);
  }

  listRuns(tenantId: string, limit = 100): readonly PipelineRunV1[] {
    validateIdentifier(tenantId, "tenant id");
    validateLimit(limit);
    return this.#database.prepare(
      `SELECT * FROM pipeline_runs WHERE tenant_id = ? ORDER BY created_at DESC, run_id DESC LIMIT ?`
    ).all(tenantId, limit).map(toRun);
  }

  startStage(input: StartPipelineStageInput): PipelineStageAttemptV1 {
    validateIdentifier(input.tenantId, "tenant id");
    validateIdentifier(input.runId, "run id");
    validateIdentifier(input.workerId, "worker id");
    validateIdentifier(input.idempotencyKey, "idempotency key");
    const requestHash = sha256(canonicalJson(input));
    const now = this.#now();
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const replay = this.#readAttemptReceipt(input.tenantId, "start_stage", input.workerId, input.idempotencyKey, requestHash);
      if (replay) {
        const result = this.#getAttempt(input.tenantId, input.runId, replay.stage, replay.attempt);
        this.#database.exec("COMMIT");
        return result;
      }
      const run = this.#getRun(input.tenantId, input.runId);
      if (run.cancellationRequested) transition("Cancelled pipeline cannot start another stage");
      if (run.status !== "queued" || run.currentStage === null) transition("Pipeline is not ready to start a stage");
      const latest = this.#database.prepare(
        `SELECT COALESCE(MAX(attempt), 0) AS attempt FROM pipeline_stage_attempts
          WHERE tenant_id = ? AND run_id = ? AND stage = ?`
      ).get(input.tenantId, input.runId, run.currentStage) as { attempt: number };
      const attempt = latest.attempt + 1;
      if (attempt > run.maximumAttemptsPerStage) transition("Pipeline stage exhausted its attempt budget");
      this.#database.prepare(
        `INSERT INTO pipeline_stage_attempts (
           tenant_id, run_id, stage, attempt, status, worker_id, started_at
         ) VALUES (?, ?, ?, ?, 'running', ?, ?)`
      ).run(input.tenantId, input.runId, run.currentStage, attempt, input.workerId, now);
      this.#database.prepare(
        `UPDATE pipeline_runs SET status = 'running', updated_at = ?
          WHERE tenant_id = ? AND run_id = ?`
      ).run(now, input.tenantId, input.runId);
      this.#recordReceipt(
        input.tenantId,
        "start_stage",
        input.workerId,
        input.idempotencyKey,
        requestHash,
        { attempt, stage: run.currentStage },
        now
      );
      const result = this.#getAttempt(input.tenantId, input.runId, run.currentStage, attempt);
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      rollback(this.#database);
      throw error;
    }
  }

  completeStage(input: CompletePipelineStageInput): PipelineRunV1 {
    validateComplete(input);
    const requestHash = sha256(canonicalJson(input));
    const now = this.#now();
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const replay = this.#readRunReceipt(input.tenantId, "complete_stage", input.workerId, input.idempotencyKey, requestHash);
      if (replay) {
        const result = this.#getRun(input.tenantId, replay.runId);
        this.#database.exec("COMMIT");
        return result;
      }
      const run = this.#getRun(input.tenantId, input.runId);
      this.#assertRunningAttempt(run, input.stage, input.attempt, input.workerId);
      if (input.stage === "extract" && !input.snapshotId) invalid("Extract completion requires a snapshot id");
      if (input.stage === "certify" && !input.certificationManifestId) {
        invalid("Certification completion requires a certification manifest id");
      }
      if (input.snapshotId && input.stage !== "extract") invalid("snapshotId is accepted only for extract completion");
      if (input.certificationManifestId && input.stage !== "certify") {
        invalid("certificationManifestId is accepted only for certify completion");
      }
      this.#database.prepare(
        `UPDATE pipeline_stage_attempts
            SET status = 'succeeded', finished_at = ?, evidence_hash = ?
          WHERE tenant_id = ? AND run_id = ? AND stage = ? AND attempt = ?`
      ).run(now, normalizeHash(input.evidenceHash, "evidence hash"), input.tenantId, input.runId, input.stage, input.attempt);
      const next = nextStage(input.stage);
      this.#database.prepare(
        `UPDATE pipeline_runs
            SET status = ?, current_stage = ?, snapshot_id = COALESCE(?, snapshot_id),
                certification_manifest_id = COALESCE(?, certification_manifest_id), updated_at = ?
          WHERE tenant_id = ? AND run_id = ?`
      ).run(
        next === null ? "succeeded" : "queued",
        next,
        input.snapshotId ?? null,
        input.certificationManifestId ?? null,
        now,
        input.tenantId,
        input.runId
      );
      for (const message of input.outbox ?? []) {
        this.#insertOutbox(input.tenantId, input.runId, input.stage, message, now);
      }
      this.#recordReceipt(input.tenantId, "complete_stage", input.workerId, input.idempotencyKey, requestHash, { runId: input.runId }, now);
      const result = this.#getRun(input.tenantId, input.runId);
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      rollback(this.#database);
      throw error;
    }
  }

  failStage(input: FailPipelineStageInput): PipelineRunV1 {
    validateFail(input);
    const requestHash = sha256(canonicalJson(input));
    const now = this.#now();
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const replay = this.#readRunReceipt(input.tenantId, "fail_stage", input.workerId, input.idempotencyKey, requestHash);
      if (replay) {
        const result = this.#getRun(input.tenantId, replay.runId);
        this.#database.exec("COMMIT");
        return result;
      }
      const run = this.#getRun(input.tenantId, input.runId);
      this.#assertRunningAttempt(run, input.stage, input.attempt, input.workerId);
      this.#database.prepare(
        `UPDATE pipeline_stage_attempts
            SET status = 'failed', finished_at = ?, error_code = ?
          WHERE tenant_id = ? AND run_id = ? AND stage = ? AND attempt = ?`
      ).run(now, input.errorCode, input.tenantId, input.runId, input.stage, input.attempt);
      const retryable = input.retryable && input.attempt < run.maximumAttemptsPerStage;
      const terminalStatus: PipelineRunStatus = retryable ? "queued" : input.stage === "dq" || input.stage === "reconcile" || input.stage === "certify" ? "blocked" : "failed";
      this.#database.prepare(
        `UPDATE pipeline_runs SET status = ?, error_code = ?, updated_at = ?
          WHERE tenant_id = ? AND run_id = ?`
      ).run(terminalStatus, input.errorCode, now, input.tenantId, input.runId);
      this.#recordReceipt(input.tenantId, "fail_stage", input.workerId, input.idempotencyKey, requestHash, { runId: input.runId }, now);
      const result = this.#getRun(input.tenantId, input.runId);
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      rollback(this.#database);
      throw error;
    }
  }

  requestCancellation(tenantId: string, runId: string, actorId: string, idempotencyKey: string): PipelineRunV1 {
    validateIdentifier(tenantId, "tenant id");
    validateIdentifier(runId, "run id");
    validateIdentifier(actorId, "actor id");
    validateIdentifier(idempotencyKey, "idempotency key");
    const requestHash = sha256(canonicalJson({ tenantId, runId, actorId, idempotencyKey }));
    const now = this.#now();
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const replay = this.#readRunReceipt(tenantId, "cancel_run", actorId, idempotencyKey, requestHash);
      if (replay) {
        const result = this.#getRun(tenantId, replay.runId);
        this.#database.exec("COMMIT");
        return result;
      }
      const run = this.#getRun(tenantId, runId);
      if (run.status === "succeeded" || run.status === "failed" || run.status === "blocked") {
        transition("Terminal pipeline cannot be cancelled");
      }
      const status = run.status === "queued" ? "cancelled" : run.status;
      this.#database.prepare(
        `UPDATE pipeline_runs SET cancellation_requested = 1, status = ?, updated_at = ?
          WHERE tenant_id = ? AND run_id = ?`
      ).run(status, now, tenantId, runId);
      this.#recordReceipt(tenantId, "cancel_run", actorId, idempotencyKey, requestHash, { runId }, now);
      const result = this.#getRun(tenantId, runId);
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      rollback(this.#database);
      throw error;
    }
  }

  listStageAttempts(tenantId: string, runId: string): readonly PipelineStageAttemptV1[] {
    validateIdentifier(tenantId, "tenant id");
    validateIdentifier(runId, "run id");
    return this.#database.prepare(
      `SELECT * FROM pipeline_stage_attempts
        WHERE tenant_id = ? AND run_id = ? ORDER BY started_at, stage, attempt`
    ).all(tenantId, runId).map(toAttempt);
  }

  listOutbox(tenantId: string, runId: string): readonly OutboxMessageV1[] {
    validateIdentifier(tenantId, "tenant id");
    validateIdentifier(runId, "run id");
    return this.#database.prepare(
      `SELECT * FROM pipeline_outbox WHERE tenant_id = ? AND run_id = ? ORDER BY created_at, message_id`
    ).all(tenantId, runId).map(toOutbox);
  }

  claimOutbox(tenantId: string, dispatcherId: string, leaseSeconds: number): ClaimedOutboxMessageV1 | null {
    validateIdentifier(tenantId, "tenant id");
    validateIdentifier(dispatcherId, "dispatcher id");
    if (!Number.isSafeInteger(leaseSeconds) || leaseSeconds < 5 || leaseSeconds > 3_600) {
      invalid("leaseSeconds must be an integer from 5 through 3600");
    }
    const now = this.#now();
    const expiry = new Date(Date.parse(now) + leaseSeconds * 1_000).toISOString();
    const token = randomUUID();
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      this.#database.prepare(
        `UPDATE pipeline_outbox
            SET status = CASE WHEN attempt_count >= maximum_attempts THEN 'dead_letter' ELSE 'pending' END,
                claimed_by = NULL, claim_token_hash = NULL, lease_expires_at = NULL
          WHERE tenant_id = ? AND status = 'claimed' AND lease_expires_at <= ?`
      ).run(tenantId, now);
      const candidate = this.#database.prepare(
        `SELECT message_id FROM pipeline_outbox
          WHERE tenant_id = ? AND status = 'pending' AND available_at <= ? AND attempt_count < maximum_attempts
          ORDER BY created_at, message_id LIMIT 1`
      ).get(tenantId, now) as { message_id: string } | undefined;
      if (!candidate) {
        this.#database.exec("COMMIT");
        return null;
      }
      this.#database.prepare(
        `UPDATE pipeline_outbox
            SET status = 'claimed', attempt_count = attempt_count + 1, claimed_by = ?,
                claim_token_hash = ?, lease_expires_at = ?
          WHERE tenant_id = ? AND message_id = ? AND status = 'pending'`
      ).run(dispatcherId, sha256(token), expiry, tenantId, candidate.message_id);
      const record = this.#getOutbox(tenantId, candidate.message_id);
      this.#database.exec("COMMIT");
      return { ...record, status: "claimed", claimToken: token, claimedBy: dispatcherId, leaseExpiresAt: expiry };
    } catch (error) {
      rollback(this.#database);
      throw error;
    }
  }

  acknowledgeOutbox(tenantId: string, messageId: string, dispatcherId: string, claimToken: string, receiptHash: string): OutboxMessageV1 {
    return this.#finishOutbox(tenantId, messageId, dispatcherId, claimToken, true, normalizeHash(receiptHash, "receipt hash"));
  }

  failOutbox(tenantId: string, messageId: string, dispatcherId: string, claimToken: string): OutboxMessageV1 {
    return this.#finishOutbox(tenantId, messageId, dispatcherId, claimToken, false, null);
  }

  close(): void {
    this.#database.close();
  }

  #finishOutbox(
    tenantId: string,
    messageId: string,
    dispatcherId: string,
    claimToken: string,
    delivered: boolean,
    receiptHash: string | null
  ): OutboxMessageV1 {
    validateIdentifier(tenantId, "tenant id");
    validateIdentifier(messageId, "message id");
    validateIdentifier(dispatcherId, "dispatcher id");
    validateIdentifier(claimToken, "claim token");
    const now = this.#now();
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const current = this.#database.prepare(
        `SELECT status, claimed_by, claim_token_hash, lease_expires_at, attempt_count, maximum_attempts
           FROM pipeline_outbox WHERE tenant_id = ? AND message_id = ?`
      ).get(tenantId, messageId) as {
        status: string; claimed_by: string | null; claim_token_hash: string | null;
        lease_expires_at: string | null; attempt_count: number; maximum_attempts: number;
      } | undefined;
      if (!current) notFound("Outbox message was not found");
      if (
        current.status !== "claimed" || current.claimed_by !== dispatcherId || !current.claim_token_hash ||
        !safeEqual(current.claim_token_hash, sha256(claimToken)) || !current.lease_expires_at || current.lease_expires_at <= now
      ) claimRejected("Outbox claim is invalid or expired");
      const status: OutboxStatus = delivered
        ? "delivered"
        : current.attempt_count >= current.maximum_attempts ? "dead_letter" : "pending";
      this.#database.prepare(
        `UPDATE pipeline_outbox
            SET status = ?, available_at = ?, claimed_by = NULL, claim_token_hash = NULL,
                lease_expires_at = NULL, delivered_at = ?, receipt_hash = ?
          WHERE tenant_id = ? AND message_id = ?`
      ).run(status, now, delivered ? now : null, receiptHash, tenantId, messageId);
      const result = this.#getOutbox(tenantId, messageId);
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      rollback(this.#database);
      throw error;
    }
  }

  #insertOutbox(tenantId: string, runId: string, stage: PipelineStage, input: OutboxMessageInput, now: string): void {
    validateOutboxInput(input);
    const payloadJson = canonicalJson(input.payload);
    if (Buffer.byteLength(payloadJson, "utf8") > 64_000) invalid("Outbox payload exceeds 64 KB");
    this.#database.prepare(
      `INSERT INTO pipeline_outbox (
         tenant_id, message_id, run_id, stage, kind, event_type, destination_ref,
         template_ref, payload_json, status, attempt_count, maximum_attempts,
         available_at, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)`
    ).run(
      tenantId,
      randomUUID(),
      runId,
      stage,
      input.kind,
      input.eventType,
      input.destinationRef ?? null,
      input.templateRef ?? null,
      payloadJson,
      input.maximumAttempts ?? 5,
      now,
      now
    );
  }

  #assertRunningAttempt(run: PipelineRunV1, stage: PipelineStage, attempt: number, workerId: string): void {
    if (run.status !== "running" || run.currentStage !== stage) transition("Pipeline stage is not running");
    const record = this.#getAttempt(run.tenantId, run.runId, stage, attempt);
    if (record.status !== "running" || record.workerId !== workerId || record.stage !== stage) {
      transition("Pipeline stage attempt does not belong to this worker");
    }
  }

  #getRun(tenantId: string, runId: string): PipelineRunV1 {
    const row = this.#database.prepare(
      "SELECT * FROM pipeline_runs WHERE tenant_id = ? AND run_id = ?"
    ).get(tenantId, runId);
    if (!row) notFound("Pipeline run was not found");
    return toRun(row);
  }

  #getAttempt(tenantId: string, runId: string, stage: PipelineStage, attempt: number): PipelineStageAttemptV1 {
    const row = this.#database.prepare(
      `SELECT * FROM pipeline_stage_attempts
        WHERE tenant_id = ? AND run_id = ? AND stage = ? AND attempt = ?`
    ).get(tenantId, runId, stage, attempt);
    if (!row) notFound("Pipeline stage attempt was not found");
    return toAttempt(row);
  }

  #getOutbox(tenantId: string, messageId: string): OutboxMessageV1 {
    const row = this.#database.prepare(
      "SELECT * FROM pipeline_outbox WHERE tenant_id = ? AND message_id = ?"
    ).get(tenantId, messageId);
    if (!row) notFound("Outbox message was not found");
    return toOutbox(row);
  }

  #readAttemptReceipt(
    tenantId: string,
    operation: string,
    actorId: string,
    key: string,
    hash: string
  ): { attempt: number; stage: PipelineStage } | null {
    const row = this.#readReceipt(tenantId, operation, actorId, key, hash);
    return row ? JSON.parse(row) as { attempt: number; stage: PipelineStage } : null;
  }

  #readRunReceipt(tenantId: string, operation: string, actorId: string, key: string, hash: string): { runId: string } | null {
    const row = this.#readReceipt(tenantId, operation, actorId, key, hash);
    return row ? JSON.parse(row) as { runId: string } : null;
  }

  #readReceipt(tenantId: string, operation: string, actorId: string, key: string, hash: string): string | null {
    const row = this.#database.prepare(
      `SELECT request_hash, response_json FROM pipeline_idempotency
        WHERE tenant_id = ? AND operation = ? AND actor_id = ? AND idempotency_key = ?`
    ).get(tenantId, operation, actorId, key) as { request_hash: string; response_json: string } | undefined;
    if (!row) return null;
    assertReplay(row.request_hash, hash);
    return row.response_json;
  }

  #recordReceipt(
    tenantId: string,
    operation: string,
    actorId: string,
    key: string,
    hash: string,
    response: Readonly<Record<string, unknown>>,
    now: string
  ): void {
    this.#database.prepare(
      `INSERT INTO pipeline_idempotency (
         tenant_id, operation, actor_id, idempotency_key, request_hash, response_json, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(tenantId, operation, actorId, key, hash, canonicalJson(response), now);
  }

  #now(): string {
    const value = this.#clock();
    if (Number.isNaN(value.getTime())) invalid("Clock returned an invalid date");
    return value.toISOString();
  }
}

const PIPELINE_SCHEMA = `
CREATE TABLE pipeline_runs (
  tenant_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  pipeline_definition_id TEXT NOT NULL,
  pipeline_definition_version TEXT NOT NULL,
  source_contract_id TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  delivery_mode TEXT NOT NULL CHECK (delivery_mode IN ('full','delta','correction','backfill')),
  delivery_reference_hash TEXT NOT NULL CHECK (length(delivery_reference_hash) = 64),
  watermark_start TEXT,
  watermark_end TEXT,
  supersedes_run_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('queued','running','blocked','failed','cancelled','succeeded')),
  current_stage TEXT CHECK (current_stage IN ('detect','extract','profile','map','dq','reconcile','certify','analyze','monitor','report')),
  snapshot_id TEXT,
  certification_manifest_id TEXT,
  maximum_attempts_per_stage INTEGER NOT NULL CHECK (maximum_attempts_per_stage BETWEEN 1 AND 10),
  cancellation_requested INTEGER NOT NULL CHECK (cancellation_requested IN (0,1)),
  error_code TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, run_id),
  FOREIGN KEY (tenant_id, supersedes_run_id) REFERENCES pipeline_runs (tenant_id, run_id)
) STRICT;
CREATE INDEX pipeline_runs_queue ON pipeline_runs (tenant_id, status, updated_at, run_id);
CREATE TRIGGER pipeline_runs_no_delete BEFORE DELETE ON pipeline_runs BEGIN SELECT RAISE(ABORT, 'pipeline runs are immutable'); END;

CREATE TABLE pipeline_stage_attempts (
  tenant_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  stage TEXT NOT NULL CHECK (stage IN ('detect','extract','profile','map','dq','reconcile','certify','analyze','monitor','report')),
  attempt INTEGER NOT NULL CHECK (attempt BETWEEN 1 AND 10),
  status TEXT NOT NULL CHECK (status IN ('running','failed','succeeded')),
  worker_id TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  evidence_hash TEXT CHECK (evidence_hash IS NULL OR length(evidence_hash) = 64),
  error_code TEXT,
  PRIMARY KEY (tenant_id, run_id, stage, attempt),
  FOREIGN KEY (tenant_id, run_id) REFERENCES pipeline_runs (tenant_id, run_id)
) STRICT;
CREATE TRIGGER pipeline_stage_attempts_no_delete BEFORE DELETE ON pipeline_stage_attempts BEGIN SELECT RAISE(ABORT, 'pipeline attempts are immutable'); END;

CREATE TABLE pipeline_outbox (
  tenant_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('audit','notification')),
  event_type TEXT NOT NULL,
  destination_ref TEXT,
  template_ref TEXT,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','claimed','delivered','dead_letter')),
  attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
  maximum_attempts INTEGER NOT NULL CHECK (maximum_attempts BETWEEN 1 AND 20),
  available_at TEXT NOT NULL,
  claimed_by TEXT,
  claim_token_hash TEXT,
  lease_expires_at TEXT,
  delivered_at TEXT,
  receipt_hash TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, message_id),
  FOREIGN KEY (tenant_id, run_id) REFERENCES pipeline_runs (tenant_id, run_id)
) STRICT;
CREATE INDEX pipeline_outbox_dispatch ON pipeline_outbox (tenant_id, status, available_at, created_at);
CREATE TRIGGER pipeline_outbox_no_delete BEFORE DELETE ON pipeline_outbox BEGIN SELECT RAISE(ABORT, 'outbox messages are append-only'); END;

CREATE TABLE pipeline_idempotency (
  tenant_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
  response_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, operation, actor_id, idempotency_key)
) STRICT;
CREATE TRIGGER pipeline_idempotency_no_update BEFORE UPDATE ON pipeline_idempotency BEGIN SELECT RAISE(ABORT, 'idempotency receipts are immutable'); END;
CREATE TRIGGER pipeline_idempotency_no_delete BEFORE DELETE ON pipeline_idempotency BEGIN SELECT RAISE(ABORT, 'idempotency receipts are immutable'); END;
`;

function validateCreateRun(input: CreatePipelineRunInput): void {
  validateIdentifier(input.tenantId, "tenant id");
  validateIdentifier(input.pipelineDefinitionId, "pipeline definition id");
  validateIdentifier(input.pipelineDefinitionVersion, "pipeline definition version");
  validateIdentifier(input.sourceContractId, "source contract id");
  validateIdentifier(input.requestedBy, "requester binding");
  validateIdentifier(input.idempotencyKey, "idempotency key");
  if (!(["full", "delta", "correction", "backfill"] as const).includes(input.deliveryMode)) invalid("Invalid delivery mode");
  if (!input.deliveryReference.trim() || input.deliveryReference.length > 2_048) invalid("Delivery reference is invalid");
  if ((input.deliveryMode === "correction" || input.deliveryMode === "backfill") !== Boolean(input.supersedesRunId)) {
    invalid("Correction/backfill runs require supersedesRunId; full/delta runs must not supply it");
  }
  if (input.supersedesRunId) validateIdentifier(input.supersedesRunId, "superseded run id");
  if ((input.watermarkStart === undefined) !== (input.watermarkEnd === undefined)) {
    invalid("Watermark start and end must be supplied together");
  }
  if (input.watermarkStart !== undefined && input.watermarkEnd !== undefined && input.watermarkStart > input.watermarkEnd) {
    invalid("Watermark range is inverted");
  }
  const attempts = input.maximumAttemptsPerStage ?? 3;
  if (!Number.isSafeInteger(attempts) || attempts < 1 || attempts > 10) invalid("maximumAttemptsPerStage must be 1 through 10");
}

function validateComplete(input: CompletePipelineStageInput): void {
  validateIdentifier(input.tenantId, "tenant id");
  validateIdentifier(input.runId, "run id");
  validateStage(input.stage);
  validateIdentifier(input.workerId, "worker id");
  validateIdentifier(input.idempotencyKey, "idempotency key");
  if (!Number.isSafeInteger(input.attempt) || input.attempt < 1 || input.attempt > 10) invalid("Invalid attempt");
  normalizeHash(input.evidenceHash, "evidence hash");
  if (input.snapshotId) validateIdentifier(input.snapshotId, "snapshot id");
  if (input.certificationManifestId) validateIdentifier(input.certificationManifestId, "certification manifest id");
  if ((input.outbox?.length ?? 0) > 50) invalid("A stage may enqueue at most 50 outbox messages");
}

function validateFail(input: FailPipelineStageInput): void {
  validateIdentifier(input.tenantId, "tenant id");
  validateIdentifier(input.runId, "run id");
  validateStage(input.stage);
  validateIdentifier(input.workerId, "worker id");
  validateIdentifier(input.idempotencyKey, "idempotency key");
  validateIdentifier(input.errorCode, "error code");
  if (!Number.isSafeInteger(input.attempt) || input.attempt < 1 || input.attempt > 10) invalid("Invalid attempt");
}

function validateOutboxInput(input: OutboxMessageInput): void {
  if (input.kind !== "audit" && input.kind !== "notification") invalid("Invalid outbox kind");
  validateIdentifier(input.eventType, "event type");
  if (input.kind === "notification") {
    if (!input.destinationRef || !input.templateRef) invalid("Notification requires governed destination and template references");
    validateIdentifier(input.destinationRef, "destination reference");
    validateIdentifier(input.templateRef, "template reference");
  } else if (input.destinationRef !== undefined || input.templateRef !== undefined) {
    invalid("Audit messages cannot carry delivery destinations or templates");
  }
  const attempts = input.maximumAttempts ?? 5;
  if (!Number.isSafeInteger(attempts) || attempts < 1 || attempts > 20) invalid("maximumAttempts must be 1 through 20");
  rejectDeliverySelectors(input.payload, 0);
}

function rejectDeliverySelectors(value: unknown, depth: number): void {
  if (depth > 12) invalid("Outbox payload nesting is too deep");
  if (Array.isArray(value)) {
    if (value.length > 10_000) invalid("Outbox payload array is too large");
    for (const item of value) rejectDeliverySelectors(item, depth + 1);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, nested] of Object.entries(value)) {
    if (/(?:recipient|destination|webhook|callback|url|uri|email|phone|secret|token|credential)/iu.test(key)) {
      invalid(`Outbox payload key '${key}' is not allowed`);
    }
    rejectDeliverySelectors(nested, depth + 1);
  }
}

function nextStage(stage: PipelineStage): PipelineStage | null {
  const index = PIPELINE_STAGES.indexOf(stage);
  return index === PIPELINE_STAGES.length - 1 ? null : PIPELINE_STAGES[index + 1]!;
}

function validateStage(value: string): asserts value is PipelineStage {
  if (!(PIPELINE_STAGES as readonly string[]).includes(value)) invalid("Invalid pipeline stage");
}

function toRun(row: any): PipelineRunV1 {
  return {
    schemaVersion: 1,
    tenantId: row.tenant_id,
    runId: row.run_id,
    pipelineDefinitionId: row.pipeline_definition_id,
    pipelineDefinitionVersion: row.pipeline_definition_version,
    sourceContractId: row.source_contract_id,
    requestedBy: row.requested_by,
    deliveryMode: row.delivery_mode,
    deliveryReferenceHash: row.delivery_reference_hash,
    watermarkStart: row.watermark_start,
    watermarkEnd: row.watermark_end,
    supersedesRunId: row.supersedes_run_id,
    status: row.status,
    currentStage: row.current_stage,
    snapshotId: row.snapshot_id,
    certificationManifestId: row.certification_manifest_id,
    maximumAttemptsPerStage: row.maximum_attempts_per_stage,
    cancellationRequested: row.cancellation_requested === 1,
    errorCode: row.error_code,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  } as PipelineRunV1;
}

function toAttempt(row: any): PipelineStageAttemptV1 {
  return {
    schemaVersion: 1,
    tenantId: row.tenant_id,
    runId: row.run_id,
    stage: row.stage,
    attempt: row.attempt,
    status: row.status,
    workerId: row.worker_id,
    startedAt: row.started_at,
    finishedAt: row.finished_at,
    evidenceHash: row.evidence_hash,
    errorCode: row.error_code
  } as PipelineStageAttemptV1;
}

function toOutbox(row: any): OutboxMessageV1 {
  return {
    schemaVersion: 1,
    tenantId: row.tenant_id,
    messageId: row.message_id,
    runId: row.run_id,
    stage: row.stage,
    kind: row.kind,
    eventType: row.event_type,
    destinationRef: row.destination_ref,
    templateRef: row.template_ref,
    payload: JSON.parse(row.payload_json),
    status: row.status,
    attemptCount: row.attempt_count,
    maximumAttempts: row.maximum_attempts,
    availableAt: row.available_at,
    claimedBy: row.claimed_by,
    leaseExpiresAt: row.lease_expires_at,
    deliveredAt: row.delivered_at,
    receiptHash: row.receipt_hash,
    createdAt: row.created_at
  } as OutboxMessageV1;
}

function validateIdentifier(value: string, label: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/u.test(value)) invalid(`${label} is invalid`);
}

function validateLimit(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > 500) invalid("limit must be 1 through 500");
}

function normalizeHash(value: string, label: string): string {
  const normalized = value.startsWith("sha256:") ? value.slice(7) : value;
  if (!/^[0-9a-f]{64}$/u.test(normalized)) invalid(`${label} must be a lowercase SHA-256 digest`);
  return normalized;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) invalid("Canonical JSON accepts only safe integer numbers");
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value === "object") {
    const record = value as Readonly<Record<string, unknown>>;
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      if (record[key] !== undefined) result[key] = canonicalize(record[key]);
    }
    return result;
  }
  invalid("Value is not canonical JSON");
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function assertReplay(actual: string, expected: string): void {
  if (!safeEqual(actual, expected)) {
    throw new PipelineStoreError("IDEMPOTENCY_CONFLICT", "Idempotency key was reused with different input");
  }
}

function invalid(message: string): never {
  throw new PipelineStoreError("INVALID_INPUT", message);
}

function transition(message: string): never {
  throw new PipelineStoreError("INVALID_TRANSITION", message);
}

function notFound(message: string): never {
  throw new PipelineStoreError("NOT_FOUND", message);
}

function claimRejected(message: string): never {
  throw new PipelineStoreError("CLAIM_REJECTED", message);
}

function rollback(database: DatabaseSync): void {
  try {
    database.exec("ROLLBACK");
  } catch {
    // Preserve the original failure.
  }
}
