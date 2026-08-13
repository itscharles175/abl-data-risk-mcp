import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { z } from "zod/v4";

import {
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  canonicalJson,
  parseWithSchema,
  type Sha256Hash
} from "../contracts/canonical.js";
import {
  migrateSqliteComponent,
  type SqliteComponentMigration
} from "../infrastructure/sqlite-component-schema.js";

export const PORTFOLIO_SURVEILLANCE_V4_STATE_COMPONENT =
  "abl.portfolio-surveillance-v4-state" as const;
export const PORTFOLIO_SURVEILLANCE_V4_STATE_SCHEMA_VERSION = 1 as const;

export const PORTFOLIO_SURVEILLANCE_V4_JOB_KIND =
  "portfolio_surveillance_v4" as const;
export const GOVERNED_EXECUTION_ENVELOPE_V4_KIND =
  "governed_execution_envelope_v4" as const;
export const GOVERNED_PORTFOLIO_SURVEILLANCE_PLAN_V4_KIND =
  "governed_portfolio_surveillance_plan_v4" as const;
export const GOVERNED_ANALYSIS_RESULT_V4_KIND =
  "governed_analysis_result_v4" as const;
export const GOVERNED_RESULT_MANIFEST_V4_KIND =
  "governed_result_manifest_v4" as const;

const MAXIMUM_POINTER_BYTES = 100_000_000;
const BareSha256HashSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const ByteLengthSchema = z.number().int().positive().max(MAXIMUM_POINTER_BYTES);

const EnvelopePointerSchema = z
  .object({
    envelopeId: IdentifierSchema,
    kind: z.literal(GOVERNED_EXECUTION_ENVELOPE_V4_KIND),
    mediaType: z.literal("application/json"),
    contentHash: Sha256HashSchema,
    byteLength: ByteLengthSchema
  })
  .strict();

const PlanArtifactPointerSchema = z
  .object({
    artifactId: BareSha256HashSchema,
    kind: z.literal(GOVERNED_PORTFOLIO_SURVEILLANCE_PLAN_V4_KIND),
    mediaType: z.literal("application/json"),
    contentHash: BareSha256HashSchema,
    byteLength: ByteLengthSchema
  })
  .strict();

const ResultArtifactPointerSchema = z
  .object({
    artifactId: BareSha256HashSchema,
    kind: z.literal(GOVERNED_ANALYSIS_RESULT_V4_KIND),
    mediaType: z.literal("application/json"),
    contentHash: BareSha256HashSchema,
    byteLength: ByteLengthSchema
  })
  .strict();

const ManifestArtifactPointerSchema = z
  .object({
    artifactId: BareSha256HashSchema,
    kind: z.literal(GOVERNED_RESULT_MANIFEST_V4_KIND),
    mediaType: z.literal("application/json"),
    contentHash: BareSha256HashSchema,
    byteLength: ByteLengthSchema
  })
  .strict();

const AttemptFenceSchema = z
  .object({
    attemptNumber: z.number().int().min(1).max(10),
    workerId: IdentifierSchema,
    leaseTokenHash: BareSha256HashSchema,
    leaseExpiresAt: IsoTimestampSchema
  })
  .strict();

const AuditPointerSchema = z.object({
  sequence: z.number().int().positive(),
  eventHash: Sha256HashSchema
}).strict();

export type PortfolioSurveillanceV4EnvelopePointerV1 = Readonly<
  z.infer<typeof EnvelopePointerSchema>
>;
export type PortfolioSurveillanceV4PlanArtifactPointerV1 = Readonly<
  z.infer<typeof PlanArtifactPointerSchema>
>;
export type PortfolioSurveillanceV4ResultArtifactPointerV1 = Readonly<
  z.infer<typeof ResultArtifactPointerSchema>
>;
export type PortfolioSurveillanceV4ManifestArtifactPointerV1 = Readonly<
  z.infer<typeof ManifestArtifactPointerSchema>
>;
export type PortfolioSurveillanceV4AttemptFenceV1 = Readonly<
  z.infer<typeof AttemptFenceSchema>
>;

const SubmissionBodySchema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    jobId: IdentifierSchema,
    jobKind: z.literal(PORTFOLIO_SURVEILLANCE_V4_JOB_KIND),
    requestedBy: IdentifierSchema,
    requestHash: Sha256HashSchema,
    startAuthorizationAudit: AuditPointerSchema,
    envelope: EnvelopePointerSchema,
    planArtifact: PlanArtifactPointerSchema,
    recordedAt: IsoTimestampSchema
  })
  .strict();

const SubmissionSchema = SubmissionBodySchema.extend({
  submissionHash: Sha256HashSchema
}).strict();

export type PortfolioSurveillanceV4SubmissionV1 = Readonly<
  z.infer<typeof SubmissionSchema>
>;

const ReceiptBodySchema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    actorId: IdentifierSchema,
    idempotencyKey: IdentifierSchema,
    requestHash: Sha256HashSchema,
    bindingHash: Sha256HashSchema,
    jobId: IdentifierSchema,
    submissionHash: Sha256HashSchema,
    createdAt: IsoTimestampSchema
  })
  .strict();

const ReceiptSchema = ReceiptBodySchema.extend({ receiptHash: Sha256HashSchema }).strict();

export type PortfolioSurveillanceV4IdempotencyReceiptV1 = Readonly<
  z.infer<typeof ReceiptSchema>
>;

const EventBaseSchema = z.object({
  contractVersion: z.literal(1),
  tenantId: IdentifierSchema,
  jobId: IdentifierSchema,
  eventId: IdentifierSchema,
  actorId: IdentifierSchema,
  occurredAt: IsoTimestampSchema
});

const SubmissionEventBodySchema = EventBaseSchema.extend({
  eventType: z.literal("portfolio_surveillance_v4.submission_recorded"),
  submissionHash: Sha256HashSchema
}).strict();

const SubmissionAuthorizationEventBodySchema = EventBaseSchema.extend({
  eventType: z.literal("portfolio_surveillance_v4.submission_authorization_recorded"),
  authorizationAudit: AuditPointerSchema
}).strict();

const ResultEventBodySchema = EventBaseSchema.extend({
  eventType: z.literal("portfolio_surveillance_v4.result_artifact_persisted"),
  attemptFence: AttemptFenceSchema,
  signedPlanId: IdentifierSchema,
  executionCodeVersion: IdentifierSchema,
  resultArtifact: ResultArtifactPointerSchema
}).strict();

const ManifestEventBodySchema = EventBaseSchema.extend({
  eventType: z.literal("portfolio_surveillance_v4.manifest_artifact_persisted"),
  attemptFence: AttemptFenceSchema,
  signedPlanId: IdentifierSchema,
  executionCodeVersion: IdentifierSchema,
  resultArtifact: ResultArtifactPointerSchema,
  manifestArtifact: ManifestArtifactPointerSchema
}).strict();

const CompletionPreparationEventBodySchema = EventBaseSchema.extend({
  eventType: z.literal("portfolio_surveillance_v4.completion_prepared"),
  attemptFence: AttemptFenceSchema,
  signedPlanId: IdentifierSchema,
  executionCodeVersion: IdentifierSchema,
  resultArtifact: ResultArtifactPointerSchema,
  manifestArtifact: ManifestArtifactPointerSchema
}).strict();

const QueueCompletionEventBodySchema = EventBaseSchema.extend({
  eventType: z.literal("portfolio_surveillance_v4.queue_completion_recorded"),
  queueRequestHash: BareSha256HashSchema,
  resultHandleHash: BareSha256HashSchema,
  queueUpdatedAt: IsoTimestampSchema,
  completionAudit: AuditPointerSchema,
  resultArtifact: ResultArtifactPointerSchema,
  manifestArtifact: ManifestArtifactPointerSchema
}).strict();

const CancellationEventBodySchema = EventBaseSchema.extend({
  eventType: z.literal("portfolio_surveillance_v4.cancelled"),
  reasonCode: IdentifierSchema
}).strict();

const FailureEventBodySchema = EventBaseSchema.extend({
  eventType: z.literal("portfolio_surveillance_v4.failed"),
  attemptFence: AttemptFenceSchema,
  errorCode: IdentifierSchema
}).strict();

const EventBodySchema = z.discriminatedUnion("eventType", [
  SubmissionEventBodySchema,
  SubmissionAuthorizationEventBodySchema,
  ResultEventBodySchema,
  ManifestEventBodySchema,
  CompletionPreparationEventBodySchema,
  QueueCompletionEventBodySchema,
  CancellationEventBodySchema,
  FailureEventBodySchema
]);

type EventBody = Readonly<z.infer<typeof EventBodySchema>>;

export type PortfolioSurveillanceV4StateEventV1 = EventBody &
  Readonly<{
    tenantSequence: number;
    previousEventHash: Sha256Hash | null;
    eventHash: Sha256Hash;
  }>;

export type PortfolioSurveillanceV4StateStatus =
  | "submitted"
  | "result_artifact_persisted"
  | "manifest_artifact_persisted"
  | "completion_prepared"
  | "completed"
  | "cancelled"
  | "failed";

export interface PortfolioSurveillanceV4JobStateV1 {
  readonly submission: PortfolioSurveillanceV4SubmissionV1;
  readonly status: PortfolioSurveillanceV4StateStatus;
  readonly resultArtifact?: PortfolioSurveillanceV4ResultArtifactPointerV1;
  readonly signedPlanId?: string;
  readonly executionCodeVersion?: string;
  readonly submissionAuthorizationAudit?: PortfolioSurveillanceV4AuditPointerV1;
  readonly manifestArtifact?: PortfolioSurveillanceV4ManifestArtifactPointerV1;
  readonly queueCompletion?: PortfolioSurveillanceV4QueueCompletionEvidenceV1;
  readonly terminalCode?: string;
  readonly events: readonly PortfolioSurveillanceV4StateEventV1[];
}

export interface RecordPortfolioSurveillanceV4SubmissionInput {
  readonly tenantId: string;
  readonly jobId: string;
  readonly requestedBy: string;
  readonly idempotencyKey: string;
  readonly requestHash: Sha256Hash;
  readonly startAuthorizationAudit: PortfolioSurveillanceV4AuditPointerV1;
  readonly envelope: PortfolioSurveillanceV4EnvelopePointerV1;
  readonly planArtifact: PortfolioSurveillanceV4PlanArtifactPointerV1;
}

export interface RecordPortfolioSurveillanceV4ResultArtifactInput {
  readonly tenantId: string;
  readonly jobId: string;
  readonly actorId: string;
  readonly attemptFence: PortfolioSurveillanceV4AttemptFenceV1;
  readonly signedPlanId: string;
  readonly executionCodeVersion: string;
  readonly resultArtifact: PortfolioSurveillanceV4ResultArtifactPointerV1;
}

export interface RecordPortfolioSurveillanceV4ManifestArtifactInput
  extends RecordPortfolioSurveillanceV4ResultArtifactInput {
  readonly manifestArtifact: PortfolioSurveillanceV4ManifestArtifactPointerV1;
}

export interface RecordPortfolioSurveillanceV4CompletionPreparationInput
  extends RecordPortfolioSurveillanceV4ManifestArtifactInput {}

export interface PortfolioSurveillanceV4QueueCompletionEvidenceV1 {
  readonly queueRequestHash: string;
  readonly resultHandleHash: string;
  readonly queueUpdatedAt: string;
  readonly completionAudit: PortfolioSurveillanceV4AuditPointerV1;
}

export type PortfolioSurveillanceV4AuditPointerV1 = Readonly<z.infer<typeof AuditPointerSchema>>;

export interface RecordPortfolioSurveillanceV4SubmissionAuthorizationInput {
  readonly tenantId: string;
  readonly jobId: string;
  readonly actorId: string;
  readonly authorizationAudit: PortfolioSurveillanceV4AuditPointerV1;
}

export interface RecordPortfolioSurveillanceV4QueueCompletionInput
  extends PortfolioSurveillanceV4QueueCompletionEvidenceV1 {
  readonly tenantId: string;
  readonly jobId: string;
  readonly actorId: string;
  readonly resultArtifact: PortfolioSurveillanceV4ResultArtifactPointerV1;
  readonly manifestArtifact: PortfolioSurveillanceV4ManifestArtifactPointerV1;
}

export interface RecordPortfolioSurveillanceV4CancellationInput {
  readonly tenantId: string;
  readonly jobId: string;
  readonly actorId: string;
  readonly reasonCode: string;
}

export interface RecordPortfolioSurveillanceV4FailureInput {
  readonly tenantId: string;
  readonly jobId: string;
  readonly actorId: string;
  readonly attemptFence: PortfolioSurveillanceV4AttemptFenceV1;
  readonly errorCode: string;
}

export interface PortfolioSurveillanceV4StateWriteResult {
  readonly state: PortfolioSurveillanceV4JobStateV1;
  readonly replayed: boolean;
}

export interface PortfolioSurveillanceV4SubmissionWriteResult
  extends PortfolioSurveillanceV4StateWriteResult {
  readonly receipt: PortfolioSurveillanceV4IdempotencyReceiptV1;
}

export interface PortfolioSurveillanceV4StatePageRequest {
  readonly limit?: number;
  readonly cursor?: string;
}

export interface PortfolioSurveillanceV4StatePageV1 {
  readonly items: readonly PortfolioSurveillanceV4JobStateV1[];
  readonly nextCursor: string | null;
}

export interface PortfolioSurveillanceV4StateStoreOptions {
  readonly clock?: () => Date;
  readonly busyTimeoutMs?: number;
}

export type PortfolioSurveillanceV4StateStoreErrorCode =
  | "INVALID_ARGUMENT"
  | "IDEMPOTENCY_CONFLICT"
  | "ALREADY_EXISTS"
  | "NOT_FOUND"
  | "INVALID_TRANSITION"
  | "FENCE_MISMATCH"
  | "POINTER_CONFLICT"
  | "CLOCK_ROLLBACK"
  | "INTEGRITY_FAILURE"
  | "STORE_CLOSED";

export class PortfolioSurveillanceV4StateStoreError extends Error {
  constructor(
    readonly code: PortfolioSurveillanceV4StateStoreErrorCode,
    message: string
  ) {
    super(message);
    this.name = "PortfolioSurveillanceV4StateStoreError";
  }
}

interface SubmissionRow {
  readonly tenant_id: string;
  readonly job_id: string;
  readonly job_kind: string;
  readonly requested_by: string;
  readonly request_hash: string;
  readonly start_authorization_audit_sequence: number;
  readonly start_authorization_audit_hash: string;
  readonly envelope_id: string;
  readonly envelope_kind: string;
  readonly envelope_content_hash: string;
  readonly envelope_byte_length: number;
  readonly plan_artifact_id: string;
  readonly plan_kind: string;
  readonly plan_content_hash: string;
  readonly plan_byte_length: number;
  readonly recorded_at: string;
  readonly submission_hash: string;
  readonly submission_json: string;
}

interface ReceiptRow {
  readonly tenant_id: string;
  readonly actor_id: string;
  readonly idempotency_key: string;
  readonly request_hash: string;
  readonly binding_hash: string;
  readonly job_id: string;
  readonly submission_hash: string;
  readonly created_at: string;
  readonly receipt_hash: string;
  readonly receipt_json: string;
}

interface EventRow {
  readonly sequence: number;
  readonly tenant_id: string;
  readonly tenant_sequence: number;
  readonly event_id: string;
  readonly job_id: string;
  readonly event_type: EventBody["eventType"];
  readonly actor_id: string;
  readonly attempt_number: number | null;
  readonly worker_id: string | null;
  readonly lease_token_hash: string | null;
  readonly lease_expires_at: string | null;
  readonly occurred_at: string;
  readonly previous_event_hash: string | null;
  readonly event_hash: string;
  readonly event_json: string;
}

interface StateCursorV1 {
  readonly version: 1;
  readonly tenantId: string;
  readonly afterJobId: string;
}

const PORTFOLIO_SURVEILLANCE_V4_STATE_SCHEMA = `
CREATE TABLE portfolio_surveillance_v4_submissions (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  job_id TEXT NOT NULL CHECK (length(job_id) BETWEEN 1 AND 128),
  job_kind TEXT NOT NULL CHECK (job_kind = 'portfolio_surveillance_v4'),
  requested_by TEXT NOT NULL CHECK (length(requested_by) BETWEEN 1 AND 128),
  request_hash TEXT NOT NULL CHECK (length(request_hash) = 71 AND request_hash GLOB 'sha256:*'),
  start_authorization_audit_sequence INTEGER NOT NULL CHECK (start_authorization_audit_sequence > 0),
  start_authorization_audit_hash TEXT NOT NULL CHECK (length(start_authorization_audit_hash) = 71 AND start_authorization_audit_hash GLOB 'sha256:*'),
  envelope_id TEXT NOT NULL CHECK (length(envelope_id) BETWEEN 1 AND 128),
  envelope_kind TEXT NOT NULL CHECK (envelope_kind = 'governed_execution_envelope_v4'),
  envelope_content_hash TEXT NOT NULL CHECK (length(envelope_content_hash) = 71 AND envelope_content_hash GLOB 'sha256:*'),
  envelope_byte_length INTEGER NOT NULL CHECK (envelope_byte_length BETWEEN 1 AND 100000000),
  plan_artifact_id TEXT NOT NULL CHECK (length(plan_artifact_id) = 64 AND plan_artifact_id NOT GLOB '*[^0-9a-f]*'),
  plan_kind TEXT NOT NULL CHECK (plan_kind = 'governed_portfolio_surveillance_plan_v4'),
  plan_content_hash TEXT NOT NULL CHECK (length(plan_content_hash) = 64 AND plan_content_hash NOT GLOB '*[^0-9a-f]*'),
  plan_byte_length INTEGER NOT NULL CHECK (plan_byte_length BETWEEN 1 AND 100000000),
  recorded_at TEXT NOT NULL,
  submission_hash TEXT NOT NULL CHECK (length(submission_hash) = 71 AND submission_hash GLOB 'sha256:*'),
  submission_json TEXT NOT NULL CHECK (json_valid(submission_json)),
  PRIMARY KEY (tenant_id, job_id),
  UNIQUE (tenant_id, submission_hash)
) STRICT;

CREATE INDEX portfolio_surveillance_v4_submissions_tenant_job
  ON portfolio_surveillance_v4_submissions (tenant_id, job_id);

CREATE TRIGGER portfolio_surveillance_v4_submissions_no_update
BEFORE UPDATE ON portfolio_surveillance_v4_submissions
BEGIN SELECT RAISE(ABORT, 'portfolio surveillance v4 submissions are immutable'); END;

CREATE TRIGGER portfolio_surveillance_v4_submissions_no_delete
BEFORE DELETE ON portfolio_surveillance_v4_submissions
BEGIN SELECT RAISE(ABORT, 'portfolio surveillance v4 submissions are immutable'); END;

CREATE TABLE portfolio_surveillance_v4_idempotency (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
  idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  request_hash TEXT NOT NULL CHECK (length(request_hash) = 71 AND request_hash GLOB 'sha256:*'),
  binding_hash TEXT NOT NULL CHECK (length(binding_hash) = 71 AND binding_hash GLOB 'sha256:*'),
  job_id TEXT NOT NULL CHECK (length(job_id) BETWEEN 1 AND 128),
  submission_hash TEXT NOT NULL CHECK (length(submission_hash) = 71 AND submission_hash GLOB 'sha256:*'),
  created_at TEXT NOT NULL,
  receipt_hash TEXT NOT NULL CHECK (length(receipt_hash) = 71 AND receipt_hash GLOB 'sha256:*'),
  receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
  PRIMARY KEY (tenant_id, actor_id, idempotency_key),
  UNIQUE (tenant_id, job_id),
  FOREIGN KEY (tenant_id, job_id)
    REFERENCES portfolio_surveillance_v4_submissions (tenant_id, job_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER portfolio_surveillance_v4_idempotency_no_update
BEFORE UPDATE ON portfolio_surveillance_v4_idempotency
BEGIN SELECT RAISE(ABORT, 'portfolio surveillance v4 idempotency receipts are immutable'); END;

CREATE TRIGGER portfolio_surveillance_v4_idempotency_no_delete
BEFORE DELETE ON portfolio_surveillance_v4_idempotency
BEGIN SELECT RAISE(ABORT, 'portfolio surveillance v4 idempotency receipts are immutable'); END;

CREATE TABLE portfolio_surveillance_v4_state_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  tenant_sequence INTEGER NOT NULL CHECK (tenant_sequence > 0),
  event_id TEXT NOT NULL CHECK (length(event_id) BETWEEN 1 AND 128),
  job_id TEXT NOT NULL CHECK (length(job_id) BETWEEN 1 AND 128),
  event_type TEXT NOT NULL CHECK (event_type IN (
    'portfolio_surveillance_v4.submission_recorded',
    'portfolio_surveillance_v4.submission_authorization_recorded',
    'portfolio_surveillance_v4.result_artifact_persisted',
    'portfolio_surveillance_v4.manifest_artifact_persisted',
    'portfolio_surveillance_v4.completion_prepared',
    'portfolio_surveillance_v4.queue_completion_recorded',
    'portfolio_surveillance_v4.cancelled',
    'portfolio_surveillance_v4.failed'
  )),
  actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
  attempt_number INTEGER CHECK (attempt_number IS NULL OR attempt_number BETWEEN 1 AND 10),
  worker_id TEXT,
  lease_token_hash TEXT CHECK (lease_token_hash IS NULL OR (length(lease_token_hash) = 64 AND lease_token_hash NOT GLOB '*[^0-9a-f]*')),
  lease_expires_at TEXT,
  occurred_at TEXT NOT NULL,
  previous_event_hash TEXT CHECK (previous_event_hash IS NULL OR (length(previous_event_hash) = 71 AND previous_event_hash GLOB 'sha256:*')),
  event_hash TEXT NOT NULL CHECK (length(event_hash) = 71 AND event_hash GLOB 'sha256:*'),
  event_json TEXT NOT NULL CHECK (json_valid(event_json)),
  UNIQUE (tenant_id, tenant_sequence),
  UNIQUE (tenant_id, event_id),
  CHECK (
    (event_type IN ('portfolio_surveillance_v4.submission_recorded','portfolio_surveillance_v4.submission_authorization_recorded','portfolio_surveillance_v4.queue_completion_recorded','portfolio_surveillance_v4.cancelled')
      AND attempt_number IS NULL AND worker_id IS NULL AND lease_token_hash IS NULL AND lease_expires_at IS NULL)
    OR
    (event_type IN (
      'portfolio_surveillance_v4.result_artifact_persisted',
      'portfolio_surveillance_v4.manifest_artifact_persisted',
      'portfolio_surveillance_v4.completion_prepared',
      'portfolio_surveillance_v4.failed'
    ) AND attempt_number IS NOT NULL AND worker_id IS NOT NULL AND lease_token_hash IS NOT NULL AND lease_expires_at IS NOT NULL)
  ),
  FOREIGN KEY (tenant_id, job_id)
    REFERENCES portfolio_surveillance_v4_submissions (tenant_id, job_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE INDEX portfolio_surveillance_v4_state_events_tenant_sequence
  ON portfolio_surveillance_v4_state_events (tenant_id, tenant_sequence);

CREATE INDEX portfolio_surveillance_v4_state_events_tenant_job
  ON portfolio_surveillance_v4_state_events (tenant_id, job_id, tenant_sequence);

CREATE UNIQUE INDEX portfolio_surveillance_v4_state_events_single_stage
  ON portfolio_surveillance_v4_state_events (tenant_id, job_id, event_type)
  WHERE event_type <> 'portfolio_surveillance_v4.completion_prepared';

CREATE UNIQUE INDEX portfolio_surveillance_v4_state_events_preparation_attempt
  ON portfolio_surveillance_v4_state_events (tenant_id, job_id, event_type, attempt_number)
  WHERE event_type = 'portfolio_surveillance_v4.completion_prepared';

CREATE TRIGGER portfolio_surveillance_v4_state_events_no_update
BEFORE UPDATE ON portfolio_surveillance_v4_state_events
BEGIN SELECT RAISE(ABORT, 'portfolio surveillance v4 state events are append-only'); END;

CREATE TRIGGER portfolio_surveillance_v4_state_events_no_delete
BEFORE DELETE ON portfolio_surveillance_v4_state_events
BEGIN SELECT RAISE(ABORT, 'portfolio surveillance v4 state events are append-only'); END;
`;

export const PORTFOLIO_SURVEILLANCE_V4_STATE_MIGRATIONS = Object.freeze([
  { version: 1, sql: PORTFOLIO_SURVEILLANCE_V4_STATE_SCHEMA }
] as const satisfies readonly SqliteComponentMigration[]);

/**
 * Durable workflow bookkeeping only. Artifact pointers are preserved exactly;
 * this store deliberately does not assert that referenced bytes exist or are valid.
 */
export class SqlitePortfolioSurveillanceV4StateStore {
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;
  #closed = false;

  constructor(databasePathValue: string, options: PortfolioSurveillanceV4StateStoreOptions = {}) {
    const databasePath = requiredPath(databasePathValue);
    if (databasePath !== ":memory:") mkdirSync(dirname(databasePath), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(databasePath);
    this.#clock = options.clock ?? (() => new Date());
    const busyTimeoutMs = integer(options.busyTimeoutMs ?? 5_000, "busyTimeoutMs", 0, 60_000);
    try {
      this.#database.exec(
        `PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${busyTimeoutMs};`
      );
      migrateSqliteComponent(this.#database, {
        componentName: PORTFOLIO_SURVEILLANCE_V4_STATE_COMPONENT,
        supportedVersion: PORTFOLIO_SURVEILLANCE_V4_STATE_SCHEMA_VERSION,
        migrations: PORTFOLIO_SURVEILLANCE_V4_STATE_MIGRATIONS,
        unsupportedVersionError: (current, supported) =>
          new PortfolioSurveillanceV4StateStoreError(
            "INTEGRITY_FAILURE",
            `Portfolio surveillance v4 state schema ${current} is newer than supported version ${supported}`
          )
      });
    } catch (error) {
      this.#database.close();
      if (error instanceof PortfolioSurveillanceV4StateStoreError) throw error;
      throw integrity("Portfolio surveillance v4 state schema initialization failed", error);
    }
  }

  recordSubmission(
    inputValue: RecordPortfolioSurveillanceV4SubmissionInput
  ): PortfolioSurveillanceV4SubmissionWriteResult {
    this.#assertOpen();
    const input = parseSubmissionInput(inputValue);
    const bindingHash = submissionBindingHash(input);
    return this.#transaction(() => {
      const existingReceiptRow = this.#database
        .prepare(
          `SELECT * FROM portfolio_surveillance_v4_idempotency
            WHERE tenant_id = ? AND actor_id = ? AND idempotency_key = ?`
        )
        .get(input.tenantId, input.requestedBy, input.idempotencyKey) as ReceiptRow | undefined;
      if (existingReceiptRow) {
        const receipt = this.#receiptFromRow(existingReceiptRow);
        if (
          receipt.bindingHash !== bindingHash ||
          receipt.requestHash !== input.requestHash ||
          receipt.jobId !== input.jobId
        ) {
          throw new PortfolioSurveillanceV4StateStoreError(
            "IDEMPOTENCY_CONFLICT",
            "The actor-scoped idempotency key is bound to a different v4 submission"
          );
        }
        const state = this.#readState(input.tenantId, input.jobId);
        if (!state || state.submission.submissionHash !== receipt.submissionHash) {
          throw integrity("Idempotency receipt does not resolve to its immutable submission");
        }
        return Object.freeze({ state, receipt, replayed: true });
      }

      if (this.#readSubmission(input.tenantId, input.jobId)) {
        throw new PortfolioSurveillanceV4StateStoreError(
          "ALREADY_EXISTS",
          "Portfolio surveillance v4 job id is already bound"
        );
      }

      const recordedAt = this.#nextEventTime(input.tenantId);
      const body = parseStored(
        SubmissionBodySchema,
        {
          contractVersion: 1,
          tenantId: input.tenantId,
          jobId: input.jobId,
          jobKind: PORTFOLIO_SURVEILLANCE_V4_JOB_KIND,
          requestedBy: input.requestedBy,
          requestHash: input.requestHash,
          startAuthorizationAudit: input.startAuthorizationAudit,
          envelope: input.envelope,
          planArtifact: input.planArtifact,
          recordedAt
        },
        "submission"
      );
      const submission = parseStored(
        SubmissionSchema,
        { ...body, submissionHash: canonicalHash(body) },
        "submission"
      );
      this.#insertSubmission(submission);

      const receiptBody = parseStored(
        ReceiptBodySchema,
        {
          contractVersion: 1,
          tenantId: input.tenantId,
          actorId: input.requestedBy,
          idempotencyKey: input.idempotencyKey,
          requestHash: input.requestHash,
          bindingHash,
          jobId: input.jobId,
          submissionHash: submission.submissionHash,
          createdAt: recordedAt
        },
        "idempotency receipt"
      );
      const receipt = parseStored(
        ReceiptSchema,
        { ...receiptBody, receiptHash: canonicalHash(receiptBody) },
        "idempotency receipt"
      );
      this.#insertReceipt(receipt);
      this.#appendEventAt({
        contractVersion: 1,
        tenantId: input.tenantId,
        jobId: input.jobId,
        eventId: randomUUID(),
        eventType: "portfolio_surveillance_v4.submission_recorded",
        actorId: input.requestedBy,
        occurredAt: recordedAt,
        submissionHash: submission.submissionHash
      });
      const state = this.#readState(input.tenantId, input.jobId);
      if (!state) throw integrity("Submission did not become durable");
      return Object.freeze({ state, receipt, replayed: false });
    });
  }

  recordSubmissionAuthorization(
    inputValue: RecordPortfolioSurveillanceV4SubmissionAuthorizationInput
  ): PortfolioSurveillanceV4StateWriteResult {
    this.#assertOpen();
    const input = parseSubmissionAuthorizationInput(inputValue);
    return this.#transaction(() => {
      const state = this.#requiredState(input.tenantId, input.jobId);
      const candidate = (occurredAt: string): EventBody => ({
        contractVersion: 1,
        tenantId: input.tenantId,
        jobId: input.jobId,
        eventId: randomUUID(),
        eventType: "portfolio_surveillance_v4.submission_authorization_recorded",
        actorId: input.actorId,
        occurredAt,
        authorizationAudit: input.authorizationAudit
      });
      const existing = eventOfType(
        state,
        "portfolio_surveillance_v4.submission_authorization_recorded"
      );
      if (existing) {
        assertEventReplay(existing, candidate(existing.occurredAt));
        return Object.freeze({ state, replayed: true });
      }
      if (state.status !== "submitted" || input.actorId !== state.submission.requestedBy) {
        invalidTransition("Submission authorization must bind the immutable requester before work begins");
      }
      const occurredAt = this.#nextEventTime(input.tenantId);
      this.#appendEventAt(candidate(occurredAt));
      return Object.freeze({
        state: this.#requiredState(input.tenantId, input.jobId),
        replayed: false
      });
    });
  }

  recordResultArtifact(
    inputValue: RecordPortfolioSurveillanceV4ResultArtifactInput
  ): PortfolioSurveillanceV4StateWriteResult {
    const input = parseResultInput(inputValue);
    return this.#recordAttemptEvent(
      input,
      "portfolio_surveillance_v4.result_artifact_persisted",
      (state) => {
        if (state.status !== "submitted") invalidTransition("Result artifact requires submitted state");
      },
      (occurredAt) => ({
        contractVersion: 1,
        tenantId: input.tenantId,
        jobId: input.jobId,
        eventId: randomUUID(),
        eventType: "portfolio_surveillance_v4.result_artifact_persisted" as const,
        actorId: input.actorId,
        occurredAt,
        attemptFence: input.attemptFence,
        signedPlanId: input.signedPlanId,
        executionCodeVersion: input.executionCodeVersion,
        resultArtifact: input.resultArtifact
      })
    );
  }

  recordManifestArtifact(
    inputValue: RecordPortfolioSurveillanceV4ManifestArtifactInput
  ): PortfolioSurveillanceV4StateWriteResult {
    const input = parseManifestInput(inputValue);
    return this.#recordAttemptEvent(
      input,
      "portfolio_surveillance_v4.manifest_artifact_persisted",
      (state) => {
        if (state.status !== "result_artifact_persisted" || !state.resultArtifact) {
          invalidTransition("Manifest artifact requires a persisted result artifact");
        }
        assertPointer(state.resultArtifact, input.resultArtifact, "result artifact");
        assertExecutionProvenance(state, input.signedPlanId, input.executionCodeVersion);
        const previousFence = lastAttemptFence(state);
        if (!previousFence) throw integrity("Persisted result artifact is missing its attempt fence");
        assertFenceMayAdvance(previousFence, input.attemptFence);
      },
      (occurredAt) => ({
        contractVersion: 1,
        tenantId: input.tenantId,
        jobId: input.jobId,
        eventId: randomUUID(),
        eventType: "portfolio_surveillance_v4.manifest_artifact_persisted" as const,
        actorId: input.actorId,
        occurredAt,
        attemptFence: input.attemptFence,
        signedPlanId: input.signedPlanId,
        executionCodeVersion: input.executionCodeVersion,
        resultArtifact: input.resultArtifact,
        manifestArtifact: input.manifestArtifact
      })
    );
  }

  recordCompletionPreparation(
    inputValue: RecordPortfolioSurveillanceV4CompletionPreparationInput
  ): PortfolioSurveillanceV4StateWriteResult {
    const input = parseManifestInput(inputValue);
    this.#assertOpen();
    return this.#transaction(() => {
      const state = this.#requiredState(input.tenantId, input.jobId);
      const existing = state.events.find(
        (event) =>
          event.eventType === "portfolio_surveillance_v4.completion_prepared" &&
          event.attemptFence.attemptNumber === input.attemptFence.attemptNumber
      );
      const candidate = (occurredAt: string): EventBody => ({
        contractVersion: 1,
        tenantId: input.tenantId,
        jobId: input.jobId,
        eventId: randomUUID(),
        eventType: "portfolio_surveillance_v4.completion_prepared",
        actorId: input.actorId,
        occurredAt,
        attemptFence: input.attemptFence,
        signedPlanId: input.signedPlanId,
        executionCodeVersion: input.executionCodeVersion,
        resultArtifact: input.resultArtifact,
        manifestArtifact: input.manifestArtifact
      });
      if (existing) {
        assertEventReplay(existing, candidate(existing.occurredAt));
        return Object.freeze({ state, replayed: true });
      }
      assertNotTerminal(state);
      if (
        (state.status !== "manifest_artifact_persisted" &&
          state.status !== "completion_prepared") ||
        !state.resultArtifact ||
        !state.manifestArtifact
      ) {
        invalidTransition("Completion preparation requires persisted result and manifest artifacts");
      }
      assertPointer(state.resultArtifact, input.resultArtifact, "result artifact");
      assertPointer(state.manifestArtifact, input.manifestArtifact, "manifest artifact");
      assertExecutionProvenance(state, input.signedPlanId, input.executionCodeVersion);
      const previousFence = lastAttemptFence(state);
      if (!previousFence) throw integrity("Completion preparation is missing its predecessor fence");
      assertFenceMayAdvance(previousFence, input.attemptFence);
      const occurredAt = this.#nextEventTime(input.tenantId);
      assertActiveFence(input.actorId, input.attemptFence, occurredAt);
      this.#appendEventAt(candidate(occurredAt));
      return Object.freeze({
        state: this.#requiredState(input.tenantId, input.jobId),
        replayed: false
      });
    });
  }

  recordQueueCompletion(
    inputValue: RecordPortfolioSurveillanceV4QueueCompletionInput
  ): PortfolioSurveillanceV4StateWriteResult {
    this.#assertOpen();
    const input = parseQueueCompletionInput(inputValue);
    return this.#transaction(() => {
      const state = this.#requiredState(input.tenantId, input.jobId);
      const candidate = (occurredAt: string): EventBody => ({
        contractVersion: 1,
        tenantId: input.tenantId,
        jobId: input.jobId,
        eventId: randomUUID(),
        eventType: "portfolio_surveillance_v4.queue_completion_recorded",
        actorId: input.actorId,
        occurredAt,
        queueRequestHash: input.queueRequestHash,
        resultHandleHash: input.resultHandleHash,
        queueUpdatedAt: input.queueUpdatedAt,
        completionAudit: input.completionAudit,
        resultArtifact: input.resultArtifact,
        manifestArtifact: input.manifestArtifact
      });
      const existing = eventOfType(state, "portfolio_surveillance_v4.queue_completion_recorded");
      if (existing) {
        assertEventReplay(existing, candidate(existing.occurredAt));
        return Object.freeze({ state, replayed: true });
      }
      assertNotTerminal(state);
      if (
        state.status !== "completion_prepared" ||
        !state.resultArtifact ||
        !state.manifestArtifact
      ) {
        invalidTransition("Queue completion requires a fenced completion preparation");
      }
      if (input.actorId !== state.submission.requestedBy) {
        invalidTransition("Queue completion actor must match the immutable requester binding");
      }
      assertPointer(state.resultArtifact, input.resultArtifact, "result artifact");
      assertPointer(state.manifestArtifact, input.manifestArtifact, "manifest artifact");
      const occurredAt = this.#nextEventTime(input.tenantId);
      this.#appendEventAt(candidate(occurredAt));
      return Object.freeze({
        state: this.#requiredState(input.tenantId, input.jobId),
        replayed: false
      });
    });
  }

  recordCancellation(
    inputValue: RecordPortfolioSurveillanceV4CancellationInput
  ): PortfolioSurveillanceV4StateWriteResult {
    this.#assertOpen();
    const input = parseCancellationInput(inputValue);
    return this.#transaction(() => {
      const state = this.#requiredState(input.tenantId, input.jobId);
      const existing = eventOfType(state, "portfolio_surveillance_v4.cancelled");
      if (existing) {
        if (existing.actorId !== input.actorId || existing.reasonCode !== input.reasonCode) {
          invalidTransition("Cancellation event already exists with different immutable content");
        }
        return Object.freeze({ state, replayed: true });
      }
      assertNotTerminal(state);
      const occurredAt = this.#nextEventTime(input.tenantId);
      this.#appendEventAt({
        contractVersion: 1,
        tenantId: input.tenantId,
        jobId: input.jobId,
        eventId: randomUUID(),
        eventType: "portfolio_surveillance_v4.cancelled",
        actorId: input.actorId,
        occurredAt,
        reasonCode: input.reasonCode
      });
      return Object.freeze({ state: this.#requiredState(input.tenantId, input.jobId), replayed: false });
    });
  }

  recordFailure(
    inputValue: RecordPortfolioSurveillanceV4FailureInput
  ): PortfolioSurveillanceV4StateWriteResult {
    this.#assertOpen();
    const input = parseFailureInput(inputValue);
    return this.#transaction(() => {
      const state = this.#requiredState(input.tenantId, input.jobId);
      const existing = eventOfType(state, "portfolio_surveillance_v4.failed");
      if (existing) {
        if (
          existing.actorId !== input.actorId ||
          existing.errorCode !== input.errorCode ||
          canonicalJson(existing.attemptFence) !== canonicalJson(input.attemptFence)
        ) {
          invalidTransition("Failure event already exists with different immutable content");
        }
        return Object.freeze({ state, replayed: true });
      }
      assertNotTerminal(state);
      const previousFence = lastAttemptFence(state);
      if (previousFence) assertFenceMayAdvance(previousFence, input.attemptFence);
      const occurredAt = this.#nextEventTime(input.tenantId);
      assertActiveFence(input.actorId, input.attemptFence, occurredAt);
      this.#appendEventAt({
        contractVersion: 1,
        tenantId: input.tenantId,
        jobId: input.jobId,
        eventId: randomUUID(),
        eventType: "portfolio_surveillance_v4.failed",
        actorId: input.actorId,
        occurredAt,
        attemptFence: input.attemptFence,
        errorCode: input.errorCode
      });
      return Object.freeze({ state: this.#requiredState(input.tenantId, input.jobId), replayed: false });
    });
  }

  get(tenantIdValue: string, jobIdValue: string): PortfolioSurveillanceV4JobStateV1 | undefined {
    this.#assertOpen();
    return this.#readState(identifier(tenantIdValue, "tenantId"), identifier(jobIdValue, "jobId"));
  }

  list(
    tenantIdValue: string,
    page: PortfolioSurveillanceV4StatePageRequest = {}
  ): PortfolioSurveillanceV4StatePageV1 {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenantId");
    const limit = integer(page.limit ?? 100, "limit", 1, 1_000);
    const afterJobId = page.cursor ? decodeCursor(page.cursor, tenantId).afterJobId : "";
    const rows = this.#database
      .prepare(
        `SELECT * FROM portfolio_surveillance_v4_submissions
          WHERE tenant_id = ? AND job_id > ?
          ORDER BY job_id
          LIMIT ?`
      )
      .all(tenantId, afterJobId, limit + 1) as unknown as SubmissionRow[];
    const hasNext = rows.length > limit;
    const selected = hasNext ? rows.slice(0, limit) : rows;
    const events = this.#readTenantEvents(tenantId);
    const items = selected.map((row) => {
      const submission = this.#submissionFromRow(row);
      this.#assertSubmissionReceipt(submission);
      return stateFrom(submission, events.filter((event) => event.jobId === submission.jobId));
    });
    const last = selected.at(-1);
    return Object.freeze({
      items: Object.freeze(items),
      nextCursor:
        hasNext && last
          ? encodeCursor({ version: 1, tenantId, afterJobId: last.job_id })
          : null
    });
  }

  getIdempotencyReceipt(
    tenantIdValue: string,
    actorIdValue: string,
    idempotencyKeyValue: string
  ): PortfolioSurveillanceV4IdempotencyReceiptV1 | undefined {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenantId");
    const actorId = identifier(actorIdValue, "actorId");
    const idempotencyKey = identifier(idempotencyKeyValue, "idempotencyKey");
    const row = this.#database
      .prepare(
        `SELECT * FROM portfolio_surveillance_v4_idempotency
          WHERE tenant_id = ? AND actor_id = ? AND idempotency_key = ?`
      )
      .get(tenantId, actorId, idempotencyKey) as ReceiptRow | undefined;
    if (!row) return undefined;
    const receipt = this.#receiptFromRow(row);
    const submission = this.#readSubmission(tenantId, receipt.jobId);
    if (!submission) throw integrity("Idempotency receipt references a missing submission");
    assertReceiptSubmission(receipt, submission);
    const state = this.#readState(tenantId, receipt.jobId);
    if (!state) throw integrity("Idempotency receipt is missing its submission audit event");
    return receipt;
  }

  getEvents(
    tenantIdValue: string,
    jobIdValue: string
  ): readonly PortfolioSurveillanceV4StateEventV1[] {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenantId");
    const jobId = identifier(jobIdValue, "jobId");
    const state = this.#readState(tenantId, jobId);
    return state?.events ?? Object.freeze([]);
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#database.close();
  }

  #recordAttemptEvent<T extends {
    readonly tenantId: string;
    readonly jobId: string;
    readonly actorId: string;
    readonly attemptFence: PortfolioSurveillanceV4AttemptFenceV1;
  }>(
    input: T,
    eventType:
      | "portfolio_surveillance_v4.result_artifact_persisted"
      | "portfolio_surveillance_v4.manifest_artifact_persisted",
    beforeAppend: (state: PortfolioSurveillanceV4JobStateV1) => void,
    body: (occurredAt: string) => EventBody
  ): PortfolioSurveillanceV4StateWriteResult {
    this.#assertOpen();
    return this.#transaction(() => {
      const state = this.#requiredState(input.tenantId, input.jobId);
      const existing = eventOfType(state, eventType);
      if (existing) {
        assertEventReplay(existing, body(existing.occurredAt));
        return Object.freeze({ state, replayed: true });
      }
      assertNotTerminal(state);
      beforeAppend(state);
      const occurredAt = this.#nextEventTime(input.tenantId);
      assertActiveFence(input.actorId, input.attemptFence, occurredAt);
      this.#appendEventAt(body(occurredAt));
      return Object.freeze({ state: this.#requiredState(input.tenantId, input.jobId), replayed: false });
    });
  }

  #readState(tenantId: string, jobId: string): PortfolioSurveillanceV4JobStateV1 | undefined {
    const submission = this.#readSubmission(tenantId, jobId);
    if (!submission) return undefined;
    this.#assertSubmissionReceipt(submission);
    const events = this.#readTenantEvents(tenantId).filter((event) => event.jobId === jobId);
    return stateFrom(submission, events);
  }

  #requiredState(tenantId: string, jobId: string): PortfolioSurveillanceV4JobStateV1 {
    const state = this.#readState(tenantId, jobId);
    if (!state) {
      throw new PortfolioSurveillanceV4StateStoreError(
        "NOT_FOUND",
        "Portfolio surveillance v4 submission was not found in the tenant"
      );
    }
    return state;
  }

  #readSubmission(
    tenantId: string,
    jobId: string
  ): PortfolioSurveillanceV4SubmissionV1 | undefined {
    const row = this.#database
      .prepare(
        `SELECT * FROM portfolio_surveillance_v4_submissions
          WHERE tenant_id = ? AND job_id = ?`
      )
      .get(tenantId, jobId) as SubmissionRow | undefined;
    return row ? this.#submissionFromRow(row) : undefined;
  }

  #submissionFromRow(row: SubmissionRow): PortfolioSurveillanceV4SubmissionV1 {
    const submission = parseCanonicalJson(SubmissionSchema, row.submission_json, "submission");
    const { submissionHash, ...body } = submission;
    try {
      assertCanonicalHash(body, submissionHash, "PortfolioSurveillanceV4SubmissionV1");
    } catch (error) {
      throw integrity("Submission hash verification failed", error);
    }
    if (
      submission.tenantId !== row.tenant_id ||
      submission.jobId !== row.job_id ||
      submission.jobKind !== row.job_kind ||
      submission.requestedBy !== row.requested_by ||
      submission.requestHash !== row.request_hash ||
      submission.startAuthorizationAudit.sequence !== row.start_authorization_audit_sequence ||
      submission.startAuthorizationAudit.eventHash !== row.start_authorization_audit_hash ||
      submission.envelope.envelopeId !== row.envelope_id ||
      submission.envelope.kind !== row.envelope_kind ||
      submission.envelope.contentHash !== row.envelope_content_hash ||
      submission.envelope.byteLength !== row.envelope_byte_length ||
      submission.planArtifact.artifactId !== row.plan_artifact_id ||
      submission.planArtifact.kind !== row.plan_kind ||
      submission.planArtifact.contentHash !== row.plan_content_hash ||
      submission.planArtifact.byteLength !== row.plan_byte_length ||
      submission.recordedAt !== row.recorded_at ||
      submission.submissionHash !== row.submission_hash
    ) {
      throw integrity("Submission index columns do not match canonical content");
    }
    return submission;
  }

  #receiptFromRow(row: ReceiptRow): PortfolioSurveillanceV4IdempotencyReceiptV1 {
    const receipt = parseCanonicalJson(ReceiptSchema, row.receipt_json, "idempotency receipt");
    const { receiptHash, ...body } = receipt;
    try {
      assertCanonicalHash(body, receiptHash, "PortfolioSurveillanceV4IdempotencyReceiptV1");
    } catch (error) {
      throw integrity("Idempotency receipt hash verification failed", error);
    }
    if (
      receipt.tenantId !== row.tenant_id ||
      receipt.actorId !== row.actor_id ||
      receipt.idempotencyKey !== row.idempotency_key ||
      receipt.requestHash !== row.request_hash ||
      receipt.bindingHash !== row.binding_hash ||
      receipt.jobId !== row.job_id ||
      receipt.submissionHash !== row.submission_hash ||
      receipt.createdAt !== row.created_at ||
      receipt.receiptHash !== row.receipt_hash
    ) {
      throw integrity("Idempotency receipt columns do not match canonical content");
    }
    return receipt;
  }

  #assertSubmissionReceipt(submission: PortfolioSurveillanceV4SubmissionV1): void {
    const rows = this.#database
      .prepare(
        `SELECT * FROM portfolio_surveillance_v4_idempotency
          WHERE tenant_id = ? AND job_id = ?`
      )
      .all(submission.tenantId, submission.jobId) as unknown as ReceiptRow[];
    if (rows.length !== 1) throw integrity("Submission must have exactly one idempotency receipt");
    assertReceiptSubmission(this.#receiptFromRow(rows[0]!), submission);
  }

  #readTenantEvents(tenantId: string): readonly PortfolioSurveillanceV4StateEventV1[] {
    const rows = this.#database
      .prepare(
        `SELECT * FROM portfolio_surveillance_v4_state_events
          WHERE tenant_id = ?
          ORDER BY tenant_sequence`
      )
      .all(tenantId) as unknown as EventRow[];
    let previousEventHash: Sha256Hash | null = null;
    let previousOccurredAt: string | null = null;
    return Object.freeze(
      rows.map((row, index) => {
        const body = parseCanonicalJson(EventBodySchema, row.event_json, "state event");
        const expectedFence = "attemptFence" in body ? body.attemptFence : undefined;
        if (
          row.sequence < 1 ||
          row.tenant_sequence !== index + 1 ||
          body.tenantId !== row.tenant_id ||
          body.jobId !== row.job_id ||
          body.eventId !== row.event_id ||
          body.eventType !== row.event_type ||
          body.actorId !== row.actor_id ||
          body.occurredAt !== row.occurred_at ||
          (expectedFence?.attemptNumber ?? null) !== row.attempt_number ||
          (expectedFence?.workerId ?? null) !== row.worker_id ||
          (expectedFence?.leaseTokenHash ?? null) !== row.lease_token_hash ||
          (expectedFence?.leaseExpiresAt ?? null) !== row.lease_expires_at ||
          row.previous_event_hash !== previousEventHash ||
          (previousOccurredAt !== null && body.occurredAt < previousOccurredAt)
        ) {
          throw integrity("Portfolio surveillance v4 event chain ordering or indexes are invalid");
        }
        const eventHash = hashEvent(body, row.tenant_sequence, previousEventHash);
        if (eventHash !== row.event_hash) {
          throw integrity("Portfolio surveillance v4 event hash chain failed verification");
        }
        previousEventHash = eventHash;
        previousOccurredAt = body.occurredAt;
        return Object.freeze({
          ...body,
          tenantSequence: row.tenant_sequence,
          previousEventHash: row.previous_event_hash as Sha256Hash | null,
          eventHash
        }) as PortfolioSurveillanceV4StateEventV1;
      })
    );
  }

  #insertSubmission(submission: PortfolioSurveillanceV4SubmissionV1): void {
    this.#database
      .prepare(
        `INSERT INTO portfolio_surveillance_v4_submissions (
          tenant_id, job_id, job_kind, requested_by, request_hash,
          start_authorization_audit_sequence, start_authorization_audit_hash,
          envelope_id, envelope_kind, envelope_content_hash, envelope_byte_length,
          plan_artifact_id, plan_kind, plan_content_hash, plan_byte_length,
          recorded_at, submission_hash, submission_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        submission.tenantId,
        submission.jobId,
        submission.jobKind,
        submission.requestedBy,
        submission.requestHash,
        submission.startAuthorizationAudit.sequence,
        submission.startAuthorizationAudit.eventHash,
        submission.envelope.envelopeId,
        submission.envelope.kind,
        submission.envelope.contentHash,
        submission.envelope.byteLength,
        submission.planArtifact.artifactId,
        submission.planArtifact.kind,
        submission.planArtifact.contentHash,
        submission.planArtifact.byteLength,
        submission.recordedAt,
        submission.submissionHash,
        canonicalJson(submission)
      );
  }

  #insertReceipt(receipt: PortfolioSurveillanceV4IdempotencyReceiptV1): void {
    this.#database
      .prepare(
        `INSERT INTO portfolio_surveillance_v4_idempotency (
          tenant_id, actor_id, idempotency_key, request_hash, binding_hash,
          job_id, submission_hash, created_at, receipt_hash, receipt_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        receipt.tenantId,
        receipt.actorId,
        receipt.idempotencyKey,
        receipt.requestHash,
        receipt.bindingHash,
        receipt.jobId,
        receipt.submissionHash,
        receipt.createdAt,
        receipt.receiptHash,
        canonicalJson(receipt)
      );
  }

  #appendEventAt(bodyValue: EventBody): PortfolioSurveillanceV4StateEventV1 {
    const body = parseStored(EventBodySchema, bodyValue, "state event");
    const last = this.#database
      .prepare(
        `SELECT tenant_sequence, occurred_at, event_hash
           FROM portfolio_surveillance_v4_state_events
          WHERE tenant_id = ?
          ORDER BY tenant_sequence DESC
          LIMIT 1`
      )
      .get(body.tenantId) as
      | { readonly tenant_sequence: number; readonly occurred_at: string; readonly event_hash: string }
      | undefined;
    if (last && body.occurredAt < last.occurred_at) {
      throw new PortfolioSurveillanceV4StateStoreError(
        "CLOCK_ROLLBACK",
        "State event clock moved behind the tenant audit chain"
      );
    }
    const tenantSequence = (last?.tenant_sequence ?? 0) + 1;
    const previousEventHash = (last?.event_hash as Sha256Hash | undefined) ?? null;
    const eventHash = hashEvent(body, tenantSequence, previousEventHash);
    const fence = "attemptFence" in body ? body.attemptFence : undefined;
    this.#database
      .prepare(
        `INSERT INTO portfolio_surveillance_v4_state_events (
          tenant_id, tenant_sequence, event_id, job_id, event_type, actor_id,
          attempt_number, worker_id, lease_token_hash, lease_expires_at,
          occurred_at, previous_event_hash, event_hash, event_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        body.tenantId,
        tenantSequence,
        body.eventId,
        body.jobId,
        body.eventType,
        body.actorId,
        fence?.attemptNumber ?? null,
        fence?.workerId ?? null,
        fence?.leaseTokenHash ?? null,
        fence?.leaseExpiresAt ?? null,
        body.occurredAt,
        previousEventHash,
        eventHash,
        canonicalJson(body)
      );
    return Object.freeze({ ...body, tenantSequence, previousEventHash, eventHash });
  }

  #nextEventTime(tenantId: string): string {
    const value = this.#clock();
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
      throw new PortfolioSurveillanceV4StateStoreError("INVALID_ARGUMENT", "State store clock is invalid");
    }
    const now = parseInput(IsoTimestampSchema, value.toISOString(), "state store clock");
    const last = this.#database
      .prepare(
        `SELECT occurred_at FROM portfolio_surveillance_v4_state_events
          WHERE tenant_id = ? ORDER BY tenant_sequence DESC LIMIT 1`
      )
      .get(tenantId) as { readonly occurred_at: string } | undefined;
    if (last && now < last.occurred_at) {
      throw new PortfolioSurveillanceV4StateStoreError(
        "CLOCK_ROLLBACK",
        "State store clock moved behind the tenant audit chain"
      );
    }
    return now;
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
        // Preserve the original error.
      }
      throw error;
    }
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw new PortfolioSurveillanceV4StateStoreError("STORE_CLOSED", "State store is closed");
    }
  }
}

function parseSubmissionInput(
  inputValue: RecordPortfolioSurveillanceV4SubmissionInput
): RecordPortfolioSurveillanceV4SubmissionInput {
  const schema = z
    .object({
      tenantId: IdentifierSchema,
      jobId: IdentifierSchema,
      requestedBy: IdentifierSchema,
      idempotencyKey: IdentifierSchema,
      requestHash: Sha256HashSchema,
      startAuthorizationAudit: AuditPointerSchema,
      envelope: EnvelopePointerSchema,
      planArtifact: PlanArtifactPointerSchema
    })
    .strict();
  return parseInput(schema, inputValue, "submission input");
}

function parseSubmissionAuthorizationInput(
  inputValue: RecordPortfolioSurveillanceV4SubmissionAuthorizationInput
): RecordPortfolioSurveillanceV4SubmissionAuthorizationInput {
  return parseInput(
    z.object({
      tenantId: IdentifierSchema,
      jobId: IdentifierSchema,
      actorId: IdentifierSchema,
      authorizationAudit: AuditPointerSchema
    }).strict(),
    inputValue,
    "submission authorization input"
  );
}

function parseResultInput(
  inputValue: RecordPortfolioSurveillanceV4ResultArtifactInput
): RecordPortfolioSurveillanceV4ResultArtifactInput {
  return parseInput(
    z
      .object({
        tenantId: IdentifierSchema,
        jobId: IdentifierSchema,
        actorId: IdentifierSchema,
        attemptFence: AttemptFenceSchema,
        signedPlanId: IdentifierSchema,
        executionCodeVersion: IdentifierSchema,
        resultArtifact: ResultArtifactPointerSchema
      })
      .strict(),
    inputValue,
    "result artifact input"
  );
}

function parseManifestInput(
  inputValue: RecordPortfolioSurveillanceV4ManifestArtifactInput
): RecordPortfolioSurveillanceV4ManifestArtifactInput {
  return parseInput(
    z
      .object({
        tenantId: IdentifierSchema,
        jobId: IdentifierSchema,
        actorId: IdentifierSchema,
        attemptFence: AttemptFenceSchema,
        signedPlanId: IdentifierSchema,
        executionCodeVersion: IdentifierSchema,
        resultArtifact: ResultArtifactPointerSchema,
        manifestArtifact: ManifestArtifactPointerSchema
      })
      .strict(),
    inputValue,
    "manifest artifact input"
  );
}

function parseQueueCompletionInput(
  inputValue: RecordPortfolioSurveillanceV4QueueCompletionInput
): RecordPortfolioSurveillanceV4QueueCompletionInput {
  return parseInput(
    z
      .object({
        tenantId: IdentifierSchema,
        jobId: IdentifierSchema,
        actorId: IdentifierSchema,
        queueRequestHash: BareSha256HashSchema,
        resultHandleHash: BareSha256HashSchema,
        queueUpdatedAt: IsoTimestampSchema,
        completionAudit: AuditPointerSchema,
        resultArtifact: ResultArtifactPointerSchema,
        manifestArtifact: ManifestArtifactPointerSchema
      })
      .strict(),
    inputValue,
    "queue completion input"
  );
}

function parseCancellationInput(
  inputValue: RecordPortfolioSurveillanceV4CancellationInput
): RecordPortfolioSurveillanceV4CancellationInput {
  return parseInput(
    z
      .object({
        tenantId: IdentifierSchema,
        jobId: IdentifierSchema,
        actorId: IdentifierSchema,
        reasonCode: IdentifierSchema
      })
      .strict(),
    inputValue,
    "cancellation input"
  );
}

function parseFailureInput(
  inputValue: RecordPortfolioSurveillanceV4FailureInput
): RecordPortfolioSurveillanceV4FailureInput {
  return parseInput(
    z
      .object({
        tenantId: IdentifierSchema,
        jobId: IdentifierSchema,
        actorId: IdentifierSchema,
        attemptFence: AttemptFenceSchema,
        errorCode: IdentifierSchema
      })
      .strict(),
    inputValue,
    "failure input"
  );
}

function stateFrom(
  submission: PortfolioSurveillanceV4SubmissionV1,
  events: readonly PortfolioSurveillanceV4StateEventV1[]
): PortfolioSurveillanceV4JobStateV1 {
  if (events.length === 0) throw integrity("Submission is missing its audit event");
  let status: PortfolioSurveillanceV4StateStatus = "submitted";
  let resultArtifact: PortfolioSurveillanceV4ResultArtifactPointerV1 | undefined;
  let signedPlanId: string | undefined;
  let executionCodeVersion: string | undefined;
  let submissionAuthorizationAudit: PortfolioSurveillanceV4AuditPointerV1 | undefined;
  let manifestArtifact: PortfolioSurveillanceV4ManifestArtifactPointerV1 | undefined;
  let queueCompletion: PortfolioSurveillanceV4QueueCompletionEvidenceV1 | undefined;
  let terminalCode: string | undefined;
  let fence: PortfolioSurveillanceV4AttemptFenceV1 | undefined;
  let sawSubmission = false;

  for (const event of events) {
    if (event.eventType === "portfolio_surveillance_v4.submission_recorded") {
      if (sawSubmission || event.submissionHash !== submission.submissionHash || event.actorId !== submission.requestedBy) {
        throw integrity("Submission audit binding is invalid");
      }
      sawSubmission = true;
      continue;
    }
    if (!sawSubmission) throw integrity("State event precedes submission audit binding");
    if (status === "completed" || status === "cancelled" || status === "failed") {
      throw integrity("State event follows a terminal event");
    }
    if (event.eventType === "portfolio_surveillance_v4.submission_authorization_recorded") {
      if (status !== "submitted" || submissionAuthorizationAudit) {
        throw integrity("Submission authorization event is out of order");
      }
      if (event.actorId !== submission.requestedBy) {
        throw integrity("Submission authorization actor does not match requester binding");
      }
      submissionAuthorizationAudit = event.authorizationAudit;
    } else if (event.eventType === "portfolio_surveillance_v4.result_artifact_persisted") {
      if (status !== "submitted") throw integrity("Result artifact event is out of order");
      if (!submissionAuthorizationAudit) throw integrity("Result precedes submission authorization");
      assertEventActorFence(event);
      status = "result_artifact_persisted";
      resultArtifact = event.resultArtifact;
      signedPlanId = event.signedPlanId;
      executionCodeVersion = event.executionCodeVersion;
      fence = event.attemptFence;
    } else if (event.eventType === "portfolio_surveillance_v4.manifest_artifact_persisted") {
      if (status !== "result_artifact_persisted" || !resultArtifact || !fence) {
        throw integrity("Manifest artifact event is out of order");
      }
      assertEventActorFence(event);
      assertPointer(resultArtifact, event.resultArtifact, "result artifact");
      if (event.signedPlanId !== signedPlanId || event.executionCodeVersion !== executionCodeVersion) {
        throw integrity("Manifest execution provenance does not match result stage");
      }
      assertFenceMayAdvance(fence, event.attemptFence);
      status = "manifest_artifact_persisted";
      manifestArtifact = event.manifestArtifact;
      fence = event.attemptFence;
    } else if (event.eventType === "portfolio_surveillance_v4.completion_prepared") {
      if (
        (status !== "manifest_artifact_persisted" && status !== "completion_prepared") ||
        !resultArtifact ||
        !manifestArtifact ||
        !fence
      ) {
        throw integrity("Completion preparation event is out of order");
      }
      assertEventActorFence(event);
      assertPointer(resultArtifact, event.resultArtifact, "result artifact");
      assertPointer(manifestArtifact, event.manifestArtifact, "manifest artifact");
      if (event.signedPlanId !== signedPlanId || event.executionCodeVersion !== executionCodeVersion) {
        throw integrity("Completion preparation provenance does not match result stage");
      }
      assertFenceMayAdvance(fence, event.attemptFence);
      status = "completion_prepared";
      fence = event.attemptFence;
    } else if (event.eventType === "portfolio_surveillance_v4.queue_completion_recorded") {
      if (status !== "completion_prepared" || !resultArtifact || !manifestArtifact) {
        throw integrity("Queue completion event is out of order");
      }
      if (event.actorId !== submission.requestedBy) {
        throw integrity("Queue completion actor does not match requester binding");
      }
      assertPointer(resultArtifact, event.resultArtifact, "result artifact");
      assertPointer(manifestArtifact, event.manifestArtifact, "manifest artifact");
      queueCompletion = Object.freeze({
        queueRequestHash: event.queueRequestHash,
        resultHandleHash: event.resultHandleHash,
        queueUpdatedAt: event.queueUpdatedAt,
        completionAudit: event.completionAudit
      });
      status = "completed";
    } else if (event.eventType === "portfolio_surveillance_v4.cancelled") {
      status = "cancelled";
      terminalCode = event.reasonCode;
    } else {
      assertEventActorFence(event);
      if (fence) assertFenceMayAdvance(fence, event.attemptFence);
      status = "failed";
      terminalCode = event.errorCode;
    }
  }
  if (!sawSubmission) throw integrity("Submission audit event is missing");
  return Object.freeze({
    submission,
    status,
    ...(resultArtifact ? { resultArtifact } : {}),
    ...(signedPlanId ? { signedPlanId } : {}),
    ...(executionCodeVersion ? { executionCodeVersion } : {}),
    ...(submissionAuthorizationAudit ? { submissionAuthorizationAudit } : {}),
    ...(manifestArtifact ? { manifestArtifact } : {}),
    ...(queueCompletion ? { queueCompletion } : {}),
    ...(terminalCode ? { terminalCode } : {}),
    events: Object.freeze([...events])
  });
}

function submissionBindingHash(input: RecordPortfolioSurveillanceV4SubmissionInput): Sha256Hash {
  return canonicalHash({
    contractVersion: 1,
    tenantId: input.tenantId,
    jobId: input.jobId,
    requestedBy: input.requestedBy,
    requestHash: input.requestHash,
    startAuthorizationAudit: input.startAuthorizationAudit,
    envelope: input.envelope,
    planArtifact: input.planArtifact
  });
}

function assertReceiptSubmission(
  receipt: PortfolioSurveillanceV4IdempotencyReceiptV1,
  submission: PortfolioSurveillanceV4SubmissionV1
): void {
  const bindingHash = submissionBindingHash({
    tenantId: submission.tenantId,
    jobId: submission.jobId,
    requestedBy: submission.requestedBy,
    idempotencyKey: receipt.idempotencyKey,
    requestHash: submission.requestHash,
    startAuthorizationAudit: submission.startAuthorizationAudit,
    envelope: submission.envelope,
    planArtifact: submission.planArtifact
  });
  if (
    receipt.tenantId !== submission.tenantId ||
    receipt.actorId !== submission.requestedBy ||
    receipt.requestHash !== submission.requestHash ||
    receipt.bindingHash !== bindingHash ||
    receipt.jobId !== submission.jobId ||
    receipt.submissionHash !== submission.submissionHash ||
    receipt.createdAt !== submission.recordedAt
  ) {
    throw integrity("Idempotency receipt does not match its immutable submission");
  }
}

function hashEvent(
  body: EventBody,
  tenantSequence: number,
  previousEventHash: Sha256Hash | null
): Sha256Hash {
  return canonicalHash({ ...body, tenantSequence, previousEventHash });
}

function lastAttemptFence(
  state: PortfolioSurveillanceV4JobStateV1
): PortfolioSurveillanceV4AttemptFenceV1 | undefined {
  for (let index = state.events.length - 1; index >= 0; index -= 1) {
    const event = state.events[index]!;
    if ("attemptFence" in event) return event.attemptFence;
  }
  return undefined;
}

function eventOfType<T extends EventBody["eventType"]>(
  state: PortfolioSurveillanceV4JobStateV1,
  eventType: T
): Extract<PortfolioSurveillanceV4StateEventV1, { readonly eventType: T }> | undefined {
  return state.events.find((event) => event.eventType === eventType) as
    | Extract<PortfolioSurveillanceV4StateEventV1, { readonly eventType: T }>
    | undefined;
}

function assertEventReplay(existing: PortfolioSurveillanceV4StateEventV1, candidate: EventBody): void {
  const { eventId: _existingEventId, occurredAt: _existingOccurredAt, ...existingComparable } = existing;
  const {
    eventId: _candidateEventId,
    occurredAt: _candidateOccurredAt,
    ...candidateComparable
  } = candidate;
  const {
    tenantSequence: _tenantSequence,
    previousEventHash: _previousEventHash,
    eventHash: _eventHash,
    ...existingBody
  } = existingComparable;
  if (canonicalJson(existingBody) !== canonicalJson(candidateComparable)) {
    if ("attemptFence" in candidate && "attemptFence" in existing) {
      if (canonicalJson(candidate.attemptFence) !== canonicalJson(existing.attemptFence)) {
        throw new PortfolioSurveillanceV4StateStoreError(
          "FENCE_MISMATCH",
          "The immutable stage is already bound to a different attempt fence"
        );
      }
    }
    throw new PortfolioSurveillanceV4StateStoreError(
      "POINTER_CONFLICT",
      "The immutable stage is already bound to different artifact pointers"
    );
  }
}

function assertFenceMayAdvance(
  previous: PortfolioSurveillanceV4AttemptFenceV1,
  candidate: PortfolioSurveillanceV4AttemptFenceV1
): void {
  if (candidate.attemptNumber < previous.attemptNumber) {
    throw new PortfolioSurveillanceV4StateStoreError(
      "FENCE_MISMATCH",
      "Attempt fence cannot move backward"
    );
  }
  if (candidate.attemptNumber === previous.attemptNumber) assertFenceExact(previous, candidate);
}

function assertExecutionProvenance(
  state: PortfolioSurveillanceV4JobStateV1,
  signedPlanId: string,
  executionCodeVersion: string
): void {
  if (
    state.signedPlanId !== signedPlanId ||
    state.executionCodeVersion !== executionCodeVersion
  ) {
    throw new PortfolioSurveillanceV4StateStoreError(
      "POINTER_CONFLICT",
      "Execution provenance cannot change after result persistence"
    );
  }
}

function assertFenceExact(
  expected: PortfolioSurveillanceV4AttemptFenceV1 | undefined,
  actual: PortfolioSurveillanceV4AttemptFenceV1
): void {
  if (!expected || canonicalJson(expected) !== canonicalJson(actual)) {
    throw new PortfolioSurveillanceV4StateStoreError(
      "FENCE_MISMATCH",
      "Attempt number and lease identity do not match the active staged result"
    );
  }
}

function assertActiveFence(
  actorId: string,
  fence: PortfolioSurveillanceV4AttemptFenceV1,
  occurredAt: string
): void {
  if (actorId !== fence.workerId) {
    throw new PortfolioSurveillanceV4StateStoreError(
      "FENCE_MISMATCH",
      "Stage actor must match the fenced worker identity"
    );
  }
  if (occurredAt > fence.leaseExpiresAt) {
    throw new PortfolioSurveillanceV4StateStoreError(
      "FENCE_MISMATCH",
      "Attempt lease expired before the state event"
    );
  }
}

function assertEventActorFence(
  event: Extract<PortfolioSurveillanceV4StateEventV1, { readonly attemptFence: unknown }>
): void {
  if (event.actorId !== event.attemptFence.workerId || event.occurredAt > event.attemptFence.leaseExpiresAt) {
    throw integrity("Stored state event attempt fence is invalid");
  }
}

function assertPointer(left: unknown, right: unknown, label: string): void {
  if (canonicalJson(left) !== canonicalJson(right)) {
    throw new PortfolioSurveillanceV4StateStoreError(
      "POINTER_CONFLICT",
      `${label} pointer does not match the immutable staged pointer`
    );
  }
}

function assertNotTerminal(state: PortfolioSurveillanceV4JobStateV1): void {
  if (state.status === "completed" || state.status === "cancelled" || state.status === "failed") {
    invalidTransition("Portfolio surveillance v4 job is terminal");
  }
}

function invalidTransition(message: string): never {
  throw new PortfolioSurveillanceV4StateStoreError("INVALID_TRANSITION", message);
}

function parseInput<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  try {
    return parseWithSchema(schema, value, label);
  } catch (error) {
    throw new PortfolioSurveillanceV4StateStoreError(
      "INVALID_ARGUMENT",
      `${label} failed strict validation${error instanceof Error ? `: ${error.message}` : ""}`
    );
  }
}

function parseStored<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  try {
    return parseWithSchema(schema, value, label);
  } catch (error) {
    throw integrity(`Stored ${label} failed strict validation`, error);
  }
}

function parseCanonicalJson<T>(schema: z.ZodType<T>, json: string, label: string): T {
  try {
    const raw = JSON.parse(json) as unknown;
    if (canonicalJson(raw) !== json) throw new Error("JSON is not canonical");
    return parseStored(schema, raw, label);
  } catch (error) {
    if (error instanceof PortfolioSurveillanceV4StateStoreError) throw error;
    throw integrity(`Stored ${label} JSON is invalid`, error);
  }
}

function identifier(value: string, label: string): string {
  return parseInput(IdentifierSchema, value, label);
}

function integer(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new PortfolioSurveillanceV4StateStoreError(
      "INVALID_ARGUMENT",
      `${label} must be an integer from ${minimum} through ${maximum}`
    );
  }
  return value;
}

function requiredPath(value: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new PortfolioSurveillanceV4StateStoreError("INVALID_ARGUMENT", "Database path is required");
  }
  return value === ":memory:" ? value : resolve(value);
}

function encodeCursor(cursor: StateCursorV1): string {
  return Buffer.from(canonicalJson(cursor), "utf8").toString("base64url");
}

function decodeCursor(value: string, tenantId: string): StateCursorV1 {
  try {
    const json = Buffer.from(value, "base64url").toString("utf8");
    const raw = JSON.parse(json) as unknown;
    if (canonicalJson(raw) !== json) throw new Error("cursor is not canonical");
    const cursor = parseInput(
      z
        .object({
          version: z.literal(1),
          tenantId: IdentifierSchema,
          afterJobId: IdentifierSchema
        })
        .strict(),
      raw,
      "cursor"
    );
    if (cursor.tenantId !== tenantId) throw new Error("cursor tenant mismatch");
    return cursor;
  } catch (error) {
    if (
      error instanceof PortfolioSurveillanceV4StateStoreError &&
      error.code === "INVALID_ARGUMENT"
    ) {
      throw error;
    }
    throw new PortfolioSurveillanceV4StateStoreError("INVALID_ARGUMENT", "Cursor is invalid");
  }
}

function integrity(message: string, cause?: unknown): PortfolioSurveillanceV4StateStoreError {
  return new PortfolioSurveillanceV4StateStoreError(
    "INTEGRITY_FAILURE",
    `${message}${cause instanceof Error ? `: ${cause.message}` : ""}`
  );
}
