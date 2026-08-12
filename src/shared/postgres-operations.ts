import { createHash, randomUUID } from "node:crypto";

import type {
  ArtifactDeletionRequestStorePort,
  ArtifactDeletionRequestV1,
  CreateArtifactDeletionRequest
} from "./deletion-contracts.js";
import type { PgPoolPort, PgQueryablePort } from "./postgres-port.js";
import { withPgTransaction } from "./postgres-port.js";

export class SharedPersistenceError extends Error {
  constructor(
    readonly code:
      | "INVALID_INPUT"
      | "IDEMPOTENCY_CONFLICT"
      | "LEASE_NOT_ACQUIRED"
      | "FENCE_REJECTED"
      | "REPLAY_REJECTED"
      | "NOT_FOUND"
      | "INVALID_TRANSITION",
    message: string
  ) {
    super(message);
    this.name = "SharedPersistenceError";
  }
}

export interface FencedLeaseV1 {
  readonly contractVersion: 1;
  readonly tenantId: string;
  readonly resourceKind: string;
  readonly resourceId: string;
  readonly ownerId: string;
  readonly leaseId: string;
  readonly fenceToken: string;
  readonly acquiredAt: string;
  readonly leaseExpiresAt: string;
}

interface LeaseRow {
  readonly tenant_id: string;
  readonly resource_kind: string;
  readonly resource_id: string;
  readonly owner_id: string;
  readonly lease_id: string;
  readonly fence_token: string | number | bigint;
  readonly acquired_at: string | Date;
  readonly lease_expires_at: string | Date;
}

export class PostgresFencedLeaseRepository {
  readonly #pool: PgPoolPort;
  readonly #clock: () => Date;

  constructor(pool: PgPoolPort, clock: () => Date = () => new Date()) {
    this.#pool = pool;
    this.#clock = clock;
  }

  async acquire(input: {
    readonly tenantId: string;
    readonly resourceKind: string;
    readonly resourceId: string;
    readonly ownerId: string;
    readonly leaseMilliseconds: number;
  }): Promise<FencedLeaseV1 | null> {
    validateIdentifier(input.tenantId, "tenantId");
    validateIdentifier(input.resourceKind, "resourceKind");
    validateIdentifier(input.resourceId, "resourceId");
    validateIdentifier(input.ownerId, "ownerId");
    validateLeaseMilliseconds(input.leaseMilliseconds);
    const now = this.#clock();
    const acquiredAt = iso(now);
    const leaseExpiresAt = iso(new Date(now.getTime() + input.leaseMilliseconds));
    const result = await this.#pool.query<LeaseRow>(
      `/* abl.shared.acquire_lease */
       INSERT INTO abl_shared_leases (
         tenant_id, resource_kind, resource_id, owner_id, lease_id,
         fence_token, acquired_at, lease_expires_at, released_at
       ) VALUES ($1, $2, $3, $4, $5, 1, $6::timestamptz, $7::timestamptz, NULL)
       ON CONFLICT (tenant_id, resource_kind, resource_id) DO UPDATE
         SET owner_id = EXCLUDED.owner_id,
             lease_id = EXCLUDED.lease_id,
             fence_token = abl_shared_leases.fence_token + 1,
             acquired_at = EXCLUDED.acquired_at,
             lease_expires_at = EXCLUDED.lease_expires_at,
             released_at = NULL
       WHERE abl_shared_leases.lease_expires_at <= EXCLUDED.acquired_at
          OR abl_shared_leases.released_at IS NOT NULL
       RETURNING tenant_id, resource_kind, resource_id, owner_id, lease_id,
                 fence_token, acquired_at, lease_expires_at`,
      [
        input.tenantId,
        input.resourceKind,
        input.resourceId,
        input.ownerId,
        randomUUID(),
        acquiredAt,
        leaseExpiresAt
      ]
    );
    const row = result.rows[0];
    return row ? leaseFromRow(row) : null;
  }

  async renew(lease: FencedLeaseV1, leaseMilliseconds: number): Promise<FencedLeaseV1 | null> {
    validateLease(lease);
    validateLeaseMilliseconds(leaseMilliseconds);
    const now = this.#clock();
    const expiresAt = iso(new Date(now.getTime() + leaseMilliseconds));
    const result = await this.#pool.query<LeaseRow>(
      `/* abl.shared.renew_lease */
       UPDATE abl_shared_leases
          SET lease_expires_at = $8::timestamptz
        WHERE tenant_id = $1 AND resource_kind = $2 AND resource_id = $3
          AND owner_id = $4 AND lease_id = $5 AND fence_token = $6::bigint
          AND released_at IS NULL AND lease_expires_at > $7::timestamptz
       RETURNING tenant_id, resource_kind, resource_id, owner_id, lease_id,
                 fence_token, acquired_at, lease_expires_at`,
      [
        lease.tenantId,
        lease.resourceKind,
        lease.resourceId,
        lease.ownerId,
        lease.leaseId,
        lease.fenceToken,
        iso(now),
        expiresAt
      ]
    );
    const row = result.rows[0];
    return row ? leaseFromRow(row) : null;
  }

  async release(lease: FencedLeaseV1): Promise<boolean> {
    validateLease(lease);
    const now = iso(this.#clock());
    const result = await this.#pool.query(
      `/* abl.shared.release_lease */
       UPDATE abl_shared_leases
          SET released_at = $7::timestamptz, lease_expires_at = $7::timestamptz
        WHERE tenant_id = $1 AND resource_kind = $2 AND resource_id = $3
          AND owner_id = $4 AND lease_id = $5 AND fence_token = $6::bigint
          AND released_at IS NULL AND lease_expires_at > $7::timestamptz`,
      [
        lease.tenantId,
        lease.resourceKind,
        lease.resourceId,
        lease.ownerId,
        lease.leaseId,
        lease.fenceToken,
        now
      ]
    );
    return result.rowCount === 1;
  }

  /**
   * Executes the mutation while holding the lease row lock. This is the safe
   * boundary for writes protected by a fence: checking outside the transaction
   * would leave a time-of-check/time-of-use gap.
   */
  async executeFenced<T>(
    lease: FencedLeaseV1,
    mutation: (client: PgQueryablePort, fenceToken: string) => Promise<T>
  ): Promise<T> {
    validateLease(lease);
    const now = iso(this.#clock());
    return withPgTransaction(this.#pool, "serializable", async (client) => {
      const result = await client.query<LeaseRow>(
        `/* abl.shared.assert_lease_fence */
         SELECT tenant_id, resource_kind, resource_id, owner_id, lease_id,
                fence_token, acquired_at, lease_expires_at
           FROM abl_shared_leases
          WHERE tenant_id = $1 AND resource_kind = $2 AND resource_id = $3
            AND owner_id = $4 AND lease_id = $5 AND fence_token = $6::bigint
            AND released_at IS NULL AND lease_expires_at > $7::timestamptz
          FOR UPDATE`,
        [
          lease.tenantId,
          lease.resourceKind,
          lease.resourceId,
          lease.ownerId,
          lease.leaseId,
          lease.fenceToken,
          now
        ]
      );
      if (!result.rows[0]) {
        throw new SharedPersistenceError("FENCE_REJECTED", "The lease fence is stale or expired");
      }
      return mutation(client, lease.fenceToken);
    });
  }
}

export type WorkItemStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";

export interface SharedWorkItemV1 {
  readonly contractVersion: 1;
  readonly tenantId: string;
  readonly workId: string;
  readonly queueName: string;
  readonly idempotencyKey: string;
  readonly requestHash: string;
  readonly request: Readonly<Record<string, unknown>>;
  readonly cost: number;
  readonly priority: number;
  readonly status: WorkItemStatus;
  readonly availableAt: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly workerId: string | null;
  readonly claimId: string | null;
  readonly leaseFenceToken: string;
  readonly leaseExpiresAt: string | null;
  readonly attemptCount: number;
  readonly maxAttempts: number;
  readonly resultRef: string | null;
  readonly errorCode: string | null;
}

export interface ClaimedSharedWorkItemV1 extends SharedWorkItemV1 {
  readonly status: "running";
  readonly workerId: string;
  readonly claimId: string;
  readonly leaseExpiresAt: string;
}

interface WorkRow {
  readonly tenant_id: string;
  readonly work_id: string;
  readonly queue_name: string;
  readonly idempotency_key: string;
  readonly request_hash: string;
  readonly request_json: unknown;
  readonly cost: number;
  readonly priority: number;
  readonly status: WorkItemStatus;
  readonly available_at: string | Date;
  readonly created_at: string | Date;
  readonly updated_at: string | Date;
  readonly worker_id: string | null;
  readonly claim_id: string | null;
  readonly lease_fence_token: string | number | bigint;
  readonly lease_expires_at: string | Date | null;
  readonly attempt_count: number;
  readonly max_attempts: number;
  readonly result_ref: string | null;
  readonly error_code: string | null;
}

interface TenantCandidateRow {
  readonly tenant_id: string;
}

export class PostgresFairWorkRepository {
  readonly #pool: PgPoolPort;
  readonly #clock: () => Date;

  constructor(pool: PgPoolPort, clock: () => Date = () => new Date()) {
    this.#pool = pool;
    this.#clock = clock;
  }

  async enqueue(input: {
    readonly tenantId: string;
    readonly queueName: string;
    readonly idempotencyKey: string;
    readonly request: Readonly<Record<string, unknown>>;
    readonly workId?: string;
    readonly cost?: number;
    readonly priority?: number;
    readonly maxAttempts?: number;
    readonly availableAt?: string;
    readonly tenantWeight?: number;
  }): Promise<SharedWorkItemV1> {
    validateIdentifier(input.tenantId, "tenantId");
    validateIdentifier(input.queueName, "queueName");
    validateIdentifier(input.idempotencyKey, "idempotencyKey");
    if (input.workId !== undefined) validateIdentifier(input.workId, "workId");
    const cost = boundedInteger(input.cost ?? 1, 1, 1_000, "cost");
    const priority = boundedInteger(input.priority ?? 0, -100, 100, "priority");
    const maxAttempts = boundedInteger(input.maxAttempts ?? 3, 1, 20, "maxAttempts");
    const weight = boundedInteger(input.tenantWeight ?? 1, 1, 100, "tenantWeight");
    const requestJson = canonicalJson(input.request);
    const requestHash = sha256(requestJson);
    const now = iso(this.#clock());
    const availableAt = input.availableAt ? normalizeTimestamp(input.availableAt, "availableAt") : now;
    const workId = input.workId ?? randomUUID();

    return withPgTransaction(this.#pool, "read committed", async (client) => {
      await client.query(
        `/* abl.shared.ensure_tenant_schedule */
         INSERT INTO abl_tenant_scheduler (tenant_id, weight, virtual_finish)
         VALUES ($1, $2, COALESCE((SELECT MIN(virtual_finish) FROM abl_tenant_scheduler), 0))
         ON CONFLICT (tenant_id) DO NOTHING`,
        [input.tenantId, weight]
      );
      const inserted = await client.query<WorkRow>(
        `/* abl.shared.enqueue_work */
         INSERT INTO abl_shared_work_items (
           tenant_id, work_id, queue_name, idempotency_key, request_hash,
           request_json, cost, priority, status, available_at, created_at,
           updated_at, max_attempts
         ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, 'queued',
                   $9::timestamptz, $10::timestamptz, $10::timestamptz, $11)
         ON CONFLICT (tenant_id, queue_name, idempotency_key) DO NOTHING
         RETURNING *`,
        [
          input.tenantId,
          workId,
          input.queueName,
          input.idempotencyKey,
          requestHash,
          requestJson,
          cost,
          priority,
          availableAt,
          now,
          maxAttempts
        ]
      );
      const created = inserted.rows[0];
      if (created) return workFromRow(created);
      const existing = await client.query<WorkRow>(
        `/* abl.shared.get_work_by_idempotency */
         SELECT * FROM abl_shared_work_items
          WHERE tenant_id = $1 AND queue_name = $2 AND idempotency_key = $3`,
        [input.tenantId, input.queueName, input.idempotencyKey]
      );
      const row = existing.rows[0];
      if (!row) throw new SharedPersistenceError("NOT_FOUND", "Idempotent work record disappeared");
      if (row.request_hash !== requestHash) {
        throw new SharedPersistenceError(
          "IDEMPOTENCY_CONFLICT",
          "The idempotency key was used with a different request"
        );
      }
      return workFromRow(row);
    });
  }

  async claimNext(input: {
    readonly queueName: string;
    readonly workerId: string;
    readonly leaseMilliseconds: number;
  }): Promise<ClaimedSharedWorkItemV1 | null> {
    validateIdentifier(input.queueName, "queueName");
    validateIdentifier(input.workerId, "workerId");
    validateLeaseMilliseconds(input.leaseMilliseconds);
    const nowDate = this.#clock();
    const now = iso(nowDate);
    const expiresAt = iso(new Date(nowDate.getTime() + input.leaseMilliseconds));

    return withPgTransaction(this.#pool, "read committed", async (client) => {
      const candidates = await client.query<TenantCandidateRow>(
        `/* abl.shared.choose_fair_tenant */
         SELECT scheduler.tenant_id
           FROM abl_tenant_scheduler AS scheduler
          WHERE EXISTS (
            SELECT 1 FROM abl_shared_work_items AS work
             WHERE work.tenant_id = scheduler.tenant_id
               AND work.queue_name = $1
               AND work.attempt_count < work.max_attempts
               AND work.available_at <= $2::timestamptz
               AND (work.status = 'queued'
                    OR (work.status = 'running' AND work.lease_expires_at <= $2::timestamptz))
          )
          ORDER BY scheduler.virtual_finish ASC,
                   scheduler.last_dispatched_at ASC NULLS FIRST,
                   scheduler.tenant_id ASC
          FOR UPDATE SKIP LOCKED
          LIMIT 1`,
        [input.queueName, now]
      );
      const tenantId = candidates.rows[0]?.tenant_id;
      if (!tenantId) return null;
      const claimed = await client.query<WorkRow>(
        `/* abl.shared.claim_fair_work */
         WITH candidate AS (
           SELECT tenant_id, work_id
             FROM abl_shared_work_items
            WHERE tenant_id = $1 AND queue_name = $2
              AND attempt_count < max_attempts
              AND available_at <= $3::timestamptz
              AND (status = 'queued'
                   OR (status = 'running' AND lease_expires_at <= $3::timestamptz))
            ORDER BY priority DESC, created_at ASC, work_id ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
         )
         UPDATE abl_shared_work_items AS work
            SET status = 'running', worker_id = $4, claim_id = $5,
                lease_fence_token = work.lease_fence_token + 1,
                lease_expires_at = $6::timestamptz,
                attempt_count = work.attempt_count + 1,
                updated_at = $3::timestamptz
           FROM candidate
          WHERE work.tenant_id = candidate.tenant_id AND work.work_id = candidate.work_id
         RETURNING work.*`,
        [tenantId, input.queueName, now, input.workerId, randomUUID(), expiresAt]
      );
      const row = claimed.rows[0];
      if (!row) return null;
      await client.query(
        `/* abl.shared.advance_fair_tenant */
         UPDATE abl_tenant_scheduler
            SET virtual_finish = virtual_finish + ($2::numeric / weight),
                last_dispatched_at = $3::timestamptz
          WHERE tenant_id = $1`,
        [tenantId, row.cost, now]
      );
      return claimedWorkFromRow(row);
    });
  }

  async renewClaim(claim: ClaimedSharedWorkItemV1, leaseMilliseconds: number): Promise<ClaimedSharedWorkItemV1 | null> {
    validateWorkClaim(claim);
    validateLeaseMilliseconds(leaseMilliseconds);
    const nowDate = this.#clock();
    const now = iso(nowDate);
    const expiresAt = iso(new Date(nowDate.getTime() + leaseMilliseconds));
    const result = await this.#pool.query<WorkRow>(
      `/* abl.shared.renew_work_claim */
       UPDATE abl_shared_work_items
          SET lease_expires_at = $7::timestamptz, updated_at = $6::timestamptz
        WHERE tenant_id = $1 AND work_id = $2 AND status = 'running'
          AND worker_id = $3 AND claim_id = $4 AND lease_fence_token = $5::bigint
          AND lease_expires_at > $6::timestamptz
       RETURNING *`,
      [
        claim.tenantId,
        claim.workId,
        claim.workerId,
        claim.claimId,
        claim.leaseFenceToken,
        now,
        expiresAt
      ]
    );
    const row = result.rows[0];
    return row ? claimedWorkFromRow(row) : null;
  }

  async completeClaim(claim: ClaimedSharedWorkItemV1, resultRef: string): Promise<SharedWorkItemV1> {
    validateWorkClaim(claim);
    validateIdentifier(resultRef, "resultRef");
    const now = iso(this.#clock());
    const result = await this.#pool.query<WorkRow>(
      `/* abl.shared.complete_work_claim */
       UPDATE abl_shared_work_items
          SET status = 'succeeded', result_ref = $7, worker_id = NULL,
              claim_id = NULL, lease_expires_at = NULL, updated_at = $6::timestamptz
        WHERE tenant_id = $1 AND work_id = $2 AND status = 'running'
          AND worker_id = $3 AND claim_id = $4 AND lease_fence_token = $5::bigint
          AND lease_expires_at > $6::timestamptz
       RETURNING *`,
      [
        claim.tenantId,
        claim.workId,
        claim.workerId,
        claim.claimId,
        claim.leaseFenceToken,
        now,
        resultRef
      ]
    );
    const row = result.rows[0];
    if (!row) throw new SharedPersistenceError("FENCE_REJECTED", "The work claim is stale or expired");
    return workFromRow(row);
  }
}

export type SharedOutboxStatus = "pending" | "claimed" | "delivered" | "dead_letter";

export interface SharedOutboxEventV1 {
  readonly contractVersion: 1;
  readonly tenantId: string;
  readonly eventId: string;
  readonly aggregateKind: string;
  readonly aggregateId: string;
  readonly topic: string;
  readonly payloadHash: string;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly status: SharedOutboxStatus;
  readonly availableAt: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly claimedBy: string | null;
  readonly claimId: string | null;
  readonly leaseFenceToken: string;
  readonly leaseExpiresAt: string | null;
  readonly attemptCount: number;
  readonly maxAttempts: number;
  readonly deliveredAt: string | null;
  readonly receiptHash: string | null;
  readonly errorCode: string | null;
}

export interface ClaimedSharedOutboxEventV1 extends SharedOutboxEventV1 {
  readonly status: "claimed";
  readonly claimedBy: string;
  readonly claimId: string;
  readonly leaseExpiresAt: string;
}

interface OutboxRow {
  readonly tenant_id: string;
  readonly event_id: string;
  readonly aggregate_kind: string;
  readonly aggregate_id: string;
  readonly topic: string;
  readonly payload_hash: string;
  readonly payload_json: unknown;
  readonly status: SharedOutboxStatus;
  readonly available_at: string | Date;
  readonly created_at: string | Date;
  readonly updated_at: string | Date;
  readonly claimed_by: string | null;
  readonly claim_id: string | null;
  readonly lease_fence_token: string | number | bigint;
  readonly lease_expires_at: string | Date | null;
  readonly attempt_count: number;
  readonly max_attempts: number;
  readonly delivered_at: string | Date | null;
  readonly receipt_hash: string | null;
  readonly error_code: string | null;
}

export class PostgresTransactionalOutboxRepository {
  readonly #pool: PgPoolPort;
  readonly #clock: () => Date;

  constructor(pool: PgPoolPort, clock: () => Date = () => new Date()) {
    this.#pool = pool;
    this.#clock = clock;
  }

  /** Pass a transaction client to make domain-state and outbox writes atomic. */
  async enqueue(
    queryable: PgQueryablePort,
    input: {
      readonly tenantId: string;
      readonly eventId: string;
      readonly aggregateKind: string;
      readonly aggregateId: string;
      readonly topic: string;
      readonly payload: Readonly<Record<string, unknown>>;
      readonly availableAt?: string;
      readonly maxAttempts?: number;
    }
  ): Promise<SharedOutboxEventV1> {
    for (const [value, name] of [
      [input.tenantId, "tenantId"],
      [input.eventId, "eventId"],
      [input.aggregateKind, "aggregateKind"],
      [input.aggregateId, "aggregateId"],
      [input.topic, "topic"]
    ] as const) validateIdentifier(value, name);
    const maxAttempts = boundedInteger(input.maxAttempts ?? 8, 1, 20, "maxAttempts");
    const payloadJson = canonicalJson(input.payload);
    const payloadHash = sha256(payloadJson);
    const now = iso(this.#clock());
    const availableAt = input.availableAt ? normalizeTimestamp(input.availableAt, "availableAt") : now;
    const inserted = await queryable.query<OutboxRow>(
      `/* abl.shared.enqueue_outbox */
       INSERT INTO abl_transactional_outbox (
         tenant_id, event_id, aggregate_kind, aggregate_id, topic,
         payload_hash, payload_json, status, available_at, created_at,
         updated_at, max_attempts
       ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, 'pending',
                 $8::timestamptz, $9::timestamptz, $9::timestamptz, $10)
       ON CONFLICT (tenant_id, event_id) DO NOTHING
       RETURNING *`,
      [
        input.tenantId,
        input.eventId,
        input.aggregateKind,
        input.aggregateId,
        input.topic,
        payloadHash,
        payloadJson,
        availableAt,
        now,
        maxAttempts
      ]
    );
    const created = inserted.rows[0];
    if (created) return outboxFromRow(created);
    const existing = await queryable.query<OutboxRow>(
      `/* abl.shared.get_outbox_event */
       SELECT * FROM abl_transactional_outbox WHERE tenant_id = $1 AND event_id = $2`,
      [input.tenantId, input.eventId]
    );
    const row = existing.rows[0];
    if (!row) throw new SharedPersistenceError("NOT_FOUND", "Idempotent outbox event disappeared");
    if (row.payload_hash !== payloadHash || row.topic !== input.topic) {
      throw new SharedPersistenceError(
        "IDEMPOTENCY_CONFLICT",
        "The event id was used with different outbox content"
      );
    }
    return outboxFromRow(row);
  }

  async enqueueAtomically(
    input: Parameters<PostgresTransactionalOutboxRepository["enqueue"]>[1],
    mutate: (client: PgQueryablePort) => Promise<void>
  ): Promise<SharedOutboxEventV1> {
    return withPgTransaction(this.#pool, "read committed", async (client) => {
      await mutate(client);
      return this.enqueue(client, input);
    });
  }

  async claimNext(input: {
    readonly tenantId: string;
    readonly topic: string;
    readonly dispatcherId: string;
    readonly leaseMilliseconds: number;
  }): Promise<ClaimedSharedOutboxEventV1 | null> {
    validateIdentifier(input.tenantId, "tenantId");
    validateIdentifier(input.topic, "topic");
    validateIdentifier(input.dispatcherId, "dispatcherId");
    validateLeaseMilliseconds(input.leaseMilliseconds);
    const nowDate = this.#clock();
    const now = iso(nowDate);
    const expiresAt = iso(new Date(nowDate.getTime() + input.leaseMilliseconds));
    const result = await this.#pool.query<OutboxRow>(
      `/* abl.shared.claim_outbox */
       WITH candidate AS (
         SELECT tenant_id, event_id
           FROM abl_transactional_outbox
          WHERE tenant_id = $1 AND topic = $2
            AND attempt_count < max_attempts
            AND available_at <= $3::timestamptz
            AND (status = 'pending'
                 OR (status = 'claimed' AND lease_expires_at <= $3::timestamptz))
          ORDER BY created_at ASC, event_id ASC
          FOR UPDATE SKIP LOCKED
          LIMIT 1
       )
       UPDATE abl_transactional_outbox AS event
          SET status = 'claimed', claimed_by = $4, claim_id = $5,
              lease_fence_token = event.lease_fence_token + 1,
              lease_expires_at = $6::timestamptz,
              attempt_count = event.attempt_count + 1,
              updated_at = $3::timestamptz
         FROM candidate
        WHERE event.tenant_id = candidate.tenant_id AND event.event_id = candidate.event_id
       RETURNING event.*`,
      [input.tenantId, input.topic, now, input.dispatcherId, randomUUID(), expiresAt]
    );
    const row = result.rows[0];
    return row ? claimedOutboxFromRow(row) : null;
  }

  async acknowledge(claim: ClaimedSharedOutboxEventV1, receiptHash: string): Promise<SharedOutboxEventV1> {
    validateOutboxClaim(claim);
    validateSha256(receiptHash, "receiptHash");
    const now = iso(this.#clock());
    const result = await this.#pool.query<OutboxRow>(
      `/* abl.shared.ack_outbox */
       UPDATE abl_transactional_outbox
          SET status = 'delivered', delivered_at = $7::timestamptz,
              receipt_hash = $8, claimed_by = NULL, claim_id = NULL,
              lease_expires_at = NULL, updated_at = $7::timestamptz
        WHERE tenant_id = $1 AND event_id = $2 AND status = 'claimed'
          AND claimed_by = $3 AND claim_id = $4 AND lease_fence_token = $5::bigint
          AND lease_expires_at > $6::timestamptz
       RETURNING *`,
      [
        claim.tenantId,
        claim.eventId,
        claim.claimedBy,
        claim.claimId,
        claim.leaseFenceToken,
        now,
        now,
        receiptHash
      ]
    );
    const row = result.rows[0];
    if (!row) throw new SharedPersistenceError("FENCE_REJECTED", "The outbox claim is stale or expired");
    return outboxFromRow(row);
  }

  async fail(
    claim: ClaimedSharedOutboxEventV1,
    errorCode: string,
    retryAt?: string
  ): Promise<SharedOutboxEventV1> {
    validateOutboxClaim(claim);
    validateIdentifier(errorCode, "errorCode");
    const now = iso(this.#clock());
    const availableAt = retryAt ? normalizeTimestamp(retryAt, "retryAt") : now;
    const result = await this.#pool.query<OutboxRow>(
      `/* abl.shared.fail_outbox */
       UPDATE abl_transactional_outbox
          SET status = CASE WHEN attempt_count >= max_attempts THEN 'dead_letter' ELSE 'pending' END,
              available_at = $8::timestamptz, error_code = $7,
              claimed_by = NULL, claim_id = NULL, lease_expires_at = NULL,
              updated_at = $6::timestamptz
        WHERE tenant_id = $1 AND event_id = $2 AND status = 'claimed'
          AND claimed_by = $3 AND claim_id = $4 AND lease_fence_token = $5::bigint
          AND lease_expires_at > $6::timestamptz
       RETURNING *`,
      [
        claim.tenantId,
        claim.eventId,
        claim.claimedBy,
        claim.claimId,
        claim.leaseFenceToken,
        now,
        errorCode,
        availableAt
      ]
    );
    const row = result.rows[0];
    if (!row) throw new SharedPersistenceError("FENCE_REJECTED", "The outbox claim is stale or expired");
    return outboxFromRow(row);
  }
}

export interface ReplayReservationV1 {
  readonly contractVersion: 1;
  readonly tenantId: string;
  readonly principalBindingHash: string;
  readonly nonceHash: string;
  readonly reservationId: string;
  readonly generation: string;
  readonly expiresAt: string;
}

interface ReplayRow {
  readonly tenant_id: string;
  readonly principal_binding_hash: string;
  readonly nonce_hash: string;
  readonly reservation_id: string;
  readonly generation: string | number | bigint;
  readonly expires_at: string | Date;
}

export class PostgresReplayProtectionRepository {
  readonly #pool: PgPoolPort;
  readonly #clock: () => Date;

  constructor(pool: PgPoolPort, clock: () => Date = () => new Date()) {
    this.#pool = pool;
    this.#clock = clock;
  }

  async reserve(input: {
    readonly tenantId: string;
    readonly principalBindingHash: string;
    readonly nonceHash: string;
    readonly ttlMilliseconds: number;
  }): Promise<ReplayReservationV1 | null> {
    validateIdentifier(input.tenantId, "tenantId");
    validateSha256(input.principalBindingHash, "principalBindingHash");
    validateSha256(input.nonceHash, "nonceHash");
    validateLeaseMilliseconds(input.ttlMilliseconds);
    const nowDate = this.#clock();
    const now = iso(nowDate);
    const expiresAt = iso(new Date(nowDate.getTime() + input.ttlMilliseconds));
    const result = await this.#pool.query<ReplayRow>(
      `/* abl.shared.reserve_replay */
       INSERT INTO abl_replay_reservations (
         tenant_id, principal_binding_hash, nonce_hash, reservation_id,
         generation, state, reserved_at, expires_at, consumed_at
       ) VALUES ($1, $2, $3, $4, 1, 'reserved', $5::timestamptz, $6::timestamptz, NULL)
       ON CONFLICT (tenant_id, principal_binding_hash, nonce_hash) DO UPDATE
         SET reservation_id = EXCLUDED.reservation_id,
             generation = abl_replay_reservations.generation + 1,
             state = 'reserved', reserved_at = EXCLUDED.reserved_at,
             expires_at = EXCLUDED.expires_at, consumed_at = NULL
       WHERE abl_replay_reservations.expires_at <= EXCLUDED.reserved_at
       RETURNING tenant_id, principal_binding_hash, nonce_hash, reservation_id,
                 generation, expires_at`,
      [
        input.tenantId,
        input.principalBindingHash,
        input.nonceHash,
        randomUUID(),
        now,
        expiresAt
      ]
    );
    const row = result.rows[0];
    return row ? replayFromRow(row) : null;
  }

  async consume(reservation: ReplayReservationV1): Promise<boolean> {
    validateReplayReservation(reservation);
    const now = iso(this.#clock());
    const result = await this.#pool.query(
      `/* abl.shared.consume_replay */
       UPDATE abl_replay_reservations
          SET state = 'consumed', consumed_at = $7::timestamptz
        WHERE tenant_id = $1 AND principal_binding_hash = $2 AND nonce_hash = $3
          AND reservation_id = $4 AND generation = $5::bigint
          AND state = 'reserved' AND expires_at > $6::timestamptz`,
      [
        reservation.tenantId,
        reservation.principalBindingHash,
        reservation.nonceHash,
        reservation.reservationId,
        reservation.generation,
        now,
        now
      ]
    );
    return result.rowCount === 1;
  }
}

interface DeletionRow {
  readonly tenant_id: string;
  readonly request_id: string;
  readonly artifact_id: string;
  readonly object_key: string;
  readonly object_version_id: string;
  readonly requested_by: string;
  readonly reason_hash: string;
  readonly execute_after: string | Date;
  readonly status: ArtifactDeletionRequestV1["status"];
  readonly approved_by: string | null;
  readonly approved_at: string | Date | null;
  readonly execution_id: string | null;
  readonly completed_at: string | Date | null;
  readonly error_code: string | null;
  readonly created_at: string | Date;
  readonly updated_at: string | Date;
}

export class PostgresArtifactDeletionRequestRepository implements ArtifactDeletionRequestStorePort {
  readonly #pool: PgPoolPort;
  readonly #clock: () => Date;

  constructor(pool: PgPoolPort, clock: () => Date = () => new Date()) {
    this.#pool = pool;
    this.#clock = clock;
  }

  async create(input: CreateArtifactDeletionRequest): Promise<ArtifactDeletionRequestV1> {
    validateDeletionInput(input);
    const now = iso(this.#clock());
    const result = await this.#pool.query<DeletionRow>(
      `/* abl.shared.create_artifact_deletion */
       INSERT INTO abl_artifact_deletion_requests (
         tenant_id, request_id, artifact_id, object_key, object_version_id,
         requested_by, reason_hash, execute_after, status, created_at, updated_at
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz,
                 'pending', $9::timestamptz, $9::timestamptz)
       RETURNING *`,
      [
        input.tenantId,
        randomUUID(),
        input.artifactId,
        input.objectKey,
        input.objectVersionId,
        input.requestedBy,
        sha256(input.reason),
        normalizeTimestamp(input.executeAfter, "executeAfter"),
        now
      ]
    );
    const row = result.rows[0];
    if (!row) throw new SharedPersistenceError("NOT_FOUND", "Deletion request was not persisted");
    return deletionFromRow(row);
  }

  async get(tenantId: string, requestId: string): Promise<ArtifactDeletionRequestV1 | undefined> {
    validateIdentifier(tenantId, "tenantId");
    validateIdentifier(requestId, "requestId");
    const result = await this.#pool.query<DeletionRow>(
      `/* abl.shared.get_artifact_deletion */
       SELECT * FROM abl_artifact_deletion_requests
        WHERE tenant_id = $1 AND request_id = $2`,
      [tenantId, requestId]
    );
    const row = result.rows[0];
    return row ? deletionFromRow(row) : undefined;
  }

  async approve(
    tenantId: string,
    requestId: string,
    approvedBy: string,
    approvedAt: string
  ): Promise<ArtifactDeletionRequestV1 | undefined> {
    validateIdentifier(approvedBy, "approvedBy");
    const result = await this.#pool.query<DeletionRow>(
      `/* abl.shared.approve_artifact_deletion */
       UPDATE abl_artifact_deletion_requests
          SET status = 'approved', approved_by = $3,
              approved_at = $4::timestamptz, updated_at = $4::timestamptz
        WHERE tenant_id = $1 AND request_id = $2 AND status = 'pending'
          AND requested_by <> $3
       RETURNING *`,
      [tenantId, requestId, approvedBy, normalizeTimestamp(approvedAt, "approvedAt")]
    );
    const row = result.rows[0];
    return row ? deletionFromRow(row) : undefined;
  }

  async markExecuting(
    tenantId: string,
    requestId: string,
    executionId: string,
    now: string
  ): Promise<ArtifactDeletionRequestV1 | undefined> {
    validateIdentifier(executionId, "executionId");
    const result = await this.#pool.query<DeletionRow>(
      `/* abl.shared.execute_artifact_deletion */
       UPDATE abl_artifact_deletion_requests
          SET status = 'executing', execution_id = $3, updated_at = $4::timestamptz
        WHERE tenant_id = $1 AND request_id = $2 AND status = 'approved'
          AND execute_after <= $4::timestamptz
       RETURNING *`,
      [tenantId, requestId, executionId, normalizeTimestamp(now, "now")]
    );
    const row = result.rows[0];
    return row ? deletionFromRow(row) : undefined;
  }

  async markCompleted(
    tenantId: string,
    requestId: string,
    executionId: string,
    now: string
  ): Promise<ArtifactDeletionRequestV1 | undefined> {
    return this.#finish(tenantId, requestId, executionId, now, "completed", null);
  }

  async markFailed(
    tenantId: string,
    requestId: string,
    executionId: string,
    errorCode: string,
    now: string
  ): Promise<ArtifactDeletionRequestV1 | undefined> {
    validateIdentifier(errorCode, "errorCode");
    return this.#finish(tenantId, requestId, executionId, now, "failed", errorCode);
  }

  async #finish(
    tenantId: string,
    requestId: string,
    executionId: string,
    now: string,
    status: "completed" | "failed",
    errorCode: string | null
  ): Promise<ArtifactDeletionRequestV1 | undefined> {
    const result = await this.#pool.query<DeletionRow>(
      `/* abl.shared.finish_artifact_deletion */
       UPDATE abl_artifact_deletion_requests
          SET status = $5,
              completed_at = CASE WHEN $5 = 'completed' THEN $4::timestamptz ELSE NULL END,
              error_code = $6, updated_at = $4::timestamptz
        WHERE tenant_id = $1 AND request_id = $2 AND status = 'executing'
          AND execution_id = $3
       RETURNING *`,
      [tenantId, requestId, executionId, normalizeTimestamp(now, "now"), status, errorCode]
    );
    const row = result.rows[0];
    return row ? deletionFromRow(row) : undefined;
  }
}

function leaseFromRow(row: LeaseRow): FencedLeaseV1 {
  return Object.freeze({
    contractVersion: 1,
    tenantId: row.tenant_id,
    resourceKind: row.resource_kind,
    resourceId: row.resource_id,
    ownerId: row.owner_id,
    leaseId: row.lease_id,
    fenceToken: String(row.fence_token),
    acquiredAt: iso(row.acquired_at),
    leaseExpiresAt: iso(row.lease_expires_at)
  });
}

function workFromRow(row: WorkRow): SharedWorkItemV1 {
  return Object.freeze({
    contractVersion: 1,
    tenantId: row.tenant_id,
    workId: row.work_id,
    queueName: row.queue_name,
    idempotencyKey: row.idempotency_key,
    requestHash: row.request_hash,
    request: parseObject(row.request_json, "work request"),
    cost: Number(row.cost),
    priority: Number(row.priority),
    status: row.status,
    availableAt: iso(row.available_at),
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
    workerId: row.worker_id,
    claimId: row.claim_id,
    leaseFenceToken: String(row.lease_fence_token),
    leaseExpiresAt: row.lease_expires_at === null ? null : iso(row.lease_expires_at),
    attemptCount: Number(row.attempt_count),
    maxAttempts: Number(row.max_attempts),
    resultRef: row.result_ref,
    errorCode: row.error_code
  });
}

function claimedWorkFromRow(row: WorkRow): ClaimedSharedWorkItemV1 {
  const work = workFromRow(row);
  if (work.status !== "running" || !work.workerId || !work.claimId || !work.leaseExpiresAt) {
    throw new SharedPersistenceError("INVALID_TRANSITION", "Claim query returned a non-running work item");
  }
  return Object.freeze({
    ...work,
    status: "running",
    workerId: work.workerId,
    claimId: work.claimId,
    leaseExpiresAt: work.leaseExpiresAt
  });
}

function outboxFromRow(row: OutboxRow): SharedOutboxEventV1 {
  return Object.freeze({
    contractVersion: 1,
    tenantId: row.tenant_id,
    eventId: row.event_id,
    aggregateKind: row.aggregate_kind,
    aggregateId: row.aggregate_id,
    topic: row.topic,
    payloadHash: row.payload_hash,
    payload: parseObject(row.payload_json, "outbox payload"),
    status: row.status,
    availableAt: iso(row.available_at),
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
    claimedBy: row.claimed_by,
    claimId: row.claim_id,
    leaseFenceToken: String(row.lease_fence_token),
    leaseExpiresAt: row.lease_expires_at === null ? null : iso(row.lease_expires_at),
    attemptCount: Number(row.attempt_count),
    maxAttempts: Number(row.max_attempts),
    deliveredAt: row.delivered_at === null ? null : iso(row.delivered_at),
    receiptHash: row.receipt_hash,
    errorCode: row.error_code
  });
}

function claimedOutboxFromRow(row: OutboxRow): ClaimedSharedOutboxEventV1 {
  const event = outboxFromRow(row);
  if (event.status !== "claimed" || !event.claimedBy || !event.claimId || !event.leaseExpiresAt) {
    throw new SharedPersistenceError("INVALID_TRANSITION", "Claim query returned a non-claimed outbox event");
  }
  return Object.freeze({
    ...event,
    status: "claimed",
    claimedBy: event.claimedBy,
    claimId: event.claimId,
    leaseExpiresAt: event.leaseExpiresAt
  });
}

function replayFromRow(row: ReplayRow): ReplayReservationV1 {
  return Object.freeze({
    contractVersion: 1,
    tenantId: row.tenant_id,
    principalBindingHash: row.principal_binding_hash,
    nonceHash: row.nonce_hash,
    reservationId: row.reservation_id,
    generation: String(row.generation),
    expiresAt: iso(row.expires_at)
  });
}

function deletionFromRow(row: DeletionRow): ArtifactDeletionRequestV1 {
  return Object.freeze({
    contractVersion: 1,
    tenantId: row.tenant_id,
    requestId: row.request_id,
    artifactId: row.artifact_id,
    objectKey: row.object_key,
    objectVersionId: row.object_version_id,
    requestedBy: row.requested_by,
    reasonHash: row.reason_hash,
    executeAfter: iso(row.execute_after),
    status: row.status,
    approvedBy: row.approved_by,
    approvedAt: row.approved_at === null ? null : iso(row.approved_at),
    executionId: row.execution_id,
    completedAt: row.completed_at === null ? null : iso(row.completed_at),
    errorCode: row.error_code,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at)
  });
}

function validateLease(lease: FencedLeaseV1): void {
  if (lease.contractVersion !== 1) invalid("Unsupported lease contract version");
  validateIdentifier(lease.tenantId, "tenantId");
  validateIdentifier(lease.resourceKind, "resourceKind");
  validateIdentifier(lease.resourceId, "resourceId");
  validateIdentifier(lease.ownerId, "ownerId");
  validateIdentifier(lease.leaseId, "leaseId");
  validatePositiveBigint(lease.fenceToken, "fenceToken");
}

function validateWorkClaim(claim: ClaimedSharedWorkItemV1): void {
  if (claim.contractVersion !== 1 || claim.status !== "running") invalid("Invalid work claim");
  for (const [value, name] of [
    [claim.tenantId, "tenantId"],
    [claim.workId, "workId"],
    [claim.workerId, "workerId"],
    [claim.claimId, "claimId"]
  ] as const) validateIdentifier(value, name);
  validatePositiveBigint(claim.leaseFenceToken, "leaseFenceToken");
}

function validateOutboxClaim(claim: ClaimedSharedOutboxEventV1): void {
  if (claim.contractVersion !== 1 || claim.status !== "claimed") invalid("Invalid outbox claim");
  for (const [value, name] of [
    [claim.tenantId, "tenantId"],
    [claim.eventId, "eventId"],
    [claim.claimedBy, "claimedBy"],
    [claim.claimId, "claimId"]
  ] as const) validateIdentifier(value, name);
  validatePositiveBigint(claim.leaseFenceToken, "leaseFenceToken");
}

function validateReplayReservation(reservation: ReplayReservationV1): void {
  if (reservation.contractVersion !== 1) invalid("Unsupported replay-reservation contract version");
  validateIdentifier(reservation.tenantId, "tenantId");
  validateSha256(reservation.principalBindingHash, "principalBindingHash");
  validateSha256(reservation.nonceHash, "nonceHash");
  validateIdentifier(reservation.reservationId, "reservationId");
  validatePositiveBigint(reservation.generation, "generation");
}

function validateDeletionInput(input: CreateArtifactDeletionRequest): void {
  for (const [value, name] of [
    [input.tenantId, "tenantId"],
    [input.artifactId, "artifactId"],
    [input.objectKey, "objectKey"],
    [input.objectVersionId, "objectVersionId"],
    [input.requestedBy, "requestedBy"]
  ] as const) validateIdentifier(value, name, name === "objectKey" ? 1_024 : 256);
  if (!input.reason.trim() || input.reason.length > 2_000) invalid("reason must contain 1 through 2000 characters");
  normalizeTimestamp(input.executeAfter, "executeAfter");
}

function validateLeaseMilliseconds(value: number): void {
  boundedInteger(value, 1_000, 3_600_000, "leaseMilliseconds");
}

function validatePositiveBigint(value: string, name: string): void {
  if (!/^[1-9][0-9]*$/.test(value)) invalid(`${name} must be a positive integer string`);
}

function validateIdentifier(value: string, name: string, maximumLength = 256): void {
  if (!value.trim() || value.length > maximumLength || /[\u0000-\u001f\u007f]/u.test(value)) {
    invalid(`${name} must contain 1 through ${maximumLength} printable characters`);
  }
}

function validateSha256(value: string, name: string): void {
  if (!/^[a-f0-9]{64}$/.test(value)) invalid(`${name} must be a lowercase SHA-256 digest`);
}

function boundedInteger(value: number, minimum: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalid(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function parseObject(value: unknown, name: string): Readonly<Record<string, unknown>> {
  const parsed = typeof value === "string" ? JSON.parse(value) as unknown : value;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new SharedPersistenceError("INVALID_TRANSITION", `${name} is not a JSON object`);
  }
  return Object.freeze({ ...(parsed as Record<string, unknown>) });
}

function canonicalJson(value: unknown): string {
  const seen = new Set<object>();
  function normalize(candidate: unknown): unknown {
    if (candidate === null || typeof candidate === "string" || typeof candidate === "boolean") return candidate;
    if (typeof candidate === "number") {
      if (!Number.isFinite(candidate)) invalid("JSON numbers must be finite");
      return candidate;
    }
    if (Array.isArray(candidate)) return candidate.map(normalize);
    if (typeof candidate === "object") {
      if (seen.has(candidate)) invalid("JSON input must not contain cycles");
      seen.add(candidate);
      const record = candidate as Record<string, unknown>;
      const result: Record<string, unknown> = {};
      for (const key of Object.keys(record).sort()) {
        const item = record[key];
        if (item === undefined) invalid("JSON input must not contain undefined values");
        result[key] = normalize(item);
      }
      seen.delete(candidate);
      return result;
    }
    invalid("Input is not canonical JSON");
  }
  return JSON.stringify(normalize(value));
}

function normalizeTimestamp(value: string, name: string): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) invalid(`${name} must be an ISO timestamp`);
  return date.toISOString();
}

function iso(value: string | Date): string {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) {
    throw new SharedPersistenceError("INVALID_TRANSITION", "PostgreSQL returned an invalid timestamp");
  }
  return date.toISOString();
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function invalid(message: string): never {
  throw new SharedPersistenceError("INVALID_INPUT", message);
}
