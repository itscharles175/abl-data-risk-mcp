import assert from "node:assert/strict";
import { test } from "node:test";

import {
  PostgresFairWorkRepository,
  PostgresFencedLeaseRepository,
  PostgresReplayProtectionRepository,
  PostgresTransactionalOutboxRepository,
  SharedPersistenceError
} from "../src/shared/postgres-operations.js";
import { SHARED_POSTGRES_MIGRATION_V1 } from "../src/shared/postgres-migrations.js";
import type {
  PgClientPort,
  PgPoolPort,
  PgQueryResult
} from "../src/shared/postgres-port.js";

interface MutableLeaseRow {
  tenant_id: string;
  resource_kind: string;
  resource_id: string;
  owner_id: string;
  lease_id: string;
  fence_token: number;
  acquired_at: string;
  lease_expires_at: string;
  released_at: string | null;
}

interface MutableWorkRow {
  tenant_id: string;
  work_id: string;
  queue_name: string;
  idempotency_key: string;
  request_hash: string;
  request_json: string;
  cost: number;
  priority: number;
  status: "queued" | "running" | "succeeded" | "failed" | "cancelled";
  available_at: string;
  created_at: string;
  updated_at: string;
  worker_id: string | null;
  claim_id: string | null;
  lease_fence_token: number;
  lease_expires_at: string | null;
  attempt_count: number;
  max_attempts: number;
  result_ref: string | null;
  error_code: string | null;
}

interface MutableOutboxRow {
  tenant_id: string;
  event_id: string;
  aggregate_kind: string;
  aggregate_id: string;
  topic: string;
  payload_hash: string;
  payload_json: string;
  status: "pending" | "claimed" | "delivered" | "dead_letter";
  available_at: string;
  created_at: string;
  updated_at: string;
  claimed_by: string | null;
  claim_id: string | null;
  lease_fence_token: number;
  lease_expires_at: string | null;
  attempt_count: number;
  max_attempts: number;
  delivered_at: string | null;
  receipt_hash: string | null;
  error_code: string | null;
}

interface MutableReplayRow {
  tenant_id: string;
  principal_binding_hash: string;
  nonce_hash: string;
  reservation_id: string;
  generation: number;
  state: "reserved" | "consumed";
  reserved_at: string;
  expires_at: string;
  consumed_at: string | null;
}

class ConformancePgPool implements PgPoolPort, PgClientPort {
  readonly statements: { readonly text: string; readonly values: readonly unknown[] }[] = [];
  readonly leases = new Map<string, MutableLeaseRow>();
  readonly scheduler = new Map<string, { weight: number; virtualFinish: number; lastDispatchedAt: string | null }>();
  readonly work = new Map<string, MutableWorkRow>();
  readonly outbox = new Map<string, MutableOutboxRow>();
  readonly replay = new Map<string, MutableReplayRow>();

  async connect(): Promise<PgClientPort> {
    return this;
  }

  release(): void {}

  async query<Row extends object = Record<string, unknown>>(
    text: string,
    values: readonly unknown[] = []
  ): Promise<PgQueryResult<Row>> {
    this.statements.push({ text, values: [...values] });
    const rows = this.#route(text, values);
    return { rows: rows as readonly Row[], rowCount: rows.length };
  }

  #route(text: string, values: readonly unknown[]): readonly object[] {
    if (/^(BEGIN|COMMIT|ROLLBACK)/.test(text)) return [];
    if (text.includes("abl.shared.acquire_lease")) {
      const [tenant, kind, resource, owner, leaseId, acquiredAt, expiresAt] = strings(values);
      const key = joinKey(tenant!, kind!, resource!);
      const current = this.leases.get(key);
      if (current && current.released_at === null && current.lease_expires_at > acquiredAt!) return [];
      const row: MutableLeaseRow = {
        tenant_id: tenant!, resource_kind: kind!, resource_id: resource!, owner_id: owner!,
        lease_id: leaseId!, fence_token: (current?.fence_token ?? 0) + 1,
        acquired_at: acquiredAt!, lease_expires_at: expiresAt!, released_at: null
      };
      this.leases.set(key, row);
      return [row];
    }
    if (text.includes("abl.shared.renew_lease")) {
      const [tenant, kind, resource, owner, leaseId, fence, now, expiresAt] = strings(values);
      const row = this.leases.get(joinKey(tenant!, kind!, resource!));
      if (!leaseMatches(row, owner!, leaseId!, fence!, now!)) return [];
      row!.lease_expires_at = expiresAt!;
      return [row!];
    }
    if (text.includes("abl.shared.release_lease")) {
      const [tenant, kind, resource, owner, leaseId, fence, now] = strings(values);
      const row = this.leases.get(joinKey(tenant!, kind!, resource!));
      if (!leaseMatches(row, owner!, leaseId!, fence!, now!)) return [];
      row!.released_at = now!;
      row!.lease_expires_at = now!;
      return [row!];
    }
    if (text.includes("abl.shared.assert_lease_fence")) {
      const [tenant, kind, resource, owner, leaseId, fence, now] = strings(values);
      const row = this.leases.get(joinKey(tenant!, kind!, resource!));
      return leaseMatches(row, owner!, leaseId!, fence!, now!) ? [row!] : [];
    }
    if (text.includes("abl.shared.ensure_tenant_schedule")) {
      const tenant = String(values[0]);
      if (!this.scheduler.has(tenant)) {
        const minimum = Math.min(0, ...[...this.scheduler.values()].map((entry) => entry.virtualFinish));
        this.scheduler.set(tenant, { weight: Number(values[1]), virtualFinish: minimum, lastDispatchedAt: null });
      }
      return [];
    }
    if (text.includes("abl.shared.enqueue_work")) {
      const tenant = String(values[0]);
      const queue = String(values[2]);
      const idempotency = String(values[3]);
      const duplicate = [...this.work.values()].find(
        (row) => row.tenant_id === tenant && row.queue_name === queue && row.idempotency_key === idempotency
      );
      if (duplicate) return [];
      const row: MutableWorkRow = {
        tenant_id: tenant,
        work_id: String(values[1]),
        queue_name: queue,
        idempotency_key: idempotency,
        request_hash: String(values[4]),
        request_json: String(values[5]),
        cost: Number(values[6]),
        priority: Number(values[7]),
        status: "queued",
        available_at: String(values[8]),
        created_at: String(values[9]),
        updated_at: String(values[9]),
        worker_id: null,
        claim_id: null,
        lease_fence_token: 0,
        lease_expires_at: null,
        attempt_count: 0,
        max_attempts: Number(values[10]),
        result_ref: null,
        error_code: null
      };
      this.work.set(joinKey(tenant, row.work_id), row);
      return [row];
    }
    if (text.includes("abl.shared.get_work_by_idempotency")) {
      return [...this.work.values()].filter(
        (row) => row.tenant_id === values[0] && row.queue_name === values[1] && row.idempotency_key === values[2]
      );
    }
    if (text.includes("abl.shared.choose_fair_tenant")) {
      const queue = String(values[0]);
      const now = String(values[1]);
      const candidates = [...this.scheduler.entries()].filter(([tenant]) =>
        [...this.work.values()].some((row) =>
          row.tenant_id === tenant && row.queue_name === queue && row.attempt_count < row.max_attempts &&
          row.available_at <= now && (row.status === "queued" || (row.status === "running" && row.lease_expires_at! <= now))
        )
      );
      candidates.sort(([tenantA, a], [tenantB, b]) =>
        a.virtualFinish - b.virtualFinish || nullFirst(a.lastDispatchedAt, b.lastDispatchedAt) || tenantA.localeCompare(tenantB)
      );
      return candidates[0] ? [{ tenant_id: candidates[0][0] }] : [];
    }
    if (text.includes("abl.shared.claim_fair_work")) {
      const tenant = String(values[0]);
      const queue = String(values[1]);
      const now = String(values[2]);
      const candidates = [...this.work.values()].filter((row) =>
        row.tenant_id === tenant && row.queue_name === queue && row.attempt_count < row.max_attempts &&
        row.available_at <= now && (row.status === "queued" || (row.status === "running" && row.lease_expires_at! <= now))
      );
      candidates.sort((a, b) => b.priority - a.priority || a.created_at.localeCompare(b.created_at) || a.work_id.localeCompare(b.work_id));
      const row = candidates[0];
      if (!row) return [];
      row.status = "running";
      row.worker_id = String(values[3]);
      row.claim_id = String(values[4]);
      row.lease_fence_token += 1;
      row.lease_expires_at = String(values[5]);
      row.attempt_count += 1;
      row.updated_at = now;
      return [row];
    }
    if (text.includes("abl.shared.advance_fair_tenant")) {
      const schedule = this.scheduler.get(String(values[0]))!;
      schedule.virtualFinish += Number(values[1]) / schedule.weight;
      schedule.lastDispatchedAt = String(values[2]);
      return [];
    }
    if (text.includes("abl.shared.renew_work_claim")) {
      const row = this.work.get(joinKey(String(values[0]), String(values[1])));
      if (!workClaimMatches(row, values, String(values[5]))) return [];
      row!.lease_expires_at = String(values[6]);
      row!.updated_at = String(values[5]);
      return [row!];
    }
    if (text.includes("abl.shared.complete_work_claim")) {
      const row = this.work.get(joinKey(String(values[0]), String(values[1])));
      if (!workClaimMatches(row, values, String(values[5]))) return [];
      row!.status = "succeeded";
      row!.result_ref = String(values[6]);
      row!.worker_id = null;
      row!.claim_id = null;
      row!.lease_expires_at = null;
      row!.updated_at = String(values[5]);
      return [row!];
    }
    if (text.includes("abl.shared.enqueue_outbox")) {
      const key = joinKey(String(values[0]), String(values[1]));
      if (this.outbox.has(key)) return [];
      const row: MutableOutboxRow = {
        tenant_id: String(values[0]), event_id: String(values[1]), aggregate_kind: String(values[2]),
        aggregate_id: String(values[3]), topic: String(values[4]), payload_hash: String(values[5]),
        payload_json: String(values[6]), status: "pending", available_at: String(values[7]),
        created_at: String(values[8]), updated_at: String(values[8]), claimed_by: null, claim_id: null,
        lease_fence_token: 0, lease_expires_at: null, attempt_count: 0, max_attempts: Number(values[9]),
        delivered_at: null, receipt_hash: null, error_code: null
      };
      this.outbox.set(key, row);
      return [row];
    }
    if (text.includes("abl.shared.get_outbox_event")) {
      const row = this.outbox.get(joinKey(String(values[0]), String(values[1])));
      return row ? [row] : [];
    }
    if (text.includes("abl.shared.claim_outbox")) {
      const tenant = String(values[0]);
      const topic = String(values[1]);
      const now = String(values[2]);
      const row = [...this.outbox.values()]
        .filter((candidate) => candidate.tenant_id === tenant && candidate.topic === topic &&
          candidate.attempt_count < candidate.max_attempts && candidate.available_at <= now &&
          (candidate.status === "pending" || (candidate.status === "claimed" && candidate.lease_expires_at! <= now)))
        .sort((a, b) => a.created_at.localeCompare(b.created_at) || a.event_id.localeCompare(b.event_id))[0];
      if (!row) return [];
      row.status = "claimed";
      row.claimed_by = String(values[3]);
      row.claim_id = String(values[4]);
      row.lease_fence_token += 1;
      row.lease_expires_at = String(values[5]);
      row.attempt_count += 1;
      row.updated_at = now;
      return [row];
    }
    if (text.includes("abl.shared.ack_outbox")) {
      const row = this.outbox.get(joinKey(String(values[0]), String(values[1])));
      if (!outboxClaimMatches(row, values, String(values[5]))) return [];
      row!.status = "delivered";
      row!.delivered_at = String(values[6]);
      row!.receipt_hash = String(values[7]);
      row!.claimed_by = null;
      row!.claim_id = null;
      row!.lease_expires_at = null;
      row!.updated_at = String(values[6]);
      return [row!];
    }
    if (text.includes("abl.shared.fail_outbox")) {
      const row = this.outbox.get(joinKey(String(values[0]), String(values[1])));
      if (!outboxClaimMatches(row, values, String(values[5]))) return [];
      row!.status = row!.attempt_count >= row!.max_attempts ? "dead_letter" : "pending";
      row!.available_at = String(values[7]);
      row!.error_code = String(values[6]);
      row!.claimed_by = null;
      row!.claim_id = null;
      row!.lease_expires_at = null;
      return [row!];
    }
    if (text.includes("abl.shared.reserve_replay")) {
      const key = joinKey(String(values[0]), String(values[1]), String(values[2]));
      const now = String(values[4]);
      const current = this.replay.get(key);
      if (current && current.expires_at > now) return [];
      const row: MutableReplayRow = {
        tenant_id: String(values[0]), principal_binding_hash: String(values[1]), nonce_hash: String(values[2]),
        reservation_id: String(values[3]), generation: (current?.generation ?? 0) + 1,
        state: "reserved", reserved_at: now, expires_at: String(values[5]), consumed_at: null
      };
      this.replay.set(key, row);
      return [row];
    }
    if (text.includes("abl.shared.consume_replay")) {
      const key = joinKey(String(values[0]), String(values[1]), String(values[2]));
      const row = this.replay.get(key);
      if (!row || row.reservation_id !== values[3] || String(row.generation) !== String(values[4]) ||
          row.state !== "reserved" || row.expires_at <= String(values[5])) return [];
      row.state = "consumed";
      row.consumed_at = String(values[6]);
      return [row];
    }
    if (text.includes("test.fenced_mutation")) return [];
    throw new Error(`Unhandled conformance SQL: ${text.slice(0, 80)}`);
  }
}

test("fenced leases reject stale workers and never interpolate tenant input into SQL", async () => {
  const pool = new ConformancePgPool();
  let now = new Date("2026-08-12T12:00:00.000Z");
  const leases = new PostgresFencedLeaseRepository(pool, () => now);
  const maliciousTenant = "tenant-a'; DROP TABLE abl_shared_leases; --";
  const first = await leases.acquire({
    tenantId: maliciousTenant,
    resourceKind: "portfolio",
    resourceId: "p-1",
    ownerId: "worker-a",
    leaseMilliseconds: 1_000
  });
  assert.ok(first);
  assert.equal(await leases.acquire({
    tenantId: maliciousTenant,
    resourceKind: "portfolio",
    resourceId: "p-1",
    ownerId: "worker-b",
    leaseMilliseconds: 1_000
  }), null);
  now = new Date(now.getTime() + 1_001);
  const second = await leases.acquire({
    tenantId: maliciousTenant,
    resourceKind: "portfolio",
    resourceId: "p-1",
    ownerId: "worker-b",
    leaseMilliseconds: 1_000
  });
  assert.ok(second);
  assert.equal(second.fenceToken, "2");
  await assert.rejects(
    leases.executeFenced(first, async () => "unsafe"),
    (error: unknown) => error instanceof SharedPersistenceError && error.code === "FENCE_REJECTED"
  );
  const value = await leases.executeFenced(second, async (client, fence) => {
    await client.query(
      "/* test.fenced_mutation */ UPDATE portfolio_state SET state = $3 WHERE tenant_id = $1 AND fence_token = $2",
      [maliciousTenant, fence, "certified"]
    );
    return "safe";
  });
  assert.equal(value, "safe");
  assert.ok(pool.statements.every((statement) => !statement.text.includes(maliciousTenant)));
  assert.ok(pool.statements.some((statement) => statement.values.includes(maliciousTenant)));
});

test("weighted tenant scheduler is fair while claims remain tenant fenced", async () => {
  const pool = new ConformancePgPool();
  const clock = () => new Date("2026-08-12T12:00:00.000Z");
  const work = new PostgresFairWorkRepository(pool, clock);
  await work.enqueue({ tenantId: "tenant-a", queueName: "analytics", idempotencyKey: "a-1", request: { n: 1 } });
  await work.enqueue({ tenantId: "tenant-a", queueName: "analytics", idempotencyKey: "a-2", request: { n: 2 } });
  await work.enqueue({ tenantId: "tenant-b", queueName: "analytics", idempotencyKey: "b-1", request: { n: 3 } });

  const first = await work.claimNext({ queueName: "analytics", workerId: "worker-1", leaseMilliseconds: 5_000 });
  const second = await work.claimNext({ queueName: "analytics", workerId: "worker-2", leaseMilliseconds: 5_000 });
  const third = await work.claimNext({ queueName: "analytics", workerId: "worker-3", leaseMilliseconds: 5_000 });
  assert.deepEqual([first?.tenantId, second?.tenantId, third?.tenantId], ["tenant-a", "tenant-b", "tenant-a"]);
  assert.equal(first?.leaseFenceToken, "1");
  assert.equal(second?.leaseFenceToken, "1");
  assert.equal(third?.leaseFenceToken, "1");
});

test("outbox and replay keys are tenant scoped and expired claims cannot acknowledge", async () => {
  const pool = new ConformancePgPool();
  let now = new Date("2026-08-12T12:00:00.000Z");
  const clock = () => now;
  const outbox = new PostgresTransactionalOutboxRepository(pool, clock);
  const base = {
    eventId: "same-event",
    aggregateKind: "pipeline",
    aggregateId: "run-1",
    topic: "audit",
    payload: { state: "certified" }
  };
  await outbox.enqueue(pool, { tenantId: "tenant-a", ...base });
  await outbox.enqueue(pool, { tenantId: "tenant-b", ...base });
  const stale = await outbox.claimNext({ tenantId: "tenant-a", topic: "audit", dispatcherId: "d-1", leaseMilliseconds: 1_000 });
  assert.ok(stale);
  assert.equal(await outbox.claimNext({ tenantId: "tenant-b", topic: "audit", dispatcherId: "d-2", leaseMilliseconds: 1_000 }).then((claim) => claim?.tenantId), "tenant-b");
  now = new Date(now.getTime() + 1_001);
  const replacement = await outbox.claimNext({ tenantId: "tenant-a", topic: "audit", dispatcherId: "d-3", leaseMilliseconds: 1_000 });
  assert.ok(replacement);
  assert.equal(replacement.leaseFenceToken, "2");
  await assert.rejects(
    outbox.acknowledge(stale, "a".repeat(64)),
    (error: unknown) => error instanceof SharedPersistenceError && error.code === "FENCE_REJECTED"
  );

  const replay = new PostgresReplayProtectionRepository(pool, clock);
  const principal = "b".repeat(64);
  const nonce = "c".repeat(64);
  const reservationA = await replay.reserve({ tenantId: "tenant-a", principalBindingHash: principal, nonceHash: nonce, ttlMilliseconds: 1_000 });
  assert.ok(reservationA);
  assert.equal(await replay.reserve({ tenantId: "tenant-a", principalBindingHash: principal, nonceHash: nonce, ttlMilliseconds: 1_000 }), null);
  assert.ok(await replay.reserve({ tenantId: "tenant-b", principalBindingHash: principal, nonceHash: nonce, ttlMilliseconds: 1_000 }));
  assert.equal(await replay.consume(reservationA), true);
  assert.equal(await replay.consume(reservationA), false);
  now = new Date(now.getTime() + 1_001);
  const nextGeneration = await replay.reserve({ tenantId: "tenant-a", principalBindingHash: principal, nonceHash: nonce, ttlMilliseconds: 1_000 });
  assert.equal(nextGeneration?.generation, "2");
});

test("migration declares composite tenant keys and lock-safe claiming", () => {
  assert.match(SHARED_POSTGRES_MIGRATION_V1, /PRIMARY KEY \(tenant_id, resource_kind, resource_id\)/);
  assert.match(SHARED_POSTGRES_MIGRATION_V1, /PRIMARY KEY \(tenant_id, principal_binding_hash, nonce_hash\)/);
  assert.match(SHARED_POSTGRES_MIGRATION_V1, /CHECK \(approved_by IS NULL OR approved_by <> requested_by\)/);
});

function leaseMatches(
  row: MutableLeaseRow | undefined,
  owner: string,
  leaseId: string,
  fence: string,
  now: string
): boolean {
  return Boolean(row && row.owner_id === owner && row.lease_id === leaseId &&
    String(row.fence_token) === fence && row.released_at === null && row.lease_expires_at > now);
}

function workClaimMatches(row: MutableWorkRow | undefined, values: readonly unknown[], now: string): boolean {
  return Boolean(row && row.status === "running" && row.worker_id === values[2] && row.claim_id === values[3] &&
    String(row.lease_fence_token) === String(values[4]) && row.lease_expires_at! > now);
}

function outboxClaimMatches(row: MutableOutboxRow | undefined, values: readonly unknown[], now: string): boolean {
  return Boolean(row && row.status === "claimed" && row.claimed_by === values[2] && row.claim_id === values[3] &&
    String(row.lease_fence_token) === String(values[4]) && row.lease_expires_at! > now);
}

function strings(values: readonly unknown[]): (string | undefined)[] {
  return values.map((value) => value === undefined ? undefined : String(value));
}

function joinKey(...parts: string[]): string {
  return parts.join("\u0000");
}

function nullFirst(left: string | null, right: string | null): number {
  if (left === right) return 0;
  if (left === null) return -1;
  if (right === null) return 1;
  return left.localeCompare(right);
}
