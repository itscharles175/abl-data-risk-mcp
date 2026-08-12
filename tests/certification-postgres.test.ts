import assert from "node:assert/strict";
import { test } from "node:test";

import { Pool } from "pg";

import {
  POSTGRES_CERTIFICATION_SQL_V1,
  PgCancelBackendPortV1,
  PostgresCertificationError,
  PostgresCertificationHarnessV1,
  PostgresCrossTenantCanaryObserverV1,
  type PostgresCancellationPortV1,
  type PostgresCertificationClientV1,
  type PostgresCertificationPoolV1,
  type PostgresCertificationQuery,
  type PostgresRlsRelationV1
} from "../src/certification/index.js";

interface Call {
  readonly text: string;
  readonly values: readonly unknown[];
  readonly signal: AbortSignal | undefined;
}

interface FakeOptions {
  readonly role?: Readonly<Record<string, unknown>>;
  readonly inheritedRoles?: readonly string[];
  readonly grantViolations?: readonly Readonly<Record<string, unknown>>[];
  readonly rlsCatalog?: Readonly<Record<string, unknown>>;
  readonly visible?: Readonly<Record<string, unknown>>;
  readonly deniedVisible?: boolean;
  readonly nativeNumeric?: string;
  readonly numericText?: string;
  readonly nativeBigint?: string;
  readonly bigintText?: string;
  readonly wrongCursorOrdinal?: boolean;
}

class FakeCertificationClient implements PostgresCertificationClientV1 {
  readonly calls: Call[] = [];
  readonly releases: Array<boolean | Error | undefined> = [];
  readonly #options: FakeOptions;
  cursorRows = 0;
  cursorOffset = 0;
  pendingCancellationReject: ((error: Error & { code: string }) => void) | undefined;

  constructor(options: FakeOptions = {}) {
    this.#options = options;
  }

  async query(query: string | PostgresCertificationQuery): Promise<{
    readonly rows: readonly Readonly<Record<string, unknown>>[];
  }> {
    const text = typeof query === "string" ? query : query.text;
    const values = typeof query === "string" ? [] : [...(query.values ?? [])];
    const signal = typeof query === "string" ? undefined : query.signal;
    this.calls.push({ text, values, signal });
    if (text.includes("abl_cert:role_identity")) {
      return { rows: [{
        current_user: "abl_reader",
        session_user: "abl_reader",
        backend_pid: 4242,
        rolcanlogin: true,
        rolsuper: false,
        rolcreaterole: false,
        rolcreatedb: false,
        rolreplication: false,
        rolbypassrls: false,
        ...this.#options.role
      }] };
    }
    if (text.includes("abl_cert:timeouts")) {
      return { rows: [{
        statement_timeout_ms: "500",
        lock_timeout_ms: "100",
        idle_timeout_ms: "1000",
        transaction_read_only: "on"
      }] };
    }
    if (text.includes("abl_cert:role_memberships")) {
      return { rows: (this.#options.inheritedRoles ?? []).map((role_name) => ({ role_name })) };
    }
    if (text.includes("abl_cert:dangerous_grants")) {
      return { rows: this.#options.grantViolations ?? [] };
    }
    if (text.includes("abl_cert:rls_catalog")) {
      return { rows: [{
        row_security_enabled: true,
        row_security_forced: true,
        non_owner: true,
        relation_kind: "r",
        ...this.#options.rlsCatalog
      }] };
    }
    if (text.includes("abl_cert:rls_visible")) {
      return { rows: [{
        visible_rows: "2",
        allowed_rows: "2",
        foreign_rows: "0",
        ...this.#options.visible
      }] };
    }
    if (text.includes("abl_cert:rls_denied_canary")) {
      return { rows: [{ canary_visible: this.#options.deniedVisible ?? false }] };
    }
    if (text.includes("abl_cert:exact_numeric")) {
      return { rows: [{
        native_numeric: this.#options.nativeNumeric ?? values[0],
        numeric_text: this.#options.numericText ?? values[0],
        native_bigint: this.#options.nativeBigint ?? values[1],
        bigint_text: this.#options.bigintText ?? values[1]
      }] };
    }
    if (text.includes("abl_cert:cursor_declare")) {
      this.cursorRows = Number(values[0]);
      this.cursorOffset = 0;
      return { rows: [] };
    }
    if (text.includes("abl_cert:cursor_fetch")) {
      const fetch = /FETCH FORWARD (\d+)/.exec(text);
      assert.ok(fetch);
      const count = Number(fetch[1]);
      const remaining = Math.max(0, this.cursorRows - this.cursorOffset);
      const size = Math.min(count, remaining);
      const rows = Array.from({ length: size }, (_, index) => ({
        ordinal: String(
          this.#options.wrongCursorOrdinal && this.cursorOffset + index === 1
            ? 99
            : this.cursorOffset + index + 1
        )
      }));
      this.cursorOffset += size;
      return { rows };
    }
    if (text.includes("abl_cert:cancellation")) {
      return new Promise((_resolve, reject) => {
        this.pendingCancellationReject = reject as (error: Error & { code: string }) => void;
      });
    }
    return { rows: [] };
  }

  cancelPending(): void {
    const error = Object.assign(new Error("cancelled"), { code: "57014" });
    this.pendingCancellationReject?.(error);
  }

  release(destroy?: boolean | Error): void {
    this.releases.push(destroy);
  }
}

class FakePool implements PostgresCertificationPoolV1 {
  connectCount = 0;
  constructor(readonly client: PostgresCertificationClientV1) {}
  async connect(): Promise<PostgresCertificationClientV1> {
    this.connectCount += 1;
    return this.client;
  }
}

test("PostgreSQL certification passes only with least privilege, RLS canary and bounded execution evidence", async () => {
  const client = new FakeCertificationClient();
  const cancellation = cancellationFor(client, true);
  const harness = harnessFor(client, cancellation, true);
  const report = await harness.certify();

  assert.equal(report.certified, true);
  assert.equal(report.backendPid, 4242);
  assert.equal(report.checks.length, 10);
  assert.ok(report.checks.every((check) => check.status === "pass"));
  assert.match(report.reportHash, /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(client.releases, [false]);
  assert.equal(client.calls[0]!.text, POSTGRES_CERTIFICATION_SQL_V1.begin);
  assert.ok(client.calls.some((call) => call.text.includes("DECLARE \"abl_cert_cursor\" NO SCROLL CURSOR")));
  assert.ok(client.calls.some((call) => call.text.includes("FETCH FORWARD 2")));
  const rlsCalls = client.calls.filter((call) => call.text.includes("abl_cert:rls_"));
  assert.equal(rlsCalls.some((call) => call.text.includes("tenant-a") || call.text.includes("tenant-b")), false);
  assert.deepEqual(
    rlsCalls.flatMap((call) => call.values).filter((value) => typeof value === "string" && value.startsWith("tenant-")),
    ["tenant-a", "tenant-b"]
  );
  const cancellationCall = client.calls.find((call) => call.text.includes("abl_cert:cancellation"));
  assert.equal(cancellationCall?.signal?.aborted, true);
});

test("PostgreSQL certification returns a complete hard-fail report for privilege, RLS, numeric and cursor drift", async () => {
  const client = new FakeCertificationClient({
    role: { rolsuper: true, rolbypassrls: true },
    inheritedRoles: ["pg_write_all_data"],
    grantViolations: [{
      violation_kind: "relation_write",
      object_name: "servicing.loan_tape",
      privileges: "UPDATE"
    }],
    rlsCatalog: { row_security_forced: false },
    visible: { foreign_rows: "1" },
    deniedVisible: true,
    nativeNumeric: "9007199254740993.123456788",
    wrongCursorOrdinal: true
  });
  const report = await harnessFor(client, cancellationFor(client, true), false).certify();

  assert.equal(report.certified, false);
  const statuses = Object.fromEntries(report.checks.map((check) => [check.checkId, check.status]));
  assert.equal(statuses.least_privilege_attributes, "fail");
  assert.equal(statuses.dangerous_grants, "fail");
  assert.equal(statuses.rls_isolation, "fail");
  assert.equal(statuses.exact_numeric_text, "fail");
  assert.equal(statuses.cursor_bounds, "fail");
  assert.equal(statuses.cancellation, "pass");
  assert.equal(statuses.transaction_cleanup, "pass");
  assert.equal(report.checks.some((check) => check.message === "Check did not complete"), false);
});

test("cancellation evidence hard-fails when the safe backend seam does not attest cancellation", async () => {
  const client = new FakeCertificationClient();
  const report = await harnessFor(client, cancellationFor(client, false), true).certify();
  const cancellation = report.checks.find((check) => check.checkId === "cancellation");
  assert.equal(cancellation?.status, "fail");
  assert.equal(report.certified, false);
  assert.equal(report.checks.find((check) => check.checkId === "transaction_cleanup")?.status, "pass");
});

test("pg_cancel_backend seam is exact, parameterized and cannot select arbitrary targets", async () => {
  const calls: Call[] = [];
  const client: PostgresCertificationClientV1 = {
    async query(query) {
      const text = typeof query === "string" ? query : query.text;
      const values = typeof query === "string" ? [] : [...(query.values ?? [])];
      calls.push({ text, values, signal: undefined });
      return { rows: [{ cancelled: true }] };
    },
    release() {}
  };
  const pool = new FakePool(client);
  const port = new PgCancelBackendPortV1(pool);
  const controller = new AbortController();
  controller.abort();
  assert.equal(await port.cancelBackend({ backendPid: 4242, reason: "certification_probe", signal: controller.signal }), true);
  assert.equal(calls.length, 1);
  assert.match(calls[0]!.text, /pg_cancel_backend\(\$1::integer\)/);
  assert.equal(calls[0]!.text.includes("4242"), false);
  assert.deepEqual(calls[0]!.values, [4242]);
  await assert.rejects(
    port.cancelBackend({ backendPid: 0, reason: "certification_probe", signal: controller.signal }),
    (error: unknown) => error instanceof PostgresCertificationError && error.code === "INVALID_CONFIG"
  );
  assert.equal(pool.connectCount, 1);
});

test("privileged canary observer is read-only, exact and parameterized", async () => {
  const calls: Call[] = [];
  const client: PostgresCertificationClientV1 = {
    async query(query) {
      const text = typeof query === "string" ? query : query.text;
      const values = typeof query === "string" ? [] : [...(query.values ?? [])];
      calls.push({ text, values, signal: undefined });
      if (text.includes("observer_canary")) return { rows: [{ canary_exists: true }] };
      return { rows: [] };
    },
    release() {}
  };
  const observer = new PostgresCrossTenantCanaryObserverV1(new FakePool(client));
  assert.equal(await observer.verifyCanaryExists(relation()), true);
  assert.equal(calls[0]!.text, POSTGRES_CERTIFICATION_SQL_V1.begin);
  assert.equal(calls.at(-1)!.text, POSTGRES_CERTIFICATION_SQL_V1.rollback);
  const probe = calls.find((call) => call.text.includes("observer_canary"))!;
  assert.equal(probe.text.includes("tenant-b"), false);
  assert.deepEqual(probe.values, ["tenant-b", "DENIED-001"]);
});

test("certification configuration rejects SQL identifiers, arbitrary GUCs and unbounded probes", () => {
  const client = new FakeCertificationClient();
  const base = {
    pool: new FakePool(client),
    cancellation: cancellationFor(client, true),
    canaryObserver: { async verifyCanaryExists() { return true; } },
    expectedRole: "abl_reader",
    allowedRelations: [relation()]
  } as const;
  assert.throws(
    () => new PostgresCertificationHarnessV1({
      ...base,
      allowedRelations: [{ ...relation(), schema: "servicing; DROP SCHEMA public" }]
    }),
    (error: unknown) => error instanceof PostgresCertificationError && error.code === "INVALID_CONFIG"
  );
  assert.throws(
    () => new PostgresCertificationHarnessV1({
      ...base,
      allowedRelations: [{ ...relation(), tenantContextGuc: "search_path" }]
    }),
    (error: unknown) => error instanceof PostgresCertificationError && error.code === "INVALID_CONFIG"
  );
  assert.throws(
    () => new PostgresCertificationHarnessV1({ ...base, cursorFetchRows: 100_000 }),
    (error: unknown) => error instanceof PostgresCertificationError && error.code === "INVALID_CONFIG"
  );
});

test("operator-run live PostgreSQL certification", async (context) => {
  const required = [
    "ABL_CERT_PG_DSN",
    "ABL_CERT_PG_CANCEL_DSN",
    "ABL_CERT_PG_OBSERVER_DSN",
    "ABL_CERT_PG_EXPECTED_ROLE",
    "ABL_CERT_PG_SCHEMA",
    "ABL_CERT_PG_TABLE",
    "ABL_CERT_PG_TENANT_COLUMN",
    "ABL_CERT_PG_TENANT_GUC",
    "ABL_CERT_PG_ALLOWED_TENANT",
    "ABL_CERT_PG_DENIED_TENANT",
    "ABL_CERT_PG_CANARY_COLUMN",
    "ABL_CERT_PG_DENIED_CANARY"
  ] as const;
  const missing = required.filter((name) => !process.env[name]);
  if (missing.length > 0) {
    context.skip(`dedicated live certification environment is not configured (${missing.join(", ")})`);
    return;
  }
  const testedPool = new Pool({ connectionString: process.env.ABL_CERT_PG_DSN!, max: 1 });
  const cancelPool = new Pool({ connectionString: process.env.ABL_CERT_PG_CANCEL_DSN!, max: 1 });
  const observerPool = new Pool({ connectionString: process.env.ABL_CERT_PG_OBSERVER_DSN!, max: 1 });
  try {
    const liveRelation: PostgresRlsRelationV1 = {
      schema: process.env.ABL_CERT_PG_SCHEMA!,
      table: process.env.ABL_CERT_PG_TABLE!,
      tenantColumn: process.env.ABL_CERT_PG_TENANT_COLUMN!,
      tenantContextGuc: process.env.ABL_CERT_PG_TENANT_GUC!,
      allowedTenantId: process.env.ABL_CERT_PG_ALLOWED_TENANT!,
      deniedTenantId: process.env.ABL_CERT_PG_DENIED_TENANT!,
      canaryColumn: process.env.ABL_CERT_PG_CANARY_COLUMN!,
      deniedCanaryValue: process.env.ABL_CERT_PG_DENIED_CANARY!,
      minimumVisibleRows: Number(process.env.ABL_CERT_PG_MINIMUM_VISIBLE_ROWS ?? "1")
    };
    const harness = new PostgresCertificationHarnessV1({
      pool: testedPool as unknown as PostgresCertificationPoolV1,
      cancellation: new PgCancelBackendPortV1(cancelPool as unknown as PostgresCertificationPoolV1),
      canaryObserver: new PostgresCrossTenantCanaryObserverV1(observerPool as unknown as PostgresCertificationPoolV1),
      expectedRole: process.env.ABL_CERT_PG_EXPECTED_ROLE!,
      allowedRelations: [liveRelation],
      statementTimeoutMs: 5_000,
      lockTimeoutMs: 1_000,
      idleInTransactionTimeoutMs: 10_000
    });
    const report = await harness.certify();
    assert.equal(report.certified, true, JSON.stringify(report, null, 2));
  } finally {
    await Promise.all([testedPool.end(), cancelPool.end(), observerPool.end()]);
  }
});

function harnessFor(
  client: FakeCertificationClient,
  cancellation: PostgresCancellationPortV1,
  observerResult: boolean
): PostgresCertificationHarnessV1 {
  const times = ["2026-08-12T12:00:00.000Z", "2026-08-12T12:00:01.000Z"];
  return new PostgresCertificationHarnessV1({
    pool: new FakePool(client),
    cancellation,
    canaryObserver: { async verifyCanaryExists() { return observerResult; } },
    expectedRole: "abl_reader",
    allowedRelations: [relation()],
    statementTimeoutMs: 500,
    lockTimeoutMs: 100,
    idleInTransactionTimeoutMs: 1_000,
    cursorFetchRows: 2,
    cursorProbeRows: 5,
    cancellationDelayMs: 1,
    cancellationMaximumWaitMs: 500,
    cancellationSleepSeconds: 2,
    now: () => times.shift()!
  });
}

function cancellationFor(
  client: FakeCertificationClient,
  attested: boolean
): PostgresCancellationPortV1 {
  return {
    async cancelBackend(input) {
      assert.equal(input.backendPid, 4242);
      assert.equal(input.reason, "certification_probe");
      assert.equal(input.signal.aborted, true);
      client.cancelPending();
      return attested;
    }
  };
}

function relation(): PostgresRlsRelationV1 {
  return {
    schema: "servicing",
    table: "loan_tape",
    tenantColumn: "tenant_id",
    tenantContextGuc: "app.tenant_id",
    allowedTenantId: "tenant-a",
    deniedTenantId: "tenant-b",
    canaryColumn: "loan_id",
    deniedCanaryValue: "DENIED-001",
    minimumVisibleRows: 1,
    requireForcedRls: true
  };
}
