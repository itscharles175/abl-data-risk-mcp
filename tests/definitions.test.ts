import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import { DefinitionStore, DefinitionStoreError } from "../src/control/definitions.js";

const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "abl-definitions-"));
  directories.push(directory);
  return new DefinitionStore(join(directory, "definitions.sqlite"), {
    clock: () => new Date("2026-08-11T12:00:00Z")
  });
}

function activate(store: DefinitionStore, definitionId: string, suffix: string) {
  for (const [toStatus, key] of [
    ["validated", `validate-${suffix}`],
    ["approved", `approve-${suffix}`],
    ["active", `activate-${suffix}`]
  ] as const) {
    store.transition({
      tenantId: "tenant-a",
      definitionId,
      toStatus,
      actor: "checker-a",
      idempotencyKey: key
    });
  }
}

test("effective policy versions are maker-checker governed and time selectable", () => {
  const store = fixture();
  const first = store.propose({
    tenantId: "tenant-a",
    definitionId: "policy-v1",
    definitionKey: "facility-1-ar",
    kind: "borrowing_base_policy",
    version: "1.0.0",
    effectiveFrom: "2026-01-01",
    document: { advanceRate: "0.85" },
    proposedBy: "maker-a",
    idempotencyKey: "propose-v1"
  });
  activate(store, first.definitionId, "v1");
  const second = store.propose({
    tenantId: "tenant-a",
    definitionId: "policy-v2",
    definitionKey: "facility-1-ar",
    kind: "borrowing_base_policy",
    version: "2.0.0",
    effectiveFrom: "2026-07-01",
    document: { advanceRate: "0.8" },
    proposedBy: "maker-a",
    idempotencyKey: "propose-v2"
  });
  activate(store, second.definitionId, "v2");

  assert.equal(store.get("tenant-a", first.definitionId)?.status, "superseded");
  assert.equal(store.selectEffective("tenant-a", "borrowing_base_policy", "facility-1-ar", "2026-06-30").version, "1.0.0");
  assert.equal(store.selectEffective("tenant-a", "borrowing_base_policy", "facility-1-ar", "2026-07-01").version, "2.0.0");
  assert.equal(store.listAuditEvents("tenant-a").length, 9);
  store.close();
});

test("proposal and transition idempotency reject changed requests", () => {
  const store = fixture();
  const input = {
    tenantId: "tenant-a",
    definitionId: "recipe-v1",
    definitionKey: "monthly-strat",
    kind: "stratification_recipe" as const,
    version: "1.0.0",
    effectiveFrom: "2026-01-01",
    document: { dimension: "risk_rating" },
    proposedBy: "maker-a",
    idempotencyKey: "proposal-1"
  };
  assert.equal(store.propose(input).definitionId, store.propose(input).definitionId);
  assert.throws(
    () => store.propose({ ...input, definitionId: "recipe-v2" }),
    (error: unknown) => error instanceof DefinitionStoreError && error.code === "IDEMPOTENCY_CONFLICT"
  );
  assert.throws(
    () =>
      store.transition({
        tenantId: "tenant-a",
        definitionId: "recipe-v1",
        toStatus: "validated",
        actor: "maker-a",
        idempotencyKey: "self-review"
      }),
    (error: unknown) => error instanceof DefinitionStoreError && error.code === "MAKER_CHECKER_VIOLATION"
  );
  store.close();
});

test("definitions never cross tenant boundaries", () => {
  const store = fixture();
  store.propose({
    tenantId: "tenant-a",
    definitionId: "monitor-v1",
    definitionKey: "availability",
    kind: "monitor_definition",
    version: "1.0.0",
    effectiveFrom: "2026-01-01",
    document: { comparator: "lt", threshold: "100" },
    proposedBy: "maker-a",
    idempotencyKey: "proposal-monitor"
  });
  assert.equal(store.get("tenant-b", "monitor-v1"), undefined);
  assert.throws(
    () => store.selectEffective("tenant-b", "monitor_definition", "availability", "2026-08-01"),
    (error: unknown) => error instanceof DefinitionStoreError && error.code === "NOT_FOUND"
  );
  store.close();
});
