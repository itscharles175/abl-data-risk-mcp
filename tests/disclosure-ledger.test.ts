import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { DisclosureLedger, DisclosureLedgerError } from "../src/security/disclosure-ledger.js";

const HASH = "a".repeat(64);
const token = (value: string) => createHash("sha256").update(value).digest("hex");
const populationHash = (tokens: readonly string[]) => createHash("sha256").update(JSON.stringify([...tokens].sort())).digest("hex");

function request(id: string, members: readonly string[]) {
  const tokens = members.map(token).sort();
  return {
    tenantId: "tenant-a",
    audienceId: "role-risk-analyst",
    purpose: "portfolio-surveillance",
    datasetId: "loans",
    snapshotHash: HASH,
    metricDefinitionHash: HASH,
    queryFingerprint: token(id),
    minimumCohortSize: 3,
    cells: [{ cellKey: "risk-grade:A", populationHash: populationHash(tokens), memberTokens: tokens }],
    actor: "principal-a",
    idempotencyKey: id
  };
}

test("disclosure ledger permits stable cohorts but blocks small cells and adaptive differencing", () => {
  const ledger = new DisclosureLedger(":memory:");
  try {
    const first = ledger.assess(request("first", ["L1", "L2", "L3", "L4", "L5"]));
    assert.equal(first.effect, "permit");
    const replay = ledger.assess(request("first", ["L1", "L2", "L3", "L4", "L5"]));
    assert.equal(replay.decisionHash, first.decisionHash);
    const small = ledger.assess(request("small", ["L1", "L2"]));
    assert.deepEqual([small.effect, small.reason], ["deny", "small_cell"]);
    const differenced = ledger.assess(request("second", ["L1", "L2", "L3", "L4"]));
    assert.deepEqual([differenced.effect, differenced.reason], ["deny", "differencing_risk"]);
    const materiallyDifferent = ledger.assess(request("third", ["L6", "L7", "L8", "L9", "L10"]));
    assert.equal(materiallyDifferent.effect, "permit");
  } finally {
    ledger.close();
  }
});

test("disclosure population hashes, tenant bindings, and idempotency fail closed", () => {
  const ledger = new DisclosureLedger(":memory:");
  try {
    const valid = request("same", ["L1", "L2", "L3"]);
    ledger.assess(valid);
    assert.throws(
      () => ledger.assess({ ...valid, queryFingerprint: token("changed") }),
      (error: unknown) => error instanceof DisclosureLedgerError && error.code === "IDEMPOTENCY_CONFLICT"
    );
    assert.throws(
      () => ledger.assess({ ...request("bad", ["L4", "L5", "L6"]), cells: [{ cellKey: "risk-grade:A", populationHash: HASH, memberTokens: [token("L4"), token("L5"), token("L6")] }] }),
      (error: unknown) => error instanceof DisclosureLedgerError && error.code === "INVALID_INPUT"
    );
  } finally {
    ledger.close();
  }
});
