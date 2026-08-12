import assert from "node:assert/strict";
import { test } from "node:test";

import {
  compareSourceProfilesV2,
  profileSourceV2,
  reconcileSegmentsV2,
  runDataQualityV2
} from "../src/domain/data-quality-v2.js";

test("source profiles capture schema, distributions, units, temporal semantics, and material drift", () => {
  const before = profileSourceV2([
    { loan_id: "L1", current_balance: "100", status: "current", as_of_date: "2026-01-31" },
    { loan_id: "L2", current_balance: "200", status: "current", as_of_date: "2026-01-31" }
  ]);
  const after = profileSourceV2([
    { loan_id: "L1", current_balance: "100.5", status: "default", as_of_date: "2026-02-28", new_field: "x" },
    { loan_id: "L2", current_balance: null, status: "default", as_of_date: "2026-02-28", new_field: "x" }
  ]);
  const drift = compareSourceProfilesV2(before, after, { nullShareThreshold: "0.25", categoryShareThreshold: "0.25" });
  assert.ok(drift.some((item) => item.field === "current_balance" && item.kind === "type" && item.material));
  assert.ok(drift.some((item) => item.field === "current_balance" && item.kind === "null_share" && item.material));
  assert.ok(drift.some((item) => item.field === "status" && item.kind === "category" && item.material));
  assert.ok(drift.some((item) => item.field === "new_field" && item.kind === "added"));
  assert.match(after.profileHash, /^sha256:[0-9a-f]{64}$/u);
});

test("DQ v2 preserves critical severity and reports dollar/share materiality", () => {
  const result = runDataQualityV2({
    records: [
      { loan_id: "L1", current_balance: "100", principal: "80", interest: "20", status: "current" },
      { loan_id: "L1", current_balance: "500", principal: "400", interest: "50", status: "unknown" }
    ],
    balanceField: "current_balance",
    materialBalance: "250",
    remediationRefs: { unique_id: "runbook://duplicate-loans" },
    rules: [
      { ruleId: "unique_id", type: "unique", field: "loan_id", severity: "critical", blocking: true },
      { ruleId: "status_codes", type: "allowed_values", field: "status", values: ["current", "default"], severity: "error", blocking: true },
      { ruleId: "balance_math", type: "equals_sum", field: "current_balance", addends: ["principal", "interest"], tolerance: "0", severity: "critical", blocking: true }
    ]
  });
  assert.equal(result.publicationDecision, "block");
  assert.equal(result.findings[0]?.severity, "critical");
  assert.equal(result.findings[0]?.affectedBalance, "600");
  assert.equal(result.findings[0]?.affectedShare, "1");
  assert.equal(result.findings[0]?.materiality, "material");
  assert.equal(result.findings[0]?.remediationRef, "runbook://duplicate-loans");
});

test("segmented reconciliation catches facility, entity, currency, status, and collateral differences exactly", () => {
  const records = [
    { facility_id: "F1", legal_entity: "E1", currency: "USD", status: "current", collateral: "AR", balance: "100.01" },
    { facility_id: "F1", legal_entity: "E1", currency: "USD", status: "current", collateral: "AR", balance: "200.02" },
    { facility_id: "F2", legal_entity: "E2", currency: "CAD", status: "default", collateral: "inventory", balance: "50" }
  ];
  const dimensions = ["facility_id", "legal_entity", "status", "collateral"];
  const expected = [
    { dimensions: { facility_id: "F1", legal_entity: "E1", status: "current", collateral: "AR" }, rowCount: 2, balance: "300.03", currency: "USD" },
    { dimensions: { facility_id: "F2", legal_entity: "E2", status: "default", collateral: "inventory" }, rowCount: 1, balance: "49.99", currency: "CAD" }
  ];
  const result = reconcileSegmentsV2({ records, dimensions, balanceField: "balance", currencyField: "currency", expected, balanceTolerance: "0.005" });
  assert.equal(result.passed, false);
  assert.equal(result.checks.filter((check) => !check.passed).length, 1);
  assert.equal(result.checks.find((check) => check.currency === "CAD")?.difference, "0.01");
});
