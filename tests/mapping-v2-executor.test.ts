import assert from "node:assert/strict";
import { test } from "node:test";

import { createMappingSpecV2 } from "../src/contracts/mapping-v2.js";
import { executeMappingSpecV2, MappingExecutionError } from "../src/services/mapping-v2-executor.js";

const HASH = "sha256:" + "a".repeat(64);
const HASH_B = "sha256:" + "b".repeat(64);

function spec() {
  return createMappingSpecV2({
    contractVersion: 2,
    tenantId: "tenant-a",
    mappingSpecId: "mapping-loans-v2",
    mappingKey: "servicer-loan-tape",
    revision: 1,
    status: "active",
    sourceContract: { sourceContractId: "loans", revision: 1, sourceContractHash: HASH },
    dictionaryBundle: {
      contractVersion: 1,
      bundleKind: "dictionary",
      bundleId: "core-dictionary",
      version: "2.0.0",
      contentHash: HASH,
      artifactId: "dictionary-artifact",
      mediaType: "application/json",
      createdAt: "2026-01-01T00:00:00.000Z",
      dictionaryVersion: "2.0.0",
      dictionaryHash: HASH,
      fieldPolicyVersion: "2.0.0",
      fieldPolicyHash: HASH_B
    },
    rules: [
      { ruleId: "loan-id", canonicalField: "loan_id", expression: { op: "exact_cast", input: { op: "source", column: "loan_no" }, to: "identifier" }, onError: "fail_application" },
      { ruleId: "balance", canonicalField: "current_balance", expression: { op: "scale_decimal", input: { op: "source", column: "balance_cents" }, factor: "0.01", decimalPlaces: 2, rounding: "reject" }, onError: "fail_application" },
      { ruleId: "as-of", canonicalField: "as_of_date", expression: { op: "parse_date", input: { op: "source", column: "report_date" }, formats: ["MM/DD/YYYY"], timezone: "UTC" }, onError: "reject_row" },
      { ruleId: "risk", canonicalField: "risk_rating", expression: { op: "code_map", input: { op: "source", column: "grade" }, values: { "1": "A", "2": "B" }, unknown: "null" }, onError: "null" },
      { ruleId: "label", canonicalField: "display_label", expression: { op: "combine", inputs: [{ op: "source", column: "loan_no" }, { op: "source", column: "grade" }], separator: " / ", skipNulls: true }, onError: "null" }
    ],
    requiredCanonicalFields: ["loan_id", "current_balance", "as_of_date"],
    createdBy: "maker-a",
    createdAt: "2026-01-01T00:00:00.000Z",
    approvedBy: "checker-b",
    approvedAt: "2026-01-02T00:00:00.000Z"
  });
}

test("mapping v2 executes bounded exact transformations and rejects bad rows deterministically", () => {
  const result = executeMappingSpecV2({
    spec: spec(),
    records: [
      { loan_no: "L-1", balance_cents: "12345", report_date: "01/31/2026", grade: "1" },
      { loan_no: "L-2", balance_cents: "500", report_date: "02/30/2026", grade: "9" }
    ]
  });
  assert.equal(result.outputRowCount, 1);
  assert.equal(result.rejectedRowCount, 1);
  assert.deepEqual(result.records[0], {
    loan_id: "L-1",
    current_balance: "123.45",
    as_of_date: "2026-01-31",
    risk_rating: "A",
    display_label: "L-1 / 1"
  });
  assert.equal(result.rejections[0]?.ruleId, "as-of");
  assert.match(result.executionHash, /^sha256:[0-9a-f]{64}$/u);
});

test("mapping v2 rejects lossy numbers and never accepts executable expressions", () => {
  assert.throws(
    () => executeMappingSpecV2({ spec: spec(), records: [{ loan_no: "L", balance_cents: 1.5, report_date: "01/01/2026", grade: "1" }] }),
    (error: unknown) => error instanceof MappingExecutionError && error.code === "INVALID_INPUT"
  );
  assert.throws(
    () => executeMappingSpecV2({ spec: spec(), records: [{ loan_no: "L", balance_cents: "1.005", report_date: "01/01/2026", grade: "1" }] }),
    (error: unknown) => error instanceof MappingExecutionError && error.code === "MAPPING_FAILED"
  );
});
