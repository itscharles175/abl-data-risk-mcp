import assert from "node:assert/strict";
import { test } from "node:test";

import { activeFieldsOn, createFieldPackV1 } from "../src/contracts/dictionary-v2.js";

test("field packs govern semantic, temporal, privacy, ownership, test, and compatibility metadata", () => {
  const pack = createFieldPackV1({
    contractVersion: 1,
    tenantId: "tenant-a",
    fieldPackId: "loan-core",
    version: "2.0.0",
    status: "active",
    effectiveFrom: "2026-01-01",
    fields: [
      {
        canonicalId: "borrower_id", label: "Borrower ID", description: "Tenant-scoped borrower identity", entity: "borrower", grain: "one row per borrower", logicalType: "identifier", temporalKind: "dimension", unit: "opaque", scale: "1", signConvention: "natural", currencySemantics: "not_applicable", owner: "credit-risk", steward: "data-steward", sourceLineage: "servicer borrower key", sensitivity: "restricted", directIdentifier: true, quasiIdentifier: false, allowedPurposes: ["portfolio-surveillance"], allowedRoles: ["risk_analyst"], maskingRule: "tokenize", aggregation: "count_distinct", retentionClass: "credit-record", residencyClass: "client-vpc", exportClass: "approved_detail", requiredTests: ["not-null", "unique"], effectiveFrom: "2026-01-01"
      },
      {
        canonicalId: "current_balance", label: "Current Balance", description: "Outstanding principal balance", entity: "loan_history", grain: "loan as-of date", logicalType: "currency", temporalKind: "stock", unit: "currency", scale: "0.01", signConvention: "asset_positive", currencySemantics: "record_currency", owner: "portfolio-risk", steward: "data-steward", sourceLineage: "servicer principal balance", sensitivity: "confidential", directIdentifier: false, quasiIdentifier: false, allowedPurposes: ["portfolio-surveillance"], allowedRoles: ["risk_analyst"], maskingRule: "none", aggregation: "sum", retentionClass: "credit-record", residencyClass: "client-vpc", exportClass: "aggregate_only", requiredTests: ["non-negative", "reconcile"], effectiveFrom: "2026-01-01"
      }
    ],
    changes: [{ fieldId: "current_balance", compatibility: "behavioral", description: "Explicit record currency semantics", migrationRef: "migration-balance-v2" }],
    createdBy: "maker-a",
    approvedBy: "checker-b"
  });
  assert.match(pack.fieldPackHash, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(activeFieldsOn(pack, "2026-06-30").length, 2);
  assert.throws(() => createFieldPackV1({
    ...pack,
    approvedBy: "maker-a",
    fieldPackHash: undefined as never
  } as never));
});
