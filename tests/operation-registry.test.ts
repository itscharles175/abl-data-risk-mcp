import assert from "node:assert/strict";
import { test } from "node:test";

import { OperationRegistryError, OperationRegistryV1 } from "../src/services/operation-registry.js";

const HASH = "a".repeat(64);

test("operation registry composes schema, definitions, fields, execution, accounting, and disclosure policy", async () => {
  const registry = new OperationRegistryV1().register({
    schemaVersion: 1,
    name: "portfolio.stratification.v2",
    kind: "analysis",
    inputSchemaHash: HASH,
    outputSchemaHash: HASH,
    disclosurePolicyId: "aggregate-k10",
    validateInput(value: unknown) {
      const input = value as { datasetId: string; fields: string[] };
      if (!input.datasetId || !Array.isArray(input.fields)) throw new Error("invalid");
      return input;
    },
    requiredDefinitions: () => [{ kind: "metric_definition", id: "current-balance" }, { kind: "bin_definition", id: "risk-grade" }],
    requestedFields: (input) => input.fields,
    execute: (input) => ({ datasetId: input.datasetId, rows: [{ bucket: "A", balance: "100" }] }),
    accountResult: (result) => ({ rows: result.rows.length, bytes: Buffer.byteLength(JSON.stringify(result)), populationHashes: [HASH], disclosureFields: ["risk_rating", "current_balance"] })
  }).seal();
  const description = registry.describe("portfolio.stratification.v2", { datasetId: "loans", fields: ["current_balance", "risk_rating", "risk_rating"] });
  assert.deepEqual(description.requestedFields, ["current_balance", "risk_rating"]);
  assert.deepEqual(description.requiredDefinitions.map((definition) => definition.kind), ["bin_definition", "metric_definition"]);
  const receipt = await registry.execute<{ datasetId: string; rows: { bucket: string; balance: string }[] }>("portfolio.stratification.v2", { datasetId: "loans", fields: ["risk_rating"] }, {
    tenantId: "tenant-a", principalBinding: HASH, purpose: "portfolio-surveillance", maximumResultRows: 10, maximumResultBytes: 10_000, maximumExecutionMs: 1_000
  });
  assert.equal(receipt.output.rows[0]?.balance, "100");
  assert.match(receipt.operationFingerprint, /^sha256:/u);
});

test("mutations preflight compact receipts before executing and analysis results remain bounded", async () => {
  let mutations = 0;
  const registry = new OperationRegistryV1().register({
    schemaVersion: 1, name: "mapping.activate.v2", kind: "control_mutation", inputSchemaHash: HASH, outputSchemaHash: HASH, disclosurePolicyId: "control-receipt", maximumReceiptBytes: 512,
    validateInput: (value: unknown) => value as { id: string }, requiredDefinitions: () => [], requestedFields: () => [],
    execute: () => { mutations += 1; return { status: "active" }; },
    accountResult: (result) => ({ rows: 1, bytes: Buffer.byteLength(JSON.stringify(result)), populationHashes: [], disclosureFields: [] })
  }).seal();
  await assert.rejects(
    registry.execute("mapping.activate.v2", { id: "m" }, { tenantId: "t", principalBinding: HASH, purpose: "governance", maximumResultRows: 1, maximumResultBytes: 256, maximumExecutionMs: 1_000 }),
    (error: unknown) => error instanceof OperationRegistryError && error.code === "RESULT_LIMIT_EXCEEDED"
  );
  assert.equal(mutations, 0);
});
