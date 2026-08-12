import assert from "node:assert/strict";
import { test } from "node:test";

import { canonicalHash } from "../src/contracts/canonical.js";
import {
  AdapterValidationError,
  createConformedDataset,
  runAdapterConformanceKitV1,
  sha256Bytes,
  verifyConformedDataset,
  type BoundedTabularAdapter
} from "../src/adapters/index.js";

const LIMITS = Object.freeze({ maximumRows: 10, maximumColumns: 10, maximumCellCharacters: 100 });
const SOURCE_HASH = sha256Bytes(Buffer.from("fixture"));

test("adapter conformance kit replays fixtures and publishes deterministic evidence", async () => {
  const adapter = fixtureAdapter(() => "LN-001");
  const results = await runAdapterConformanceKitV1({
    adapter,
    limits: LIMITS,
    cases: [{
      caseId: "exact-decimal-fixture",
      input: { ignored: true },
      expectedRowCount: 1,
      expectedColumnCount: 2,
      expectedSourceContentHash: SOURCE_HASH
    }]
  });
  assert.equal(results.length, 1);
  assert.equal(results[0]!.sourceContentHash, SOURCE_HASH);
  assert.match(results[0]!.populationHash, /^sha256:[a-f0-9]{64}$/);
});

test("adapter conformance kit rejects non-determinism and tampered evidence", async () => {
  let call = 0;
  const nonDeterministic = fixtureAdapter(() => (++call % 2 === 0 ? "LN-002" : "LN-001"));
  await assert.rejects(
    runAdapterConformanceKitV1({
      adapter: nonDeterministic,
      limits: LIMITS,
      cases: [{ caseId: "unstable", input: {}, expectedRowCount: 1, expectedColumnCount: 2 }]
    }),
    (error: unknown) => adapterError(error, "INTEGRITY_FAILURE", /non-deterministic/)
  );

  const valid = await fixtureAdapter(() => "LN-001").ingest({});
  const tampered = {
    ...valid,
    records: [{ ...valid.records[0]!, balance: "11.00" }]
  };
  assert.throws(
    () => verifyConformedDataset(tampered, LIMITS),
    (error: unknown) => adapterError(error, "INTEGRITY_FAILURE", /hashes or counts/)
  );
});

function fixtureAdapter(
  loanId: () => string
): BoundedTabularAdapter<Readonly<Record<string, unknown>>> {
  return {
    adapterKind: "parquet",
    async ingest() {
      return createConformedDataset({
        adapterKind: "parquet",
        sourceMediaType: "application/vnd.apache.parquet",
        sourceContentHash: SOURCE_HASH,
        parser: {
          parserId: "fixture-decoder",
          parserVersion: "1",
          optionsHash: canonicalHash({ exact: true })
        },
        columns: [
          { name: "loan_id", logicalType: "text", nullable: false },
          { name: "balance", logicalType: "decimal", nullable: false, decimalPrecision: 10, decimalScale: 2 }
        ],
        records: [{ loan_id: loanId(), balance: "10.00" }],
        limits: LIMITS
      });
    }
  };
}

function adapterError(
  error: unknown,
  code: AdapterValidationError["code"],
  message: RegExp
): boolean {
  assert.ok(error instanceof AdapterValidationError);
  assert.equal(error.code, code);
  assert.match(error.message, message);
  return true;
}
