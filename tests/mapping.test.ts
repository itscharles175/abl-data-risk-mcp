import * as assert from "node:assert/strict";
import { test } from "node:test";

import {
  classifySourceType,
  compareTypes,
  normalizeFieldName,
  suggestFieldMappings,
  validateFieldMappings,
} from "../src/domain/mapping.js";
import type { FieldMapping, SourceColumn } from "../src/domain/mapping.js";

test("normalization and SQL type classification are deterministic", () => {
  assert.equal(normalizeFieldName("CurrentBalance_USD"), "current balance usd");
  assert.equal(classifySourceType("NUMERIC(18, 2)"), "decimal");
  assert.equal(classifySourceType("timestamp with time zone"), "datetime");
  assert.equal(classifySourceType("VARCHAR(64)"), "string");
  assert.equal(classifySourceType("made_up_type"), "unknown");
  assert.equal(compareTypes("numeric(18,2)", "currency"), "exact");
  assert.equal(compareTypes("timestamp", "date"), "compatible");
  assert.equal(compareTypes("varchar", "currency"), "compatible");
  assert.equal(compareTypes("text", "date"), "compatible");
});

test("suggestions rank canonical-id and alias matches first with evidence", () => {
  const suggestions = suggestFieldMappings(
    [
      { name: "loan_id", type: "varchar(40)" },
      { name: "eligible_ar", type: "decimal(18,2)" },
      { name: "curr_bal_amt", type: "numeric(20,2)" },
    ],
    { profile: "borrowing_base", maxCandidates: 4 },
  );

  assert.equal(suggestions[0]?.candidates[0]?.canonicalField, "loan_id");
  assert.ok(
    suggestions[0]?.candidates[0]?.evidence.some(
      (item) => item.kind === "canonical_id_exact",
    ),
  );
  assert.equal(
    suggestions[1]?.candidates[0]?.canonicalField,
    "accounts_receivable_eligible",
  );
  assert.ok(
    suggestions[1]?.candidates[0]?.evidence.some((item) => item.kind === "alias_exact"),
  );
  assert.equal(suggestions[2]?.candidates[0]?.canonicalField, "outstanding_balance");

  const repeated = suggestFieldMappings(
    [{ name: "curr_bal_amt", type: "numeric(20,2)" }],
    { profile: "borrowing_base", maxCandidates: 4 },
  );
  assert.deepEqual(repeated[0]?.candidates, suggestions[2]?.candidates);
});

test("type mismatch evidence affects and can filter suggestions", () => {
  const included = suggestFieldMappings([{ name: "maturity_date", type: "decimal" }]);
  assert.equal(included[0]?.candidates[0]?.canonicalField, "maturity_date");
  assert.equal(included[0]?.candidates[0]?.typeCompatibility, "incompatible");
  assert.ok(
    included[0]?.candidates[0]?.evidence.some(
      (item) => item.kind === "type_incompatible" && item.contribution < 0,
    ),
  );

  const excluded = suggestFieldMappings(
    [{ name: "maturity_date", type: "decimal" }],
    { includeTypeMismatches: false },
  );
  assert.ok(
    !excluded[0]?.candidates.some((candidate) => candidate.canonicalField === "maturity_date"),
  );
});

test("a complete, correctly typed base profile is ready", () => {
  const columns: readonly SourceColumn[] = [
    { name: "Report Date", type: "date" },
    { name: "Facility Number", type: "varchar(50)" },
    { name: "Loan Number", type: "varchar(50)" },
    { name: "Customer ID", type: "bigint" },
    { name: "Currency", type: "char(3)" },
    { name: "Credit Limit", type: "decimal(18,2)" },
    { name: "Principal Balance", type: "numeric(18,2)" },
  ];
  const mappings: readonly FieldMapping[] = [
    { sourceColumn: "Report Date", canonicalField: "as_of_date" },
    { sourceColumn: "Facility Number", canonicalField: "facility_id" },
    { sourceColumn: "Loan Number", canonicalField: "loan_id" },
    { sourceColumn: "Customer ID", canonicalField: "borrower_id" },
    { sourceColumn: "Currency", canonicalField: "currency_code" },
    { sourceColumn: "Credit Limit", canonicalField: "commitment_amount" },
    { sourceColumn: "Principal Balance", canonicalField: "outstanding_balance" },
  ];

  const result = validateFieldMappings(columns, mappings, "base");
  assert.equal(result.ready, true);
  assert.equal(result.readiness, "ready");
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.warnings, []);
  assert.equal(result.coverage.requiredFields, result.coverage.mappedRequiredFields);
  assert.deepEqual(result.coverage.missingRequiredFields, []);
});

test("validation detects unknowns, duplicates, mismatches, and profile gaps", () => {
  const columns: readonly SourceColumn[] = [
    { name: "loan_no", type: "varchar(30)" },
    { name: "other_loan_no", type: "varchar(30)" },
    { name: "bad_balance", type: "date" },
    { name: "unused", type: "text" },
  ];
  const mappings: readonly FieldMapping[] = [
    { sourceColumn: "loan_no", canonicalField: "loan_id" },
    { sourceColumn: "other_loan_no", canonicalField: "loan_id" },
    { sourceColumn: "bad_balance", canonicalField: "outstanding_balance" },
    { sourceColumn: "missing_source", canonicalField: "made_up_field" },
  ];

  const result = validateFieldMappings(columns, mappings, "vintage");
  const errorCodes = new Set(result.errors.map((item) => item.code));
  const warningCodes = new Set(result.warnings.map((item) => item.code));

  assert.equal(result.ready, false);
  assert.equal(result.readiness, "not_ready");
  assert.ok(errorCodes.has("UNKNOWN_SOURCE_COLUMN"));
  assert.ok(errorCodes.has("UNKNOWN_CANONICAL_FIELD"));
  assert.ok(errorCodes.has("DUPLICATE_TARGET_MAPPING"));
  assert.ok(errorCodes.has("TYPE_MISMATCH"));
  assert.ok(errorCodes.has("MISSING_REQUIRED_FIELD"));
  assert.ok(warningCodes.has("UNMAPPED_SOURCE_COLUMN"));
  assert.ok(result.coverage.missingRequiredFields.includes("origination_date"));
});

test("warnings yield needs_review while remaining non-blocking", () => {
  const columns: readonly SourceColumn[] = [
    { name: "AsOf", type: "timestamp" },
    { name: "Facility", type: "varchar" },
    { name: "Loan", type: "varchar" },
    { name: "Borrower", type: "varchar" },
    { name: "CCY", type: "varchar" },
    { name: "Commitment", type: "integer" },
    { name: "Balance", type: "decimal" },
    { name: "Unmapped Note", type: "text" },
  ];
  const mappings: readonly FieldMapping[] = [
    { sourceColumn: "AsOf", canonicalField: "as_of_date" },
    { sourceColumn: "Facility", canonicalField: "facility_id" },
    { sourceColumn: "Loan", canonicalField: "loan_id" },
    { sourceColumn: "Borrower", canonicalField: "borrower_id" },
    { sourceColumn: "CCY", canonicalField: "currency_code" },
    { sourceColumn: "Commitment", canonicalField: "commitment_amount" },
    { sourceColumn: "Balance", canonicalField: "outstanding_balance" },
  ];

  const result = validateFieldMappings(columns, mappings, "base");
  assert.equal(result.ready, true);
  assert.equal(result.readiness, "needs_review");
  assert.deepEqual(result.errors, []);
  assert.ok(result.warnings.some((item) => item.code === "TYPE_COERCION_REQUIRED"));
  assert.ok(result.warnings.some((item) => item.code === "UNMAPPED_SOURCE_COLUMN"));
});
