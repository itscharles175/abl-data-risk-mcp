import * as assert from "node:assert/strict";
import { test } from "node:test";

import {
  CANONICAL_FIELDS,
  DICTIONARY_VERSION,
  getCanonicalField,
  listCanonicalFields,
} from "../src/domain/dictionary.js";
import { CANONICAL_DICTIONARY_HASH } from "../src/domain/dictionary-fingerprint.js";
import {
  CANONICAL_FIELD_POLICIES,
  FIELD_POLICY_VERSION,
  getCanonicalFieldPolicy,
} from "../src/domain/field-policy.js";

test("dictionary exposes unique, complete, stable field metadata", () => {
  assert.match(DICTIONARY_VERSION, /^\d+\.\d+\.\d+$/);
  assert.match(CANONICAL_DICTIONARY_HASH, /^[a-f0-9]{64}$/);
  assert.match(FIELD_POLICY_VERSION, /^\d+\.\d+\.\d+$/);
  assert.equal(CANONICAL_FIELD_POLICIES.length, CANONICAL_FIELDS.length);
  assert.ok(CANONICAL_FIELDS.length >= 40, "expected a useful loan and ABL field set");

  const ids = new Set<string>();
  for (const field of CANONICAL_FIELDS) {
    assert.ok(!ids.has(field.id), `duplicate canonical id: ${field.id}`);
    ids.add(field.id);
    assert.ok(field.label.length > 0);
    assert.ok(field.description.length > 0);
    assert.ok(field.logicalType.length > 0);
    assert.ok(Array.isArray(field.aliases));
    assert.ok(Array.isArray(field.requiredFor));
    assert.ok(Array.isArray(field.analysisTags));
    assert.ok(field.sensitivity.length > 0);
    assert.ok(field.unit.length > 0);
    assert.ok(field.semanticNotes.length > 0);
  }
});

test("field policy covers every canonical field and defaults unknown fields to restricted", () => {
  assert.equal(getCanonicalFieldPolicy("loan_id").directIdentifier, true);
  assert.equal(getCanonicalFieldPolicy("loan_id").aggregationEligibility, "denied");
  assert.equal(getCanonicalFieldPolicy("outstanding_balance").aggregationEligibility, "allowed");
  assert.equal(getCanonicalFieldPolicy("not_in_dictionary").defaultMask, "redact");
  assert.equal(getCanonicalFieldPolicy("not_in_dictionary").exportRequiresExplicitPolicy, true);
});

test("canonical lookup is exact and returns undefined for unknown ids", () => {
  assert.equal(getCanonicalField("outstanding_balance")?.label, "Outstanding Balance");
  assert.equal(getCanonicalField("OUTSTANDING_BALANCE"), undefined);
  assert.equal(getCanonicalField("not_a_field"), undefined);
});

test("dictionary filters compose", () => {
  const borrowingBaseCurrencyFields = listCanonicalFields({
    requiredFor: "borrowing_base",
    logicalType: "currency",
    sensitivity: ["confidential"],
  });

  assert.ok(borrowingBaseCurrencyFields.length > 0);
  assert.ok(
    borrowingBaseCurrencyFields.some((field) => field.id === "borrowing_base_amount"),
  );
  assert.ok(
    borrowingBaseCurrencyFields.every(
      (field) =>
        field.logicalType === "currency" &&
        field.requiredFor.includes("borrowing_base") &&
        field.sensitivity === "confidential",
    ),
  );
});

test("dictionary contains both core tape and detailed ABL concepts", () => {
  const expected = [
    "loan_id",
    "origination_date",
    "outstanding_balance",
    "default_flag",
    "accounts_receivable_eligible",
    "inventory_advance_rate",
    "total_reserves",
    "borrowing_base_amount",
    "receivable_age_days",
    "inventory_nolv",
  ];

  for (const id of expected) assert.ok(getCanonicalField(id), `missing ${id}`);
});
