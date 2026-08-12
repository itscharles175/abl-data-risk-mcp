import { createHash } from "node:crypto";

import { CANONICAL_FIELDS, DICTIONARY_VERSION } from "./dictionary.js";
import { CANONICAL_FIELD_POLICIES, FIELD_POLICY_VERSION } from "./field-policy.js";

/** Stable content fingerprint shared by catalog responses and every governed run manifest. */
export const CANONICAL_DICTIONARY_HASH = createHash("sha256")
  .update(
    stableJson({
      fields: CANONICAL_FIELDS,
      fieldPolicies: CANONICAL_FIELD_POLICIES,
      fieldPolicyVersion: FIELD_POLICY_VERSION,
      version: DICTIONARY_VERSION
    })
  )
  .digest("hex");

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Readonly<Record<string, unknown>>)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, nested]) => `${JSON.stringify(key)}:${stableJson(nested)}`)
      .join(",")}}`;
  }
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new TypeError("Canonical dictionary contains a non-JSON value");
  return serialized;
}
