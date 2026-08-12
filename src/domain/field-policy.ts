import { CANONICAL_FIELDS, type AnalysisTag, type CanonicalFieldDefinition } from "./dictionary.js";

export const FIELD_POLICY_VERSION = "1.0.0" as const;

export type DefaultFieldMask = "none" | "tokenize" | "redact";
export type AggregationEligibility = "allowed" | "bucket_only" | "denied";

export interface CanonicalFieldPolicy {
  readonly fieldId: string;
  readonly ownerRole: "tenant_data_steward";
  readonly directIdentifier: boolean;
  readonly quasiIdentifier: boolean;
  readonly defaultMask: DefaultFieldMask;
  readonly aggregationEligibility: AggregationEligibility;
  readonly allowedPurposes: readonly (AnalysisTag | "data_quality" | "mapping" | "reconciliation")[];
  readonly retentionPolicy: "tenant_governed";
  readonly residencyPolicy: "tenant_governed";
  readonly exportRequiresExplicitPolicy: boolean;
}

export const CANONICAL_FIELD_POLICIES: readonly CanonicalFieldPolicy[] = Object.freeze(
  CANONICAL_FIELDS.map((field) => Object.freeze(policyFor(field)))
);

const POLICY_BY_FIELD = new Map(CANONICAL_FIELD_POLICIES.map((policy) => [policy.fieldId, policy]));

/** Unknown fields fail closed and are never silently treated as ordinary dimensions. */
export function getCanonicalFieldPolicy(fieldId: string): CanonicalFieldPolicy {
  return (
    POLICY_BY_FIELD.get(fieldId) ??
    Object.freeze({
      fieldId,
      ownerRole: "tenant_data_steward",
      directIdentifier: false,
      quasiIdentifier: true,
      defaultMask: "redact",
      aggregationEligibility: "denied",
      allowedPurposes: Object.freeze([]),
      retentionPolicy: "tenant_governed",
      residencyPolicy: "tenant_governed",
      exportRequiresExplicitPolicy: true
    })
  );
}

function policyFor(field: CanonicalFieldDefinition): CanonicalFieldPolicy {
  const directIdentifier = field.logicalType === "identifier";
  const quasiIdentifier =
    !directIdentifier &&
    (field.sensitivity === "restricted" ||
      field.analysisTags.includes("identity") ||
      field.analysisTags.includes("terms"));
  const aggregationEligibility: AggregationEligibility =
    directIdentifier || field.sensitivity === "restricted"
      ? "denied"
      : field.logicalType === "string" || field.unit === "code" || field.unit === "date"
        ? "bucket_only"
        : "allowed";
  const defaultMask: DefaultFieldMask = directIdentifier
    ? "tokenize"
    : field.sensitivity === "restricted"
      ? "redact"
      : "none";
  return {
    fieldId: field.id,
    ownerRole: "tenant_data_steward",
    directIdentifier,
    quasiIdentifier,
    defaultMask,
    aggregationEligibility,
    allowedPurposes: Object.freeze([
      "mapping" as const,
      "data_quality" as const,
      "reconciliation" as const,
      ...field.analysisTags
    ]),
    retentionPolicy: "tenant_governed",
    residencyPolicy: "tenant_governed",
    exportRequiresExplicitPolicy: field.sensitivity !== "non_sensitive"
  };
}
