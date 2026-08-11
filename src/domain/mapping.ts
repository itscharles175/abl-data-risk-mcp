import { CANONICAL_FIELDS, DICTIONARY_VERSION, getCanonicalField } from "./dictionary.js";
import type {
  AnalysisProfile,
  CanonicalFieldDefinition,
  CanonicalFieldId,
  LogicalType,
} from "./dictionary.js";

/** Minimal source metadata available from SQL catalogs and flat-file headers. */
export interface SourceColumn {
  readonly name: string;
  /** Native SQL/warehouse type (for example varchar(50), numeric(18,2), or date). */
  readonly type?: string;
  readonly description?: string;
  readonly nullable?: boolean;
}

/** Persistable, provider-neutral mapping pair. */
export interface FieldMapping {
  readonly sourceColumn: string;
  readonly canonicalField: string;
}

export type SourceTypeFamily =
  | "string"
  | "integer"
  | "decimal"
  | "boolean"
  | "date"
  | "datetime"
  | "binary"
  | "json"
  | "unknown";

export type TypeCompatibility = "exact" | "compatible" | "incompatible" | "unknown";

export type MappingEvidenceKind =
  | "canonical_id_exact"
  | "alias_exact"
  | "label_exact"
  | "token_overlap"
  | "type_exact"
  | "type_compatible"
  | "type_incompatible"
  | "profile_relevance";

export interface MappingEvidence {
  readonly kind: MappingEvidenceKind;
  readonly message: string;
  /** Signed contribution to the 0..1 candidate score. */
  readonly contribution: number;
  readonly matchedValue?: string;
}

export interface MappingCandidate {
  readonly canonicalField: CanonicalFieldId;
  readonly label: string;
  readonly logicalType: LogicalType;
  /** Deterministic confidence score in the inclusive range 0..1. */
  readonly score: number;
  readonly typeCompatibility: TypeCompatibility;
  readonly evidence: readonly MappingEvidence[];
}

export interface SourceMappingSuggestion {
  readonly sourceColumn: string;
  readonly sourceType?: string;
  readonly candidates: readonly MappingCandidate[];
}

export interface MappingSuggestionOptions {
  /** Optional profile gives a small, explicit tie-breaking relevance boost. */
  readonly profile?: AnalysisProfile;
  /** Maximum candidates returned per source column. Default: 5. */
  readonly maxCandidates?: number;
  /** Inclusive score threshold in the range 0..1. Default: 0.30. */
  readonly minimumScore?: number;
  /** If false, type-incompatible candidates are removed. Default: true. */
  readonly includeTypeMismatches?: boolean;
}

export type MappingIssueCode =
  | "UNKNOWN_PROFILE"
  | "INVALID_SOURCE_COLUMN"
  | "DUPLICATE_SOURCE_COLUMN"
  | "UNKNOWN_SOURCE_COLUMN"
  | "UNKNOWN_CANONICAL_FIELD"
  | "DUPLICATE_SOURCE_MAPPING"
  | "DUPLICATE_TARGET_MAPPING"
  | "TYPE_MISMATCH"
  | "TYPE_COERCION_REQUIRED"
  | "SOURCE_TYPE_UNKNOWN"
  | "MISSING_REQUIRED_FIELD"
  | "UNMAPPED_SOURCE_COLUMN";

export interface MappingIssue {
  readonly code: MappingIssueCode;
  readonly severity: "error" | "warning";
  readonly message: string;
  readonly sourceColumn?: string;
  readonly canonicalField?: string;
  readonly sourceType?: string;
  readonly expectedType?: LogicalType;
}

export type MappingReadiness = "ready" | "needs_review" | "not_ready";

export interface MappingCoverage {
  readonly sourceColumns: number;
  readonly mappedSourceColumns: number;
  readonly requiredFields: number;
  readonly mappedRequiredFields: number;
  readonly missingRequiredFields: readonly CanonicalFieldId[];
}

export interface MappingValidationResult {
  readonly profile: AnalysisProfile;
  readonly ready: boolean;
  readonly readiness: MappingReadiness;
  readonly errors: readonly MappingIssue[];
  readonly warnings: readonly MappingIssue[];
  readonly coverage: MappingCoverage;
}

const PROFILE_VALUES: readonly AnalysisProfile[] = [
  "base",
  "stratification",
  "vintage",
  "borrowing_base",
];

const TOKEN_EXPANSIONS: Readonly<Record<string, readonly string[]>> = {
  acct: ["account"],
  accts: ["accounts"],
  amt: ["amount"],
  ar: ["accounts", "receivable"],
  bal: ["balance"],
  bb: ["borrowing", "base"],
  bps: ["basis", "points"],
  ccy: ["currency"],
  conc: ["concentration"],
  curr: ["current"],
  cust: ["customer"],
  dt: ["date"],
  eff: ["effective"],
  elig: ["eligible"],
  exp: ["expiration"],
  fac: ["facility"],
  flg: ["flag"],
  grossar: ["gross", "accounts", "receivable"],
  id: ["id"],
  ind: ["indicator"],
  inv: ["inventory"],
  lim: ["limit"],
  ln: ["loan"],
  nbr: ["number"],
  no: ["number"],
  num: ["number"],
  orig: ["original"],
  pct: ["rate"],
  perc: ["rate"],
  prin: ["principal"],
  qty: ["quantity"],
  rcbl: ["receivable"],
  recv: ["receivable"],
  rpt: ["reporting"],
  src: ["source"],
  tot: ["total"],
  val: ["value"],
};

const GENERIC_TOKENS = new Set([
  "amount",
  "code",
  "date",
  "flag",
  "id",
  "name",
  "number",
  "rate",
  "status",
  "total",
  "value",
]);

interface NameMatch {
  readonly kind:
    | "canonical_id_exact"
    | "alias_exact"
    | "label_exact"
    | "token_overlap";
  readonly contribution: number;
  readonly matchedValue: string;
  readonly message: string;
}

/**
 * Normalizes names without depending on locale or database identifier rules.
 * This is exported to let adapters show exactly how a name was compared.
 */
export function normalizeFieldName(value: string): string {
  return value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/%/g, " rate ")
    .replace(/&/g, " and ")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .replace(/\s+/g, " ");
}

function expandedTokens(value: string): readonly string[] {
  const normalized = normalizeFieldName(value);
  if (!normalized) return [];

  const tokens: string[] = [];
  for (const token of normalized.split(" ")) {
    const expansion = TOKEN_EXPANSIONS[token];
    if (expansion) tokens.push(...expansion);
    else tokens.push(token);
  }
  return [...new Set(tokens)];
}

function tokenSimilarity(source: readonly string[], target: readonly string[]): number {
  if (source.length === 0 || target.length === 0) return 0;
  const sourceSet = new Set(source);
  const targetSet = new Set(target);
  let intersection = 0;
  let informativeIntersection = 0;

  for (const token of sourceSet) {
    if (targetSet.has(token)) {
      intersection += 1;
      if (!GENERIC_TOKENS.has(token)) informativeIntersection += 1;
    }
  }

  if (intersection === 0) return 0;
  const dice = (2 * intersection) / (sourceSet.size + targetSet.size);
  const containment = intersection / Math.min(sourceSet.size, targetSet.size);
  const informativeness = informativeIntersection > 0 ? 1 : 0.78;
  return (0.65 * dice + 0.35 * containment) * informativeness;
}

function bestNameMatch(sourceName: string, field: CanonicalFieldDefinition): NameMatch | undefined {
  const source = normalizeFieldName(sourceName);
  if (!source) return undefined;

  if (source === normalizeFieldName(field.id)) {
    return {
      kind: "canonical_id_exact",
      contribution: 0.92,
      matchedValue: field.id,
      message: `Source name exactly matches canonical id '${field.id}' after normalization.`,
    };
  }

  const exactAlias = field.aliases.find((alias) => source === normalizeFieldName(alias));
  if (exactAlias) {
    return {
      kind: "alias_exact",
      contribution: 0.88,
      matchedValue: exactAlias,
      message: `Source name exactly matches known alias '${exactAlias}' after normalization.`,
    };
  }

  if (source === normalizeFieldName(field.label)) {
    return {
      kind: "label_exact",
      contribution: 0.86,
      matchedValue: field.label,
      message: `Source name exactly matches label '${field.label}' after normalization.`,
    };
  }

  const sourceTokens = expandedTokens(sourceName);
  const variants = [field.id, field.label, ...field.aliases];
  let bestSimilarity = 0;
  let bestVariant = "";
  for (const variant of variants) {
    const similarity = tokenSimilarity(sourceTokens, expandedTokens(variant));
    if (
      similarity > bestSimilarity ||
      (similarity === bestSimilarity && variant.localeCompare(bestVariant) < 0)
    ) {
      bestSimilarity = similarity;
      bestVariant = variant;
    }
  }

  // A name signal is required; type compatibility alone never generates a candidate.
  if (bestSimilarity < 0.26) return undefined;
  const contribution = Math.min(0.76, bestSimilarity * 0.76);
  return {
    kind: "token_overlap",
    contribution,
    matchedValue: bestVariant,
    message: `Normalized tokens overlap with '${bestVariant}' (${round(bestSimilarity, 3)} similarity).`,
  };
}

/** Classifies common SQL, warehouse, Arrow, and spreadsheet type labels. */
export function classifySourceType(sourceType?: string): SourceTypeFamily {
  if (!sourceType || !sourceType.trim()) return "unknown";
  const type = sourceType.trim().toLowerCase().replace(/\s+/g, " ");

  if (/\b(json|jsonb|variant|object|array|struct|map)\b/.test(type)) return "json";
  if (/\b(binary|varbinary|blob|bytea|image)\b/.test(type)) return "binary";
  if (/\b(timestamp|datetime|datetime2|datetimeoffset|timestamptz|smalldatetime|instant)\b/.test(type)) {
    return "datetime";
  }
  if (/\bdate\b/.test(type)) return "date";
  if (/\b(bool|boolean)\b/.test(type) || /^bit(?:\s*\(\s*1\s*\))?$/.test(type)) return "boolean";
  if (/^tinyint\s*\(\s*1\s*\)$/.test(type)) return "boolean";
  if (/\b(bigint|smallint|tinyint|integer|int|int2|int4|int8|serial|bigserial|smallserial)\b/.test(type)) {
    return "integer";
  }
  if (/\b(decimal|numeric|number|money|smallmoney|float|float4|float8|double|real|dec|fixed)\b/.test(type)) {
    return "decimal";
  }
  if (/\b(char|varchar|nvarchar|nchar|text|string|uuid|uniqueidentifier|enum|clob)\b/.test(type)) {
    return "string";
  }
  return "unknown";
}

/** Compares a native source type with a canonical logical type. */
export function compareTypes(
  sourceType: string | undefined,
  logicalType: LogicalType,
): TypeCompatibility {
  const source = classifySourceType(sourceType);
  if (source === "unknown") return "unknown";

  switch (logicalType) {
    case "identifier":
      return source === "string" || source === "integer" ? "exact" : "incompatible";
    case "string":
      return source === "string" ? "exact" : "incompatible";
    case "integer":
      if (source === "integer") return "exact";
      return source === "decimal" ? "compatible" : "incompatible";
    case "decimal":
    case "currency":
    case "percentage":
      if (source === "decimal") return "exact";
      return source === "integer" ? "compatible" : "incompatible";
    case "boolean":
      return source === "boolean" ? "exact" : "incompatible";
    case "date":
      if (source === "date") return "exact";
      return source === "datetime" ? "compatible" : "incompatible";
    case "datetime":
      if (source === "datetime") return "exact";
      return source === "date" ? "compatible" : "incompatible";
  }

  const exhaustive: never = logicalType;
  return exhaustive;
}

function typeEvidence(
  sourceType: string | undefined,
  logicalType: LogicalType,
): { readonly compatibility: TypeCompatibility; readonly evidence?: MappingEvidence } {
  const compatibility = compareTypes(sourceType, logicalType);
  if (compatibility === "unknown") return { compatibility };
  if (compatibility === "exact") {
    return {
      compatibility,
      evidence: {
        kind: "type_exact",
        contribution: 0.08,
        message: `Source type '${sourceType}' exactly supports logical type '${logicalType}'.`,
      },
    };
  }
  if (compatibility === "compatible") {
    return {
      compatibility,
      evidence: {
        kind: "type_compatible",
        contribution: 0.04,
        message: `Source type '${sourceType}' can be safely adapted to logical type '${logicalType}'.`,
      },
    };
  }
  return {
    compatibility,
    evidence: {
      kind: "type_incompatible",
      contribution: -0.15,
      message: `Source type '${sourceType}' conflicts with logical type '${logicalType}'.`,
    },
  };
}

function round(value: number, digits: number): number {
  const factor = 10 ** digits;
  return Math.round((value + Number.EPSILON) * factor) / factor;
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
}

interface ResolvedSuggestionOptions {
  readonly profile?: AnalysisProfile;
  readonly maxCandidates: number;
  readonly minimumScore: number;
  readonly includeTypeMismatches: boolean;
}

function normalizedOptions(options: MappingSuggestionOptions): ResolvedSuggestionOptions {
  const maxCandidates = Number.isFinite(options.maxCandidates)
    ? Math.max(0, Math.floor(options.maxCandidates ?? 5))
    : 5;
  const minimumScore = Number.isFinite(options.minimumScore)
    ? clamp(options.minimumScore ?? 0.3, 0, 1)
    : 0.3;
  return {
    ...(options.profile === undefined ? {} : { profile: options.profile }),
    maxCandidates,
    minimumScore,
    includeTypeMismatches: options.includeTypeMismatches ?? true,
  };
}

/**
 * Produces deterministic, explainable mapping candidates without an LLM.
 * Candidate order is score descending, then canonical id ascending.
 */
export function suggestFieldMappings(
  sourceColumns: readonly SourceColumn[],
  options: MappingSuggestionOptions = {},
): readonly SourceMappingSuggestion[] {
  const resolved = normalizedOptions(options);
  const fields: readonly CanonicalFieldDefinition[] = CANONICAL_FIELDS;

  return sourceColumns.map((sourceColumn) => {
    const candidates: MappingCandidate[] = [];
    for (const field of fields) {
      const nameMatch = bestNameMatch(sourceColumn.name, field);
      if (!nameMatch) continue;

      const evidence: MappingEvidence[] = [nameMatch];
      const type = typeEvidence(sourceColumn.type, field.logicalType);
      if (!resolved.includeTypeMismatches && type.compatibility === "incompatible") continue;
      if (type.evidence) evidence.push(type.evidence);

      let score = nameMatch.contribution + (type.evidence?.contribution ?? 0);
      if (resolved.profile && field.requiredFor.includes(resolved.profile)) {
        const profileEvidence: MappingEvidence = {
          kind: "profile_relevance",
          contribution: 0.02,
          message: `Field is required for the '${resolved.profile}' profile.`,
        };
        evidence.push(profileEvidence);
        score += profileEvidence.contribution;
      }

      score = round(clamp(score, 0, 1), 4);
      if (score < resolved.minimumScore) continue;
      candidates.push({
        canonicalField: field.id as CanonicalFieldId,
        label: field.label,
        logicalType: field.logicalType,
        score,
        typeCompatibility: type.compatibility,
        evidence,
      });
    }

    candidates.sort(
      (left, right) =>
        right.score - left.score || left.canonicalField.localeCompare(right.canonicalField),
    );
    return {
      sourceColumn: sourceColumn.name,
      ...(sourceColumn.type === undefined ? {} : { sourceType: sourceColumn.type }),
      candidates: candidates.slice(0, resolved.maxCandidates),
    };
  });
}

function issue(
  code: MappingIssueCode,
  severity: "error" | "warning",
  message: string,
  context: Omit<MappingIssue, "code" | "severity" | "message"> = {},
): MappingIssue {
  return { code, severity, message, ...context };
}

function isAnalysisProfile(value: string): value is AnalysisProfile {
  return (PROFILE_VALUES as readonly string[]).includes(value);
}

/**
 * Validates a mapping specification and reports whether it can support a target
 * analysis profile. Errors are blocking; warnings require review but are not
 * blocking. Required-field coverage only counts mappings with known source and
 * target fields.
 */
export function validateFieldMappings(
  sourceColumns: readonly SourceColumn[],
  mappings: readonly FieldMapping[],
  profile: AnalysisProfile,
): MappingValidationResult {
  const errors: MappingIssue[] = [];
  const warnings: MappingIssue[] = [];
  const sourceByExactName = new Map<string, SourceColumn>();
  const sourceByNormalizedName = new Map<string, SourceColumn[]>();
  const uniqueSourceNames = new Set<string>();

  for (const column of sourceColumns) {
    if (!column.name.trim()) {
      errors.push(
        issue("INVALID_SOURCE_COLUMN", "error", "Source column names must not be blank.", {
          sourceColumn: column.name,
        }),
      );
      continue;
    }
    if (sourceByExactName.has(column.name)) {
      errors.push(
        issue(
          "DUPLICATE_SOURCE_COLUMN",
          "error",
          `Source metadata contains duplicate column '${column.name}'.`,
          { sourceColumn: column.name },
        ),
      );
    } else {
      sourceByExactName.set(column.name, column);
      uniqueSourceNames.add(column.name);
    }

    const normalized = normalizeFieldName(column.name);
    const bucket = sourceByNormalizedName.get(normalized) ?? [];
    bucket.push(column);
    sourceByNormalizedName.set(normalized, bucket);
  }

  const runtimeProfile = profile as string;
  if (!isAnalysisProfile(runtimeProfile)) {
    errors.push(
      issue("UNKNOWN_PROFILE", "error", `Unknown analysis profile '${runtimeProfile}'.`),
    );
  }

  const seenSources = new Map<string, number>();
  const seenTargets = new Map<string, number>();
  const mappedKnownSourceNames = new Set<string>();
  const validMappedFields = new Set<CanonicalFieldId>();

  mappings.forEach((mapping, mappingIndex) => {
    const normalizedSource = normalizeFieldName(mapping.sourceColumn);
    const exactSource = sourceByExactName.get(mapping.sourceColumn);
    const normalizedSources = sourceByNormalizedName.get(normalizedSource) ?? [];
    const source = exactSource ?? (normalizedSources.length === 1 ? normalizedSources[0] : undefined);
    const field = getCanonicalField(mapping.canonicalField);

    if (!source) {
      errors.push(
        issue(
          "UNKNOWN_SOURCE_COLUMN",
          "error",
          normalizedSources.length > 1
            ? `Source column '${mapping.sourceColumn}' is ambiguous after normalization.`
            : `Mapped source column '${mapping.sourceColumn}' does not exist in source metadata.`,
          { sourceColumn: mapping.sourceColumn, canonicalField: mapping.canonicalField },
        ),
      );
    }
    if (!field) {
      errors.push(
        issue(
          "UNKNOWN_CANONICAL_FIELD",
          "error",
          `Canonical field '${mapping.canonicalField}' is not in dictionary version ${DICTIONARY_VERSION}.`,
          { sourceColumn: mapping.sourceColumn, canonicalField: mapping.canonicalField },
        ),
      );
    }

    const sourceOccurrence = seenSources.get(normalizedSource);
    if (sourceOccurrence !== undefined) {
      errors.push(
        issue(
          "DUPLICATE_SOURCE_MAPPING",
          "error",
          `Source column '${mapping.sourceColumn}' is mapped more than once (entries ${sourceOccurrence + 1} and ${mappingIndex + 1}).`,
          { sourceColumn: mapping.sourceColumn, canonicalField: mapping.canonicalField },
        ),
      );
    } else {
      seenSources.set(normalizedSource, mappingIndex);
    }

    const targetOccurrence = seenTargets.get(mapping.canonicalField);
    if (targetOccurrence !== undefined) {
      errors.push(
        issue(
          "DUPLICATE_TARGET_MAPPING",
          "error",
          `Canonical field '${mapping.canonicalField}' is targeted more than once (entries ${targetOccurrence + 1} and ${mappingIndex + 1}).`,
          { sourceColumn: mapping.sourceColumn, canonicalField: mapping.canonicalField },
        ),
      );
    } else {
      seenTargets.set(mapping.canonicalField, mappingIndex);
    }

    if (!source || !field || sourceOccurrence !== undefined || targetOccurrence !== undefined) return;

    mappedKnownSourceNames.add(source.name);
    validMappedFields.add(field.id as CanonicalFieldId);
    const compatibility = compareTypes(source.type, field.logicalType);
    if (compatibility === "incompatible") {
      errors.push(
        issue(
          "TYPE_MISMATCH",
          "error",
          `Source type '${source.type}' is incompatible with '${field.id}' (${field.logicalType}).`,
          {
            sourceColumn: source.name,
            canonicalField: field.id,
            ...(source.type === undefined ? {} : { sourceType: source.type }),
            expectedType: field.logicalType,
          },
        ),
      );
    } else if (compatibility === "compatible") {
      warnings.push(
        issue(
          "TYPE_COERCION_REQUIRED",
          "warning",
          `Source type '${source.type}' requires an explicit coercion for '${field.id}' (${field.logicalType}).`,
          {
            sourceColumn: source.name,
            canonicalField: field.id,
            ...(source.type === undefined ? {} : { sourceType: source.type }),
            expectedType: field.logicalType,
          },
        ),
      );
    } else if (compatibility === "unknown") {
      warnings.push(
        issue(
          "SOURCE_TYPE_UNKNOWN",
          "warning",
          `Source type for '${source.name}' is missing or unrecognized; verify compatibility with '${field.id}'.`,
          {
            sourceColumn: source.name,
            canonicalField: field.id,
            ...(source.type === undefined ? {} : { sourceType: source.type }),
            expectedType: field.logicalType,
          },
        ),
      );
    }
  });

  const fields: readonly CanonicalFieldDefinition[] = CANONICAL_FIELDS;
  const requiredFields = isAnalysisProfile(runtimeProfile)
    ? fields.filter((field) => field.requiredFor.includes(runtimeProfile))
    : [];
  const missingRequiredFields = requiredFields
    .filter((field) => !validMappedFields.has(field.id as CanonicalFieldId))
    .map((field) => field.id as CanonicalFieldId);

  for (const fieldId of missingRequiredFields) {
    errors.push(
      issue(
        "MISSING_REQUIRED_FIELD",
        "error",
        `Required field '${fieldId}' is not mapped for the '${runtimeProfile}' profile.`,
        { canonicalField: fieldId },
      ),
    );
  }

  for (const sourceName of uniqueSourceNames) {
    if (!mappedKnownSourceNames.has(sourceName)) {
      warnings.push(
        issue(
          "UNMAPPED_SOURCE_COLUMN",
          "warning",
          `Source column '${sourceName}' is not mapped.`,
          { sourceColumn: sourceName },
        ),
      );
    }
  }

  const readiness: MappingReadiness =
    errors.length > 0 ? "not_ready" : warnings.length > 0 ? "needs_review" : "ready";
  return {
    profile,
    ready: errors.length === 0,
    readiness,
    errors,
    warnings,
    coverage: {
      sourceColumns: uniqueSourceNames.size,
      mappedSourceColumns: mappedKnownSourceNames.size,
      requiredFields: requiredFields.length,
      mappedRequiredFields: requiredFields.length - missingRequiredFields.length,
      missingRequiredFields,
    },
  };
}
