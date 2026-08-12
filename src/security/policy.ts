import { createHash } from "node:crypto";

import {
  assertActivePrincipal,
  assertVerifiedPrincipalContext,
  hasAllScopes,
  IdentityContextError,
  principalBinding,
  type VerifiedPrincipalContext,
} from "./identity.js";

const compiledPolicyBrand: unique symbol = Symbol("CompiledAuthorizationPolicy");
const COMPILED_POLICIES = new WeakSet<object>();
const ISSUED_DECISIONS = new WeakSet<object>();

export type FieldMask = "partial" | "hash" | "tokenize" | "redact";
export type PolicyEffect = "permit" | "deny";

export interface PolicyObligations {
  readonly maxResultRows: number;
  readonly maxResultBytes: number;
  /**
   * Bounds read/analysis execution and pre-commit validation. A completed
   * idempotent control mutation is acknowledged with a compact byte-bounded
   * receipt instead of being retroactively reported as a timeout.
   */
  readonly maxExecutionMs: number;
  readonly minimumCohortSize: number;
  readonly requireImmutableSnapshot: boolean;
  readonly allowRawRows: boolean;
  readonly allowExport: boolean;
  /** Opaque server-side filter identifiers. They are ANDed by the executor. */
  readonly rowFilterRefs: readonly string[];
  readonly fieldMasks: Readonly<Record<string, FieldMask>>;
  readonly auditTags: readonly string[];
}

export interface PolicyObligationOverrides {
  readonly maxResultRows?: number;
  readonly maxResultBytes?: number;
  readonly maxExecutionMs?: number;
  readonly minimumCohortSize?: number;
  readonly requireImmutableSnapshot?: boolean;
  readonly allowRawRows?: boolean;
  readonly allowExport?: boolean;
  readonly rowFilterRefs?: readonly string[];
  readonly fieldMasks?: Readonly<Record<string, FieldMask>>;
  readonly auditTags?: readonly string[];
}

export interface PolicyRule {
  readonly id: string;
  readonly effect: PolicyEffect;
  /** Exact tenant IDs or the sole value `*`. Required to prevent accidental global rules. */
  readonly tenantIds: readonly string[];
  readonly principalIds?: readonly string[];
  /** Exact MCP tool names or the sole value `*`. */
  readonly tools: readonly string[];
  /** Exact governed dataset IDs or the sole value `*`. */
  readonly datasets: readonly string[];
  readonly purposes?: readonly string[];
  /** Omit or use `*` to cover every requested field. */
  readonly fields?: readonly string[];
  /** Permit rules match only when all scopes are present. Deny rules cannot be scope-conditioned. */
  readonly requiredScopes?: readonly string[];
  readonly obligations?: PolicyObligationOverrides;
}

export interface AuthorizationPolicyDocument {
  readonly id: string;
  readonly version: string;
  readonly defaultObligations: PolicyObligations;
  readonly rules: readonly PolicyRule[];
}

interface NormalizedPolicyRule {
  readonly id: string;
  readonly effect: PolicyEffect;
  readonly tenantIds: readonly string[];
  readonly principalIds?: readonly string[];
  readonly tools: readonly string[];
  readonly datasets: readonly string[];
  readonly purposes?: readonly string[];
  readonly fields?: readonly string[];
  readonly requiredScopes: readonly string[];
  readonly obligations?: PolicyObligationOverrides;
}

export interface CompiledAuthorizationPolicy {
  readonly [compiledPolicyBrand]: true;
  readonly id: string;
  readonly version: string;
  readonly fingerprint: string;
  readonly defaultObligations: PolicyObligations;
  readonly rules: readonly NormalizedPolicyRule[];
}

export interface GovernedDatasetRef {
  readonly id: string;
  /** Resolved from server-side registry metadata, never a tool-supplied authority. */
  readonly tenantId: string;
}

export interface PolicyEvaluationRequest {
  readonly principal: VerifiedPrincipalContext;
  readonly toolName: string;
  readonly dataset: GovernedDatasetRef;
  /** Executor-derived field set. Pass an explicit empty array only for a genuinely fieldless operation. */
  readonly fields: readonly string[];
  readonly purpose?: string;
  readonly nowEpochSeconds?: number;
}

export type PolicyDenyCode =
  | "IDENTITY_INACTIVE"
  | "CROSS_TENANT"
  | "EXPLICIT_DENY"
  | "MISSING_SCOPE"
  | "NO_MATCHING_PERMIT"
  | "FIELD_NOT_PERMITTED";

export interface PolicyDenyReason {
  readonly code: PolicyDenyCode;
  readonly message: string;
  readonly fields?: readonly string[];
  readonly scopes?: readonly string[];
}

interface PolicyDecisionBase {
  readonly decisionId: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly policyFingerprint: string;
  readonly principalBinding: string;
  readonly tenantId: string;
  readonly toolName: string;
  readonly datasetId: string;
  readonly requestedFields: readonly string[];
  readonly purpose?: string;
  readonly evaluatedAtEpochSeconds: number;
  readonly matchedRuleIds: readonly string[];
}

export interface PermitPolicyDecision extends PolicyDecisionBase {
  readonly effect: "permit";
  readonly obligations: PolicyObligations;
}

export interface DenyPolicyDecision extends PolicyDecisionBase {
  readonly effect: "deny";
  readonly reasons: readonly PolicyDenyReason[];
}

export type PolicyDecision = PermitPolicyDecision | DenyPolicyDecision;

export type PolicyValidationErrorCode =
  | "INVALID_POLICY"
  | "UNCOMPILED_POLICY"
  | "UNISSUED_POLICY_DECISION"
  | "POLICY_DENIED";

export class PolicyValidationError extends Error {
  readonly code: PolicyValidationErrorCode;

  constructor(code: PolicyValidationErrorCode, message: string) {
    super(message);
    this.name = "PolicyValidationError";
    this.code = code;
  }
}

export function compileAuthorizationPolicy(
  document: AuthorizationPolicyDocument,
): CompiledAuthorizationPolicy {
  const id = identifier(document.id, "policy id");
  const version = text(document.version, "policy version", 128);
  const defaultObligations = normalizeObligations(document.defaultObligations, "default obligations");
  if (!Array.isArray(document.rules) || document.rules.length === 0 || document.rules.length > 10_000) {
    invalidPolicy("policy must contain between 1 and 10000 rules");
  }

  const seenRuleIds = new Set<string>();
  const rules = document.rules
    .map((rule) => normalizeRule(rule))
    .sort((left, right) => left.id.localeCompare(right.id));
  for (const rule of rules) {
    if (seenRuleIds.has(rule.id)) invalidPolicy(`duplicate policy rule id: ${rule.id}`);
    seenRuleIds.add(rule.id);
  }

  const normalizedDocument = {
    defaultObligations,
    id,
    rules,
    version,
  };
  const fingerprint = sha256(stableJson(normalizedDocument));
  const compiled = Object.freeze({
    [compiledPolicyBrand]: true as const,
    id,
    version,
    fingerprint,
    defaultObligations,
    rules: Object.freeze(rules),
  });
  COMPILED_POLICIES.add(compiled);
  return compiled;
}

export function isCompiledAuthorizationPolicy(
  value: unknown,
): value is CompiledAuthorizationPolicy {
  return Boolean(value && typeof value === "object" && COMPILED_POLICIES.has(value));
}

export function evaluatePolicy(
  policy: CompiledAuthorizationPolicy,
  request: PolicyEvaluationRequest,
): PolicyDecision {
  if (!isCompiledAuthorizationPolicy(policy)) {
    throw new PolicyValidationError(
      "UNCOMPILED_POLICY",
      "Authorization requires a runtime-compiled policy",
    );
  }
  assertVerifiedPrincipalContext(request.principal);

  const evaluatedAtEpochSeconds = request.nowEpochSeconds ?? currentEpochSeconds();
  integer(evaluatedAtEpochSeconds, "nowEpochSeconds", 0);
  const toolName = identifier(request.toolName, "tool name");
  const datasetId = identifier(request.dataset.id, "dataset id");
  const datasetTenantId = identifier(request.dataset.tenantId, "dataset tenant id");
  const requestedFields = normalizedIdentifiers(request.fields, "requested fields", false);
  const purpose = request.purpose === undefined ? undefined : identifier(request.purpose, "purpose");
  const binding = principalBinding(request.principal);

  const decisionContext = {
    policyId: policy.id,
    policyVersion: policy.version,
    policyFingerprint: policy.fingerprint,
    principalBinding: binding,
    tenantId: request.principal.tenantId,
    toolName,
    datasetId,
    requestedFields,
    ...(purpose === undefined ? {} : { purpose }),
    evaluatedAtEpochSeconds,
  };

  try {
    assertActivePrincipal(request.principal, evaluatedAtEpochSeconds);
  } catch (error) {
    if (!(error instanceof IdentityContextError)) throw error;
    return denyDecision(decisionContext, [], [
      { code: "IDENTITY_INACTIVE", message: "Verified identity is not active" },
    ]);
  }

  if (datasetTenantId !== request.principal.tenantId) {
    return denyDecision(decisionContext, [], [
      { code: "CROSS_TENANT", message: "Dataset tenant does not match verified identity tenant" },
    ]);
  }

  const baseMatchingRules = policy.rules.filter((rule) =>
    baseRuleMatches(rule, request.principal, toolName, datasetId, purpose),
  );
  const denyingRules = baseMatchingRules.filter(
    (rule) => rule.effect === "deny" && denyFieldsMatch(rule.fields, requestedFields),
  );
  if (denyingRules.length > 0) {
    const deniedFields = requestedFields.filter((field) =>
      denyingRules.some((rule) => selectorMatches(rule.fields, field)),
    );
    return denyDecision(decisionContext, denyingRules.map((rule) => rule.id), [
      {
        code: "EXPLICIT_DENY",
        message: "A matching policy rule explicitly denied the request",
        ...(deniedFields.length === 0 ? {} : { fields: Object.freeze(deniedFields) }),
      },
    ]);
  }

  const basePermits = baseMatchingRules.filter((rule) => rule.effect === "permit");
  const scopedPermits = basePermits.filter((rule) =>
    hasAllScopes(request.principal, rule.requiredScopes),
  );

  if (scopedPermits.length === 0) {
    const missingScopes = normalizedIdentifiers(
      basePermits.flatMap((rule) =>
        rule.requiredScopes.filter((scope) => !request.principal.scopes.includes(scope)),
      ),
      "missing scopes",
      false,
    );
    return denyDecision(decisionContext, [], [
      missingScopes.length > 0
        ? {
            code: "MISSING_SCOPE",
            message: "Verified identity lacks a scope required by matching permit rules",
            scopes: Object.freeze(missingScopes),
          }
        : {
            code: "NO_MATCHING_PERMIT",
            message: "No policy rule permits this tool and dataset",
          },
    ]);
  }

  const applicablePermits = scopedPermits.filter(
    (rule) => requestedFields.length === 0 || requestedFields.some((field) => selectorMatches(rule.fields, field)),
  );
  const uncoveredFields = requestedFields.filter(
    (field) => !applicablePermits.some((rule) => selectorMatches(rule.fields, field)),
  );
  if (uncoveredFields.length > 0 || applicablePermits.length === 0) {
    return denyDecision(decisionContext, [], [
      {
        code: "FIELD_NOT_PERMITTED",
        message: "One or more requested fields are not covered by a permit rule",
        fields: Object.freeze(uncoveredFields.length > 0 ? uncoveredFields : requestedFields),
      },
    ]);
  }

  const obligations = applicablePermits.reduce(
    (current, rule) => mergeObligations(current, rule.obligations),
    policy.defaultObligations,
  );
  return permitDecision(
    decisionContext,
    applicablePermits.map((rule) => rule.id),
    obligations,
  );
}

export function assertPermitDecision(
  decision: PolicyDecision,
): asserts decision is PermitPolicyDecision {
  if (!ISSUED_DECISIONS.has(decision)) {
    throw new PolicyValidationError(
      "UNISSUED_POLICY_DECISION",
      "Execution requires a runtime-issued policy decision",
    );
  }
  if (decision.effect !== "permit") {
    throw new PolicyValidationError("POLICY_DENIED", "Execution requires a permit decision");
  }
}

function normalizeRule(rule: PolicyRule): NormalizedPolicyRule {
  const id = identifier(rule.id, "rule id");
  if (rule.effect !== "permit" && rule.effect !== "deny") invalidPolicy(`rule ${id} has invalid effect`);
  const tenantIds = normalizedSelector(rule.tenantIds, `rule ${id} tenantIds`);
  const tools = normalizedSelector(rule.tools, `rule ${id} tools`);
  const datasets = normalizedSelector(rule.datasets, `rule ${id} datasets`);
  const principalIds = optionalSelector(rule.principalIds, `rule ${id} principalIds`);
  const purposes = optionalSelector(rule.purposes, `rule ${id} purposes`);
  const fields = optionalSelector(rule.fields, `rule ${id} fields`);
  const requiredScopes = normalizedIdentifiers(rule.requiredScopes ?? [], `rule ${id} requiredScopes`, false);
  if (rule.effect === "deny" && requiredScopes.length > 0) {
    invalidPolicy(`deny rule ${id} cannot be conditioned on scopes`);
  }
  const obligations =
    rule.obligations === undefined
      ? undefined
      : normalizeObligationOverrides(rule.obligations, `rule ${id} obligations`);
  if (rule.effect === "deny" && obligations !== undefined) {
    invalidPolicy(`deny rule ${id} cannot define obligations`);
  }

  return Object.freeze({
    id,
    effect: rule.effect,
    tenantIds: Object.freeze(tenantIds),
    ...(principalIds === undefined ? {} : { principalIds: Object.freeze(principalIds) }),
    tools: Object.freeze(tools),
    datasets: Object.freeze(datasets),
    ...(purposes === undefined ? {} : { purposes: Object.freeze(purposes) }),
    ...(fields === undefined ? {} : { fields: Object.freeze(fields) }),
    requiredScopes: Object.freeze(requiredScopes),
    ...(obligations === undefined ? {} : { obligations }),
  });
}

function normalizeObligations(value: PolicyObligations, label: string): PolicyObligations {
  return Object.freeze({
    maxResultRows: positiveInteger(value.maxResultRows, `${label}.maxResultRows`),
    maxResultBytes: positiveInteger(value.maxResultBytes, `${label}.maxResultBytes`),
    maxExecutionMs: positiveInteger(value.maxExecutionMs, `${label}.maxExecutionMs`),
    minimumCohortSize: positiveInteger(value.minimumCohortSize, `${label}.minimumCohortSize`),
    requireImmutableSnapshot: booleanValue(
      value.requireImmutableSnapshot,
      `${label}.requireImmutableSnapshot`,
    ),
    allowRawRows: booleanValue(value.allowRawRows, `${label}.allowRawRows`),
    allowExport: booleanValue(value.allowExport, `${label}.allowExport`),
    rowFilterRefs: Object.freeze(normalizedIdentifiers(value.rowFilterRefs, `${label}.rowFilterRefs`, false)),
    fieldMasks: Object.freeze(normalizedMasks(value.fieldMasks, `${label}.fieldMasks`)),
    auditTags: Object.freeze(normalizedIdentifiers(value.auditTags, `${label}.auditTags`, false)),
  });
}

function normalizeObligationOverrides(
  value: PolicyObligationOverrides,
  label: string,
): PolicyObligationOverrides {
  return Object.freeze({
    ...(value.maxResultRows === undefined
      ? {}
      : { maxResultRows: positiveInteger(value.maxResultRows, `${label}.maxResultRows`) }),
    ...(value.maxResultBytes === undefined
      ? {}
      : { maxResultBytes: positiveInteger(value.maxResultBytes, `${label}.maxResultBytes`) }),
    ...(value.maxExecutionMs === undefined
      ? {}
      : { maxExecutionMs: positiveInteger(value.maxExecutionMs, `${label}.maxExecutionMs`) }),
    ...(value.minimumCohortSize === undefined
      ? {}
      : {
          minimumCohortSize: positiveInteger(
            value.minimumCohortSize,
            `${label}.minimumCohortSize`,
          ),
        }),
    ...(value.requireImmutableSnapshot === undefined
      ? {}
      : {
          requireImmutableSnapshot: booleanValue(
            value.requireImmutableSnapshot,
            `${label}.requireImmutableSnapshot`,
          ),
        }),
    ...(value.allowRawRows === undefined
      ? {}
      : { allowRawRows: booleanValue(value.allowRawRows, `${label}.allowRawRows`) }),
    ...(value.allowExport === undefined
      ? {}
      : { allowExport: booleanValue(value.allowExport, `${label}.allowExport`) }),
    ...(value.rowFilterRefs === undefined
      ? {}
      : {
          rowFilterRefs: Object.freeze(
            normalizedIdentifiers(value.rowFilterRefs, `${label}.rowFilterRefs`, false),
          ),
        }),
    ...(value.fieldMasks === undefined
      ? {}
      : { fieldMasks: Object.freeze(normalizedMasks(value.fieldMasks, `${label}.fieldMasks`)) }),
    ...(value.auditTags === undefined
      ? {}
      : {
          auditTags: Object.freeze(
            normalizedIdentifiers(value.auditTags, `${label}.auditTags`, false),
          ),
        }),
  });
}

function mergeObligations(
  current: PolicyObligations,
  overrides?: PolicyObligationOverrides,
): PolicyObligations {
  if (overrides === undefined) return current;
  const masks: Record<string, FieldMask> = { ...current.fieldMasks };
  for (const [field, mask] of Object.entries(overrides.fieldMasks ?? {})) {
    const existing = masks[field];
    masks[field] = existing === undefined ? mask : strongerMask(existing, mask);
  }

  return Object.freeze({
    maxResultRows: Math.min(current.maxResultRows, overrides.maxResultRows ?? Number.MAX_SAFE_INTEGER),
    maxResultBytes: Math.min(
      current.maxResultBytes,
      overrides.maxResultBytes ?? Number.MAX_SAFE_INTEGER,
    ),
    maxExecutionMs: Math.min(
      current.maxExecutionMs,
      overrides.maxExecutionMs ?? Number.MAX_SAFE_INTEGER,
    ),
    minimumCohortSize: Math.max(current.minimumCohortSize, overrides.minimumCohortSize ?? 0),
    requireImmutableSnapshot:
      current.requireImmutableSnapshot || (overrides.requireImmutableSnapshot ?? false),
    allowRawRows: current.allowRawRows && (overrides.allowRawRows ?? true),
    allowExport: current.allowExport && (overrides.allowExport ?? true),
    rowFilterRefs: Object.freeze(
      normalizedIdentifiers(
        [...current.rowFilterRefs, ...(overrides.rowFilterRefs ?? [])],
        "merged rowFilterRefs",
        false,
      ),
    ),
    fieldMasks: Object.freeze(masks),
    auditTags: Object.freeze(
      normalizedIdentifiers(
        [...current.auditTags, ...(overrides.auditTags ?? [])],
        "merged auditTags",
        false,
      ),
    ),
  });
}

function permitDecision(
  context: Omit<PolicyDecisionBase, "decisionId" | "matchedRuleIds">,
  matchedRuleIds: readonly string[],
  obligations: PolicyObligations,
): PermitPolicyDecision {
  const normalizedRuleIds = normalizedIdentifiers(matchedRuleIds, "matched rule ids", false);
  const payload = {
    ...context,
    effect: "permit" as const,
    matchedRuleIds: normalizedRuleIds,
    obligations,
  };
  const decision = Object.freeze({
    decisionId: sha256(stableJson(payload)),
    ...payload,
    requestedFields: Object.freeze([...context.requestedFields]),
    matchedRuleIds: Object.freeze(normalizedRuleIds),
  });
  ISSUED_DECISIONS.add(decision);
  return decision;
}

function denyDecision(
  context: Omit<PolicyDecisionBase, "decisionId" | "matchedRuleIds">,
  matchedRuleIds: readonly string[],
  reasons: readonly PolicyDenyReason[],
): DenyPolicyDecision {
  const normalizedRuleIds = normalizedIdentifiers(matchedRuleIds, "matched rule ids", false);
  const frozenReasons = Object.freeze(reasons.map((reason) => Object.freeze(reason)));
  const payload = {
    ...context,
    effect: "deny" as const,
    matchedRuleIds: normalizedRuleIds,
    reasons: frozenReasons,
  };
  const decision = Object.freeze({
    decisionId: sha256(stableJson(payload)),
    ...payload,
    requestedFields: Object.freeze([...context.requestedFields]),
    matchedRuleIds: Object.freeze(normalizedRuleIds),
  });
  ISSUED_DECISIONS.add(decision);
  return decision;
}

function baseRuleMatches(
  rule: NormalizedPolicyRule,
  principal: VerifiedPrincipalContext,
  toolName: string,
  datasetId: string,
  purpose?: string,
): boolean {
  return (
    selectorMatches(rule.tenantIds, principal.tenantId) &&
    selectorMatches(rule.principalIds, principal.principalId) &&
    selectorMatches(rule.tools, toolName) &&
    selectorMatches(rule.datasets, datasetId) &&
    (rule.purposes === undefined ||
      (purpose !== undefined && selectorMatches(rule.purposes, purpose)))
  );
}

function denyFieldsMatch(
  ruleFields: readonly string[] | undefined,
  requestedFields: readonly string[],
): boolean {
  if (ruleFields === undefined || ruleFields.includes("*")) return true;
  return requestedFields.some((field) => ruleFields.includes(field));
}

function selectorMatches(selector: readonly string[] | undefined, value: string): boolean {
  return selector === undefined || selector.includes("*") || selector.includes(value);
}

function normalizedSelector(values: readonly string[], label: string): string[] {
  if (!Array.isArray(values) || values.length === 0) invalidPolicy(`${label} must not be empty`);
  const normalized = normalizedIdentifiers(values, label, true);
  if (normalized.includes("*") && normalized.length !== 1) {
    invalidPolicy(`${label} cannot combine * with exact values`);
  }
  return normalized;
}

function optionalSelector(
  values: readonly string[] | undefined,
  label: string,
): string[] | undefined {
  if (values === undefined) return undefined;
  return normalizedSelector(values, label);
}

function normalizedIdentifiers(
  values: readonly string[],
  label: string,
  allowWildcard: boolean,
): string[] {
  if (!Array.isArray(values) || values.length > 10_000) invalidPolicy(`${label} must be a bounded array`);
  const normalized = values.map((value) => {
    if (allowWildcard && value === "*") return value;
    return identifier(value, label);
  });
  return [...new Set(normalized)].sort();
}

function normalizedMasks(
  masks: Readonly<Record<string, FieldMask>>,
  label: string,
): Record<string, FieldMask> {
  if (!masks || typeof masks !== "object" || Array.isArray(masks)) {
    invalidPolicy(`${label} must be an object`);
  }
  const normalized: Record<string, FieldMask> = {};
  for (const [field, mask] of Object.entries(masks)) {
    const fieldId = identifier(field, `${label} field`);
    if (!MASK_STRENGTH.has(mask)) invalidPolicy(`${label}.${fieldId} has invalid mask`);
    normalized[fieldId] = mask;
  }
  return Object.fromEntries(Object.entries(normalized).sort(([left], [right]) => left.localeCompare(right)));
}

const MASK_STRENGTH = new Map<FieldMask, number>([
  ["partial", 1],
  ["hash", 2],
  ["tokenize", 3],
  ["redact", 4],
]);

function strongerMask(left: FieldMask, right: FieldMask): FieldMask {
  return (MASK_STRENGTH.get(left) ?? 0) >= (MASK_STRENGTH.get(right) ?? 0) ? left : right;
}

function identifier(value: unknown, label: string): string {
  const normalized = text(value, label, 512);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(normalized)) invalidPolicy(`${label} is invalid`);
  return normalized;
}

function text(value: unknown, label: string, maximumLength: number): string {
  if (typeof value !== "string") invalidPolicy(`${label} must be a string`);
  const normalized = value.trim();
  if (
    !normalized ||
    normalized.length > maximumLength ||
    /[\u0000-\u001f\u007f]/.test(normalized)
  ) {
    invalidPolicy(`${label} is invalid`);
  }
  return normalized;
}

function positiveInteger(value: unknown, label: string): number {
  return integer(value, label, 1);
}

function integer(value: unknown, label: string, minimum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    invalidPolicy(`${label} must be an integer >= ${minimum}`);
  }
  return value as number;
}

function booleanValue(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") invalidPolicy(`${label} must be boolean`);
  return value;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function stableJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) invalidPolicy("policy contains a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => stableJson(item)).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`)
      .join(",")}}`;
  }
  invalidPolicy("policy contains an unsupported value");
}

function currentEpochSeconds(): number {
  return Math.floor(Date.now() / 1_000);
}

function invalidPolicy(message: string): never {
  throw new PolicyValidationError("INVALID_POLICY", message);
}
