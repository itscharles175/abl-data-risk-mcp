import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import {
  assertActivePrincipal,
  assertVerifiedPrincipalContext,
  principalBinding,
  type VerifiedPrincipalContext,
} from "./identity.js";
import {
  assertPermitDecision,
  type FieldMask,
  type PermitPolicyDecision,
  type PolicyObligations,
} from "./policy.js";

const keyRingBrand: unique symbol = Symbol("HmacKeyRing");
const KEY_RINGS = new WeakMap<object, InternalKeyRing>();
const DUMMY_VERIFICATION_KEY = Buffer.alloc(32, 0xa5);
const PLAN_PREFIX = "ablp1";
const HANDLE_PREFIX = "ablh1";
const MAX_PLAN_TTL_SECONDS = 15 * 60;
const MAX_HANDLE_TTL_SECONDS = 7 * 24 * 60 * 60;
const MAX_PAYLOAD_BYTES = 64 * 1_024;

export interface HmacKeyDefinition {
  readonly id: string;
  /** At least 256 bits from a secret manager or KMS-derived key. */
  readonly secret: Uint8Array;
  readonly notBeforeEpochSeconds?: number;
  readonly notAfterEpochSeconds?: number;
}

interface InternalKey {
  readonly id: string;
  readonly secret: Buffer;
  readonly notBeforeEpochSeconds?: number;
  readonly notAfterEpochSeconds?: number;
}

interface InternalKeyRing {
  readonly currentKeyId: string;
  readonly keys: ReadonlyMap<string, InternalKey>;
}

export interface HmacKeyRing {
  readonly [keyRingBrand]: true;
  readonly currentKeyId: string;
  readonly keyIds: readonly string[];
}

export type SignedArtifactErrorCode =
  | "INVALID_KEY_RING"
  | "INVALID_PLAN_INPUT"
  | "INVALID_ARTIFACT"
  | "ARTIFACT_NOT_YET_VALID"
  | "ARTIFACT_EXPIRED"
  | "IDENTITY_MISMATCH"
  | "EXPECTATION_MISMATCH"
  | "REPLAY_DETECTED"
  | "REPLAY_DEFENSE_FAILED";

export class SignedArtifactError extends Error {
  readonly code: SignedArtifactErrorCode;

  constructor(code: SignedArtifactErrorCode, message: string) {
    super(message);
    this.name = "SignedArtifactError";
    this.code = code;
  }
}

export function createHmacKeyRing(
  keys: readonly HmacKeyDefinition[],
  currentKeyId: string,
): HmacKeyRing {
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > 32) {
    invalidKeyRing("key ring must contain between 1 and 32 keys");
  }
  const normalizedCurrentKeyId = identifier(currentKeyId, "current key id", "INVALID_KEY_RING");
  const internalKeys = new Map<string, InternalKey>();
  for (const definition of keys) {
    const id = identifier(definition.id, "key id", "INVALID_KEY_RING");
    if (internalKeys.has(id)) invalidKeyRing(`duplicate key id: ${id}`);
    if (!(definition.secret instanceof Uint8Array) || definition.secret.byteLength < 32) {
      invalidKeyRing(`key ${id} must contain at least 32 bytes`);
    }
    const notBeforeEpochSeconds = optionalEpoch(
      definition.notBeforeEpochSeconds,
      `key ${id} notBeforeEpochSeconds`,
      "INVALID_KEY_RING",
    );
    const notAfterEpochSeconds = optionalEpoch(
      definition.notAfterEpochSeconds,
      `key ${id} notAfterEpochSeconds`,
      "INVALID_KEY_RING",
    );
    if (
      notBeforeEpochSeconds !== undefined &&
      notAfterEpochSeconds !== undefined &&
      notBeforeEpochSeconds >= notAfterEpochSeconds
    ) {
      invalidKeyRing(`key ${id} validity window is invalid`);
    }
    internalKeys.set(
      id,
      Object.freeze({
        id,
        secret: Buffer.from(definition.secret),
        ...(notBeforeEpochSeconds === undefined ? {} : { notBeforeEpochSeconds }),
        ...(notAfterEpochSeconds === undefined ? {} : { notAfterEpochSeconds }),
      }),
    );
  }
  if (!internalKeys.has(normalizedCurrentKeyId)) {
    invalidKeyRing("current key id is not present in the key ring");
  }

  const ring = Object.freeze({
    [keyRingBrand]: true as const,
    currentKeyId: normalizedCurrentKeyId,
    keyIds: Object.freeze([...internalKeys.keys()].sort()),
  });
  KEY_RINGS.set(
    ring,
    Object.freeze({ currentKeyId: normalizedCurrentKeyId, keys: internalKeys }),
  );
  return ring;
}

export interface ExecutionPlanSpec {
  readonly operation: string;
  /** Fingerprint of canonical, validated operation parameters; never raw SQL. */
  readonly parameterFingerprint: string;
  readonly schemaFingerprint: string;
  readonly snapshotFingerprint?: string;
  readonly mappingFingerprint?: string;
  readonly recipeFingerprint?: string;
}

export interface ExecutionPlanClaims {
  readonly version: 1;
  readonly nonce: string;
  readonly tenantId: string;
  readonly principalBinding: string;
  readonly authorizationDecisionId: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly policyFingerprint: string;
  readonly toolName: string;
  readonly datasetId: string;
  readonly requestedFields: readonly string[];
  readonly obligations: PolicyObligations;
  readonly operation: string;
  readonly parameterFingerprint: string;
  readonly schemaFingerprint: string;
  readonly snapshotFingerprint?: string;
  readonly mappingFingerprint?: string;
  readonly recipeFingerprint?: string;
  readonly issuedAtEpochSeconds: number;
  readonly expiresAtEpochSeconds: number;
}

export interface IssueExecutionPlanInput {
  readonly principal: VerifiedPrincipalContext;
  readonly authorization: PermitPolicyDecision;
  readonly spec: ExecutionPlanSpec;
  readonly ttlSeconds: number;
  readonly nowEpochSeconds?: number;
  /** Test seam. Production callers should omit this and use cryptographic randomness. */
  readonly nonce?: string;
  readonly maxDecisionAgeSeconds?: number;
}

export interface IssuedExecutionPlan {
  readonly token: string;
  readonly planId: string;
  readonly claims: ExecutionPlanClaims;
}

export function issueExecutionPlan(
  keyRing: HmacKeyRing,
  input: IssueExecutionPlanInput,
): IssuedExecutionPlan {
  const internal = requireKeyRing(keyRing);
  assertVerifiedPrincipalContext(input.principal);
  assertPermitDecision(input.authorization);
  const now = input.nowEpochSeconds ?? currentEpochSeconds();
  epoch(now, "nowEpochSeconds", "INVALID_PLAN_INPUT");
  assertActivePrincipal(input.principal, now);

  if (
    !secureTextEqual(input.authorization.principalBinding, principalBinding(input.principal)) ||
    !secureTextEqual(input.authorization.tenantId, input.principal.tenantId)
  ) {
    invalidPlan("permit decision does not belong to the verified principal");
  }
  const maximumDecisionAge = boundedInteger(
    input.maxDecisionAgeSeconds ?? 60,
    "maxDecisionAgeSeconds",
    0,
    MAX_PLAN_TTL_SECONDS,
    "INVALID_PLAN_INPUT",
  );
  if (
    input.authorization.evaluatedAtEpochSeconds > now ||
    now - input.authorization.evaluatedAtEpochSeconds > maximumDecisionAge
  ) {
    invalidPlan("permit decision is stale or from the future");
  }

  const ttlSeconds = boundedInteger(
    input.ttlSeconds,
    "ttlSeconds",
    1,
    MAX_PLAN_TTL_SECONDS,
    "INVALID_PLAN_INPUT",
  );
  const expiresAtEpochSeconds = now + ttlSeconds;
  if (expiresAtEpochSeconds > input.principal.expiresAtEpochSeconds) {
    invalidPlan("execution plan cannot outlive the verified credential");
  }

  const key = internal.keys.get(internal.currentKeyId);
  if (!key || !keyIsUsableAt(key, now)) invalidKeyRing("current signing key is not active");
  if (
    key.notAfterEpochSeconds !== undefined &&
    expiresAtEpochSeconds > key.notAfterEpochSeconds
  ) {
    invalidPlan("execution plan cannot outlive the signing key");
  }
  const snapshotFingerprint = optionalFingerprint(
    input.spec.snapshotFingerprint,
    "snapshotFingerprint",
    "INVALID_PLAN_INPUT",
  );
  if (input.authorization.obligations.requireImmutableSnapshot && snapshotFingerprint === undefined) {
    invalidPlan("policy requires an immutable snapshot fingerprint");
  }

  const claims = freezePlanClaims({
    version: 1,
    nonce: nonce(input.nonce),
    tenantId: input.authorization.tenantId,
    principalBinding: input.authorization.principalBinding,
    authorizationDecisionId: fingerprint(
      input.authorization.decisionId,
      "authorizationDecisionId",
      "INVALID_PLAN_INPUT",
    ),
    policyId: identifier(input.authorization.policyId, "policyId", "INVALID_PLAN_INPUT"),
    policyVersion: text(input.authorization.policyVersion, "policyVersion", 128, "INVALID_PLAN_INPUT"),
    policyFingerprint: fingerprint(
      input.authorization.policyFingerprint,
      "policyFingerprint",
      "INVALID_PLAN_INPUT",
    ),
    toolName: identifier(input.authorization.toolName, "toolName", "INVALID_PLAN_INPUT"),
    datasetId: identifier(input.authorization.datasetId, "datasetId", "INVALID_PLAN_INPUT"),
    requestedFields: normalizedIdentifiers(
      input.authorization.requestedFields,
      "requestedFields",
      "INVALID_PLAN_INPUT",
    ),
    obligations: cloneObligations(input.authorization.obligations, "INVALID_PLAN_INPUT"),
    operation: identifier(input.spec.operation, "operation", "INVALID_PLAN_INPUT"),
    parameterFingerprint: fingerprint(
      input.spec.parameterFingerprint,
      "parameterFingerprint",
      "INVALID_PLAN_INPUT",
    ),
    schemaFingerprint: fingerprint(
      input.spec.schemaFingerprint,
      "schemaFingerprint",
      "INVALID_PLAN_INPUT",
    ),
    ...(snapshotFingerprint === undefined ? {} : { snapshotFingerprint }),
    ...optionalFingerprintProperty(
      "mappingFingerprint",
      input.spec.mappingFingerprint,
      "INVALID_PLAN_INPUT",
    ),
    ...optionalFingerprintProperty(
      "recipeFingerprint",
      input.spec.recipeFingerprint,
      "INVALID_PLAN_INPUT",
    ),
    issuedAtEpochSeconds: now,
    expiresAtEpochSeconds,
  });

  const payload = encodeBase64Url(Buffer.from(stableJson(claims), "utf8"));
  const signingInput = `${PLAN_PREFIX}.${key.id}.${payload}`;
  const signature = hmac(key.secret, signingInput);
  const token = `${signingInput}.${encodeBase64Url(signature)}`;
  return Object.freeze({ token, planId: sha256(token), claims });
}

export interface ReplayRecord {
  /** Stable consume-once key. Implementations must enforce uniqueness on this value. */
  readonly replayKey: string;
  readonly planId: string;
  readonly nonce: string;
  readonly tenantId: string;
  readonly principalBinding: string;
  readonly expiresAtEpochSeconds: number;
}

/**
 * Implementations must atomically insert `replayKey` if absent and retain it
 * through `expiresAtEpochSeconds`. Return true only for the first consume.
 * A separate `has` then `put` sequence is unsafe because concurrent workers can race.
 */
export interface ReplayDefense {
  consumeOnce(record: ReplayRecord): boolean | Promise<boolean>;
}

export interface ExecutionPlanExpectations {
  readonly toolName?: string;
  readonly datasetId?: string;
  readonly operation?: string;
  readonly parameterFingerprint?: string;
  readonly schemaFingerprint?: string;
  readonly policyFingerprint?: string;
  readonly snapshotFingerprint?: string;
}

export interface VerifyExecutionPlanOptions {
  readonly nowEpochSeconds?: number;
  readonly clockSkewSeconds?: number;
  readonly expected?: ExecutionPlanExpectations;
}

export interface VerifiedExecutionPlan {
  readonly planId: string;
  readonly claims: ExecutionPlanClaims;
}

export async function verifyExecutionPlan(
  keyRing: HmacKeyRing,
  token: string,
  principal: VerifiedPrincipalContext,
  replayDefense: ReplayDefense,
  options: VerifyExecutionPlanOptions = {},
): Promise<VerifiedExecutionPlan> {
  const internal = requireKeyRing(keyRing);
  assertVerifiedPrincipalContext(principal);
  if (!replayDefense || typeof replayDefense.consumeOnce !== "function") {
    throw new SignedArtifactError(
      "REPLAY_DEFENSE_FAILED",
      "Execution plan verification requires replay defense",
    );
  }
  const now = options.nowEpochSeconds ?? currentEpochSeconds();
  epoch(now, "nowEpochSeconds", "INVALID_ARTIFACT");
  const skew = boundedInteger(
    options.clockSkewSeconds ?? 30,
    "clockSkewSeconds",
    0,
    300,
    "INVALID_ARTIFACT",
  );
  const parts = splitArtifact(token, PLAN_PREFIX, 4);
  const keyId = parts[1] ?? invalidArtifact();
  const payloadSegment = parts[2] ?? invalidArtifact();
  const signatureSegment = parts[3] ?? invalidArtifact();
  const signingInput = `${PLAN_PREFIX}.${keyId}.${payloadSegment}`;
  const key = internal.keys.get(keyId);
  verifyMacOrThrow(key?.secret ?? DUMMY_VERIFICATION_KEY, signingInput, signatureSegment, Boolean(key));
  if (!key) invalidArtifact();

  const payloadBytes = decodeBase64Url(payloadSegment, MAX_PAYLOAD_BYTES);
  if (!payloadBytes) invalidArtifact();
  let parsed: unknown;
  try {
    parsed = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    invalidArtifact();
  }
  const claims = parsePlanClaims(parsed);
  if (encodeBase64Url(Buffer.from(stableJson(claims), "utf8")) !== payloadSegment) {
    invalidArtifact();
  }
  validateArtifactWindow(
    claims.issuedAtEpochSeconds,
    claims.expiresAtEpochSeconds,
    now,
    skew,
    MAX_PLAN_TTL_SECONDS,
  );
  if (!keyIsUsableForArtifact(key, claims.issuedAtEpochSeconds, now, skew)) invalidArtifact();
  assertActivePrincipal(principal, now, skew);
  if (
    !secureTextEqual(claims.principalBinding, principalBinding(principal)) ||
    !secureTextEqual(claims.tenantId, principal.tenantId)
  ) {
    throw new SignedArtifactError("IDENTITY_MISMATCH", "Execution plan is bound to another identity");
  }
  assertExpectations(claims, options.expected);

  const planId = sha256(token);
  let consumed: boolean;
  try {
    consumed = await replayDefense.consumeOnce(
      Object.freeze({
        replayKey: sha256(
          stableJson({
            nonce: claims.nonce,
            principalBinding: claims.principalBinding,
            tenantId: claims.tenantId,
          }),
        ),
        planId,
        nonce: claims.nonce,
        tenantId: claims.tenantId,
        principalBinding: claims.principalBinding,
        expiresAtEpochSeconds: claims.expiresAtEpochSeconds,
      }),
    );
  } catch {
    throw new SignedArtifactError("REPLAY_DEFENSE_FAILED", "Replay defense was unavailable");
  }
  if (consumed !== true) {
    throw new SignedArtifactError("REPLAY_DETECTED", "Execution plan was already consumed");
  }

  return Object.freeze({ planId, claims });
}

export type OpaqueHandleKind = "result" | "job";

export interface IssuePrincipalBoundHandleInput {
  readonly kind: OpaqueHandleKind;
  readonly principal: VerifiedPrincipalContext;
  readonly ttlSeconds: number;
  readonly nowEpochSeconds?: number;
  /** Test seam. Production callers should omit this and use cryptographic randomness. */
  readonly handleId?: string;
}

export interface PrincipalBoundHandleRecord {
  readonly handleId: string;
  readonly kind: OpaqueHandleKind;
  readonly tenantId: string;
  readonly principalBinding: string;
  readonly issuedAtEpochSeconds: number;
  readonly expiresAtEpochSeconds: number;
}

export interface IssuedPrincipalBoundHandle {
  /** Public opaque capability. It contains no resource ID, tenant, or principal ID. */
  readonly handle: string;
  /** Store this metadata with the result/job record under `handleId`. */
  readonly record: PrincipalBoundHandleRecord;
}

export function issuePrincipalBoundHandle(
  keyRing: HmacKeyRing,
  input: IssuePrincipalBoundHandleInput,
): IssuedPrincipalBoundHandle {
  const internal = requireKeyRing(keyRing);
  assertVerifiedPrincipalContext(input.principal);
  const now = input.nowEpochSeconds ?? currentEpochSeconds();
  epoch(now, "nowEpochSeconds", "INVALID_PLAN_INPUT");
  assertActivePrincipal(input.principal, now);
  const ttl = boundedInteger(
    input.ttlSeconds,
    "ttlSeconds",
    1,
    MAX_HANDLE_TTL_SECONDS,
    "INVALID_PLAN_INPUT",
  );
  const key = internal.keys.get(internal.currentKeyId);
  if (!key || !keyIsUsableAt(key, now)) invalidKeyRing("current signing key is not active");
  const handleId = opaqueId(input.handleId, "handleId");
  const expiresAtEpochSeconds = now + ttl;
  if (
    key.notAfterEpochSeconds !== undefined &&
    expiresAtEpochSeconds > key.notAfterEpochSeconds
  ) {
    invalidPlan("principal-bound handle cannot outlive the signing key");
  }
  const kindCode = input.kind === "result" ? "r" : input.kind === "job" ? "j" : invalidPlan("invalid handle kind");
  const publicPart = `${HANDLE_PREFIX}.${key.id}.${kindCode}.${handleId}.${now}.${expiresAtEpochSeconds}`;
  const binding = principalBinding(input.principal);
  const macInput = stableJson({
    publicPart,
    principalBinding: binding,
    tenantId: input.principal.tenantId,
  });
  const handle = `${publicPart}.${encodeBase64Url(hmac(key.secret, macInput))}`;
  const record = Object.freeze({
    handleId,
    kind: input.kind,
    tenantId: input.principal.tenantId,
    principalBinding: binding,
    issuedAtEpochSeconds: now,
    expiresAtEpochSeconds,
  });
  return Object.freeze({ handle, record });
}

export interface VerifyPrincipalBoundHandleOptions {
  readonly nowEpochSeconds?: number;
  readonly clockSkewSeconds?: number;
  readonly expectedKind?: OpaqueHandleKind;
}

export function verifyPrincipalBoundHandle(
  keyRing: HmacKeyRing,
  handle: string,
  principal: VerifiedPrincipalContext,
  options: VerifyPrincipalBoundHandleOptions = {},
): PrincipalBoundHandleRecord {
  const internal = requireKeyRing(keyRing);
  assertVerifiedPrincipalContext(principal);
  const now = options.nowEpochSeconds ?? currentEpochSeconds();
  epoch(now, "nowEpochSeconds", "INVALID_ARTIFACT");
  const skew = boundedInteger(
    options.clockSkewSeconds ?? 30,
    "clockSkewSeconds",
    0,
    300,
    "INVALID_ARTIFACT",
  );
  const parts = splitArtifact(handle, HANDLE_PREFIX, 7);
  const keyId = parts[1] ?? invalidArtifact();
  const kindCode = parts[2] ?? invalidArtifact();
  const rawHandleId = parts[3] ?? invalidArtifact();
  const issuedText = parts[4] ?? invalidArtifact();
  const expiresText = parts[5] ?? invalidArtifact();
  const signatureSegment = parts[6] ?? invalidArtifact();
  const kind: OpaqueHandleKind = kindCode === "r" ? "result" : kindCode === "j" ? "job" : invalidArtifact();
  const issuedAtEpochSeconds = decimalEpoch(issuedText);
  const expiresAtEpochSeconds = decimalEpoch(expiresText);
  const handleId = opaqueId(rawHandleId, "handleId", false);
  const publicPart = parts.slice(0, 6).join(".");
  const binding = principalBinding(principal);
  const macInput = stableJson({
    publicPart,
    principalBinding: binding,
    tenantId: principal.tenantId,
  });
  const key = internal.keys.get(keyId);
  verifyMacOrThrow(key?.secret ?? DUMMY_VERIFICATION_KEY, macInput, signatureSegment, Boolean(key));
  if (!key || !keyIsUsableForArtifact(key, issuedAtEpochSeconds, now, skew)) invalidArtifact();
  validateArtifactWindow(
    issuedAtEpochSeconds,
    expiresAtEpochSeconds,
    now,
    skew,
    MAX_HANDLE_TTL_SECONDS,
  );
  assertActivePrincipal(principal, now, skew);
  if (options.expectedKind !== undefined && options.expectedKind !== kind) {
    throw new SignedArtifactError("EXPECTATION_MISMATCH", "Handle kind did not match expectation");
  }
  return Object.freeze({
    handleId,
    kind,
    tenantId: principal.tenantId,
    principalBinding: binding,
    issuedAtEpochSeconds,
    expiresAtEpochSeconds,
  });
}

function parsePlanClaims(value: unknown): ExecutionPlanClaims {
  const record = objectRecord(value);
  exactKeys(record, [
    "authorizationDecisionId",
    "datasetId",
    "expiresAtEpochSeconds",
    "issuedAtEpochSeconds",
    "mappingFingerprint",
    "nonce",
    "obligations",
    "operation",
    "parameterFingerprint",
    "policyFingerprint",
    "policyId",
    "policyVersion",
    "principalBinding",
    "recipeFingerprint",
    "requestedFields",
    "schemaFingerprint",
    "snapshotFingerprint",
    "tenantId",
    "toolName",
    "version",
  ]);
  if (record.version !== 1) invalidArtifact();
  return freezePlanClaims({
    version: 1,
    nonce: nonce(text(record.nonce, "nonce", 256, "INVALID_ARTIFACT"), false),
    tenantId: identifier(record.tenantId, "tenantId", "INVALID_ARTIFACT"),
    principalBinding: fingerprint(record.principalBinding, "principalBinding", "INVALID_ARTIFACT"),
    authorizationDecisionId: fingerprint(
      record.authorizationDecisionId,
      "authorizationDecisionId",
      "INVALID_ARTIFACT",
    ),
    policyId: identifier(record.policyId, "policyId", "INVALID_ARTIFACT"),
    policyVersion: text(record.policyVersion, "policyVersion", 128, "INVALID_ARTIFACT"),
    policyFingerprint: fingerprint(record.policyFingerprint, "policyFingerprint", "INVALID_ARTIFACT"),
    toolName: identifier(record.toolName, "toolName", "INVALID_ARTIFACT"),
    datasetId: identifier(record.datasetId, "datasetId", "INVALID_ARTIFACT"),
    requestedFields: normalizedIdentifiers(
      arrayOfStrings(record.requestedFields),
      "requestedFields",
      "INVALID_ARTIFACT",
    ),
    obligations: cloneObligations(parseObligations(record.obligations), "INVALID_ARTIFACT"),
    operation: identifier(record.operation, "operation", "INVALID_ARTIFACT"),
    parameterFingerprint: fingerprint(
      record.parameterFingerprint,
      "parameterFingerprint",
      "INVALID_ARTIFACT",
    ),
    schemaFingerprint: fingerprint(record.schemaFingerprint, "schemaFingerprint", "INVALID_ARTIFACT"),
    ...optionalFingerprintProperty(
      "snapshotFingerprint",
      record.snapshotFingerprint,
      "INVALID_ARTIFACT",
    ),
    ...optionalFingerprintProperty(
      "mappingFingerprint",
      record.mappingFingerprint,
      "INVALID_ARTIFACT",
    ),
    ...optionalFingerprintProperty(
      "recipeFingerprint",
      record.recipeFingerprint,
      "INVALID_ARTIFACT",
    ),
    issuedAtEpochSeconds: epoch(record.issuedAtEpochSeconds, "issuedAtEpochSeconds", "INVALID_ARTIFACT"),
    expiresAtEpochSeconds: epoch(record.expiresAtEpochSeconds, "expiresAtEpochSeconds", "INVALID_ARTIFACT"),
  });
}

function freezePlanClaims(claims: ExecutionPlanClaims): ExecutionPlanClaims {
  return Object.freeze({
    ...claims,
    requestedFields: Object.freeze([...claims.requestedFields]),
    obligations: cloneObligations(claims.obligations, "INVALID_PLAN_INPUT"),
  });
}

function parseObligations(value: unknown): PolicyObligations {
  const record = objectRecord(value);
  exactKeys(record, [
    "allowExport",
    "allowRawRows",
    "auditTags",
    "fieldMasks",
    "maxExecutionMs",
    "maxResultBytes",
    "maxResultRows",
    "minimumCohortSize",
    "requireImmutableSnapshot",
    "rowFilterRefs",
  ]);
  return {
    maxResultRows: positiveInteger(record.maxResultRows, "maxResultRows", "INVALID_ARTIFACT"),
    maxResultBytes: positiveInteger(record.maxResultBytes, "maxResultBytes", "INVALID_ARTIFACT"),
    maxExecutionMs: positiveInteger(record.maxExecutionMs, "maxExecutionMs", "INVALID_ARTIFACT"),
    minimumCohortSize: positiveInteger(
      record.minimumCohortSize,
      "minimumCohortSize",
      "INVALID_ARTIFACT",
    ),
    requireImmutableSnapshot: booleanValue(record.requireImmutableSnapshot),
    allowRawRows: booleanValue(record.allowRawRows),
    allowExport: booleanValue(record.allowExport),
    rowFilterRefs: arrayOfStrings(record.rowFilterRefs),
    fieldMasks: parseMasks(record.fieldMasks),
    auditTags: arrayOfStrings(record.auditTags),
  };
}

function cloneObligations(
  obligations: PolicyObligations,
  code: "INVALID_PLAN_INPUT" | "INVALID_ARTIFACT",
): PolicyObligations {
  return Object.freeze({
    maxResultRows: positiveInteger(obligations.maxResultRows, "maxResultRows", code),
    maxResultBytes: positiveInteger(obligations.maxResultBytes, "maxResultBytes", code),
    maxExecutionMs: positiveInteger(obligations.maxExecutionMs, "maxExecutionMs", code),
    minimumCohortSize: positiveInteger(obligations.minimumCohortSize, "minimumCohortSize", code),
    requireImmutableSnapshot: booleanValue(obligations.requireImmutableSnapshot, code),
    allowRawRows: booleanValue(obligations.allowRawRows, code),
    allowExport: booleanValue(obligations.allowExport, code),
    rowFilterRefs: Object.freeze(normalizedIdentifiers(obligations.rowFilterRefs, "rowFilterRefs", code)),
    fieldMasks: Object.freeze(parseMasks(obligations.fieldMasks, code)),
    auditTags: Object.freeze(normalizedIdentifiers(obligations.auditTags, "auditTags", code)),
  });
}

function parseMasks(
  value: unknown,
  code: "INVALID_PLAN_INPUT" | "INVALID_ARTIFACT" = "INVALID_ARTIFACT",
): Record<string, FieldMask> {
  const record = objectRecord(value, code);
  const masks: Record<string, FieldMask> = {};
  for (const [fieldName, rawMask] of Object.entries(record)) {
    const field = identifier(fieldName, "mask field", code);
    if (rawMask !== "partial" && rawMask !== "hash" && rawMask !== "tokenize" && rawMask !== "redact") {
      artifactError(code, "Invalid field mask");
    }
    masks[field] = rawMask;
  }
  return Object.fromEntries(Object.entries(masks).sort(([left], [right]) => left.localeCompare(right)));
}

function assertExpectations(
  claims: ExecutionPlanClaims,
  expected: ExecutionPlanExpectations | undefined,
): void {
  if (!expected) return;
  const comparisons: readonly [unknown, string, string][] = [
    [expected.toolName, claims.toolName, "toolName"],
    [expected.datasetId, claims.datasetId, "datasetId"],
    [expected.operation, claims.operation, "operation"],
    [expected.parameterFingerprint, claims.parameterFingerprint, "parameterFingerprint"],
    [expected.schemaFingerprint, claims.schemaFingerprint, "schemaFingerprint"],
    [expected.policyFingerprint, claims.policyFingerprint, "policyFingerprint"],
    [expected.snapshotFingerprint, claims.snapshotFingerprint ?? "", "snapshotFingerprint"],
  ];
  for (const [rawExpected, actual, label] of comparisons) {
    if (rawExpected === undefined) continue;
    const normalized = label.endsWith("Fingerprint")
      ? fingerprint(rawExpected, label, "INVALID_ARTIFACT")
      : identifier(rawExpected, label, "INVALID_ARTIFACT");
    if (!secureTextEqual(normalized, actual)) {
      throw new SignedArtifactError("EXPECTATION_MISMATCH", `${label} did not match execution context`);
    }
  }
}

function validateArtifactWindow(
  issuedAt: number,
  expiresAt: number,
  now: number,
  skew: number,
  maximumTtl: number,
): void {
  if (expiresAt <= issuedAt || expiresAt - issuedAt > maximumTtl) invalidArtifact();
  if (issuedAt > now + skew) {
    throw new SignedArtifactError("ARTIFACT_NOT_YET_VALID", "Signed artifact is not yet valid");
  }
  if (now - skew >= expiresAt) {
    throw new SignedArtifactError("ARTIFACT_EXPIRED", "Signed artifact has expired");
  }
}

function keyIsUsableAt(key: InternalKey, now: number): boolean {
  return (
    (key.notBeforeEpochSeconds === undefined || now >= key.notBeforeEpochSeconds) &&
    (key.notAfterEpochSeconds === undefined || now < key.notAfterEpochSeconds)
  );
}

function keyIsUsableForArtifact(
  key: InternalKey,
  issuedAt: number,
  now: number,
  skew: number,
): boolean {
  return (
    (key.notBeforeEpochSeconds === undefined || issuedAt + skew >= key.notBeforeEpochSeconds) &&
    (key.notAfterEpochSeconds === undefined || (issuedAt < key.notAfterEpochSeconds && now - skew < key.notAfterEpochSeconds))
  );
}

function verifyMacOrThrow(
  secret: Buffer,
  input: string,
  signatureSegment: string,
  knownKey: boolean,
): void {
  const expected = hmac(secret, input);
  const supplied = decodeSignature(signatureSegment);
  const fixedLength = Buffer.alloc(expected.byteLength);
  supplied.copy(fixedLength, 0, 0, Math.min(supplied.byteLength, fixedLength.byteLength));
  const equal = timingSafeEqual(expected, fixedLength);
  if (!knownKey || supplied.byteLength !== expected.byteLength || !equal) invalidArtifact();
}

function hmac(secret: Buffer, input: string): Buffer {
  return createHmac("sha256", secret).update(input).digest();
}

function secureTextEqual(left: string, right: string): boolean {
  const leftDigest = createHash("sha256").update(left).digest();
  const rightDigest = createHash("sha256").update(right).digest();
  return timingSafeEqual(leftDigest, rightDigest);
}

function splitArtifact(value: unknown, prefix: string, count: number): string[] {
  if (typeof value !== "string" || value.length === 0 || value.length > 100_000) invalidArtifact();
  const parts = value.split(".");
  if (parts.length !== count || parts[0] !== prefix || parts.some((part) => !part)) invalidArtifact();
  identifier(parts[1], "key id", "INVALID_ARTIFACT");
  return parts;
}

function decodeSignature(value: string): Buffer {
  return decodeBase64Url(value, 128) ?? Buffer.alloc(0);
}

function decodeBase64Url(value: string, maximumBytes: number): Buffer | undefined {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return undefined;
  try {
    const decoded = Buffer.from(value, "base64url");
    if (decoded.byteLength > maximumBytes || decoded.toString("base64url") !== value) return undefined;
    return decoded;
  } catch {
    return undefined;
  }
}

function encodeBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function nonce(value?: string, generate = true): string {
  const resolved = value ?? (generate ? randomBytes(24).toString("base64url") : "");
  if (!/^[A-Za-z0-9_-]{22,128}$/.test(resolved)) invalidPlan("nonce is invalid");
  return resolved;
}

function opaqueId(value?: string, label = "opaque id", generate = true): string {
  const resolved = value ?? (generate ? randomBytes(24).toString("base64url") : "");
  if (!/^[A-Za-z0-9_-]{22,128}$/.test(resolved)) {
    if (generate) invalidPlan(`${label} is invalid`);
    invalidArtifact();
  }
  return resolved;
}

function optionalFingerprintProperty<K extends string>(
  key: K,
  value: unknown,
  code: "INVALID_PLAN_INPUT" | "INVALID_ARTIFACT",
): { readonly [P in K]?: string } {
  if (value === undefined) return {};
  return { [key]: fingerprint(value, key, code) } as { readonly [P in K]?: string };
}

function optionalFingerprint(
  value: unknown,
  label: string,
  code: "INVALID_PLAN_INPUT" | "INVALID_ARTIFACT",
): string | undefined {
  return value === undefined ? undefined : fingerprint(value, label, code);
}

function fingerprint(
  value: unknown,
  label: string,
  code: "INVALID_PLAN_INPUT" | "INVALID_ARTIFACT",
): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    artifactError(code, `${label} must be a lowercase SHA-256 fingerprint`);
  }
  return value;
}

function normalizedIdentifiers(
  values: readonly string[],
  label: string,
  code: "INVALID_PLAN_INPUT" | "INVALID_ARTIFACT",
): string[] {
  if (!Array.isArray(values) || values.length > 10_000) artifactError(code, `${label} is invalid`);
  return [...new Set(values.map((value) => identifier(value, label, code)))].sort();
}

function identifier(
  value: unknown,
  label: string,
  code: "INVALID_KEY_RING" | "INVALID_PLAN_INPUT" | "INVALID_ARTIFACT",
): string {
  const normalized = text(value, label, 512, code);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(normalized)) artifactError(code, `${label} is invalid`);
  return normalized;
}

function text(
  value: unknown,
  label: string,
  maximumLength: number,
  code: "INVALID_KEY_RING" | "INVALID_PLAN_INPUT" | "INVALID_ARTIFACT",
): string {
  if (typeof value !== "string") artifactError(code, `${label} must be a string`);
  const normalized = value.trim();
  if (
    !normalized ||
    normalized.length > maximumLength ||
    /[\u0000-\u001f\u007f]/.test(normalized)
  ) {
    artifactError(code, `${label} is invalid`);
  }
  return normalized;
}

function epoch(
  value: unknown,
  label: string,
  code: "INVALID_PLAN_INPUT" | "INVALID_ARTIFACT",
): number {
  return boundedInteger(value, label, 0, Number.MAX_SAFE_INTEGER, code);
}

function optionalEpoch(
  value: unknown,
  label: string,
  code: "INVALID_KEY_RING",
): number | undefined {
  return value === undefined ? undefined : boundedInteger(value, label, 0, Number.MAX_SAFE_INTEGER, code);
}

function decimalEpoch(value: string): number {
  if (!/^(0|[1-9][0-9]{0,15})$/.test(value)) invalidArtifact();
  return epoch(Number(value), "epoch", "INVALID_ARTIFACT");
}

function positiveInteger(
  value: unknown,
  label: string,
  code: "INVALID_PLAN_INPUT" | "INVALID_ARTIFACT",
): number {
  return boundedInteger(value, label, 1, Number.MAX_SAFE_INTEGER, code);
}

function boundedInteger(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number,
  code: "INVALID_KEY_RING" | "INVALID_PLAN_INPUT" | "INVALID_ARTIFACT",
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    artifactError(code, `${label} must be an integer from ${minimum} to ${maximum}`);
  }
  return value as number;
}

function booleanValue(
  value: unknown,
  code: "INVALID_PLAN_INPUT" | "INVALID_ARTIFACT" = "INVALID_ARTIFACT",
): boolean {
  if (typeof value !== "boolean") artifactError(code, "Expected boolean");
  return value;
}

function arrayOfStrings(value: unknown): readonly string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) invalidArtifact();
  return value;
}

function objectRecord(
  value: unknown,
  code: "INVALID_PLAN_INPUT" | "INVALID_ARTIFACT" = "INVALID_ARTIFACT",
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) artifactError(code, "Expected object");
  return value as Record<string, unknown>;
}

function exactKeys(record: Record<string, unknown>, allowedKeys: readonly string[]): void {
  const allowed = new Set(allowedKeys);
  if (Object.keys(record).some((key) => !allowed.has(key))) invalidArtifact();
  const required = allowedKeys.filter(
    (key) => !["mappingFingerprint", "recipeFingerprint", "snapshotFingerprint"].includes(key),
  );
  if (required.some((key) => !(key in record))) invalidArtifact();
}

function stableJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) invalidArtifact();
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
  invalidArtifact();
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function currentEpochSeconds(): number {
  return Math.floor(Date.now() / 1_000);
}

function requireKeyRing(keyRing: HmacKeyRing): InternalKeyRing {
  const internal = keyRing && typeof keyRing === "object" ? KEY_RINGS.get(keyRing) : undefined;
  if (!internal) invalidKeyRing("operation requires a runtime-created key ring");
  return internal;
}

function artifactError(
  code: "INVALID_KEY_RING" | "INVALID_PLAN_INPUT" | "INVALID_ARTIFACT",
  message: string,
): never {
  throw new SignedArtifactError(code, message);
}

function invalidKeyRing(message: string): never {
  throw new SignedArtifactError("INVALID_KEY_RING", message);
}

function invalidPlan(message: string): never {
  throw new SignedArtifactError("INVALID_PLAN_INPUT", message);
}

function invalidArtifact(): never {
  throw new SignedArtifactError("INVALID_ARTIFACT", "Signed artifact is invalid");
}
