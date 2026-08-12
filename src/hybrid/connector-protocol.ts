import {
  createHash,
  createPublicKey,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
  type KeyObject
} from "node:crypto";

const PLAN_PREFIX = "ablc1";
const MAX_PLAN_BYTES = 64 * 1_024;
const MAX_TTL_SECONDS = 5 * 60;

export type ConnectorDeliveryMode = "full" | "delta" | "correction" | "backfill";
export type ConnectorPlanAction = "extract" | "investigate";
export type ConnectorScalar = null | boolean | string;

export type ConnectorFilterV1 =
  | {
      readonly type: "predicate";
      readonly field: string;
      readonly operator: "eq" | "ne" | "gt" | "gte" | "lt" | "lte";
      readonly value: ConnectorScalar;
    }
  | {
      readonly type: "predicate";
      readonly field: string;
      readonly operator: "in";
      readonly value: readonly ConnectorScalar[];
    }
  | {
      readonly type: "predicate";
      readonly field: string;
      readonly operator: "is_null";
    }
  | {
      readonly type: "and";
      readonly filters: readonly ConnectorFilterV1[];
    }
  | {
      readonly type: "or";
      readonly filters: readonly ConnectorFilterV1[];
    };

export interface ConnectorExtractionPlanV1 {
  readonly action: "extract";
  readonly sourceContractId: string;
  readonly sourceContractHash: string;
  readonly adapterDefinitionId: string;
  readonly adapterDefinitionHash: string;
  readonly deliveryMode: ConnectorDeliveryMode;
  readonly watermarkStart?: string;
  readonly watermarkEnd?: string;
  readonly maximumRows: number;
  readonly maximumBytes: number;
  readonly maximumExecutionMs: number;
}

export interface ConnectorInvestigationPlanV1 {
  readonly action: "investigate";
  readonly investigationId: string;
  readonly snapshotId: string;
  readonly certificationManifestId: string;
  readonly populationHash: string;
  readonly purposeHash: string;
  readonly requestedFields: readonly string[];
  readonly masks: Readonly<Record<string, "redact" | "tokenize" | "none">>;
  readonly filter: ConnectorFilterV1 | null;
  readonly rowOffset: number;
  readonly rowLimit: number;
  readonly maximumBytes: number;
  readonly maximumExecutionMs: number;
}

export type ConnectorPlanOperationV1 = ConnectorExtractionPlanV1 | ConnectorInvestigationPlanV1;

export interface ConnectorPlanClaimsV1 {
  readonly schemaVersion: 1;
  readonly planId: string;
  readonly nonce: string;
  readonly tenantId: string;
  readonly connectorId: string;
  readonly operation: ConnectorPlanOperationV1;
  readonly policyHash: string;
  readonly issuedAtEpochSeconds: number;
  readonly expiresAtEpochSeconds: number;
}

export interface IssueConnectorPlanInput {
  readonly tenantId: string;
  readonly connectorId: string;
  readonly operation: ConnectorPlanOperationV1;
  readonly policyHash: string;
  readonly ttlSeconds: number;
  readonly nowEpochSeconds?: number;
  readonly nonce?: string;
}

export interface ConnectorSigningKey {
  readonly keyId: string;
  readonly privateKey: KeyObject;
}

export interface ConnectorVerificationKey {
  readonly keyId: string;
  readonly publicKey: KeyObject;
}

export interface IssuedConnectorPlanV1 {
  readonly token: string;
  readonly claims: ConnectorPlanClaimsV1;
}

export interface ConnectorPlanReplayRecord {
  readonly replayKey: string;
  readonly planId: string;
  readonly tenantId: string;
  readonly connectorId: string;
  readonly expiresAtEpochSeconds: number;
}

export interface ConnectorReplayDefense {
  consumeOnce(record: ConnectorPlanReplayRecord): boolean | Promise<boolean>;
}

export type ConnectorProtocolErrorCode =
  | "INVALID_INPUT"
  | "INVALID_SIGNATURE"
  | "PLAN_EXPIRED"
  | "PLAN_NOT_YET_VALID"
  | "PLAN_BINDING_MISMATCH"
  | "PLAN_REPLAYED"
  | "REPLAY_DEFENSE_UNAVAILABLE";

export class ConnectorProtocolError extends Error {
  constructor(readonly code: ConnectorProtocolErrorCode, message: string) {
    super(message);
    this.name = "ConnectorProtocolError";
  }
}

export function createConnectorSigningKey(keyId: string, privateKey: KeyObject): ConnectorSigningKey {
  validateIdentifier(keyId, "key id");
  if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") invalid("Connector signing key must be an Ed25519 private key");
  return Object.freeze({ keyId, privateKey });
}

export function createConnectorVerificationKey(keyId: string, publicKey: KeyObject): ConnectorVerificationKey {
  validateIdentifier(keyId, "key id");
  const normalized = publicKey.type === "private" ? createPublicKey(publicKey) : publicKey;
  if (normalized.type !== "public" || normalized.asymmetricKeyType !== "ed25519") invalid("Connector verification key must be an Ed25519 public key");
  return Object.freeze({ keyId, publicKey: normalized });
}

export function issueConnectorPlan(
  key: ConnectorSigningKey,
  input: IssueConnectorPlanInput
): IssuedConnectorPlanV1 {
  if (!key || key.privateKey.type !== "private" || key.privateKey.asymmetricKeyType !== "ed25519") invalid("Invalid connector signing key");
  validateIdentifier(input.tenantId, "tenant id");
  validateIdentifier(input.connectorId, "connector id");
  validateHash(input.policyHash, "policy hash");
  const now = input.nowEpochSeconds ?? Math.floor(Date.now() / 1_000);
  validateEpoch(now, "issue time");
  validateInteger(input.ttlSeconds, "ttlSeconds", 1, MAX_TTL_SECONDS);
  validateOperation(input.operation);
  const nonce = input.nonce ?? `n${randomBytes(24).toString("base64url")}`;
  validateIdentifier(nonce, "nonce");
  const body = {
    schemaVersion: 1 as const,
    nonce,
    tenantId: input.tenantId,
    connectorId: input.connectorId,
    operation: input.operation,
    policyHash: input.policyHash,
    issuedAtEpochSeconds: now,
    expiresAtEpochSeconds: now + input.ttlSeconds
  };
  const planId = sha256(canonicalJson(body));
  const claims = deepFreeze({ ...body, planId });
  const payload = Buffer.from(canonicalJson(claims), "utf8");
  if (payload.byteLength > MAX_PLAN_BYTES) invalid("Connector plan exceeds maximum size");
  const payloadSegment = payload.toString("base64url");
  const signingInput = `${PLAN_PREFIX}.${key.keyId}.${payloadSegment}`;
  const signature = sign(null, Buffer.from(signingInput, "utf8"), key.privateKey).toString("base64url");
  return Object.freeze({ token: `${signingInput}.${signature}`, claims });
}

export async function verifyConnectorPlan(
  keys: readonly ConnectorVerificationKey[],
  token: string,
  expected: { readonly tenantId: string; readonly connectorId: string },
  replayDefense: ConnectorReplayDefense,
  options: { readonly nowEpochSeconds?: number; readonly clockSkewSeconds?: number } = {}
): Promise<ConnectorPlanClaimsV1> {
  validateIdentifier(expected.tenantId, "tenant id");
  validateIdentifier(expected.connectorId, "connector id");
  if (!replayDefense || typeof replayDefense.consumeOnce !== "function") {
    throw new ConnectorProtocolError("REPLAY_DEFENSE_UNAVAILABLE", "Connector replay defense is unavailable");
  }
  const pieces = typeof token === "string" ? token.split(".") : [];
  if (pieces.length !== 4 || pieces[0] !== PLAN_PREFIX) invalidSignature();
  const keyId = pieces[1]!;
  const payloadSegment = pieces[2]!;
  const signatureSegment = pieces[3]!;
  const key = keys.find((candidate) => secureEqual(candidate.keyId, keyId));
  let payload: Buffer;
  let signature: Buffer;
  try {
    payload = Buffer.from(payloadSegment, "base64url");
    signature = Buffer.from(signatureSegment, "base64url");
  } catch {
    invalidSignature();
  }
  if (
    payload.toString("base64url") !== payloadSegment ||
    signature.toString("base64url") !== signatureSegment
  ) {
    invalidSignature();
  }
  if (payload.byteLength < 2 || payload.byteLength > MAX_PLAN_BYTES || !key) invalidSignature();
  const valid = verify(
    null,
    Buffer.from(`${PLAN_PREFIX}.${keyId}.${payloadSegment}`, "utf8"),
    key.publicKey,
    signature
  );
  if (!valid) invalidSignature();
  let claims: ConnectorPlanClaimsV1;
  try {
    claims = JSON.parse(payload.toString("utf8")) as ConnectorPlanClaimsV1;
  } catch {
    invalidSignature();
  }
  validateClaims(claims);
  if (Buffer.from(canonicalJson(claims), "utf8").toString("base64url") !== payloadSegment) invalidSignature();
  const now = options.nowEpochSeconds ?? Math.floor(Date.now() / 1_000);
  const skew = options.clockSkewSeconds ?? 30;
  validateEpoch(now, "current time");
  validateInteger(skew, "clock skew", 0, 300);
  if (claims.issuedAtEpochSeconds > now + skew) throw new ConnectorProtocolError("PLAN_NOT_YET_VALID", "Connector plan is not yet valid");
  if (claims.expiresAtEpochSeconds <= now - skew) throw new ConnectorProtocolError("PLAN_EXPIRED", "Connector plan has expired");
  if (claims.expiresAtEpochSeconds - claims.issuedAtEpochSeconds > MAX_TTL_SECONDS) invalidSignature();
  if (!secureEqual(claims.tenantId, expected.tenantId) || !secureEqual(claims.connectorId, expected.connectorId)) {
    throw new ConnectorProtocolError("PLAN_BINDING_MISMATCH", "Connector plan belongs to another tenant or connector");
  }
  let first: boolean;
  try {
    first = await replayDefense.consumeOnce({
      replayKey: sha256(canonicalJson({ connectorId: claims.connectorId, nonce: claims.nonce, tenantId: claims.tenantId })),
      planId: claims.planId,
      tenantId: claims.tenantId,
      connectorId: claims.connectorId,
      expiresAtEpochSeconds: claims.expiresAtEpochSeconds
    });
  } catch {
    throw new ConnectorProtocolError("REPLAY_DEFENSE_UNAVAILABLE", "Connector replay defense is unavailable");
  }
  if (!first) throw new ConnectorProtocolError("PLAN_REPLAYED", "Connector plan was already consumed");
  return deepFreeze(claims);
}

function validateClaims(claims: ConnectorPlanClaimsV1): void {
  if (!claims || typeof claims !== "object" || claims.schemaVersion !== 1) invalidSignature();
  const keys = Object.keys(claims).sort();
  const expected = [
    "connectorId", "expiresAtEpochSeconds", "issuedAtEpochSeconds", "nonce", "operation",
    "planId", "policyHash", "schemaVersion", "tenantId"
  ].sort();
  if (keys.length !== expected.length || keys.some((value, index) => value !== expected[index])) invalidSignature();
  validateIdentifier(claims.planId, "plan id", true);
  validateIdentifier(claims.nonce, "nonce");
  validateIdentifier(claims.tenantId, "tenant id");
  validateIdentifier(claims.connectorId, "connector id");
  validateHash(claims.policyHash, "policy hash");
  validateEpoch(claims.issuedAtEpochSeconds, "issue time");
  validateEpoch(claims.expiresAtEpochSeconds, "expiry time");
  validateOperation(claims.operation);
  const { planId, ...body } = claims;
  if (!secureEqual(planId, sha256(canonicalJson(body)))) invalidSignature();
}

function validateOperation(operation: ConnectorPlanOperationV1): void {
  if (!operation || typeof operation !== "object") invalid("Connector operation is invalid");
  if (operation.action === "extract") {
    exactKeys(operation, [
      "action", "adapterDefinitionHash", "adapterDefinitionId", "deliveryMode", "maximumBytes",
      "maximumExecutionMs", "maximumRows", "sourceContractHash", "sourceContractId",
      ...(operation.watermarkStart === undefined ? [] : ["watermarkStart"]),
      ...(operation.watermarkEnd === undefined ? [] : ["watermarkEnd"])
    ]);
    validateIdentifier(operation.sourceContractId, "source contract id");
    validateHash(operation.sourceContractHash, "source contract hash");
    validateIdentifier(operation.adapterDefinitionId, "adapter definition id");
    validateHash(operation.adapterDefinitionHash, "adapter definition hash");
    if (!(["full", "delta", "correction", "backfill"] as const).includes(operation.deliveryMode)) invalid("Invalid delivery mode");
    if ((operation.watermarkStart === undefined) !== (operation.watermarkEnd === undefined)) invalid("Watermark bounds must be supplied together");
    if (operation.watermarkStart !== undefined && operation.watermarkEnd !== undefined && operation.watermarkStart > operation.watermarkEnd) invalid("Watermark range is inverted");
    validateInteger(operation.maximumRows, "maximumRows", 1, 10_000_000);
    validateInteger(operation.maximumBytes, "maximumBytes", 1_024, 10 * 1_024 * 1_024 * 1_024);
    validateInteger(operation.maximumExecutionMs, "maximumExecutionMs", 100, 60 * 60 * 1_000);
    return;
  }
  if (operation.action !== "investigate") invalid("Connector operation is invalid");
  exactKeys(operation, [
    "action", "certificationManifestId", "filter", "investigationId", "masks", "maximumBytes",
    "maximumExecutionMs", "populationHash", "purposeHash", "requestedFields", "rowLimit",
    "rowOffset", "snapshotId"
  ]);
  validateIdentifier(operation.investigationId, "investigation id");
  validateIdentifier(operation.snapshotId, "snapshot id");
  validateIdentifier(operation.certificationManifestId, "certification manifest id");
  validateHash(operation.populationHash, "population hash");
  validateHash(operation.purposeHash, "purpose hash");
  if (!Array.isArray(operation.requestedFields) || operation.requestedFields.length < 1 || operation.requestedFields.length > 20) invalid("Investigation fields are invalid");
  for (const field of operation.requestedFields) validateIdentifier(field, "requested field");
  if (new Set(operation.requestedFields).size !== operation.requestedFields.length) invalid("Investigation fields contain duplicates");
  exactKeys(operation.masks, [...operation.requestedFields]);
  for (const field of operation.requestedFields) {
    if (!(["redact", "tokenize", "none"] as const).includes(operation.masks[field]!)) invalid("Investigation mask is invalid");
  }
  validateFilter(operation.filter);
  validateInteger(operation.rowOffset, "rowOffset", 0, 999);
  validateInteger(operation.rowLimit, "rowLimit", 1, 100);
  if (operation.rowOffset + operation.rowLimit > 1_000) invalid("Investigation exceeds its total row budget");
  validateInteger(operation.maximumBytes, "maximumBytes", 1_024, 5 * 1_024 * 1_024);
  validateInteger(operation.maximumExecutionMs, "maximumExecutionMs", 100, 60_000);
}

function validateFilter(filter: ConnectorFilterV1 | null, depth = 0, count = { value: 0 }): void {
  if (filter === null) return;
  count.value += 1;
  if (depth > 5 || count.value > 50) invalid("Investigation filter exceeds bounds");
  if (filter.type === "and" || filter.type === "or") {
    exactKeys(filter, ["filters", "type"]);
    if (!Array.isArray(filter.filters) || filter.filters.length < 1 || filter.filters.length > 10) invalid("Investigation filter group is invalid");
    for (const nested of filter.filters) validateFilter(nested, depth + 1, count);
    return;
  }
  if (filter.type !== "predicate") invalid("Investigation filter is invalid");
  exactKeys(filter, ["field", "operator", "type", ...(filter.operator === "is_null" ? [] : ["value"])]);
  validateIdentifier(filter.field, "filter field");
  if (filter.operator === "is_null") return;
  if (filter.operator === "in") {
    if (!Array.isArray(filter.value) || filter.value.length < 1 || filter.value.length > 100) invalid("Investigation in-filter is invalid");
    for (const value of filter.value) validateScalar(value);
    return;
  }
  validateScalar(filter.value);
}

function validateScalar(value: unknown): void {
  if (value !== null && typeof value !== "boolean" && typeof value !== "string") invalid("Filter value is invalid");
  if (typeof value === "string" && value.length > 2_048) invalid("Filter value is too long");
}

function exactKeys(value: object, expected: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const normalized = [...expected].sort();
  if (actual.length !== normalized.length || actual.some((key, index) => key !== normalized[index])) invalid("Connector plan contains unsupported properties");
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) invalid("Connector plan numbers must be safe integers");
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(value as object).sort()) {
      const nested = (value as Record<string, unknown>)[key];
      if (nested !== undefined) result[key] = canonicalize(nested);
    }
    return result;
  }
  invalid("Connector plan is not canonical JSON");
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value as Record<string, unknown>)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

function validateIdentifier(value: string, label: string, hashOnly = false): void {
  if (hashOnly) {
    validateHash(value, label);
    return;
  }
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u.test(value)) invalid(`${label} is invalid`);
}

function validateHash(value: string, label: string): void {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) invalid(`${label} must be a lowercase SHA-256 hash`);
}

function validateInteger(value: number, label: string, minimum: number, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalid(`${label} must be an integer from ${minimum} through ${maximum}`);
}

function validateEpoch(value: number, label: string): void {
  validateInteger(value, label, 0, 9_007_199_254_740_991);
}

function secureEqual(left: string, right: string): boolean {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function invalid(message: string): never {
  throw new ConnectorProtocolError("INVALID_INPUT", message);
}

function invalidSignature(): never {
  throw new ConnectorProtocolError("INVALID_SIGNATURE", "Connector plan is invalid");
}
