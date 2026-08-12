import { createHash, createHmac, timingSafeEqual } from "node:crypto";

import { Decimal } from "decimal.js";

import type {
  InvestigationFilter,
  InvestigationMask,
  InvestigationRecord,
  InvestigationReference,
  InvestigationRepository,
  InvestigationScalar
} from "../control/investigations.js";
import { getCanonicalField } from "../domain/dictionary.js";
import { FIELD_POLICY_VERSION, getCanonicalFieldPolicy } from "../domain/field-policy.js";
import {
  assertActivePrincipal,
  assertVerifiedPrincipalContext,
  principalBinding,
  requireScopes,
  type VerifiedPrincipalContext
} from "../security/identity.js";

export interface CertifiedInvestigationDataset {
  readonly tenantId: string;
  readonly reference: InvestigationReference;
  readonly certificationManifestId: string;
  readonly populationHash: string;
  readonly fields: readonly string[];
  readonly records: readonly Readonly<Record<string, InvestigationScalar>>[];
}

export interface InvestigationDataProvider {
  loadCertifiedDataset(
    tenantId: string,
    reference: InvestigationReference
  ): Promise<CertifiedInvestigationDataset> | CertifiedInvestigationDataset;
}

export interface CreateInvestigationInput {
  readonly reference: InvestigationReference;
  readonly requestedFields: readonly string[];
  readonly filter?: InvestigationFilter;
  readonly purpose: string;
  readonly reason: string;
  readonly rowBudget?: number;
  readonly reviewerPrincipalId?: string;
  readonly idempotencyKey: string;
}

export interface InvestigationPage {
  readonly investigationId: string;
  readonly rows: readonly Readonly<Record<string, InvestigationScalar>>[];
  readonly nextCursor: string | null;
  readonly disclosedRows: number;
  readonly remainingRowBudget: number;
  readonly populationHash: string;
  readonly masks: Readonly<Record<string, InvestigationMask>>;
  readonly disclosureHistoryFingerprint: string;
}

export interface InvestigationServiceOptions {
  readonly cursorKey: Uint8Array;
  readonly maskingKey: Uint8Array;
  readonly clock?: () => Date;
  readonly maximumDatasetRows?: number;
}

export type InvestigationServiceErrorCode =
  | "INVALID_INPUT"
  | "NOT_FOUND"
  | "FORBIDDEN"
  | "EXPIRED"
  | "DATASET_NOT_CERTIFIED"
  | "DATASET_CHANGED"
  | "ROW_BUDGET_EXCEEDED";

export class InvestigationServiceError extends Error {
  constructor(readonly code: InvestigationServiceErrorCode, message: string) {
    super(message);
    this.name = "InvestigationServiceError";
  }
}

/** Governs purpose-bound, masked and disclosure-accounted record investigation. */
export class InvestigationService {
  readonly #repository: InvestigationRepository;
  readonly #provider: InvestigationDataProvider;
  readonly #cursorKey: Buffer;
  readonly #maskingKey: Buffer;
  readonly #clock: () => Date;
  readonly #maximumDatasetRows: number;

  constructor(
    repository: InvestigationRepository,
    provider: InvestigationDataProvider,
    options: InvestigationServiceOptions
  ) {
    this.#repository = repository;
    this.#provider = provider;
    this.#cursorKey = key(options.cursorKey, "cursorKey");
    this.#maskingKey = key(options.maskingKey, "maskingKey");
    this.#clock = options.clock ?? (() => new Date());
    this.#maximumDatasetRows = integer(options.maximumDatasetRows ?? 1_000_000, "maximumDatasetRows", 1, 1_000_000);
  }

  async create(principal: VerifiedPrincipalContext, input: CreateInvestigationInput): Promise<InvestigationRecord> {
    this.#assertPrincipal(principal);
    validateCreateInput(input);
    const dataset = await this.#loadDataset(principal.tenantId, input.reference);
    const requestedFields = normalizeFields(input.requestedFields);
    const available = new Set(dataset.fields);
    for (const field of requestedFields) {
      if (!available.has(field) || !getCanonicalField(field)) invalid("Requested field is not available in the certified dataset");
    }
    const filter = input.filter ?? null;
    if (filter !== null) validateFilter(filter, available);
    const masks = Object.fromEntries(
      requestedFields.map((field) => [field, maskForField(field)] as const)
    ) as Readonly<Record<string, InvestigationMask>>;
    const now = this.#now();
    const expiresAt = new Date(now.getTime() + 15 * 60 * 1_000).toISOString();
    const binding = principalBinding(principal);
    const idempotencyKey = safeId(input.idempotencyKey, "idempotencyKey");
    return this.#repository.create({
      tenantId: principal.tenantId,
      investigationId: `inv-${digest({ binding, idempotencyKey })}`,
      principalBinding: binding,
      reference: input.reference,
      certificationManifestId: dataset.certificationManifestId,
      requestedFields,
      filter,
      filterHash: digest(filter),
      purpose: safeText(input.purpose, "purpose", 256),
      reason: safeText(input.reason, "reason", 2_048),
      masks,
      populationHash: dataset.populationHash,
      rowBudget: integer(input.rowBudget ?? 1_000, "rowBudget", 1, 1_000),
      expiresAt,
      createdBy: principal.principalId,
      ...(input.reviewerPrincipalId === undefined
        ? {}
        : { reviewerPrincipalId: safeId(input.reviewerPrincipalId, "reviewerPrincipalId") }),
      idempotencyKey
    });
  }

  async getRows(
    principal: VerifiedPrincipalContext,
    investigationId: string,
    options: { readonly cursor?: string; readonly limit?: number; readonly idempotencyKey: string }
  ): Promise<InvestigationPage> {
    this.#assertPrincipal(principal);
    const id = safeId(investigationId, "investigationId");
    const binding = principalBinding(principal);
    const investigation = this.#repository.get(principal.tenantId, id);
    if (!investigation || investigation.principalBinding !== binding) notFound();
    if (investigation.status !== "open") forbidden("Investigation is closed");
    if (Date.parse(investigation.expiresAt) <= this.#now().getTime()) {
      throw new InvestigationServiceError("EXPIRED", "Investigation has expired");
    }
    const dataset = await this.#loadDataset(principal.tenantId, investigation.reference);
    if (
      dataset.populationHash !== investigation.populationHash ||
      dataset.certificationManifestId !== investigation.certificationManifestId
    ) {
      throw new InvestigationServiceError("DATASET_CHANGED", "Certified investigation population changed");
    }
    const offset = options.cursor === undefined
      ? 0
      : this.#verifyCursor(options.cursor, investigation, binding);
    const limit = integer(options.limit ?? 100, "limit", 1, 100);
    const remaining = investigation.rowBudget - investigation.disclosedRows;
    if (remaining <= 0) {
      throw new InvestigationServiceError("ROW_BUDGET_EXCEEDED", "Investigation row budget is exhausted");
    }
    const matched = dataset.records.filter((record) =>
      investigation.filter === null ? true : evaluateFilter(investigation.filter, record)
    );
    const pageSize = Math.min(limit, remaining);
    const selected = matched.slice(offset, offset + pageSize);
    const rows = selected.map((record) =>
      maskRecord(
        record,
        investigation.requestedFields,
        investigation.masks,
        principal.tenantId,
        this.#maskingKey
      )
    );
    const nextOffset = offset + selected.length;
    const nextCursor = nextOffset < matched.length && selected.length > 0
      ? this.#issueCursor(investigation, binding, nextOffset)
      : null;
    const pageHash = digest({
      investigationId: id,
      offset,
      populationHash: investigation.populationHash,
      rows
    });
    const cursorHash = digest(options.cursor ?? "first-page");
    const disclosure = this.#repository.recordDisclosure({
      tenantId: principal.tenantId,
      investigationId: id,
      principalBinding: binding,
      pageRowCount: rows.length,
      pageHash,
      cursorHash,
      disclosedFields: investigation.requestedFields,
      appliedMasks: investigation.masks,
      fieldPolicyVersion: FIELD_POLICY_VERSION,
      actor: principal.principalId,
      idempotencyKey: safeId(options.idempotencyKey, "idempotencyKey")
    });
    return Object.freeze({
      investigationId: id,
      rows: Object.freeze(rows),
      nextCursor,
      disclosedRows: disclosure.cumulativeRowCount,
      remainingRowBudget: investigation.rowBudget - disclosure.cumulativeRowCount,
      populationHash: investigation.populationHash,
      masks: investigation.masks,
      disclosureHistoryFingerprint: disclosure.disclosureFingerprint
    });
  }

  close(
    principal: VerifiedPrincipalContext,
    investigationId: string,
    reason: string,
    idempotencyKey: string
  ): InvestigationRecord {
    this.#assertPrincipal(principal);
    return this.#repository.closeInvestigation({
      tenantId: principal.tenantId,
      investigationId: safeId(investigationId, "investigationId"),
      principalBinding: principalBinding(principal),
      actor: principal.principalId,
      reason: safeText(reason, "reason", 2_048),
      idempotencyKey: safeId(idempotencyKey, "idempotencyKey")
    });
  }

  #assertPrincipal(principal: VerifiedPrincipalContext): void {
    assertVerifiedPrincipalContext(principal);
    assertActivePrincipal(principal, Math.floor(this.#now().getTime() / 1_000));
    requireScopes(principal, ["detail:read"]);
  }

  async #loadDataset(tenantId: string, reference: InvestigationReference): Promise<CertifiedInvestigationDataset> {
    let dataset: CertifiedInvestigationDataset;
    try {
      dataset = await this.#provider.loadCertifiedDataset(tenantId, reference);
    } catch {
      throw new InvestigationServiceError("DATASET_NOT_CERTIFIED", "Certified investigation dataset is unavailable");
    }
    if (
      dataset.tenantId !== tenantId ||
      dataset.reference.kind !== reference.kind ||
      dataset.reference.id !== reference.id ||
      !/^[a-f0-9]{64}$/.test(dataset.populationHash) ||
      dataset.records.length > this.#maximumDatasetRows
    ) {
      throw new InvestigationServiceError("DATASET_NOT_CERTIFIED", "Certified investigation dataset is invalid");
    }
    return dataset;
  }

  #issueCursor(investigation: InvestigationRecord, binding: string, offset: number): string {
    const payload = base64url(
      Buffer.from(
        canonicalJson({
          expiresAt: investigation.expiresAt,
          investigationId: investigation.investigationId,
          offset,
          populationHash: investigation.populationHash,
          principalBinding: binding,
          tenantId: investigation.tenantId,
          version: 1
        }),
        "utf8"
      )
    );
    const signature = createHmac("sha256", this.#cursorKey).update(payload).digest("base64url");
    return `${payload}.${signature}`;
  }

  #verifyCursor(cursor: string, investigation: InvestigationRecord, binding: string): number {
    if (cursor.length > 4_096 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(cursor)) invalid("Cursor is invalid");
    const [payload, signature] = cursor.split(".") as [string, string];
    const expected = createHmac("sha256", this.#cursorKey).update(payload).digest();
    let actual: Buffer;
    try {
      actual = Buffer.from(signature, "base64url");
    } catch {
      invalid("Cursor is invalid");
    }
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) invalid("Cursor is invalid");
    let parsed: unknown;
    try {
      parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    } catch {
      invalid("Cursor is invalid");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) invalid("Cursor is invalid");
    const value = parsed as Record<string, unknown>;
    if (
      value.version !== 1 ||
      value.tenantId !== investigation.tenantId ||
      value.investigationId !== investigation.investigationId ||
      value.principalBinding !== binding ||
      value.populationHash !== investigation.populationHash ||
      value.expiresAt !== investigation.expiresAt
    ) {
      invalid("Cursor is invalid");
    }
    return integer(value.offset, "cursor offset", 0, this.#maximumDatasetRows);
  }

  #now(): Date {
    const value = this.#clock();
    if (!Number.isFinite(value.getTime())) invalid("Clock is invalid");
    return value;
  }
}

function validateCreateInput(input: CreateInvestigationInput): void {
  if (input.reference.kind !== "snapshot" && input.reference.kind !== "result") invalid("Reference kind is invalid");
  safeId(input.reference.id, "reference.id");
  normalizeFields(input.requestedFields);
  safeText(input.purpose, "purpose", 256);
  safeText(input.reason, "reason", 2_048);
  integer(input.rowBudget ?? 1_000, "rowBudget", 1, 1_000);
  if (input.reviewerPrincipalId !== undefined) safeId(input.reviewerPrincipalId, "reviewerPrincipalId");
  safeId(input.idempotencyKey, "idempotencyKey");
}

function normalizeFields(fields: readonly string[]): readonly string[] {
  if (!Array.isArray(fields) || fields.length < 1 || fields.length > 20) invalid("requestedFields is invalid");
  const result = fields.map((field) => safeId(field, "requested field"));
  if (new Set(result).size !== result.length) invalid("requestedFields contains duplicates");
  return Object.freeze(result);
}

function validateFilter(filter: InvestigationFilter, available: ReadonlySet<string>, depth = 0, state = { nodes: 0 }): void {
  state.nodes += 1;
  if (depth > 5 || state.nodes > 50) invalid("Filter exceeds structural bounds");
  if (filter.type === "and" || filter.type === "or") {
    if (!Array.isArray(filter.filters) || filter.filters.length < 1 || filter.filters.length > 10) invalid("Filter group is invalid");
    for (const nested of filter.filters) validateFilter(nested, available, depth + 1, state);
    return;
  }
  if (filter.type !== "predicate" || !available.has(filter.field) || !getCanonicalField(filter.field)) {
    invalid("Filter field is invalid");
  }
  const operators = ["eq", "ne", "gt", "gte", "lt", "lte", "in", "is_null"] as const;
  if (!operators.includes(filter.operator)) invalid("Filter operator is invalid");
  if (filter.operator === "is_null") {
    if (filter.value !== undefined) invalid("is_null must not include a value");
    return;
  }
  if (filter.operator === "in") {
    if (!Array.isArray(filter.value) || filter.value.length < 1 || filter.value.length > 100) invalid("in filter is invalid");
    filter.value.forEach(validateScalar);
    return;
  }
  const scalarValue = filter.value;
  if (Array.isArray(scalarValue) || scalarValue === undefined) invalid("Filter value is invalid");
  // TypeScript does not narrow readonly arrays through Array.isArray, while the
  // runtime branch above does. Keep the cast at this validated boundary.
  validateScalar(scalarValue as InvestigationScalar);
}

function evaluateFilter(
  filter: InvestigationFilter,
  record: Readonly<Record<string, InvestigationScalar>>
): boolean {
  if (filter.type === "and") return filter.filters.every((nested) => evaluateFilter(nested, record));
  if (filter.type === "or") return filter.filters.some((nested) => evaluateFilter(nested, record));
  const actual = record[filter.field] ?? null;
  if (filter.operator === "is_null") return actual === null;
  if (filter.operator === "in") {
    return (filter.value as readonly InvestigationScalar[]).some((expected) => compare(actual, expected) === 0);
  }
  const compared = compare(actual, filter.value as InvestigationScalar);
  if (filter.operator === "eq") return compared === 0;
  if (filter.operator === "ne") return compared !== 0;
  if (filter.operator === "gt") return compared > 0;
  if (filter.operator === "gte") return compared >= 0;
  if (filter.operator === "lt") return compared < 0;
  return compared <= 0;
}

function compare(left: InvestigationScalar, right: InvestigationScalar): number {
  if (left === null || right === null) return left === right ? 0 : left === null ? -1 : 1;
  if (typeof left === "boolean" || typeof right === "boolean") {
    return String(left).localeCompare(String(right));
  }
  if (isDecimal(left) && isDecimal(right)) return new Decimal(left).comparedTo(new Decimal(right));
  return left.localeCompare(right);
}

function isDecimal(value: string): boolean {
  return /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/.test(value);
}

function maskRecord(
  record: Readonly<Record<string, InvestigationScalar>>,
  fields: readonly string[],
  masks: Readonly<Record<string, InvestigationMask>>,
  tenantId: string,
  maskingKey: Buffer
): Readonly<Record<string, InvestigationScalar>> {
  return Object.freeze(
    Object.fromEntries(
      fields.map((field) => [field, maskValue(record[field] ?? null, masks[field]!, tenantId, field, maskingKey)])
    )
  );
}

function maskValue(
  value: InvestigationScalar,
  mask: InvestigationMask,
  tenantId: string,
  field: string,
  keyBytes: Buffer
): InvestigationScalar {
  if (value === null || mask === "none") return value;
  if (mask === "redact") return "[REDACTED]";
  if (mask === "tokenize") {
    return `tok_${createHmac("sha256", keyBytes).update(canonicalJson({ field, tenantId, value })).digest("hex").slice(0, 24)}`;
  }
  const text = String(value);
  if (text.length <= 4) return "*".repeat(text.length);
  return `${text.slice(0, 2)}${"*".repeat(Math.min(12, text.length - 4))}${text.slice(-2)}`;
}

function maskForField(field: string): InvestigationMask {
  const policy = getCanonicalFieldPolicy(field);
  if (policy.defaultMask === "tokenize") return "tokenize";
  if (policy.defaultMask === "redact") return "redact";
  return "none";
}

function validateScalar(value: InvestigationScalar): void {
  if (value === null || typeof value === "boolean") return;
  if (typeof value !== "string" || value.length > 4_096 || /[\u0000\r\n]/.test(value)) invalid("Filter scalar is invalid");
}

function key(value: Uint8Array, label: string): Buffer {
  if (!(value instanceof Uint8Array) || value.byteLength !== 32) invalid(`${label} must contain 32 bytes`);
  return Buffer.from(value);
}

function safeId(value: unknown, label: string): string {
  if (typeof value !== "string" || !value || value.length > 256 || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(value)) {
    invalid(`${label} is invalid`);
  }
  return value;
}

function safeText(value: unknown, label: string, maximum: number): string {
  if (typeof value !== "string" || !value.trim() || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) {
    invalid(`${label} is invalid`);
  }
  return value;
}

function integer(value: unknown, label: string, minimum: number, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalid(`${label} is invalid`);
  }
  return value;
}

function notFound(): never {
  throw new InvestigationServiceError("NOT_FOUND", "Investigation was not found");
}

function forbidden(message: string): never {
  throw new InvestigationServiceError("FORBIDDEN", message);
}

function invalid(message: string): never {
  throw new InvestigationServiceError("INVALID_INPUT", message);
}

function digest(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function base64url(value: Buffer): string {
  return value.toString("base64url");
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, nested]) => nested !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([name, nested]) => [name, canonicalize(nested)])
    );
  }
  return value;
}
