import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { Worker } from "node:worker_threads";

import type { RegisteredSnapshot, SnapshotIngestionService } from "./ingestion.js";

export type SnapshotSqlDialect = "postgres" | "sqlite";
export type SnapshotValueEncoding = "exact_text" | "native";
export type WatermarkValueKind = "date" | "datetime" | "decimal" | "integer" | "text";
export type SnapshotScalar = null | boolean | number | string;
export type SnapshotRecord = Readonly<Record<string, SnapshotScalar>>;

/**
 * Security assumptions that trusted bootstrap code must satisfy. They are not
 * accepted from an MCP/tool request and are deliberately literal-valued.
 */
export interface ReadOnlySourceAssumptions {
  /** The database principal cannot own or alter the source relation. */
  readonly principalMode: "non_owner";
  /** The connection is opened or transaction-scoped as read-only. */
  readonly accessMode: "read_only";
  /** Credentials/paths are supplied by trusted runtime configuration only. */
  readonly configurationSource: "trusted_runtime";
}

export interface AllowedSnapshotColumn {
  /** Opaque allowlist key accepted from extraction requests. */
  readonly columnId: string;
  /** Physical identifier supplied only by trusted configuration. */
  readonly sourceName: string;
  /** Field name delivered to SnapshotIngestionService. */
  readonly outputName: string;
  readonly classification: "approved";
  /** exact_text prevents database decimals and wide integers becoming JS floats. */
  readonly encoding: SnapshotValueEncoding;
}

export interface DeterministicOrderColumn {
  readonly columnId: string;
  readonly direction: "asc" | "desc";
  readonly nulls: "first" | "last";
}

export interface WatermarkPolicy {
  readonly columnId: string;
  readonly valueKind: WatermarkValueKind;
  readonly comparison: "lte";
  readonly required: true;
}

export interface SnapshotRelationPolicy {
  readonly relationId: string;
  /** Trusted tenant binding for this physical relation. */
  readonly tenantId: string;
  /** Shared relations are intentionally unsupported until RLS policy semantics can be attested. */
  readonly tenantIsolation: "dedicated_relation";
  readonly datasetId: string;
  readonly schema: string;
  readonly table: string;
  /** Views are excluded from the production ingestion boundary. */
  readonly relationKind: "table";
  readonly columns: readonly AllowedSnapshotColumn[];
  readonly orderBy: readonly DeterministicOrderColumn[];
  /** Trusted owner assertion that orderBy is a total, unique ordering. */
  readonly orderIsUnique: true;
  readonly watermark?: WatermarkPolicy;
}

export interface TrustedSqliteSnapshotSourceConfig {
  readonly sourceId: string;
  /** Trusted bootstrap configuration only; never accept this from a task/tool call. */
  readonly databasePath: string;
  readonly assumptions: ReadOnlySourceAssumptions;
  readonly relations: readonly SnapshotRelationPolicy[];
}

export interface SnapshotExtractionLimits {
  readonly maximumRows?: number;
  /** Maximum UTF-8 bytes of the canonical records array. */
  readonly maximumBytes?: number;
  /** Maximum UTF-8 bytes of one JSON-encoded scalar value. */
  readonly maximumCellBytes?: number;
  readonly maximumExecutionMs?: number;
  readonly maximumColumns?: number;
}

export interface ResolvedSnapshotExtractionLimits {
  readonly maximumRows: number;
  readonly maximumBytes: number;
  readonly maximumCellBytes: number;
  readonly maximumExecutionMs: number;
  readonly maximumColumns: number;
}

export interface SourceExtractionRequest {
  readonly tenantId: string;
  readonly datasetId: string;
  readonly relationId: string;
  readonly columnIds: readonly string[];
  readonly watermark?: { readonly upperBound: string | number };
}

export interface TrustedSnapshotExtraction {
  readonly sourceId: string;
  readonly dialect: SnapshotSqlDialect;
  readonly tenantId: string;
  readonly datasetId: string;
  readonly relationId: string;
  readonly columnIds: readonly string[];
  readonly outputColumns: readonly string[];
  readonly orderBy: readonly DeterministicOrderColumn[];
  readonly watermark?: { readonly upperBound: string | number };
  readonly queryFingerprint: string;
  readonly records: readonly SnapshotRecord[];
  readonly rowCount: number;
  readonly byteLength: number;
}

export interface TrustedSnapshotSource {
  readonly sourceId: string;
  readonly dialect: SnapshotSqlDialect;
  readonly assumptions: ReadOnlySourceAssumptions;

  extract(
    request: SourceExtractionRequest,
    limits: ResolvedSnapshotExtractionLimits,
    signal?: AbortSignal
  ): Promise<TrustedSnapshotExtraction>;
}

export interface ExtractAndRegisterSnapshotInput {
  /** Trusted caller-derived security context; never inferred from source rows. */
  readonly tenantId: string;
  /** Trusted caller-derived dataset binding; must match the relation policy. */
  readonly datasetId: string;
  readonly snapshotId: string;
  readonly relationId: string;
  readonly columnIds: readonly string[];
  readonly watermark?: { readonly upperBound: string | number };
  readonly asOfDate: string;
  readonly deliveredBy: string;
  readonly idempotencyKey: string;
  readonly expectedCanonicalContentHash?: string;
}

export interface SnapshotExtractionExecutionOptions {
  readonly signal?: AbortSignal;
}

export interface ExtractedRegisteredSnapshot extends RegisteredSnapshot {
  readonly extraction: Omit<TrustedSnapshotExtraction, "records">;
}

export type SqlSnapshotExtractionErrorCode =
  | "INVALID_REQUEST"
  | "INVALID_POLICY"
  | "READ_ONLY_REQUIRED"
  | "RELATION_NOT_ALLOWED"
  | "COLUMN_NOT_ALLOWED"
  | "WATERMARK_REQUIRED"
  | "WATERMARK_NOT_ALLOWED"
  | "ROW_LIMIT_EXCEEDED"
  | "BYTE_LIMIT_EXCEEDED"
  | "CELL_LIMIT_EXCEEDED"
  | "TIME_LIMIT_EXCEEDED"
  | "CANCELLED"
  | "UNSUPPORTED_VALUE"
  | "SOURCE_FAILURE";

export class SqlSnapshotExtractionError extends Error {
  constructor(
    readonly code: SqlSnapshotExtractionErrorCode,
    message: string
  ) {
    super(message);
    this.name = "SqlSnapshotExtractionError";
  }
}

interface NormalizedRelationPolicy extends SnapshotRelationPolicy {
  readonly columns: readonly AllowedSnapshotColumn[];
  readonly orderBy: readonly DeterministicOrderColumn[];
}

interface CompiledSqliteExtraction {
  readonly sql: string;
  readonly values: readonly (number | string)[];
  readonly outputColumns: readonly string[];
  readonly queryFingerprint: string;
}

interface SqliteWorkerSuccess {
  readonly ok: true;
  readonly records: readonly SnapshotRecord[];
  readonly byteLength: number;
}

interface SqliteWorkerFailure {
  readonly ok: false;
  readonly code: SqlSnapshotExtractionErrorCode;
}

type SqliteWorkerMessage = SqliteWorkerSuccess | SqliteWorkerFailure;

const REQUEST_KEYS = new Set([
  "asOfDate",
  "columnIds",
  "datasetId",
  "deliveredBy",
  "expectedCanonicalContentHash",
  "idempotencyKey",
  "relationId",
  "snapshotId",
  "tenantId",
  "watermark"
]);
const SOURCE_REQUEST_KEYS = new Set(["columnIds", "datasetId", "relationId", "tenantId", "watermark"]);
const WATERMARK_KEYS = new Set(["upperBound"]);
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SQL_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_$]{0,127}$/;
const CANONICAL_DECIMAL = /^-?(?:0|[1-9]\d*)(?:\.\d+)?$/;
const CANONICAL_INTEGER = /^-?(?:0|[1-9]\d*)$/;

/**
 * Reads a finite, deterministic, policy-compiled SQLite snapshot in an
 * isolated worker. The database is opened read-only; query-only and defensive
 * modes are applied, and a read authorizer is used when available.
 */
export class TrustedSqliteSnapshotSource implements TrustedSnapshotSource {
  readonly sourceId: string;
  readonly dialect = "sqlite" as const;
  readonly assumptions: ReadOnlySourceAssumptions;

  readonly #databasePath: string;
  readonly #relations: ReadonlyMap<string, NormalizedRelationPolicy>;

  constructor(config: TrustedSqliteSnapshotSourceConfig) {
    safeId(config.sourceId, "sourceId", "INVALID_POLICY");
    if (!config.databasePath.trim()) policyError("databasePath must not be blank");
    validateReadOnlyAssumptions(config.assumptions);
    this.sourceId = config.sourceId;
    this.assumptions = Object.freeze({ ...config.assumptions });
    this.#databasePath = resolve(config.databasePath);
    this.#relations = normalizePolicies(config.relations, "sqlite");
  }

  async extract(
    request: SourceExtractionRequest,
    limits: ResolvedSnapshotExtractionLimits,
    signal?: AbortSignal
  ): Promise<TrustedSnapshotExtraction> {
    validateSourceRequest(request);
    validateResolvedLimits(limits);
    if (signal?.aborted) cancelled();
    const policy = this.#relations.get(request.relationId);
    if (
      !policy ||
      policy.tenantId !== request.tenantId ||
      policy.datasetId !== request.datasetId
    ) {
      throw new SqlSnapshotExtractionError(
        "RELATION_NOT_ALLOWED",
        "The requested dataset relation is not allowlisted"
      );
    }
    const compiled = compileSqliteExtraction(policy, request, limits);
    const workerResult = await runSqliteWorker(
      {
        databasePath: this.#databasePath,
        sql: compiled.sql,
        values: compiled.values,
        maximumRows: limits.maximumRows,
        maximumBytes: limits.maximumBytes,
        maximumCellBytes: limits.maximumCellBytes
      },
      limits.maximumExecutionMs,
      signal
    );
    validateExtractedRecords(
      workerResult.records,
      compiled.outputColumns,
      limits.maximumRows,
      limits.maximumBytes,
      limits.maximumCellBytes
    );
    return {
      sourceId: this.sourceId,
      dialect: this.dialect,
      tenantId: request.tenantId,
      datasetId: request.datasetId,
      relationId: request.relationId,
      columnIds: selectedColumns(policy, request.columnIds).map((column) => column.columnId),
      outputColumns: compiled.outputColumns,
      orderBy: policy.orderBy,
      ...(request.watermark === undefined ? {} : { watermark: request.watermark }),
      queryFingerprint: compiled.queryFingerprint,
      records: workerResult.records,
      rowCount: workerResult.records.length,
      byteLength: workerResult.byteLength
    };
  }
}

/**
 * Trusted connector orchestration. This class is intentionally not registered
 * as an MCP raw-row tool: it accepts no SQL, credentials, paths, URLs, filters,
 * joins, expressions, or recipient/delivery configuration.
 */
export class SqlSnapshotExtractionService {
  readonly #source: TrustedSnapshotSource;
  readonly #ingestion: SnapshotIngestionService;
  readonly #limits: ResolvedSnapshotExtractionLimits;

  constructor(
    source: TrustedSnapshotSource,
    ingestion: SnapshotIngestionService,
    limits: SnapshotExtractionLimits = {}
  ) {
    validateReadOnlyAssumptions(source.assumptions);
    safeId(source.sourceId, "sourceId", "INVALID_POLICY");
    this.#source = source;
    this.#ingestion = ingestion;
    this.#limits = resolveLimits(limits);
  }

  async extractAndRegister(
    input: ExtractAndRegisterSnapshotInput,
    options: SnapshotExtractionExecutionOptions = {}
  ): Promise<ExtractedRegisteredSnapshot> {
    validateExtractionInput(input);
    if (options.signal?.aborted) cancelled();
    const extraction = await this.#source.extract(
      {
        tenantId: input.tenantId,
        datasetId: input.datasetId,
        relationId: input.relationId,
        columnIds: input.columnIds,
        ...(input.watermark === undefined ? {} : { watermark: input.watermark })
      },
      this.#limits,
      options.signal
    );
    if (options.signal?.aborted) cancelled();
    if (
      extraction.sourceId !== this.#source.sourceId ||
      extraction.tenantId !== input.tenantId ||
      extraction.datasetId !== input.datasetId ||
      extraction.relationId !== input.relationId
    ) {
      throw new SqlSnapshotExtractionError(
        "SOURCE_FAILURE",
        "Trusted source returned inconsistent extraction identity"
      );
    }
    const measuredBytes = validateExtractedRecords(
      extraction.records,
      extraction.outputColumns,
      this.#limits.maximumRows,
      this.#limits.maximumBytes,
      this.#limits.maximumCellBytes
    );
    if (measuredBytes !== extraction.byteLength || extraction.rowCount !== extraction.records.length) {
      throw new SqlSnapshotExtractionError(
        "SOURCE_FAILURE",
        "Trusted source returned inconsistent extraction limits metadata"
      );
    }
    const sourceBindingId = `${this.#source.sourceId}:${input.datasetId}`;
    safeId(sourceBindingId, "source binding", "INVALID_REQUEST");
    const registered = this.#ingestion.registerDeliveredSnapshot({
      tenantId: input.tenantId,
      snapshotId: input.snapshotId,
      sourceId: sourceBindingId,
      asOfDate: input.asOfDate,
      records: extraction.records,
      deliveredBy: input.deliveredBy,
      idempotencyKey: input.idempotencyKey,
      ...(input.expectedCanonicalContentHash === undefined
        ? {}
        : { expectedCanonicalContentHash: input.expectedCanonicalContentHash })
    });
    const { records: _records, ...extractionMetadata } = extraction;
    return { ...registered, extraction: extractionMetadata };
  }
}

function compileSqliteExtraction(
  policy: NormalizedRelationPolicy,
  request: SourceExtractionRequest,
  limits: ResolvedSnapshotExtractionLimits
): CompiledSqliteExtraction {
  const columns = selectedColumns(policy, request.columnIds);
  if (columns.length > limits.maximumColumns) {
    throw new SqlSnapshotExtractionError(
      "COLUMN_NOT_ALLOWED",
      `Snapshot extraction exceeds the ${limits.maximumColumns}-column limit`
    );
  }
  validateWatermarkRequest(policy, request.watermark);
  const quote = quoteIdentifier;
  const projections = columns.map((column) => {
    const source = quote(column.sourceName);
    const expression = column.encoding === "exact_text" ? `CAST(${source} AS TEXT)` : source;
    return `${expression} AS ${quote(column.outputName)}`;
  });
  const values: (number | string)[] = [];
  let where = "";
  if (policy.watermark && request.watermark) {
    const watermarkColumn = requiredColumn(policy, policy.watermark.columnId);
    values.push(request.watermark.upperBound);
    where = `\n WHERE ${quote(watermarkColumn.sourceName)} <= ?`;
  }
  const orderBy = policy.orderBy
    .map((order) => {
      const column = requiredColumn(policy, order.columnId);
      return `${quote(column.sourceName)} ${order.direction.toUpperCase()} NULLS ${order.nulls.toUpperCase()}`;
    })
    .join(", ");
  values.push(limits.maximumRows + 1);
  const sql = `SELECT ${projections.join(", ")}\n  FROM ${quote(policy.schema)}.${quote(policy.table)}${where}\n ORDER BY ${orderBy}\n LIMIT ?`;
  return {
    sql,
    values,
    outputColumns: columns.map((column) => column.outputName),
    queryFingerprint: sha256(
      canonicalJson({
        dialect: "sqlite",
        sql,
        tenantId: policy.tenantId,
        tenantIsolation: policy.tenantIsolation,
        values
      })
    )
  };
}

function normalizePolicies(
  policies: readonly SnapshotRelationPolicy[],
  dialect: SnapshotSqlDialect
): ReadonlyMap<string, NormalizedRelationPolicy> {
  if (policies.length === 0 || policies.length > 1_000) {
    policyError("relations must contain between 1 and 1000 policies");
  }
  const result = new Map<string, NormalizedRelationPolicy>();
  for (const policy of policies) {
    safeId(policy.tenantId, "tenantId", "INVALID_POLICY");
    if (policy.tenantIsolation !== "dedicated_relation") {
      policyError("tenantIsolation must attest a dedicated physical relation");
    }
    safeId(policy.relationId, "relationId", "INVALID_POLICY");
    safeId(policy.datasetId, "datasetId", "INVALID_POLICY");
    sqlIdentifier(policy.schema, "schema");
    sqlIdentifier(policy.table, "table");
    if (dialect === "sqlite" && policy.schema !== "main") {
      policyError("SQLite snapshot relations must use the main schema");
    }
    if (policy.relationKind !== "table") {
      policyError("Only physical table relations are supported");
    }
    if (policy.orderIsUnique !== true) {
      policyError("Every relation policy must attest that orderBy is total and unique");
    }
    if (policy.columns.length === 0 || policy.columns.length > 2_000) {
      policyError("Every relation must allow between 1 and 2000 columns");
    }
    const columnIds = new Set<string>();
    const outputNames = new Set<string>();
    const normalizedColumns = policy.columns.map((column) => {
      safeId(column.columnId, "columnId", "INVALID_POLICY");
      sqlIdentifier(column.sourceName, "sourceName");
      sqlIdentifier(column.outputName, "outputName");
      if (column.classification !== "approved") {
        policyError(`Column '${column.columnId}' is not approved for snapshot extraction`);
      }
      if (!(column.encoding === "exact_text" || column.encoding === "native")) {
        policyError(`Column '${column.columnId}' has an invalid encoding`);
      }
      if (columnIds.has(column.columnId)) policyError(`Duplicate columnId '${column.columnId}'`);
      if (outputNames.has(column.outputName)) policyError(`Duplicate outputName '${column.outputName}'`);
      columnIds.add(column.columnId);
      outputNames.add(column.outputName);
      return Object.freeze({ ...column });
    });
    if (policy.orderBy.length === 0 || policy.orderBy.length > 32) {
      policyError("orderBy must contain between 1 and 32 total-order columns");
    }
    const orderIds = new Set<string>();
    const normalizedOrder = policy.orderBy.map((order) => {
      if (!columnIds.has(order.columnId)) policyError(`Order column '${order.columnId}' is not allowlisted`);
      if (orderIds.has(order.columnId)) policyError(`Duplicate order column '${order.columnId}'`);
      if (!(order.direction === "asc" || order.direction === "desc")) {
        policyError("Order direction must be asc or desc");
      }
      if (!(order.nulls === "first" || order.nulls === "last")) {
        policyError("Order null handling must be first or last");
      }
      orderIds.add(order.columnId);
      return Object.freeze({ ...order });
    });
    if (policy.watermark) {
      if (!columnIds.has(policy.watermark.columnId)) {
        policyError(`Watermark column '${policy.watermark.columnId}' is not allowlisted`);
      }
      if (policy.watermark.comparison !== "lte" || policy.watermark.required !== true) {
        policyError("Watermark policies must require an inclusive upper bound");
      }
      if (!(policy.watermark.valueKind === "date" ||
        policy.watermark.valueKind === "datetime" ||
        policy.watermark.valueKind === "decimal" ||
        policy.watermark.valueKind === "integer" ||
        policy.watermark.valueKind === "text")) {
        policyError("Watermark valueKind is invalid");
      }
    }
    if (result.has(policy.relationId)) policyError(`Duplicate relationId '${policy.relationId}'`);
    result.set(
      policy.relationId,
      Object.freeze({
        ...policy,
        columns: Object.freeze(normalizedColumns),
        orderBy: Object.freeze(normalizedOrder),
        ...(policy.watermark === undefined ? {} : { watermark: Object.freeze({ ...policy.watermark }) })
      })
    );
  }
  return result;
}

function selectedColumns(
  policy: NormalizedRelationPolicy,
  requestedIds: readonly string[]
): readonly AllowedSnapshotColumn[] {
  if (requestedIds.length === 0) invalidRequest("columnIds must not be empty");
  const requested = new Set<string>();
  for (const columnId of requestedIds) {
    safeId(columnId, "columnId", "INVALID_REQUEST");
    if (requested.has(columnId)) invalidRequest(`columnIds contains duplicate '${columnId}'`);
    requested.add(columnId);
  }
  const selected = policy.columns.filter((column) => requested.has(column.columnId));
  if (selected.length !== requested.size) {
    throw new SqlSnapshotExtractionError(
      "COLUMN_NOT_ALLOWED",
      "One or more requested columns are not allowlisted for this relation"
    );
  }
  return selected;
}

function validateWatermarkRequest(
  policy: NormalizedRelationPolicy,
  watermark: SourceExtractionRequest["watermark"]
): void {
  if (policy.watermark && !watermark) {
    throw new SqlSnapshotExtractionError("WATERMARK_REQUIRED", "This relation requires a watermark upper bound");
  }
  if (!policy.watermark && watermark) {
    throw new SqlSnapshotExtractionError("WATERMARK_NOT_ALLOWED", "This relation does not accept a watermark");
  }
  if (!policy.watermark || !watermark) return;
  assertExactKeys(watermark, WATERMARK_KEYS, "watermark");
  const value = watermark.upperBound;
  if (policy.watermark.valueKind === "decimal") {
    if (typeof value !== "string" || !CANONICAL_DECIMAL.test(value)) {
      invalidRequest("Decimal watermarks must be canonical decimal strings");
    }
  } else if (policy.watermark.valueKind === "integer") {
    if (!(
      (typeof value === "number" && Number.isSafeInteger(value)) ||
      (typeof value === "string" && CANONICAL_INTEGER.test(value))
    )) {
      invalidRequest("Integer watermarks must be safe integers or canonical integer strings");
    }
  } else if (policy.watermark.valueKind === "date") {
    if (typeof value !== "string") invalidRequest("Date watermarks must be strings");
    isoDate(value, "watermark.upperBound");
  } else if (policy.watermark.valueKind === "datetime") {
    if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
      invalidRequest("Datetime watermarks must be ISO-8601 strings");
    }
  } else if (typeof value !== "string" || value.length === 0 || value.length > 4_096) {
    invalidRequest("Text watermark must be a non-empty bounded string");
  }
}

function validateExtractionInput(input: ExtractAndRegisterSnapshotInput): void {
  assertExactKeys(input, REQUEST_KEYS, "extraction input");
  safeId(input.tenantId, "tenantId", "INVALID_REQUEST");
  safeId(input.datasetId, "datasetId", "INVALID_REQUEST");
  safeId(input.snapshotId, "snapshotId", "INVALID_REQUEST");
  safeId(input.relationId, "relationId", "INVALID_REQUEST");
  safeId(input.deliveredBy, "deliveredBy", "INVALID_REQUEST");
  safeId(input.idempotencyKey, "idempotencyKey", "INVALID_REQUEST");
  isoDate(input.asOfDate, "asOfDate");
  if (!Array.isArray(input.columnIds)) invalidRequest("columnIds must be an array");
  if (input.watermark !== undefined) assertExactKeys(input.watermark, WATERMARK_KEYS, "watermark");
  if (
    input.expectedCanonicalContentHash !== undefined &&
    !/^(?:sha256:)?[a-f0-9]{64}$/.test(input.expectedCanonicalContentHash)
  ) {
    invalidRequest("expectedCanonicalContentHash must be lowercase SHA-256");
  }
}

function validateSourceRequest(request: SourceExtractionRequest): void {
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    invalidRequest("source extraction request must be an object");
  }
  assertExactKeys(request, SOURCE_REQUEST_KEYS, "source extraction request");
  safeId(request.tenantId, "tenantId", "INVALID_REQUEST");
  safeId(request.datasetId, "datasetId", "INVALID_REQUEST");
  safeId(request.relationId, "relationId", "INVALID_REQUEST");
  if (!Array.isArray(request.columnIds)) invalidRequest("columnIds must be an array");
  if (request.watermark !== undefined) assertExactKeys(request.watermark, WATERMARK_KEYS, "watermark");
}

function validateExtractedRecords(
  records: readonly SnapshotRecord[],
  outputColumns: readonly string[],
  maximumRows: number,
  maximumBytes: number,
  maximumCellBytes: number
): number {
  if (!Array.isArray(records)) sourceFailure("Trusted source did not return a records array");
  if (records.length > maximumRows) rowLimit();
  const expected = new Set(outputColumns);
  if (expected.size !== outputColumns.length) sourceFailure("Trusted source returned duplicate output columns");
  for (const record of records) {
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      sourceFailure("Trusted source returned a non-object record");
    }
    const keys = Object.keys(record);
    if (keys.length !== expected.size || keys.some((key) => !expected.has(key))) {
      sourceFailure("Trusted source returned fields outside the approved projection");
    }
    for (const value of Object.values(record)) {
      if (!(
        value === null ||
        typeof value === "string" ||
        typeof value === "boolean" ||
        (typeof value === "number" && Number.isFinite(value))
      )) {
        throw new SqlSnapshotExtractionError(
          "UNSUPPORTED_VALUE",
          "Snapshot values must be finite SQL scalars; binary and structured values are rejected"
        );
      }
      if (encodedCellBytes(value) > maximumCellBytes) cellLimit();
    }
  }
  const byteLength = Buffer.byteLength(JSON.stringify(records), "utf8");
  if (byteLength > maximumBytes) byteLimit();
  return byteLength;
}

function resolveLimits(limits: SnapshotExtractionLimits): ResolvedSnapshotExtractionLimits {
  const maximumBytes = boundedInteger(
    limits.maximumBytes ?? 8_000_000,
    "maximumBytes",
    1,
    100_000_000
  );
  return {
    maximumRows: boundedInteger(limits.maximumRows ?? 100_000, "maximumRows", 1, 1_000_000),
    maximumBytes,
    maximumCellBytes: boundedInteger(
      limits.maximumCellBytes ?? Math.min(65_536, maximumBytes),
      "maximumCellBytes",
      1,
      Math.min(1_000_000, maximumBytes)
    ),
    maximumExecutionMs: boundedInteger(
      limits.maximumExecutionMs ?? 15_000,
      "maximumExecutionMs",
      1,
      60_000
    ),
    maximumColumns: boundedInteger(limits.maximumColumns ?? 500, "maximumColumns", 1, 2_000)
  };
}

function validateResolvedLimits(limits: ResolvedSnapshotExtractionLimits): void {
  resolveLimits(limits);
}

function validateReadOnlyAssumptions(assumptions: ReadOnlySourceAssumptions): void {
  if (
    assumptions.principalMode !== "non_owner" ||
    assumptions.accessMode !== "read_only" ||
    assumptions.configurationSource !== "trusted_runtime"
  ) {
    throw new SqlSnapshotExtractionError(
      "READ_ONLY_REQUIRED",
      "Snapshot sources require a trusted-runtime, non-owner, read-only connection"
    );
  }
}

function requiredColumn(
  policy: NormalizedRelationPolicy,
  columnId: string
): AllowedSnapshotColumn {
  const column = policy.columns.find((candidate) => candidate.columnId === columnId);
  if (!column) policyError(`Policy references unknown column '${columnId}'`);
  return column;
}

function quoteIdentifier(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`;
}

function runSqliteWorker(
  workerData: {
    readonly databasePath: string;
    readonly sql: string;
    readonly values: readonly (number | string)[];
    readonly maximumRows: number;
    readonly maximumBytes: number;
    readonly maximumCellBytes: number;
  },
  maximumExecutionMs: number,
  signal?: AbortSignal
): Promise<SqliteWorkerSuccess> {
  if (signal?.aborted) cancelled();
  return new Promise((resolvePromise, rejectPromise) => {
    const maximumHeapMegabytes = Math.min(
      256,
      Math.max(32, Math.ceil(workerData.maximumBytes / 1_048_576) * 2 + 16)
    );
    const worker = new Worker(SQLITE_EXTRACTION_WORKER, {
      eval: true,
      workerData,
      resourceLimits: {
        maxOldGenerationSizeMb: maximumHeapMegabytes,
        maxYoungGenerationSizeMb: 16,
        stackSizeMb: 4
      }
    });
    let settled = false;
    const cleanup = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };
    const reject = (error: SqlSnapshotExtractionError): void => {
      if (settled) return;
      settled = true;
      cleanup();
      void worker.terminate();
      rejectPromise(error);
    };
    const onAbort = (): void => reject(new SqlSnapshotExtractionError("CANCELLED", "Snapshot extraction was cancelled"));
    const timer = setTimeout(
      () =>
        reject(
          new SqlSnapshotExtractionError(
            "TIME_LIMIT_EXCEEDED",
            `Snapshot extraction exceeded ${maximumExecutionMs} milliseconds`
          )
        ),
      maximumExecutionMs
    );
    timer.unref();
    signal?.addEventListener("abort", onAbort, { once: true });
    worker.once("message", (message: unknown) => {
      if (settled) return;
      if (!isWorkerMessage(message)) {
        reject(new SqlSnapshotExtractionError("SOURCE_FAILURE", "Snapshot worker returned an invalid response"));
        return;
      }
      if (!message.ok) {
        reject(workerFailure(message.code));
        return;
      }
      settled = true;
      cleanup();
      resolvePromise(message);
    });
    worker.once("error", () => {
      reject(new SqlSnapshotExtractionError("SOURCE_FAILURE", "Snapshot source execution failed"));
    });
    worker.once("exit", (code) => {
      if (!settled && code !== 0) {
        reject(new SqlSnapshotExtractionError("SOURCE_FAILURE", "Snapshot source worker exited unexpectedly"));
      }
    });
  });
}

function isWorkerMessage(value: unknown): value is SqliteWorkerMessage {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  if (record.ok === false) return typeof record.code === "string";
  return (
    record.ok === true &&
    Array.isArray(record.records) &&
    Number.isSafeInteger(record.byteLength) &&
    (record.byteLength as number) >= 0
  );
}

function workerFailure(code: SqlSnapshotExtractionErrorCode): SqlSnapshotExtractionError {
  if (code === "ROW_LIMIT_EXCEEDED") {
    return new SqlSnapshotExtractionError(code, "Snapshot extraction exceeded the configured row limit");
  }
  if (code === "BYTE_LIMIT_EXCEEDED") {
    return new SqlSnapshotExtractionError(code, "Snapshot extraction exceeded the configured byte limit");
  }
  if (code === "CELL_LIMIT_EXCEEDED") {
    return new SqlSnapshotExtractionError(code, "Snapshot extraction exceeded the configured cell limit");
  }
  if (code === "UNSUPPORTED_VALUE") {
    return new SqlSnapshotExtractionError(code, "Snapshot source returned a binary or structured value");
  }
  if (code === "READ_ONLY_REQUIRED") {
    return new SqlSnapshotExtractionError(code, "Snapshot source could not enforce read-only access");
  }
  return new SqlSnapshotExtractionError("SOURCE_FAILURE", "Snapshot source execution failed");
}

const SQLITE_EXTRACTION_WORKER = String.raw`
"use strict";
const { parentPort, workerData } = require("node:worker_threads");
const { DatabaseSync, constants } = require("node:sqlite");

(() => {

function fail(code) {
  parentPort.postMessage({ ok: false, code });
}

let database;
try {
  database = new DatabaseSync(workerData.databasePath, {
    readOnly: true,
    enableForeignKeyConstraints: true,
    allowExtension: false
  });
  database.exec("PRAGMA query_only = ON");
  if (typeof database.enableDefensive === "function") database.enableDefensive(true);
  if (typeof database.setAuthorizer === "function") {
    const allowed = new Set([
      constants.SQLITE_SELECT,
      constants.SQLITE_READ,
      constants.SQLITE_FUNCTION,
      constants.SQLITE_RECURSIVE
    ]);
    database.setAuthorizer((action) => allowed.has(action) ? constants.SQLITE_OK : constants.SQLITE_DENY);
  }
  const statement = database.prepare(workerData.sql);
  statement.setReadBigInts(true);
  const records = [];
  let byteLength = 2;
  for (const sourceRow of statement.iterate(...workerData.values)) {
    if (records.length >= workerData.maximumRows) {
      fail("ROW_LIMIT_EXCEEDED");
      process.exitCode = 0;
      return;
    }
    const record = {};
    for (const [key, rawValue] of Object.entries(sourceRow)) {
      let value = rawValue;
      if (typeof value === "bigint") value = value.toString();
      if (value instanceof Uint8Array || (value !== null && typeof value === "object")) {
        fail("UNSUPPORTED_VALUE");
        process.exitCode = 0;
        return;
      }
      if (typeof value === "number" && !Number.isFinite(value)) {
        fail("UNSUPPORTED_VALUE");
        process.exitCode = 0;
        return;
      }
      const encodedValue = JSON.stringify(value);
      if (
        encodedValue === undefined ||
        Buffer.byteLength(encodedValue, "utf8") > workerData.maximumCellBytes
      ) {
        fail("CELL_LIMIT_EXCEEDED");
        process.exitCode = 0;
        return;
      }
      record[key] = value;
    }
    const recordBytes = Buffer.byteLength(JSON.stringify(record), "utf8");
    const candidateBytes = byteLength + recordBytes + (records.length === 0 ? 0 : 1);
    if (candidateBytes > workerData.maximumBytes) {
      fail("BYTE_LIMIT_EXCEEDED");
      process.exitCode = 0;
      return;
    }
    records.push(record);
    byteLength = candidateBytes;
  }
  parentPort.postMessage({ ok: true, records, byteLength });
} catch (error) {
  if (error && /readonly|read-only|not authorized/i.test(String(error.message))) fail("READ_ONLY_REQUIRED");
  else fail("SOURCE_FAILURE");
} finally {
  if (database) {
    try { database.close(); } catch {}
  }
}
})();
`;

function assertExactKeys(value: object, allowed: ReadonlySet<string>, label: string): void {
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    invalidRequest(`${label} contains unsupported field '${unknown.sort()[0]}'`);
  }
}

function sqlIdentifier(value: string, label: string): void {
  if (!SQL_IDENTIFIER.test(value)) policyError(`${label} is not a safe SQL identifier`);
}

function safeId(
  value: string,
  label: string,
  code: "INVALID_POLICY" | "INVALID_REQUEST"
): void {
  if (!SAFE_ID.test(value)) {
    if (code === "INVALID_POLICY") policyError(`${label} is invalid`);
    invalidRequest(`${label} is invalid`);
  }
}

function isoDate(value: string, label: string): void {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) invalidRequest(`${label} must use YYYY-MM-DD`);
  const parsed = new Date(`${value}T00:00:00.000Z`);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== value) {
    invalidRequest(`${label} must be a real calendar date`);
  }
}

function boundedInteger(
  value: number,
  label: string,
  minimum: number,
  maximum: number
): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalidRequest(`${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, nested]) => nested !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  const serialized = JSON.stringify(value);
  if (serialized === undefined) invalidRequest("Value is not JSON serializable");
  return serialized;
}

function sha256(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function rowLimit(): never {
  throw new SqlSnapshotExtractionError(
    "ROW_LIMIT_EXCEEDED",
    "Snapshot extraction exceeded the configured row limit"
  );
}

function byteLimit(): never {
  throw new SqlSnapshotExtractionError(
    "BYTE_LIMIT_EXCEEDED",
    "Snapshot extraction exceeded the configured byte limit"
  );
}

function cellLimit(): never {
  throw new SqlSnapshotExtractionError(
    "CELL_LIMIT_EXCEEDED",
    "Snapshot extraction exceeded the configured cell limit"
  );
}

function encodedCellBytes(value: SnapshotScalar): number {
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}

function cancelled(): never {
  throw new SqlSnapshotExtractionError("CANCELLED", "Snapshot extraction was cancelled");
}

function sourceFailure(message: string): never {
  throw new SqlSnapshotExtractionError("SOURCE_FAILURE", message);
}

function invalidRequest(message: string): never {
  throw new SqlSnapshotExtractionError("INVALID_REQUEST", message);
}

function policyError(message: string): never {
  throw new SqlSnapshotExtractionError("INVALID_POLICY", message);
}
