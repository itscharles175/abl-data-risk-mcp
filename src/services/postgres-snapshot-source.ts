import { createHash } from "node:crypto";

import type { Pool, QueryResultRow } from "pg";

import {
  SqlSnapshotExtractionError,
  type AllowedSnapshotColumn,
  type DeterministicOrderColumn,
  type ReadOnlySourceAssumptions,
  type ResolvedSnapshotExtractionLimits,
  type SnapshotRecord,
  type SnapshotRelationPolicy,
  type SnapshotScalar,
  type SourceExtractionRequest,
  type TrustedSnapshotExtraction,
  type TrustedSnapshotSource
} from "./sql-snapshot-extraction.js";

export interface PostgresSnapshotClient {
  query(
    query: string | { readonly text: string; readonly values?: readonly unknown[] }
  ): Promise<{ readonly rows: readonly QueryResultRow[] }>;
  /** Passing true destroys the connection instead of returning it to the pool. */
  release(destroy?: boolean | Error): void;
}

export interface PostgresSnapshotPool {
  connect(): Promise<PostgresSnapshotClient>;
}

export interface TrustedPostgresSnapshotSourceConfig {
  readonly sourceId: string;
  /** Injected only by trusted bootstrap code; extraction requests never contain connectivity. */
  readonly pool: Pool | PostgresSnapshotPool;
  readonly assumptions: ReadOnlySourceAssumptions;
  readonly relations: readonly SnapshotRelationPolicy[];
  readonly lockTimeoutMs?: number;
  readonly idleInTransactionTimeoutMs?: number;
}

interface NormalizedRelationPolicy extends SnapshotRelationPolicy {
  readonly columns: readonly AllowedSnapshotColumn[];
  readonly orderBy: readonly DeterministicOrderColumn[];
}

interface CompiledPostgresExtraction {
  readonly sql: string;
  readonly cellAttestationSql: string;
  readonly values: readonly (number | string)[];
  readonly selectedColumns: readonly AllowedSnapshotColumn[];
  readonly outputColumns: readonly string[];
  readonly queryFingerprint: string;
}

const SOURCE_REQUEST_KEYS = new Set(["columnIds", "datasetId", "relationId", "tenantId", "watermark"]);
const WATERMARK_KEYS = new Set(["upperBound"]);
const LIMIT_KEYS = new Set([
  "maximumBytes",
  "maximumCellBytes",
  "maximumColumns",
  "maximumExecutionMs",
  "maximumRows"
]);
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SQL_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_$]{0,127}$/;
const CANONICAL_DECIMAL = /^-?(?:0|[1-9]\d*)(?:\.\d+)?$/;
const CANONICAL_INTEGER = /^-?(?:0|[1-9]\d*)$/;
const OWNERSHIP_QUERY = `SELECT
  current_setting('transaction_read_only') = 'on' AS "read_only",
  NOT pg_catalog.pg_has_role(current_user, c.relowner, 'MEMBER') AS "non_owner",
  NOT r.rolsuper AS "non_superuser",
  NOT r.rolbypassrls AS "non_bypass_rls",
  c.relrowsecurity AS "row_security_enabled",
  c.relforcerowsecurity AS "row_security_forced",
  c.relkind AS "relation_kind"
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_roles AS r ON r.rolname = current_user
WHERE n.nspname = $1 AND c.relname = $2`;

/**
 * Trusted PostgreSQL snapshot adapter. Connectivity and relation policy are
 * constructor-only capabilities; runtime requests select opaque allowlist IDs.
 */
export class TrustedPostgresSnapshotSource implements TrustedSnapshotSource {
  readonly sourceId: string;
  readonly dialect = "postgres" as const;
  readonly assumptions: ReadOnlySourceAssumptions;

  readonly #pool: PostgresSnapshotPool;
  readonly #relations: ReadonlyMap<string, NormalizedRelationPolicy>;
  readonly #lockTimeoutMs: number;
  readonly #idleInTransactionTimeoutMs: number;

  constructor(config: TrustedPostgresSnapshotSourceConfig) {
    if (!config || typeof config !== "object" || Array.isArray(config)) {
      policyError("PostgreSQL source configuration must be an object");
    }
    safeId(config.sourceId, "sourceId", "INVALID_POLICY");
    validateReadOnlyAssumptions(config.assumptions);
    if (!config.pool || typeof config.pool.connect !== "function") {
      policyError("pool must be an injected PostgreSQL pool");
    }
    this.sourceId = config.sourceId;
    this.assumptions = Object.freeze({ ...config.assumptions });
    this.#pool = config.pool as PostgresSnapshotPool;
    this.#relations = normalizePolicies(config.relations);
    this.#lockTimeoutMs = boundedInteger(config.lockTimeoutMs ?? 1_000, "lockTimeoutMs", 1, 60_000, "INVALID_POLICY");
    this.#idleInTransactionTimeoutMs = boundedInteger(
      config.idleInTransactionTimeoutMs ?? 60_000,
      "idleInTransactionTimeoutMs",
      1,
      300_000,
      "INVALID_POLICY"
    );
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
    const compiled = compilePostgresExtraction(policy, request, limits);
    const guard = new ExecutionGuard(limits.maximumExecutionMs, signal);
    let client: PostgresSnapshotClient | undefined;
    let transactionOpen = false;
    let released = false;
    const release = (destroy: boolean): void => {
      if (!client || released) return;
      released = true;
      try {
        client.release(destroy);
      } catch {
        // The caller receives a stable extraction error; pool internals are never exposed.
      }
    };

    try {
      const acquisition = this.#pool.connect();
      void acquisition
        .then((lateClient) => {
          if (guard.cancelled && lateClient !== client) safeDestroy(lateClient);
        })
        .catch(() => undefined);
      client = await guard.race(acquisition);
      guard.attachDestroy(() => release(true));
      guard.assertActive();

      await guard.race(client.query("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"));
      transactionOpen = true;
      const statementTimeoutMs = limits.maximumExecutionMs;
      const lockTimeoutMs = Math.min(this.#lockTimeoutMs, limits.maximumExecutionMs);
      const idleTimeoutMs = Math.min(this.#idleInTransactionTimeoutMs, limits.maximumExecutionMs);
      await guard.race(client.query(timeoutSql("statement_timeout", statementTimeoutMs)));
      await guard.race(client.query(timeoutSql("lock_timeout", lockTimeoutMs)));
      await guard.race(client.query(timeoutSql("idle_in_transaction_session_timeout", idleTimeoutMs)));
      await assertPhysicalReadOnlyRelation(client, policy, guard);
      const cellAttestation = await guard.race(
        client.query({ text: compiled.cellAttestationSql, values: compiled.values })
      );
      const maximumRowBytes = assertBoundedCellAttestation(
        cellAttestation.rows,
        compiled.selectedColumns,
        limits
      );
      const fetchSize = cursorFetchSize(maximumRowBytes, limits.maximumBytes);
      await guard.race(
        client.query({
          text: `DECLARE "abl_snapshot_cursor" NO SCROLL CURSOR FOR ${compiled.sql}`,
          values: compiled.values
        })
      );
      const records: SnapshotRecord[] = [];
      let byteLength = 2;
      while (true) {
        const queryResult = await guard.race(
          client.query(`FETCH FORWARD ${fetchSize} FROM "abl_snapshot_cursor"`)
        );
        if (queryResult.rows.length > fetchSize) sourceFailure();
        byteLength = materializeRecords(
          queryResult.rows,
          compiled.selectedColumns,
          limits,
          guard,
          records,
          byteLength,
          signal
        );
        if (queryResult.rows.length < fetchSize) break;
      }
      await guard.race(client.query('CLOSE "abl_snapshot_cursor"'));
      await guard.race(client.query("COMMIT"));
      transactionOpen = false;
      release(false);
      return {
        sourceId: this.sourceId,
        dialect: this.dialect,
        tenantId: request.tenantId,
        datasetId: request.datasetId,
        relationId: request.relationId,
        columnIds: compiled.selectedColumns.map((column) => column.columnId),
        outputColumns: compiled.outputColumns,
        orderBy: policy.orderBy,
        ...(request.watermark === undefined ? {} : { watermark: request.watermark }),
        queryFingerprint: compiled.queryFingerprint,
        records: Object.freeze(records),
        rowCount: records.length,
        byteLength
      };
    } catch (error) {
      if (client && transactionOpen && !guard.cancelled && !released) {
        try {
          await guard.race(client.query("ROLLBACK"));
          transactionOpen = false;
        } catch {
          release(true);
        }
      }
      release(guard.cancelled || transactionOpen);
      throw stablePostgresError(error);
    } finally {
      guard.dispose();
      release(transactionOpen);
    }
  }
}

function compilePostgresExtraction(
  policy: NormalizedRelationPolicy,
  request: SourceExtractionRequest,
  limits: ResolvedSnapshotExtractionLimits
): CompiledPostgresExtraction {
  if (request.columnIds.length > limits.maximumColumns) {
    throw new SqlSnapshotExtractionError(
      "COLUMN_NOT_ALLOWED",
      `Snapshot extraction exceeds the ${limits.maximumColumns}-column limit`
    );
  }
  const columns = selectedColumns(policy, request.columnIds);
  if (columns.length > limits.maximumColumns) {
    throw new SqlSnapshotExtractionError(
      "COLUMN_NOT_ALLOWED",
      `Snapshot extraction exceeds the ${limits.maximumColumns}-column limit`
    );
  }
  validateWatermarkRequest(policy, request.watermark);
  const projections = columns.map((column) => {
    const source = quoteIdentifier(column.sourceName);
    const expression = column.encoding === "exact_text" ? `CAST(${source} AS TEXT)` : source;
    return `${expression} AS ${quoteIdentifier(column.outputName)}`;
  });
  const values: (number | string)[] = [];
  let where = "";
  if (policy.watermark && request.watermark) {
    const watermarkColumn = requiredColumn(policy, policy.watermark.columnId);
    values.push(request.watermark.upperBound);
    where = `\n WHERE ${quoteIdentifier(watermarkColumn.sourceName)} <= $${values.length}`;
  }
  const orderBy = policy.orderBy
    .map((order) => {
      const column = requiredColumn(policy, order.columnId);
      return `${quoteIdentifier(column.sourceName)} ${order.direction.toUpperCase()} NULLS ${order.nulls.toUpperCase()}`;
    })
    .join(", ");
  values.push(limits.maximumRows + 1);
  const sql = `SELECT ${projections.join(", ")}\n  FROM ${quoteIdentifier(policy.schema)}.${quoteIdentifier(policy.table)}${where}\n ORDER BY ${orderBy}\n LIMIT $${values.length}`;
  const cellAttestations = columns.map(
    (column, index) =>
      `COALESCE(MAX(pg_catalog.octet_length(pg_catalog.to_json("bounded_snapshot".${quoteIdentifier(column.outputName)})::TEXT)), 0)::TEXT AS "cell_${index}"`
  );
  const cellAttestationSql =
    'SELECT COALESCE(MAX(pg_catalog.octet_length(pg_catalog.row_to_json("bounded_snapshot")::TEXT)), 0)::TEXT AS "maximum_row_bytes",\n       ' +
    `${cellAttestations.join(",\n       ")}\n  FROM (${sql}) AS "bounded_snapshot"`;
  return {
    sql,
    cellAttestationSql,
    values,
    selectedColumns: columns,
    outputColumns: columns.map((column) => column.outputName),
    queryFingerprint: sha256(
      canonicalJson({
        dialect: "postgres",
        maximumCellBytes: limits.maximumCellBytes,
        sql,
        tenantId: policy.tenantId,
        tenantIsolation: policy.tenantIsolation,
        values
      })
    )
  };
}

async function assertPhysicalReadOnlyRelation(
  client: PostgresSnapshotClient,
  policy: NormalizedRelationPolicy,
  guard: ExecutionGuard
): Promise<void> {
  const result = await guard.race(
    client.query({ text: OWNERSHIP_QUERY, values: [policy.schema, policy.table] })
  );
  if (result.rows.length !== 1) {
    throw new SqlSnapshotExtractionError("SOURCE_FAILURE", "Snapshot source relation verification failed");
  }
  const row = result.rows[0]!;
  if (
    row.read_only !== true ||
    row.non_owner !== true ||
    row.non_superuser !== true ||
    row.non_bypass_rls !== true
  ) {
    throw new SqlSnapshotExtractionError(
      "READ_ONLY_REQUIRED",
      "Snapshot source did not verify a non-owner, non-bypass, read-only transaction"
    );
  }
  if (row.relation_kind !== "r" && row.relation_kind !== "p") {
    throw new SqlSnapshotExtractionError("SOURCE_FAILURE", "Snapshot source relation kind did not match policy");
  }
  if (typeof row.row_security_enabled !== "boolean" || typeof row.row_security_forced !== "boolean") {
    throw new SqlSnapshotExtractionError("SOURCE_FAILURE", "Snapshot source relation verification failed");
  }
}

function assertBoundedCellAttestation(
  sourceRows: readonly QueryResultRow[],
  columns: readonly AllowedSnapshotColumn[],
  limits: ResolvedSnapshotExtractionLimits
): number {
  if (!Array.isArray(sourceRows) || sourceRows.length !== 1) sourceFailure();
  const row = sourceRows[0]!;
  if (!row || typeof row !== "object" || Array.isArray(row)) sourceFailure();
  const expectedKeys = new Set([
    "maximum_row_bytes",
    ...columns.map((_, index) => `cell_${index}`)
  ]);
  const keys = Object.keys(row);
  if (keys.length !== expectedKeys.size || keys.some((key) => !expectedKeys.has(key))) {
    sourceFailure();
  }
  const maximumRowBytes = attestedByteCount(row.maximum_row_bytes);
  if (maximumRowBytes + 2 > limits.maximumBytes) {
    throw new SqlSnapshotExtractionError(
      "BYTE_LIMIT_EXCEEDED",
      "Snapshot extraction exceeded the configured byte limit"
    );
  }
  for (let index = 0; index < columns.length; index += 1) {
    if (attestedByteCount(row[`cell_${index}`]) > limits.maximumCellBytes) {
      throw new SqlSnapshotExtractionError(
        "CELL_LIMIT_EXCEEDED",
        "Snapshot extraction exceeded the configured cell limit"
      );
    }
  }
  return maximumRowBytes;
}

function attestedByteCount(value: unknown): number {
  if (typeof value !== "string" || !/^(?:0|[1-9]\d*)$/.test(value)) sourceFailure();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) sourceFailure();
  return parsed;
}

function cursorFetchSize(maximumRowBytes: number, maximumBytes: number): number {
  const fetchBudget = Math.min(maximumBytes, 262_144);
  return Math.max(1, Math.min(512, Math.floor(fetchBudget / Math.max(1, maximumRowBytes + 1))));
}

function materializeRecords(
  sourceRows: readonly QueryResultRow[],
  columns: readonly AllowedSnapshotColumn[],
  limits: ResolvedSnapshotExtractionLimits,
  guard: ExecutionGuard,
  records: SnapshotRecord[],
  initialByteLength: number,
  signal?: AbortSignal
): number {
  if (!Array.isArray(sourceRows)) sourceFailure();
  let byteLength = initialByteLength;
  const expected = new Set(columns.map((column) => column.outputName));
  for (const sourceRow of sourceRows) {
    guard.assertActive();
    if (signal?.aborted) cancelled();
    if (records.length >= limits.maximumRows) {
      throw new SqlSnapshotExtractionError(
        "ROW_LIMIT_EXCEEDED",
        "Snapshot extraction exceeded the configured row limit"
      );
    }
    if (!sourceRow || typeof sourceRow !== "object" || Array.isArray(sourceRow)) sourceFailure();
    const sourceKeys = Object.keys(sourceRow);
    if (sourceKeys.length !== expected.size || sourceKeys.some((key) => !expected.has(key))) sourceFailure();
    const record: Record<string, SnapshotScalar> = {};
    for (const column of columns) {
      const raw = sourceRow[column.outputName] as unknown;
      if (column.encoding === "exact_text" && raw !== null && typeof raw !== "string") {
        throw new SqlSnapshotExtractionError(
          "UNSUPPORTED_VALUE",
          "PostgreSQL exact-text projection returned a non-text value"
        );
      }
      if (!isSnapshotScalar(raw)) {
        throw new SqlSnapshotExtractionError(
          "UNSUPPORTED_VALUE",
          "Snapshot source returned a binary or structured value"
        );
      }
      if (encodedCellBytes(raw) > limits.maximumCellBytes) {
        throw new SqlSnapshotExtractionError(
          "CELL_LIMIT_EXCEEDED",
          "Snapshot extraction exceeded the configured cell limit"
        );
      }
      Object.defineProperty(record, column.outputName, {
        value: raw,
        enumerable: true,
        configurable: false,
        writable: false
      });
    }
    const frozen = Object.freeze(record);
    const rowBytes = Buffer.byteLength(JSON.stringify(frozen), "utf8");
    const candidateBytes = byteLength + rowBytes + (records.length === 0 ? 0 : 1);
    if (candidateBytes > limits.maximumBytes) {
      throw new SqlSnapshotExtractionError(
        "BYTE_LIMIT_EXCEEDED",
        "Snapshot extraction exceeded the configured byte limit"
      );
    }
    records.push(frozen);
    byteLength = candidateBytes;
  }
  if (byteLength > limits.maximumBytes) {
    throw new SqlSnapshotExtractionError(
      "BYTE_LIMIT_EXCEEDED",
      "Snapshot extraction exceeded the configured byte limit"
    );
  }
  return byteLength;
}

function normalizePolicies(
  policies: readonly SnapshotRelationPolicy[]
): ReadonlyMap<string, NormalizedRelationPolicy> {
  if (!Array.isArray(policies) || policies.length === 0 || policies.length > 1_000) {
    policyError("relations must contain between 1 and 1000 policies");
  }
  const result = new Map<string, NormalizedRelationPolicy>();
  for (const policy of policies) {
    if (!policy || typeof policy !== "object") policyError("relation policy must be an object");
    safeId(policy.tenantId, "tenantId", "INVALID_POLICY");
    if (policy.tenantIsolation !== "dedicated_relation") {
      policyError("tenantIsolation must attest a dedicated physical relation");
    }
    safeId(policy.relationId, "relationId", "INVALID_POLICY");
    safeId(policy.datasetId, "datasetId", "INVALID_POLICY");
    sqlIdentifier(policy.schema, "schema");
    sqlIdentifier(policy.table, "table");
    if (policy.relationKind !== "table") {
      policyError("Only physical table relations are supported");
    }
    if (policy.orderIsUnique !== true) {
      policyError("Every relation policy must attest that orderBy is total and unique");
    }
    if (!Array.isArray(policy.columns) || policy.columns.length === 0 || policy.columns.length > 2_000) {
      policyError("Every relation must allow between 1 and 2000 columns");
    }
    const columnIds = new Set<string>();
    const outputNames = new Set<string>();
    const policyColumns = policy.columns as readonly AllowedSnapshotColumn[];
    const columns = policyColumns.map((column: AllowedSnapshotColumn) => {
      if (!column || typeof column !== "object" || Array.isArray(column)) {
        policyError("Snapshot column policy must be an object");
      }
      safeId(column.columnId, "columnId", "INVALID_POLICY");
      sqlIdentifier(column.sourceName, "sourceName");
      sqlIdentifier(column.outputName, "outputName");
      if (column.classification !== "approved") policyError("Snapshot columns must be approved");
      if (column.encoding !== "exact_text" && column.encoding !== "native") {
        policyError("Snapshot column encoding is invalid");
      }
      if (columnIds.has(column.columnId)) policyError("Relation policy contains a duplicate columnId");
      if (outputNames.has(column.outputName)) policyError("Relation policy contains a duplicate outputName");
      columnIds.add(column.columnId);
      outputNames.add(column.outputName);
      return Object.freeze({ ...column });
    });
    if (!Array.isArray(policy.orderBy) || policy.orderBy.length === 0 || policy.orderBy.length > 32) {
      policyError("orderBy must contain between 1 and 32 total-order columns");
    }
    const orderIds = new Set<string>();
    const policyOrder = policy.orderBy as readonly DeterministicOrderColumn[];
    const orderBy = policyOrder.map((order: DeterministicOrderColumn) => {
      if (!order || typeof order !== "object" || Array.isArray(order)) {
        policyError("Order column policy must be an object");
      }
      if (!columnIds.has(order.columnId)) policyError("Order column is not allowlisted");
      if (orderIds.has(order.columnId)) policyError("Relation policy contains a duplicate order column");
      if (order.direction !== "asc" && order.direction !== "desc") policyError("Order direction is invalid");
      if (order.nulls !== "first" && order.nulls !== "last") policyError("Order null handling is invalid");
      orderIds.add(order.columnId);
      return Object.freeze({ ...order });
    });
    if (policy.watermark) {
      if (typeof policy.watermark !== "object" || Array.isArray(policy.watermark)) {
        policyError("Watermark policy must be an object");
      }
      if (!columnIds.has(policy.watermark.columnId)) policyError("Watermark column is not allowlisted");
      if (policy.watermark.comparison !== "lte" || policy.watermark.required !== true) {
        policyError("Watermark policies must require an inclusive upper bound");
      }
      if (!new Set(["date", "datetime", "decimal", "integer", "text"]).has(policy.watermark.valueKind)) {
        policyError("Watermark valueKind is invalid");
      }
    }
    if (result.has(policy.relationId)) policyError("Relation policy contains a duplicate relationId");
    result.set(
      policy.relationId,
      Object.freeze({
        ...policy,
        columns: Object.freeze(columns),
        orderBy: Object.freeze(orderBy),
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
  if (!Array.isArray(requestedIds) || requestedIds.length === 0) invalidRequest("columnIds must not be empty");
  const requested = new Set<string>();
  for (const columnId of requestedIds) {
    safeId(columnId, "columnId", "INVALID_REQUEST");
    if (requested.has(columnId)) invalidRequest("columnIds must not contain duplicates");
    requested.add(columnId);
  }
  const columns = policy.columns.filter((column) => requested.has(column.columnId));
  if (columns.length !== requested.size) {
    throw new SqlSnapshotExtractionError(
      "COLUMN_NOT_ALLOWED",
      "One or more requested columns are not allowlisted for this relation"
    );
  }
  return columns;
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

function validateSourceRequest(request: SourceExtractionRequest): void {
  if (!request || typeof request !== "object" || Array.isArray(request)) invalidRequest("request must be an object");
  assertExactKeys(request, SOURCE_REQUEST_KEYS, "request");
  safeId(request.tenantId, "tenantId", "INVALID_REQUEST");
  safeId(request.datasetId, "datasetId", "INVALID_REQUEST");
  safeId(request.relationId, "relationId", "INVALID_REQUEST");
  if (!Array.isArray(request.columnIds)) invalidRequest("columnIds must be an array");
  if (request.watermark !== undefined) assertExactKeys(request.watermark, WATERMARK_KEYS, "watermark");
}

function validateResolvedLimits(limits: ResolvedSnapshotExtractionLimits): void {
  if (!limits || typeof limits !== "object" || Array.isArray(limits)) invalidRequest("limits must be an object");
  assertExactKeys(limits, LIMIT_KEYS, "limits");
  boundedInteger(limits.maximumRows, "maximumRows", 1, 1_000_000, "INVALID_REQUEST");
  boundedInteger(limits.maximumBytes, "maximumBytes", 1, 100_000_000, "INVALID_REQUEST");
  boundedInteger(
    limits.maximumCellBytes,
    "maximumCellBytes",
    1,
    Math.min(1_000_000, limits.maximumBytes),
    "INVALID_REQUEST"
  );
  boundedInteger(limits.maximumExecutionMs, "maximumExecutionMs", 1, 60_000, "INVALID_REQUEST");
  boundedInteger(limits.maximumColumns, "maximumColumns", 1, 2_000, "INVALID_REQUEST");
}

function validateReadOnlyAssumptions(assumptions: ReadOnlySourceAssumptions): void {
  if (
    !assumptions ||
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

class ExecutionGuard {
  readonly #startedAt = performance.now();
  readonly #maximumExecutionMs: number;
  readonly #signal: AbortSignal | undefined;
  readonly #cancellation: Promise<never>;
  #rejectCancellation!: (error: SqlSnapshotExtractionError) => void;
  #timer: ReturnType<typeof setTimeout>;
  #abortListener: () => void;
  #error: SqlSnapshotExtractionError | undefined;
  #destroy: (() => void) | undefined;

  constructor(maximumExecutionMs: number, signal?: AbortSignal) {
    this.#maximumExecutionMs = maximumExecutionMs;
    this.#signal = signal;
    this.#cancellation = new Promise((_, reject) => {
      this.#rejectCancellation = reject;
    });
    this.#abortListener = () => this.#cancel("CANCELLED");
    this.#timer = setTimeout(() => this.#cancel("TIME_LIMIT_EXCEEDED"), maximumExecutionMs);
    this.#timer.unref();
    signal?.addEventListener("abort", this.#abortListener, { once: true });
  }

  get cancelled(): boolean {
    return this.#error !== undefined;
  }

  attachDestroy(destroy: () => void): void {
    this.#destroy = destroy;
    if (this.#error) destroy();
  }

  async race<T>(operation: Promise<T>): Promise<T> {
    this.assertActive();
    return Promise.race([operation, this.#cancellation]);
  }

  assertActive(): void {
    if (this.#error) throw this.#error;
    if (this.#signal?.aborted) this.#cancel("CANCELLED");
    if (performance.now() - this.#startedAt > this.#maximumExecutionMs) {
      this.#cancel("TIME_LIMIT_EXCEEDED");
    }
    if (this.#error) throw this.#error;
  }

  dispose(): void {
    clearTimeout(this.#timer);
    this.#signal?.removeEventListener("abort", this.#abortListener);
  }

  #cancel(code: "CANCELLED" | "TIME_LIMIT_EXCEEDED"): void {
    if (this.#error) return;
    this.#error =
      code === "CANCELLED"
        ? new SqlSnapshotExtractionError("CANCELLED", "Snapshot extraction was cancelled")
        : new SqlSnapshotExtractionError(
            "TIME_LIMIT_EXCEEDED",
            `Snapshot extraction exceeded ${this.#maximumExecutionMs} milliseconds`
          );
    this.#destroy?.();
    this.#rejectCancellation(this.#error);
  }
}

function stablePostgresError(error: unknown): SqlSnapshotExtractionError {
  if (error instanceof SqlSnapshotExtractionError) return error;
  const code = postgresErrorCode(error);
  if (code === "57014" || code === "55P03") {
    return new SqlSnapshotExtractionError(
      "TIME_LIMIT_EXCEEDED",
      "PostgreSQL snapshot extraction exceeded an enforced database timeout"
    );
  }
  if (code === "25006") {
    return new SqlSnapshotExtractionError(
      "READ_ONLY_REQUIRED",
      "PostgreSQL snapshot extraction could not preserve read-only access"
    );
  }
  return new SqlSnapshotExtractionError("SOURCE_FAILURE", "PostgreSQL snapshot source execution failed");
}

function postgresErrorCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object") return undefined;
  const code = (error as { readonly code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

function requiredColumn(policy: NormalizedRelationPolicy, columnId: string): AllowedSnapshotColumn {
  const column = policy.columns.find((candidate) => candidate.columnId === columnId);
  if (!column) policyError("Policy references an unknown column");
  return column;
}

function timeoutSql(setting: string, milliseconds: number): string {
  return `SET LOCAL ${setting} = '${milliseconds}ms'`;
}

function quoteIdentifier(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`;
}

function isSnapshotScalar(value: unknown): value is SnapshotScalar {
  return (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  );
}

function encodedCellBytes(value: SnapshotScalar): number {
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}

function assertExactKeys(value: unknown, allowed: ReadonlySet<string>, label: string): void {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    invalidRequest(`${label} must be an object`);
  }
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length > 0) invalidRequest(`${label} contains an unsupported field`);
}

function sqlIdentifier(value: unknown, label: string): void {
  if (typeof value !== "string" || !SQL_IDENTIFIER.test(value)) {
    policyError(`${label} is not a safe SQL identifier`);
  }
}

function safeId(value: unknown, label: string, code: "INVALID_POLICY" | "INVALID_REQUEST"): void {
  if (typeof value !== "string" || !SAFE_ID.test(value)) {
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
  maximum: number,
  code: "INVALID_POLICY" | "INVALID_REQUEST"
): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    if (code === "INVALID_POLICY") policyError(`${label} is outside its trusted bound`);
    invalidRequest(`${label} is outside its execution bound`);
  }
  return value;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, nested]) => nested !== undefined)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
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

function safeDestroy(client: PostgresSnapshotClient): void {
  try {
    client.release(true);
  } catch {
    // Late connection acquisition is deliberately destroyed and never reused.
  }
}

function cancelled(): never {
  throw new SqlSnapshotExtractionError("CANCELLED", "Snapshot extraction was cancelled");
}

function sourceFailure(): never {
  throw new SqlSnapshotExtractionError("SOURCE_FAILURE", "PostgreSQL snapshot source returned an invalid result");
}

function invalidRequest(message: string): never {
  throw new SqlSnapshotExtractionError("INVALID_REQUEST", message);
}

function policyError(message: string): never {
  throw new SqlSnapshotExtractionError("INVALID_POLICY", message);
}
