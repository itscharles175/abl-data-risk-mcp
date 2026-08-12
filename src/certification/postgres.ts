import {
  canonicalHash,
  deepFreeze,
  type CanonicalJsonValue,
  type Sha256Hash
} from "../contracts/canonical.js";

export interface PostgresCertificationQuery {
  readonly text: string;
  readonly values?: readonly unknown[];
  readonly signal?: AbortSignal;
}

export interface PostgresCertificationClientV1 {
  query(
    query: string | PostgresCertificationQuery
  ): Promise<{ readonly rows: readonly Readonly<Record<string, unknown>>[] }>;
  release(destroy?: boolean | Error): void;
}

export interface PostgresCertificationPoolV1 {
  connect(): Promise<PostgresCertificationClientV1>;
}

export interface PostgresCancellationPortV1 {
  cancelBackend(input: {
    readonly backendPid: number;
    readonly reason: "certification_probe" | "operator_abort";
    readonly signal: AbortSignal;
  }): Promise<boolean>;
}

export interface PostgresCrossTenantCanaryObserverPortV1 {
  verifyCanaryExists(input: PostgresRlsRelationV1): Promise<boolean>;
}

export interface PostgresRlsRelationV1 {
  readonly schema: string;
  readonly table: string;
  readonly tenantColumn: string;
  readonly tenantContextGuc: string;
  readonly allowedTenantId: string;
  readonly deniedTenantId: string;
  readonly canaryColumn: string;
  readonly deniedCanaryValue: string;
  readonly minimumVisibleRows: number;
  readonly requireForcedRls?: boolean;
}

export interface PostgresCertificationConfigV1 {
  readonly pool: PostgresCertificationPoolV1;
  readonly cancellation: PostgresCancellationPortV1;
  readonly canaryObserver: PostgresCrossTenantCanaryObserverPortV1;
  readonly expectedRole: string;
  readonly allowedRelations: readonly Readonly<PostgresRlsRelationV1>[];
  readonly forbiddenRoleMemberships?: readonly string[];
  readonly statementTimeoutMs?: number;
  readonly lockTimeoutMs?: number;
  readonly idleInTransactionTimeoutMs?: number;
  readonly cursorFetchRows?: number;
  readonly cursorProbeRows?: number;
  readonly cancellationDelayMs?: number;
  readonly cancellationMaximumWaitMs?: number;
  readonly cancellationSleepSeconds?: number;
  readonly numericProbe?: string;
  readonly bigintProbe?: string;
  readonly now?: () => string;
}

export type PostgresCertificationCheckIdV1 =
  | "role_identity"
  | "least_privilege_attributes"
  | "transaction_read_only"
  | "timeout_enforcement"
  | "dangerous_grants"
  | "rls_isolation"
  | "exact_numeric_text"
  | "cursor_bounds"
  | "cancellation"
  | "transaction_cleanup";

export interface PostgresCertificationCheckV1 {
  readonly checkId: PostgresCertificationCheckIdV1;
  readonly status: "pass" | "fail";
  readonly message: string;
  readonly evidence: CanonicalJsonValue;
}

export interface PostgresCertificationReportV1 {
  readonly contractVersion: 1;
  readonly expectedRole: string;
  readonly backendPid: number | null;
  readonly startedAt: string;
  readonly completedAt: string;
  readonly certified: boolean;
  readonly checks: readonly Readonly<PostgresCertificationCheckV1>[];
  readonly reportHash: Sha256Hash;
}

export const POSTGRES_CERTIFICATION_SQL_V1 = Object.freeze({
  begin: "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",
  rollback: "ROLLBACK",
  roleIdentity: `/* abl_cert:role_identity */
SELECT
  current_user::text AS current_user,
  session_user::text AS session_user,
  pg_catalog.pg_backend_pid()::integer AS backend_pid,
  r.rolcanlogin,
  r.rolsuper,
  r.rolcreaterole,
  r.rolcreatedb,
  r.rolreplication,
  r.rolbypassrls
FROM pg_catalog.pg_roles AS r
WHERE r.rolname = current_user`,
  timeoutEvidence: `/* abl_cert:timeouts */
SELECT
  (EXTRACT(EPOCH FROM current_setting('statement_timeout')::interval) * 1000)::bigint::text AS statement_timeout_ms,
  (EXTRACT(EPOCH FROM current_setting('lock_timeout')::interval) * 1000)::bigint::text AS lock_timeout_ms,
  (EXTRACT(EPOCH FROM current_setting('idle_in_transaction_session_timeout')::interval) * 1000)::bigint::text AS idle_timeout_ms,
  current_setting('transaction_read_only')::text AS transaction_read_only`,
  inheritedRoles: `/* abl_cert:role_memberships */
WITH RECURSIVE inherited_roles(oid, role_name) AS (
  SELECT r.oid, r.rolname::text
  FROM pg_catalog.pg_roles AS r
  WHERE r.rolname = current_user
  UNION
  SELECT parent.oid, parent.rolname::text
  FROM inherited_roles AS child
  JOIN pg_catalog.pg_auth_members AS membership ON membership.member = child.oid
  JOIN pg_catalog.pg_roles AS parent ON parent.oid = membership.roleid
)
SELECT role_name
FROM inherited_roles
WHERE role_name <> current_user
ORDER BY role_name`,
  dangerousGrants: `/* abl_cert:dangerous_grants */
WITH allowed_relations AS (
  SELECT allowed.schema_name, allowed.relation_name
  FROM jsonb_to_recordset($1::jsonb) AS allowed(schema_name text, relation_name text)
), user_relations AS (
  SELECT c.oid, n.nspname, c.relname, c.relkind
  FROM pg_catalog.pg_class AS c
  JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
  WHERE n.nspname <> 'information_schema'
    AND n.nspname !~ '^pg_(catalog|toast|temp_)'
    AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
), violations AS (
  SELECT 'relation_write'::text AS violation_kind,
         pg_catalog.quote_ident(nspname) || '.' || pg_catalog.quote_ident(relname) AS object_name,
         concat_ws(',',
           CASE WHEN has_table_privilege(current_user, oid, 'INSERT') THEN 'INSERT' END,
           CASE WHEN has_table_privilege(current_user, oid, 'UPDATE') THEN 'UPDATE' END,
           CASE WHEN has_table_privilege(current_user, oid, 'DELETE') THEN 'DELETE' END,
           CASE WHEN has_table_privilege(current_user, oid, 'TRUNCATE') THEN 'TRUNCATE' END,
           CASE WHEN has_table_privilege(current_user, oid, 'REFERENCES') THEN 'REFERENCES' END,
           CASE WHEN has_table_privilege(current_user, oid, 'TRIGGER') THEN 'TRIGGER' END
         )::text AS privileges
  FROM user_relations
  WHERE relkind <> 'S' AND (
    has_table_privilege(current_user, oid, 'INSERT') OR
    has_table_privilege(current_user, oid, 'UPDATE') OR
    has_table_privilege(current_user, oid, 'DELETE') OR
    has_table_privilege(current_user, oid, 'TRUNCATE') OR
    has_table_privilege(current_user, oid, 'REFERENCES') OR
    has_table_privilege(current_user, oid, 'TRIGGER')
  )
  UNION ALL
  SELECT 'unapproved_select',
         pg_catalog.quote_ident(r.nspname) || '.' || pg_catalog.quote_ident(r.relname),
         'SELECT'
  FROM user_relations AS r
  WHERE r.relkind <> 'S'
    AND has_table_privilege(current_user, r.oid, 'SELECT')
    AND NOT EXISTS (
      SELECT 1 FROM allowed_relations AS a
      WHERE a.schema_name = r.nspname AND a.relation_name = r.relname
    )
  UNION ALL
  SELECT 'sequence_access',
         pg_catalog.quote_ident(nspname) || '.' || pg_catalog.quote_ident(relname),
         'USAGE/SELECT/UPDATE'
  FROM user_relations
  WHERE relkind = 'S' AND (
    has_sequence_privilege(current_user, oid, 'USAGE') OR
    has_sequence_privilege(current_user, oid, 'SELECT') OR
    has_sequence_privilege(current_user, oid, 'UPDATE')
  )
  UNION ALL
  SELECT 'schema_create', pg_catalog.quote_ident(n.nspname), 'CREATE'
  FROM pg_catalog.pg_namespace AS n
  WHERE n.nspname <> 'information_schema'
    AND n.nspname !~ '^pg_(catalog|toast|temp_)'
    AND has_schema_privilege(current_user, n.oid, 'CREATE')
  UNION ALL
  SELECT 'database_create', current_database()::text, 'CREATE'
  WHERE has_database_privilege(current_user, current_database(), 'CREATE')
  UNION ALL
  SELECT 'database_temp', current_database()::text, 'TEMP'
  WHERE has_database_privilege(current_user, current_database(), 'TEMP')
)
SELECT violation_kind, object_name, privileges
FROM violations
ORDER BY violation_kind, object_name`,
  rlsCatalog: `/* abl_cert:rls_catalog */
SELECT
  c.relrowsecurity AS row_security_enabled,
  c.relforcerowsecurity AS row_security_forced,
  NOT pg_catalog.pg_has_role(current_user, c.relowner, 'MEMBER') AS non_owner,
  c.relkind::text AS relation_kind
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relname = $2`,
  setTenantContext: `/* abl_cert:set_tenant_context */
SELECT pg_catalog.set_config($1::text, $2::text, true) AS applied`,
  exactNumeric: `/* abl_cert:exact_numeric */
SELECT
  $1::numeric AS native_numeric,
  ($1::numeric)::text AS numeric_text,
  $2::bigint AS native_bigint,
  ($2::bigint)::text AS bigint_text`,
  cancellationProbe: `/* abl_cert:cancellation */
SELECT pg_catalog.pg_sleep($1::double precision)`
});

const REQUIRED_CHECKS: readonly PostgresCertificationCheckIdV1[] = Object.freeze([
  "role_identity",
  "least_privilege_attributes",
  "transaction_read_only",
  "timeout_enforcement",
  "dangerous_grants",
  "rls_isolation",
  "exact_numeric_text",
  "cursor_bounds",
  "cancellation",
  "transaction_cleanup"
]);

const DEFAULT_FORBIDDEN_ROLES = Object.freeze([
  "pg_checkpoint",
  "pg_execute_server_program",
  "pg_monitor",
  "pg_read_all_data",
  "pg_read_all_settings",
  "pg_read_all_stats",
  "pg_read_server_files",
  "pg_signal_backend",
  "pg_stat_scan_tables",
  "pg_write_all_data",
  "pg_write_server_files"
]);

interface NormalizedConfig {
  readonly pool: PostgresCertificationPoolV1;
  readonly cancellation: PostgresCancellationPortV1;
  readonly canaryObserver: PostgresCrossTenantCanaryObserverPortV1;
  readonly expectedRole: string;
  readonly allowedRelations: readonly Readonly<Required<PostgresRlsRelationV1>>[];
  readonly forbiddenRoleMemberships: ReadonlySet<string>;
  readonly statementTimeoutMs: number;
  readonly lockTimeoutMs: number;
  readonly idleInTransactionTimeoutMs: number;
  readonly cursorFetchRows: number;
  readonly cursorProbeRows: number;
  readonly cancellationDelayMs: number;
  readonly cancellationMaximumWaitMs: number;
  readonly cancellationSleepSeconds: number;
  readonly numericProbe: string;
  readonly bigintProbe: string;
  readonly now: () => string;
}

export class PostgresCertificationHarnessV1 {
  readonly #config: NormalizedConfig;

  constructor(config: PostgresCertificationConfigV1) {
    this.#config = normalizeConfig(config);
  }

  async certify(signal?: AbortSignal): Promise<PostgresCertificationReportV1> {
    const startedAt = canonicalTimestamp(this.#config.now(), "startedAt");
    const checks = new Map<PostgresCertificationCheckIdV1, PostgresCertificationCheckV1>();
    let client: PostgresCertificationClientV1 | undefined;
    let transactionOpen = false;
    let destroyConnection = false;
    let backendPid: number | null = null;
    let executionFailure = "not_completed";

    const record = (
      checkId: PostgresCertificationCheckIdV1,
      passed: boolean,
      message: string,
      evidence: CanonicalJsonValue
    ): void => {
      if (checks.has(checkId)) throw new PostgresCertificationError("INTERNAL_ERROR", `Duplicate check '${checkId}'`);
      checks.set(checkId, deepFreeze({ checkId, status: passed ? "pass" : "fail", message, evidence }));
    };

    try {
      assertActive(signal);
      client = await this.#config.pool.connect();
      if (!client || typeof client.query !== "function" || typeof client.release !== "function") {
        throw new PostgresCertificationError("PORT_CONTRACT_VIOLATION", "Pool returned an invalid client");
      }
      await client.query(POSTGRES_CERTIFICATION_SQL_V1.begin);
      transactionOpen = true;
      await client.query(timeoutSql("statement_timeout", this.#config.statementTimeoutMs));
      await client.query(timeoutSql("lock_timeout", this.#config.lockTimeoutMs));
      await client.query(timeoutSql("idle_in_transaction_session_timeout", this.#config.idleInTransactionTimeoutMs));

      const role = oneRow(await client.query(POSTGRES_CERTIFICATION_SQL_V1.roleIdentity), "role identity");
      backendPid = safePositiveInteger(role.backend_pid, "backend_pid", 2_147_483_647);
      const identityPassed = role.current_user === this.#config.expectedRole && role.session_user === this.#config.expectedRole;
      record("role_identity", identityPassed, identityPassed ? "Current and session role match the certified principal" : "Role identity mismatch", {
        currentUser: textValue(role.current_user, "current_user"),
        sessionUser: textValue(role.session_user, "session_user")
      });
      const attributes = {
        rolcanlogin: booleanValue(role.rolcanlogin, "rolcanlogin"),
        rolsuper: booleanValue(role.rolsuper, "rolsuper"),
        rolcreaterole: booleanValue(role.rolcreaterole, "rolcreaterole"),
        rolcreatedb: booleanValue(role.rolcreatedb, "rolcreatedb"),
        rolreplication: booleanValue(role.rolreplication, "rolreplication"),
        rolbypassrls: booleanValue(role.rolbypassrls, "rolbypassrls")
      };
      const attributesPassed = attributes.rolcanlogin && !attributes.rolsuper && !attributes.rolcreaterole &&
        !attributes.rolcreatedb && !attributes.rolreplication && !attributes.rolbypassrls;
      record("least_privilege_attributes", attributesPassed, attributesPassed ? "Role attributes are least privileged" : "Role has a forbidden PostgreSQL attribute", attributes);

      const timeouts = oneRow(await client.query(POSTGRES_CERTIFICATION_SQL_V1.timeoutEvidence), "timeout evidence");
      const readOnly = timeouts.transaction_read_only === "on";
      record("transaction_read_only", readOnly, readOnly ? "Certification transaction is physically read only" : "Certification transaction is not read only", {
        transactionReadOnly: textValue(timeouts.transaction_read_only, "transaction_read_only")
      });
      const observedTimeouts = {
        statementTimeoutMs: exactInteger(timeouts.statement_timeout_ms, "statement_timeout_ms"),
        lockTimeoutMs: exactInteger(timeouts.lock_timeout_ms, "lock_timeout_ms"),
        idleTimeoutMs: exactInteger(timeouts.idle_timeout_ms, "idle_timeout_ms")
      };
      const timeoutsPassed = observedTimeouts.statementTimeoutMs === String(this.#config.statementTimeoutMs) &&
        observedTimeouts.lockTimeoutMs === String(this.#config.lockTimeoutMs) &&
        observedTimeouts.idleTimeoutMs === String(this.#config.idleInTransactionTimeoutMs);
      record("timeout_enforcement", timeoutsPassed, timeoutsPassed ? "Database timeouts match policy" : "Database timeouts differ from policy", observedTimeouts);

      const inherited = await client.query(POSTGRES_CERTIFICATION_SQL_V1.inheritedRoles);
      const inheritedRoles = inherited.rows.map((row) => textValue(row.role_name, "role_name")).sort(compareText);
      const forbiddenInherited = inheritedRoles.filter((roleName) => this.#config.forbiddenRoleMemberships.has(roleName));
      const allowedJson = JSON.stringify(this.#config.allowedRelations.map((relation) => ({
        schema_name: relation.schema,
        relation_name: relation.table
      })));
      const grantResult = await client.query({
        text: POSTGRES_CERTIFICATION_SQL_V1.dangerousGrants,
        values: [allowedJson]
      });
      const grantViolations = grantResult.rows.map((row) => ({
        kind: textValue(row.violation_kind, "violation_kind"),
        object: textValue(row.object_name, "object_name"),
        privileges: textValue(row.privileges, "privileges")
      })).sort((left, right) => compareText(`${left.kind}:${left.object}`, `${right.kind}:${right.object}`));
      const grantsPassed = forbiddenInherited.length === 0 && grantViolations.length === 0;
      record("dangerous_grants", grantsPassed, grantsPassed ? "No dangerous effective grants or inherited roles found" : "Dangerous grants or inherited roles found", {
        inheritedRoles,
        forbiddenInherited,
        grantViolations
      });

      const rlsEvidence: Array<CanonicalJsonValue> = [];
      let rlsPassed = true;
      for (const relation of this.#config.allowedRelations) {
        assertActive(signal);
        const catalog = oneRow(await client.query({
          text: POSTGRES_CERTIFICATION_SQL_V1.rlsCatalog,
          values: [relation.schema, relation.table]
        }), `RLS catalog ${relation.schema}.${relation.table}`);
        const enabled = booleanValue(catalog.row_security_enabled, "row_security_enabled");
        const forced = booleanValue(catalog.row_security_forced, "row_security_forced");
        const nonOwner = booleanValue(catalog.non_owner, "non_owner");
        const relationKind = textValue(catalog.relation_kind, "relation_kind");
        await client.query({
          text: POSTGRES_CERTIFICATION_SQL_V1.setTenantContext,
          values: [relation.tenantContextGuc, relation.allowedTenantId]
        });
        const visible = oneRow(await client.query({
          text: visiblePopulationSql(relation),
          values: [relation.allowedTenantId]
        }), `visible population ${relation.schema}.${relation.table}`);
        const visibleRows = exactInteger(visible.visible_rows, "visible_rows");
        const allowedRows = exactInteger(visible.allowed_rows, "allowed_rows");
        const foreignRows = exactInteger(visible.foreign_rows, "foreign_rows");
        const denied = oneRow(await client.query({
          text: deniedCanarySql(relation),
          values: [relation.deniedTenantId, relation.deniedCanaryValue]
        }), `denied canary ${relation.schema}.${relation.table}`);
        const deniedVisible = booleanValue(denied.canary_visible, "canary_visible");
        const observerConfirmed = await this.#config.canaryObserver.verifyCanaryExists(relation);
        const relationPassed = enabled && nonOwner && (relationKind === "r" || relationKind === "p") &&
          (!relation.requireForcedRls || forced) &&
          BigInt(visibleRows) >= BigInt(relation.minimumVisibleRows) &&
          visibleRows === allowedRows && foreignRows === "0" && !deniedVisible && observerConfirmed;
        rlsPassed = rlsPassed && relationPassed;
        rlsEvidence.push({
          relation: `${relation.schema}.${relation.table}`,
          rowSecurityEnabled: enabled,
          rowSecurityForced: forced,
          nonOwner,
          relationKind,
          visibleRows,
          allowedRows,
          foreignRows,
          deniedCanaryVisible: deniedVisible,
          observerConfirmed
        });
      }
      record("rls_isolation", rlsPassed, rlsPassed ? "RLS and cross-tenant canaries passed" : "RLS or cross-tenant canary failed", rlsEvidence);

      const numeric = oneRow(await client.query({
        text: POSTGRES_CERTIFICATION_SQL_V1.exactNumeric,
        values: [this.#config.numericProbe, this.#config.bigintProbe]
      }), "exact numeric probe");
      const nativeNumeric = exactDecimal(numeric.native_numeric, "native_numeric");
      const numericText = exactDecimal(numeric.numeric_text, "numeric_text");
      const nativeBigint = exactInteger(numeric.native_bigint, "native_bigint");
      const bigintText = exactInteger(numeric.bigint_text, "bigint_text");
      const numericPassed = nativeNumeric === this.#config.numericProbe && numericText === this.#config.numericProbe &&
        nativeBigint === this.#config.bigintProbe && bigintText === this.#config.bigintProbe;
      record("exact_numeric_text", numericPassed, numericPassed ? "Native and cast numeric values remain exact strings" : "Numeric driver parsing is lossy or non-text", {
        nativeNumeric,
        numericText,
        nativeBigint,
        bigintText
      });

      const cursorPassed = await runCursorProbe(client, this.#config.cursorFetchRows, this.#config.cursorProbeRows);
      record("cursor_bounds", cursorPassed.passed, cursorPassed.passed ? "DECLARE/FETCH cursor stayed within bounds" : "Cursor output violated fetch bounds or ordering", cursorPassed.evidence);

      const cancellationPassed = await runCancellationProbe(
        client,
        backendPid,
        this.#config.cancellation,
        this.#config.cancellationDelayMs,
        this.#config.cancellationMaximumWaitMs,
        this.#config.cancellationSleepSeconds
      );
      destroyConnection = !cancellationPassed.connectionReusable;
      record("cancellation", cancellationPassed.passed, cancellationPassed.passed ? "AbortSignal cancelled the exact backend through the safe seam" : "Cancellation probe failed", cancellationPassed.evidence);
      executionFailure = "none";
    } catch (error) {
      executionFailure = stableErrorCode(error);
      destroyConnection = true;
    } finally {
      let cleanupPassed = false;
      if (client !== undefined && transactionOpen) {
        try {
          await client.query(POSTGRES_CERTIFICATION_SQL_V1.rollback);
          transactionOpen = false;
          cleanupPassed = true;
        } catch {
          destroyConnection = true;
        }
      }
      if (!checks.has("transaction_cleanup")) {
        record("transaction_cleanup", cleanupPassed, cleanupPassed ? "Certification transaction rolled back" : "Certification transaction cleanup failed", {
          rolledBack: cleanupPassed
        });
      }
      try {
        client?.release(destroyConnection);
      } catch {
        // Report state remains deterministic and the caller never receives pool internals.
      }
    }

    for (const checkId of REQUIRED_CHECKS) {
      if (!checks.has(checkId)) {
        record(checkId, false, "Check did not complete", { executionFailure });
      }
    }
    const orderedChecks = REQUIRED_CHECKS.map((checkId) => checks.get(checkId)!);
    const completedAt = canonicalTimestamp(this.#config.now(), "completedAt");
    const certified = orderedChecks.every((check) => check.status === "pass");
    const body = {
      contractVersion: 1 as const,
      expectedRole: this.#config.expectedRole,
      backendPid,
      startedAt,
      completedAt,
      certified,
      checks: orderedChecks
    };
    return deepFreeze({ ...body, reportHash: canonicalHash(body) });
  }
}

export class PgCancelBackendPortV1 implements PostgresCancellationPortV1 {
  readonly #pool: PostgresCertificationPoolV1;

  constructor(pool: PostgresCertificationPoolV1) {
    if (!pool || typeof pool.connect !== "function") invalid("Cancellation pool is invalid");
    this.#pool = pool;
  }

  async cancelBackend(input: {
    readonly backendPid: number;
    readonly reason: "certification_probe" | "operator_abort";
    readonly signal: AbortSignal;
  }): Promise<boolean> {
    const backendPid = boundedInteger(input.backendPid, "backendPid", 1, 2_147_483_647);
    if (input.reason !== "certification_probe" && input.reason !== "operator_abort") invalid("Cancellation reason is invalid");
    const client = await this.#pool.connect();
    let destroy = false;
    try {
      const row = oneRow(await client.query({
        text: "/* abl_cert:pg_cancel_backend */ SELECT pg_catalog.pg_cancel_backend($1::integer) AS cancelled",
        values: [backendPid]
      }), "pg_cancel_backend");
      return booleanValue(row.cancelled, "cancelled");
    } catch (error) {
      destroy = true;
      throw new PostgresCertificationError("CANCELLATION_FAILED", `Cancellation seam failed (${stableErrorCode(error)})`);
    } finally {
      client.release(destroy);
    }
  }
}

export class PostgresCrossTenantCanaryObserverV1 implements PostgresCrossTenantCanaryObserverPortV1 {
  readonly #pool: PostgresCertificationPoolV1;

  constructor(pool: PostgresCertificationPoolV1) {
    if (!pool || typeof pool.connect !== "function") invalid("Canary observer pool is invalid");
    this.#pool = pool;
  }

  async verifyCanaryExists(input: PostgresRlsRelationV1): Promise<boolean> {
    const relation = normalizeRelation(input);
    const client = await this.#pool.connect();
    let transactionOpen = false;
    let destroy = false;
    try {
      await client.query(POSTGRES_CERTIFICATION_SQL_V1.begin);
      transactionOpen = true;
      const row = oneRow(await client.query({
        text: observerCanarySql(relation),
        values: [relation.deniedTenantId, relation.deniedCanaryValue]
      }), "observer canary");
      await client.query(POSTGRES_CERTIFICATION_SQL_V1.rollback);
      transactionOpen = false;
      return booleanValue(row.canary_exists, "canary_exists");
    } catch (error) {
      destroy = true;
      if (transactionOpen) {
        try { await client.query(POSTGRES_CERTIFICATION_SQL_V1.rollback); } catch { destroy = true; }
      }
      throw new PostgresCertificationError("CANARY_OBSERVER_FAILED", `Canary observer failed (${stableErrorCode(error)})`);
    } finally {
      client.release(destroy);
    }
  }
}

export type PostgresCertificationErrorCode =
  | "INVALID_CONFIG"
  | "PORT_CONTRACT_VIOLATION"
  | "CANCELLATION_FAILED"
  | "CANARY_OBSERVER_FAILED"
  | "OPERATOR_ABORTED"
  | "INTERNAL_ERROR";

export class PostgresCertificationError extends Error {
  constructor(readonly code: PostgresCertificationErrorCode, message: string) {
    super(message);
    this.name = "PostgresCertificationError";
  }
}

function normalizeConfig(input: PostgresCertificationConfigV1): NormalizedConfig {
  if (!input || typeof input !== "object" || Array.isArray(input)) invalid("Certification config must be an object");
  if (!input.pool || typeof input.pool.connect !== "function") invalid("Certification pool is invalid");
  if (!input.cancellation || typeof input.cancellation.cancelBackend !== "function") invalid("Cancellation port is invalid");
  if (!input.canaryObserver || typeof input.canaryObserver.verifyCanaryExists !== "function") invalid("Canary observer port is invalid");
  const expectedRole = sqlIdentifier(input.expectedRole, "expectedRole");
  if (!Array.isArray(input.allowedRelations) || input.allowedRelations.length < 1 || input.allowedRelations.length > 32) {
    invalid("Certification requires 1 through 32 RLS relations");
  }
  const allowedRelations = Object.freeze(input.allowedRelations.map(normalizeRelation));
  const relationKeys = allowedRelations.map((relation) => `${relation.schema}.${relation.table}`);
  if (new Set(relationKeys).size !== relationKeys.length) invalid("RLS relations must be unique");
  const forbidden = [...DEFAULT_FORBIDDEN_ROLES, ...(input.forbiddenRoleMemberships ?? [])]
    .map((role) => sqlIdentifier(role, "forbiddenRoleMembership"));
  const statementTimeoutMs = boundedInteger(input.statementTimeoutMs ?? 5_000, "statementTimeoutMs", 100, 60_000);
  const lockTimeoutMs = boundedInteger(input.lockTimeoutMs ?? 1_000, "lockTimeoutMs", 1, statementTimeoutMs);
  const idleInTransactionTimeoutMs = boundedInteger(input.idleInTransactionTimeoutMs ?? 10_000, "idleInTransactionTimeoutMs", 100, 120_000);
  const cursorFetchRows = boundedInteger(input.cursorFetchRows ?? 100, "cursorFetchRows", 1, 1_000);
  const cursorProbeRows = boundedInteger(input.cursorProbeRows ?? cursorFetchRows + 1, "cursorProbeRows", 1, 10_000);
  const cancellationDelayMs = boundedInteger(input.cancellationDelayMs ?? 25, "cancellationDelayMs", 1, 5_000);
  const cancellationMaximumWaitMs = boundedInteger(input.cancellationMaximumWaitMs ?? 5_000, "cancellationMaximumWaitMs", cancellationDelayMs + 1, 60_000);
  const cancellationSleepSeconds = boundedInteger(input.cancellationSleepSeconds ?? 30, "cancellationSleepSeconds", 1, 120);
  const numericProbe = canonicalDecimal(input.numericProbe ?? "9007199254740993.123456789", "numericProbe");
  const bigintProbe = canonicalInteger(input.bigintProbe ?? "9223372036854775807", "bigintProbe");
  const bigintValue = BigInt(bigintProbe);
  if (bigintValue < -9_223_372_036_854_775_808n || bigintValue > 9_223_372_036_854_775_807n) {
    invalid("bigintProbe must fit PostgreSQL bigint");
  }
  const now = input.now ?? (() => new Date().toISOString());
  return Object.freeze({
    pool: input.pool,
    cancellation: input.cancellation,
    canaryObserver: input.canaryObserver,
    expectedRole,
    allowedRelations,
    forbiddenRoleMemberships: new Set(forbidden),
    statementTimeoutMs,
    lockTimeoutMs,
    idleInTransactionTimeoutMs,
    cursorFetchRows,
    cursorProbeRows,
    cancellationDelayMs,
    cancellationMaximumWaitMs,
    cancellationSleepSeconds,
    numericProbe,
    bigintProbe,
    now
  });
}

function normalizeRelation(input: PostgresRlsRelationV1): Required<PostgresRlsRelationV1> {
  if (!input || typeof input !== "object" || Array.isArray(input)) invalid("RLS relation must be an object");
  const minimumVisibleRows = boundedInteger(input.minimumVisibleRows, "minimumVisibleRows", 1, 10_000_000);
  if (input.allowedTenantId === input.deniedTenantId) invalid("Allowed and denied tenant canaries must differ");
  if (input.requireForcedRls !== undefined && typeof input.requireForcedRls !== "boolean") {
    invalid("requireForcedRls must be boolean");
  }
  return Object.freeze({
    schema: sqlIdentifier(input.schema, "schema"),
    table: sqlIdentifier(input.table, "table"),
    tenantColumn: sqlIdentifier(input.tenantColumn, "tenantColumn"),
    tenantContextGuc: gucName(input.tenantContextGuc),
    allowedTenantId: boundedText(input.allowedTenantId, "allowedTenantId", 256),
    deniedTenantId: boundedText(input.deniedTenantId, "deniedTenantId", 256),
    canaryColumn: sqlIdentifier(input.canaryColumn, "canaryColumn"),
    deniedCanaryValue: boundedText(input.deniedCanaryValue, "deniedCanaryValue", 512),
    minimumVisibleRows,
    requireForcedRls: input.requireForcedRls ?? true
  });
}

function visiblePopulationSql(relation: Required<PostgresRlsRelationV1>): string {
  const tenant = quoteIdentifier(relation.tenantColumn);
  return `/* abl_cert:rls_visible */
SELECT
  count(*)::bigint::text AS visible_rows,
  count(*) FILTER (WHERE ${tenant}::text = $1::text)::bigint::text AS allowed_rows,
  count(*) FILTER (WHERE ${tenant}::text <> $1::text OR ${tenant} IS NULL)::bigint::text AS foreign_rows
FROM ${quoteIdentifier(relation.schema)}.${quoteIdentifier(relation.table)}`;
}

function deniedCanarySql(relation: Required<PostgresRlsRelationV1>): string {
  return `/* abl_cert:rls_denied_canary */
SELECT EXISTS (
  SELECT 1
  FROM ${quoteIdentifier(relation.schema)}.${quoteIdentifier(relation.table)}
  WHERE ${quoteIdentifier(relation.tenantColumn)}::text = $1::text
    AND ${quoteIdentifier(relation.canaryColumn)}::text = $2::text
) AS canary_visible`;
}

function observerCanarySql(relation: Required<PostgresRlsRelationV1>): string {
  return `/* abl_cert:observer_canary */
SELECT EXISTS (
  SELECT 1
  FROM ${quoteIdentifier(relation.schema)}.${quoteIdentifier(relation.table)}
  WHERE ${quoteIdentifier(relation.tenantColumn)}::text = $1::text
    AND ${quoteIdentifier(relation.canaryColumn)}::text = $2::text
) AS canary_exists`;
}

async function runCursorProbe(
  client: PostgresCertificationClientV1,
  fetchRows: number,
  probeRows: number
): Promise<{ readonly passed: boolean; readonly evidence: CanonicalJsonValue }> {
  const cursorName = "abl_cert_cursor";
  await client.query({
    text: `/* abl_cert:cursor_declare */ DECLARE "${cursorName}" NO SCROLL CURSOR FOR
SELECT ordinal::bigint::text AS ordinal
FROM pg_catalog.generate_series(1, $1::integer) AS ordinal
ORDER BY ordinal`,
    values: [probeRows]
  });
  let expectedOrdinal = 1;
  let totalRows = 0;
  let bounded = true;
  while (true) {
    const result = await client.query(`/* abl_cert:cursor_fetch */ FETCH FORWARD ${fetchRows} FROM "${cursorName}"`);
    if (result.rows.length > fetchRows) bounded = false;
    for (const row of result.rows) {
      const ordinal = exactInteger(row.ordinal, "cursor ordinal");
      if (ordinal !== String(expectedOrdinal)) bounded = false;
      expectedOrdinal += 1;
      totalRows += 1;
      if (totalRows > probeRows) bounded = false;
    }
    if (result.rows.length < fetchRows) break;
  }
  await client.query(`/* abl_cert:cursor_close */ CLOSE "${cursorName}"`);
  const passed = bounded && totalRows === probeRows;
  return {
    passed,
    evidence: { fetchRows, expectedRows: probeRows, observedRows: totalRows, ordered: bounded }
  };
}

async function runCancellationProbe(
  client: PostgresCertificationClientV1,
  backendPid: number,
  cancellation: PostgresCancellationPortV1,
  cancellationDelayMs: number,
  maximumWaitMs: number,
  sleepSeconds: number
): Promise<{
  readonly passed: boolean;
  readonly connectionReusable: boolean;
  readonly evidence: CanonicalJsonValue;
}> {
  const controller = new AbortController();
  let cancellationPromise: Promise<boolean> | undefined;
  const cancel = (): void => {
    cancellationPromise ??= cancellation.cancelBackend({
      backendPid,
      reason: "certification_probe",
      signal: controller.signal
    });
  };
  controller.signal.addEventListener("abort", cancel, { once: true });
  const timer = setTimeout(() => controller.abort(), cancellationDelayMs);
  let queryCode = "none";
  let queryCancelled = false;
  try {
    await withDeadline(
      client.query({
        text: POSTGRES_CERTIFICATION_SQL_V1.cancellationProbe,
        values: [sleepSeconds],
        signal: controller.signal
      }),
      maximumWaitMs
    );
  } catch (error) {
    queryCode = stableErrorCode(error);
    queryCancelled = queryCode === "57014" || queryCode === "AbortError";
  } finally {
    clearTimeout(timer);
    if (!controller.signal.aborted) controller.abort();
  }
  let backendCancelled = false;
  try {
    backendCancelled = await withDeadline(cancellationPromise ?? Promise.resolve(false), maximumWaitMs);
  } catch (error) {
    queryCode = queryCode === "none" ? stableErrorCode(error) : queryCode;
  }
  const passed = controller.signal.aborted && backendCancelled && queryCancelled;
  return {
    passed,
    connectionReusable: queryCancelled,
    evidence: {
      abortSignalObserved: controller.signal.aborted,
      backendCancelled,
      queryCancelled,
      queryCode
    }
  };
}

function timeoutSql(name: "statement_timeout" | "lock_timeout" | "idle_in_transaction_session_timeout", value: number): string {
  return `SET LOCAL ${name} = '${value}ms'`;
}

function oneRow(
  result: { readonly rows: readonly Readonly<Record<string, unknown>>[] },
  label: string
): Readonly<Record<string, unknown>> {
  if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) {
    throw new PostgresCertificationError("PORT_CONTRACT_VIOLATION", `${label} must return exactly one row`);
  }
  return result.rows[0]!;
}

function booleanValue(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") {
    throw new PostgresCertificationError("PORT_CONTRACT_VIOLATION", `${label} must be boolean`);
  }
  return value;
}

function textValue(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length > 2_000 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new PostgresCertificationError("PORT_CONTRACT_VIOLATION", `${label} must be bounded text`);
  }
  return value;
}

function exactInteger(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^-?(?:0|[1-9]\d*)$/.test(value) || value === "-0") {
    throw new PostgresCertificationError("PORT_CONTRACT_VIOLATION", `${label} must be an exact integer string`);
  }
  return value;
}

function exactDecimal(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new PostgresCertificationError("PORT_CONTRACT_VIOLATION", `${label} must remain an exact string`);
  }
  return canonicalDecimal(value, label);
}

function canonicalInteger(value: string, label: string): string {
  if (typeof value !== "string" || value.length > 1_000 || !/^-?(?:0|[1-9]\d*)$/.test(value) || value === "-0") {
    invalid(`${label} must be a canonical integer string`);
  }
  return value;
}

function canonicalDecimal(value: string, label: string): string {
  if (
    typeof value !== "string" ||
    value.length > 1_000 ||
    !/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value) ||
    /^-0(?:\.0+)?$/.test(value)
  ) {
    invalid(`${label} must be a canonical exact decimal string`);
  }
  return value;
}

function safePositiveInteger(value: unknown, label: string, maximum: number): number {
  if (typeof value !== "number") {
    throw new PostgresCertificationError("PORT_CONTRACT_VIOLATION", `${label} must be an integer`);
  }
  return boundedInteger(value, label, 1, maximum);
}

function boundedInteger(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalid(`${label} is outside policy`);
  return value;
}

function boundedText(value: string, label: string, maximum: number): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) {
    invalid(`${label} must be bounded text`);
  }
  return value;
}

function sqlIdentifier(value: string, label: string): string {
  if (typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_$]{0,127}$/.test(value)) {
    invalid(`${label} must be a PostgreSQL identifier`);
  }
  return value;
}

function gucName(value: string): string {
  if (typeof value !== "string" || !/^[a-z_][a-z0-9_]{0,62}(?:\.[a-z_][a-z0-9_]{0,62})+$/.test(value)) {
    invalid("tenantContextGuc must be a namespaced custom setting");
  }
  return value;
}

function canonicalTimestamp(value: string, label: string): string {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value) ||
    !Number.isFinite(Date.parse(value))
  ) {
    invalid(`${label} must be a canonical UTC timestamp`);
  }
  return value;
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function assertActive(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) throw new PostgresCertificationError("OPERATOR_ABORTED", "Certification was cancelled");
}

function stableErrorCode(error: unknown): string {
  if (error instanceof PostgresCertificationError) return error.code;
  if (error && typeof error === "object") {
    const candidate = error as { readonly code?: unknown; readonly name?: unknown };
    if (typeof candidate.code === "string" && /^[A-Za-z0-9_]{1,32}$/.test(candidate.code)) return candidate.code;
    if (typeof candidate.name === "string" && /^[A-Za-z][A-Za-z0-9_]{0,31}$/.test(candidate.name)) return candidate.name;
  }
  return "DATABASE_ERROR";
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

async function withDeadline<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new PostgresCertificationError("CANCELLATION_FAILED", "Cancellation deadline exceeded")), timeoutMs);
      })
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function invalid(message: string): never {
  throw new PostgresCertificationError("INVALID_CONFIG", message);
}
