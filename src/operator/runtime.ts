import { createHash } from "node:crypto";
import { userInfo } from "node:os";

import * as z from "zod/v4";
import pg from "pg";

import { loadConfig, type SourceConfig } from "../config.js";
import { MonitoringAlertStore } from "../control/alerts.js";
import { ArtifactStore } from "../control/artifacts.js";
import { DefinitionStore } from "../control/definitions.js";
import { GovernedDefinitionV2Store } from "../control/governed-definitions-v2.js";
import { InputCertificationStore } from "../control/input-certifications.js";
import { ControlStore } from "../control/store.js";
import { isRestrictedColumn, tableKey } from "../infrastructure/sql/types.js";
import { loadRuntimeConfiguration, type RuntimeEnvironment } from "../runtime/config.js";
import { TenantMembershipStore } from "../security/membership-store.js";
import { SnapshotIngestionService } from "../services/ingestion.js";
import { InputCertificationService } from "../services/input-certification.js";
import { GovernedDefinitionV2Resolver } from "../services/governed-definition-v2-resolver.js";
import { TrustedPostgresSnapshotSource } from "../services/postgres-snapshot-source.js";
import {
  SqlSnapshotExtractionService,
  TrustedSqliteSnapshotSource,
  type SnapshotExtractionLimits,
  type SnapshotRelationPolicy
} from "../services/sql-snapshot-extraction.js";
import {
  OperatorControlPlane,
  readBoundedJsonFile,
  type OperatorPrincipal
} from "./control-plane.js";
import { operatorIdentifierSchema } from "./schemas.js";

export type OperatorRuntimeErrorCode =
  | "INVALID_OPERATOR_CONFIGURATION"
  | "SOURCE_NOT_CONFIGURED"
  | "UNSUPPORTED_SQL_DIALECT"
  | "SQL_POLICY_VIOLATION";

export class OperatorRuntimeError extends Error {
  constructor(
    readonly code: OperatorRuntimeErrorCode,
    message: string
  ) {
    super(message);
    this.name = "OperatorRuntimeError";
  }
}

export interface OperatorRuntime {
  readonly controlPlane: OperatorControlPlane;
  close(): Promise<void>;
}

const { Pool } = pg;

const sqlColumnSchema = z
  .object({
    columnId: operatorIdentifierSchema,
    sourceName: z.string().regex(/^[A-Za-z_][A-Za-z0-9_$]{0,127}$/),
    outputName: z.string().regex(/^[A-Za-z_][A-Za-z0-9_$]{0,127}$/),
    classification: z.literal("approved"),
    encoding: z.enum(["exact_text", "native"])
  })
  .strict();
const orderColumnSchema = z
  .object({
    columnId: operatorIdentifierSchema,
    direction: z.enum(["asc", "desc"]),
    nulls: z.enum(["first", "last"])
  })
  .strict();
const watermarkSchema = z
  .object({
    columnId: operatorIdentifierSchema,
    valueKind: z.enum(["date", "datetime", "decimal", "integer", "text"]),
    comparison: z.literal("lte"),
    required: z.literal(true)
  })
  .strict();
const relationPolicySchema = z
  .object({
    relationId: operatorIdentifierSchema,
    tenantId: operatorIdentifierSchema,
    tenantIsolation: z.literal("dedicated_relation"),
    datasetId: operatorIdentifierSchema,
    schema: z.string().regex(/^[A-Za-z_][A-Za-z0-9_$]{0,127}$/),
    table: z.string().regex(/^[A-Za-z_][A-Za-z0-9_$]{0,127}$/),
    relationKind: z.literal("table"),
    columns: z.array(sqlColumnSchema).min(1).max(2_000),
    orderBy: z.array(orderColumnSchema).min(1).max(32),
    orderIsUnique: z.literal(true),
    watermark: watermarkSchema.optional()
  })
  .strict();
const extractionLimitsSchema = z
  .object({
    maximumRows: z.number().int().min(1).max(1_000_000).optional(),
    maximumBytes: z.number().int().min(1).max(100_000_000).optional(),
    maximumCellBytes: z.number().int().min(1).max(1_000_000).optional(),
    maximumExecutionMs: z.number().int().min(1).max(60_000).optional(),
    maximumColumns: z.number().int().min(1).max(2_000).optional()
  })
  .strict();
const sqlPolicyFileSchema = z
  .object({
    version: z.literal(1),
    sources: z
      .array(
        z
          .object({
            sourceId: operatorIdentifierSchema,
            relations: z.array(relationPolicySchema).min(1).max(1_000),
            limits: extractionLimitsSchema.optional()
          })
          .strict()
      )
      .max(100)
  })
  .strict();

/**
 * Derives one stable, non-PII audit identity from the authenticated local OS
 * account. Shell aliases and request fields cannot create alternate actors.
 */
export function deriveLocalOperatorPrincipal(
  account?: Readonly<{ readonly uid: number; readonly username: string }>
): OperatorPrincipal {
  let resolvedAccount = account;
  if (resolvedAccount === undefined) {
    try {
      resolvedAccount = userInfo();
    } catch {
      throw new OperatorRuntimeError(
        "INVALID_OPERATOR_CONFIGURATION",
        "Local operator account identity is unavailable"
      );
    }
  }
  if (
    !Number.isSafeInteger(resolvedAccount.uid) ||
    resolvedAccount.uid < -1 ||
    !resolvedAccount.username ||
    resolvedAccount.username.length > 1_024 ||
    /[\u0000\r\n]/.test(resolvedAccount.username)
  ) {
    throw new OperatorRuntimeError(
      "INVALID_OPERATOR_CONFIGURATION",
      "Local operator account identity is unavailable"
    );
  }
  const accountKey = resolvedAccount.uid >= 0
    ? `uid:${resolvedAccount.uid}`
    : `username:${resolvedAccount.username}`;
  const digest = createHash("sha256")
    .update(`${process.platform}\u0000${accountKey}`)
    .digest("hex");
  return Object.freeze({
    principalId: `local-os:${digest}`,
    authenticationMethod: "local_os_account",
    authorizationScope: "global_admin"
  });
}

/**
 * Creates the privileged local operator graph. The supplied principal must
 * come from a trusted process boundary; tenant ids in request files are only
 * resource selectors and never confer authorization.
 */
export function createOperatorRuntime(
  environment: RuntimeEnvironment = process.env,
  principal: OperatorPrincipal = deriveLocalOperatorPrincipal()
): OperatorRuntime {
  const runtime = loadRuntimeConfiguration(environment);
  let keysReleased = false;
  const releaseArtifactKeys = (): void => {
    if (keysReleased) return;
    keysReleased = true;
    for (const material of Object.values(runtime.artifactKeyRing.keys)) material.fill(0);
  };

  let control: ControlStore | undefined;
  let definitions: DefinitionStore | undefined;
  let governedDefinitionsV2: GovernedDefinitionV2Store | undefined;
  let alerts: MonitoringAlertStore | undefined;
  let memberships: TenantMembershipStore | undefined;
  let inputCertifications: InputCertificationStore | undefined;
  try {
    const sourceConfiguration = loadConfig(runtime.storage.sourceConfigPath);
    const sqlPolicies = loadSqlPolicies(environment.ABL_OPERATOR_SQL_POLICIES_FILE);
    const controlStore = control = new ControlStore(runtime.storage.controlDatabasePath);
    const definitionStore = definitions = new DefinitionStore(runtime.storage.controlDatabasePath);
    const governedDefinitionV2Store = governedDefinitionsV2 = new GovernedDefinitionV2Store(
      runtime.storage.controlDatabasePath
    );
    const governedDefinitionV2Resolver = new GovernedDefinitionV2Resolver(
      governedDefinitionV2Store
    );
    const alertStore = alerts = new MonitoringAlertStore(runtime.storage.controlDatabasePath);
    const membershipStore = memberships = new TenantMembershipStore(runtime.storage.controlDatabasePath);
    const inputCertificationStore = inputCertifications = new InputCertificationStore(
      runtime.storage.controlDatabasePath
    );
    const artifacts = new ArtifactStore(runtime.storage.artifactRoot, runtime.artifactKeyRing);
    const ingestion = new SnapshotIngestionService(controlStore, artifacts);
    const inputCertification = new InputCertificationService({
      control: controlStore,
      definitions: definitionStore,
      artifacts,
      inputCertifications: inputCertificationStore
    });
    const sqlRuntime = buildSqlExtractors(
      sourceConfiguration.sources,
      sqlPolicies,
      ingestion,
      environment
    );
    const controlPlane = new OperatorControlPlane({
      principal,
      control: controlStore,
      definitions: definitionStore,
      governedDefinitionsV2: governedDefinitionV2Store,
      governedDefinitionV2Resolver,
      artifacts,
      memberships: membershipStore,
      alerts: alertStore,
      ingestion,
      inputCertification,
      sqlExtractors: sqlRuntime.extractors
    });
    let closed = false;
    return {
      controlPlane,
      close: async () => {
        if (closed) return;
        closed = true;
        try {
          await sqlRuntime.close();
        } catch {
          // Pool shutdown is best-effort; all local durable stores still close below.
        } finally {
          membershipStore.close();
          inputCertificationStore.close();
          alertStore.close();
          governedDefinitionV2Store.close();
          definitionStore.close();
          controlStore.close();
          releaseArtifactKeys();
        }
      }
    };
  } catch (error) {
    memberships?.close();
    inputCertifications?.close();
    alerts?.close();
    governedDefinitionsV2?.close();
    definitions?.close();
    control?.close();
    releaseArtifactKeys();
    throw error;
  }
}

interface SqlPolicySource {
  readonly sourceId: string;
  readonly relations: readonly SnapshotRelationPolicy[];
  readonly limits?: SnapshotExtractionLimits | undefined;
}

function loadSqlPolicies(path: string | undefined): readonly SqlPolicySource[] {
  if (path === undefined) return [];
  if (!path || path.length > 4_096 || /[\u0000\r\n]/.test(path)) {
    throw new OperatorRuntimeError(
      "INVALID_OPERATOR_CONFIGURATION",
      "Operator SQL policy path is invalid"
    );
  }
  const parsed = sqlPolicyFileSchema.safeParse(readBoundedJsonFile(path, 1_000_000));
  if (!parsed.success) {
    throw new OperatorRuntimeError(
      "INVALID_OPERATOR_CONFIGURATION",
      "Operator SQL policy file is invalid"
    );
  }
  const seen = new Set<string>();
  for (const source of parsed.data.sources) {
    if (seen.has(source.sourceId)) {
      throw new OperatorRuntimeError(
        "INVALID_OPERATOR_CONFIGURATION",
        "Operator SQL policy contains a duplicate source"
      );
    }
    seen.add(source.sourceId);
  }
  return parsed.data.sources as readonly SqlPolicySource[];
}

interface SqlExtractorRuntime {
  readonly extractors: ReadonlyMap<string, SqlSnapshotExtractionService>;
  close(): Promise<void>;
}

function buildSqlExtractors(
  sources: readonly SourceConfig[],
  policies: readonly SqlPolicySource[],
  ingestion: SnapshotIngestionService,
  environment: RuntimeEnvironment
): SqlExtractorRuntime {
  const sourceById = new Map(sources.map((source) => [source.id, source]));
  const extractors = new Map<string, SqlSnapshotExtractionService>();
  const pools: pg.Pool[] = [];
  try {
    for (const policy of policies) {
      const source = sourceById.get(policy.sourceId);
      if (!source) {
        throw new OperatorRuntimeError(
          "SOURCE_NOT_CONFIGURED",
          "Operator SQL policy references an unavailable source"
        );
      }
      validateSourcePolicy(source, policy.relations);
      const assumptions = {
        principalMode: "non_owner" as const,
        accessMode: "read_only" as const,
        configurationSource: "trusted_runtime" as const
      };
      const trustedSource = source.dialect === "sqlite"
        ? new TrustedSqliteSnapshotSource({
            sourceId: source.id,
            databasePath: source.path,
            assumptions,
            relations: policy.relations
          })
        : new TrustedPostgresSnapshotSource({
            sourceId: source.id,
            pool: postgresPool(source, environment, pools),
            assumptions,
            relations: policy.relations
          });
      extractors.set(
        source.id,
        new SqlSnapshotExtractionService(
          trustedSource,
          ingestion,
          effectiveLimits(source, policy.limits)
        )
      );
    }
  } catch (error) {
    for (const pool of pools) void pool.end().catch(() => undefined);
    throw error;
  }
  return {
    extractors,
    close: async () => {
      await Promise.all(pools.map(async (pool) => pool.end()));
    }
  };
}

function validateSourcePolicy(
  source: SourceConfig,
  relations: readonly SnapshotRelationPolicy[]
): void {
  const allowedSchemas = new Set(source.allowedSchemas);
  const allowedTables = new Set(source.allowedTables);
  for (const relation of relations) {
    if (!allowedSchemas.has(relation.schema) || !allowedTables.has(tableKey(relation))) {
      throw new OperatorRuntimeError(
        "SQL_POLICY_VIOLATION",
        "Operator SQL relation is outside the source allowlist"
      );
    }
    for (const column of relation.columns) {
      if (isRestrictedColumn(column.sourceName, source.restrictedColumns)) {
        throw new OperatorRuntimeError(
          "SQL_POLICY_VIOLATION",
          "Operator SQL policy includes a restricted source column"
        );
      }
    }
  }
}

function postgresPool(
  source: Extract<SourceConfig, { readonly dialect: "postgres" }>,
  environment: RuntimeEnvironment,
  pools: pg.Pool[]
): pg.Pool {
  const connectionString = environment[source.connectionEnv];
  if (
    typeof connectionString !== "string" ||
    connectionString.length === 0 ||
    connectionString.length > 16_384 ||
    /[\u0000\r\n]/.test(connectionString)
  ) {
    throw new OperatorRuntimeError(
      "INVALID_OPERATOR_CONFIGURATION",
      "Trusted PostgreSQL connectivity is unavailable"
    );
  }
  const pool = new Pool({
    connectionString,
    application_name: "abl-operator-snapshot",
    max: 2,
    idleTimeoutMillis: 10_000,
    connectionTimeoutMillis: 5_000
  });
  pools.push(pool);
  return pool;
}

function effectiveLimits(
  source: SourceConfig,
  requested: SnapshotExtractionLimits | undefined
): SnapshotExtractionLimits {
  const maximumBytes = requested?.maximumBytes ?? 8_000_000;
  return {
    maximumRows: Math.min(requested?.maximumRows ?? source.maxResultRows, source.maxResultRows),
    maximumBytes,
    maximumCellBytes: Math.min(requested?.maximumCellBytes ?? 65_536, maximumBytes),
    maximumExecutionMs: Math.min(
      requested?.maximumExecutionMs ?? source.statementTimeoutMs,
      source.statementTimeoutMs
    ),
    maximumColumns: requested?.maximumColumns ?? 500
  };
}
