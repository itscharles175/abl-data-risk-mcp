import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  canonicalHash,
  canonicalJson,
  deepFreeze,
  IdentifierSchema,
  IsoDateSchema,
  IsoTimestampSchema,
  parseGovernedDatasetScopeBindingV1,
  Sha256HashSchema,
  type CanonicalJsonValue,
  type DatasetSnapshotV2,
  type GovernedDatasetScopeBindingV1,
  type Sha256Hash
} from "../contracts/index.js";
import {
  migrateSqliteComponent,
  type SqliteComponentMigration
} from "../infrastructure/sqlite-component-schema.js";
import type { GovernedDefinitionV2Resolver } from "../services/governed-definition-v2-resolver.js";
import {
  ActiveMappingExecutionAuthorityV1,
  type ActiveMappingExecutionV1
} from "../services/active-mapping-execution-authority-v1.js";
import type {
  ModernCertificationDefinitionAuthorityV1,
  ModernCertificationDefinitionResolutionV1,
  ModernDataQualityDefinitionV1,
  ModernReconciliationDefinitionV1
} from "../services/modern-snapshot-certification.js";
import type { ModernSnapshotExtractionReceiptV1 } from "../services/modern-snapshot-capture.js";
import type { GovernedSourceDeliveryRecordV1 } from "../contracts/source-delivery-authority-v1.js";
import type { SqliteHistoricalRuntimeAuthorityV1 } from "./historical-runtime-authority-v1.js";

export const CERTIFICATION_DEFINITION_AUTHORITY_COMPONENT = "abl.certification-definition-authority" as const;
export const CERTIFICATION_DEFINITION_AUTHORITY_SCHEMA_VERSION = 1 as const;

const SCHEMA = `
CREATE TABLE certification_definition_sets_v1 (
  tenant_id TEXT NOT NULL,
  certification_set_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision > 0),
  source_contract_id TEXT NOT NULL,
  source_contract_revision INTEGER NOT NULL CHECK (source_contract_revision > 0),
  source_contract_hash TEXT NOT NULL CHECK (length(source_contract_hash) = 71 AND source_contract_hash GLOB 'sha256:*'),
  dataset_id TEXT NOT NULL,
  facility_id TEXT NOT NULL,
  binding_id TEXT NOT NULL,
  binding_revision INTEGER NOT NULL CHECK (binding_revision > 0),
  binding_hash TEXT NOT NULL CHECK (length(binding_hash) = 71 AND binding_hash GLOB 'sha256:*'),
  effective_from TEXT NOT NULL,
  effective_to TEXT,
  status TEXT NOT NULL CHECK (status = 'active'),
  definition_json TEXT NOT NULL CHECK (json_valid(definition_json)),
  definition_hash TEXT NOT NULL CHECK (length(definition_hash) = 71 AND definition_hash GLOB 'sha256:*'),
  registered_by TEXT NOT NULL,
  registered_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, certification_set_id, revision),
  UNIQUE (tenant_id, source_contract_id, source_contract_revision, dataset_id, facility_id, effective_from)
) STRICT;
CREATE INDEX certification_definition_sets_selector_v1
  ON certification_definition_sets_v1 (
    tenant_id, source_contract_id, source_contract_revision, source_contract_hash,
    dataset_id, facility_id, effective_from
  );
CREATE TRIGGER certification_definition_sets_v1_no_update
BEFORE UPDATE ON certification_definition_sets_v1
BEGIN SELECT RAISE(ABORT, 'certification definition sets are immutable'); END;
CREATE TRIGGER certification_definition_sets_v1_no_delete
BEFORE DELETE ON certification_definition_sets_v1
BEGIN SELECT RAISE(ABORT, 'certification definition sets are immutable'); END;
`;

export const CERTIFICATION_DEFINITION_AUTHORITY_MIGRATIONS = Object.freeze([
  { version: 1, sql: SCHEMA }
] as const satisfies readonly SqliteComponentMigration[]);

export interface CertifiedControlDefinitionIdentityV1 {
  readonly tenantId: string;
  readonly datasetId: string;
  readonly facilityId: string;
  readonly definitionId: string;
  readonly revision: number;
  readonly status: "approved";
  readonly createdBy: string;
  readonly approvedBy: string;
  readonly approvedAt: string;
  readonly definitionHash: Sha256Hash;
}

export interface CertificationDefinitionSetV1 {
  readonly contractVersion: 1;
  readonly tenantId: string;
  readonly certificationSetId: string;
  readonly revision: number;
  readonly sourceContract: DatasetSnapshotV2["sourceContract"];
  readonly scopeBinding: GovernedDatasetScopeBindingV1;
  readonly mappingDefinitionVersionId: string;
  readonly runtime: Readonly<{
    runtimeBundleId: string;
    runtimeBundleHash: Sha256Hash;
  }>;
  readonly dataQuality: Readonly<{
    identity: CertifiedControlDefinitionIdentityV1;
    execution: ModernDataQualityDefinitionV1;
  }>;
  readonly reconciliation: Readonly<{
    identity: CertifiedControlDefinitionIdentityV1;
    execution: ModernReconciliationDefinitionV1;
  }>;
  readonly compilerCompatibility: Readonly<{
    bundleId: string;
    version: string;
    contentHash: Sha256Hash;
  }>;
  readonly effectiveFrom: string;
  readonly effectiveTo?: string;
  readonly status: "active";
  readonly registeredBy: string;
  readonly registeredAt: string;
  readonly definitionHash: Sha256Hash;
}

export interface TrustedCertificationDefinitionActorV1 {
  readonly tenantId: string;
  readonly actorId: string;
  readonly authority: "platform_operator";
  readonly identitySource: "server_derived";
}

export interface BoundCertificationSnapshotEvidenceV1 {
  readonly tenantId: string;
  readonly sourceContract: DatasetSnapshotV2["sourceContract"];
  readonly deliveryHash: Sha256Hash;
  readonly extractionReceipt: ModernSnapshotExtractionReceiptV1;
  readonly delivery: GovernedSourceDeliveryRecordV1;
  readonly scopeBinding: GovernedDatasetScopeBindingV1;
  readonly asOfDate: string;
}

export interface RegisterCertificationDefinitionSetV1 {
  readonly certificationSetId: string;
  readonly revision: number;
  readonly scopeBinding: GovernedDatasetScopeBindingV1;
  readonly mappingDefinitionVersionId: string;
  readonly runtimeBundleId: string;
  readonly runtimeBundleHash: Sha256Hash;
  readonly dataQuality: CertificationDefinitionSetV1["dataQuality"];
  readonly reconciliation: CertificationDefinitionSetV1["reconciliation"];
  readonly compilerCompatibility: CertificationDefinitionSetV1["compilerCompatibility"];
  readonly effectiveFrom: string;
  readonly effectiveTo?: string;
  /**
   * Only trusted import/migration code may set this flag. Runtime composition
   * remains disabled until source-contract and scope-binding lifecycle proof
   * is supplied by a separate governed authority adapter.
   */
  readonly trustedImportOnly: true;
}

export type CertificationDefinitionAuthorityErrorCode =
  | "INVALID_INPUT"
  | "NOT_FOUND"
  | "CONFLICT"
  | "INTEGRITY_FAILURE"
  | "STORE_CLOSED";

export class CertificationDefinitionAuthorityError extends Error {
  constructor(readonly code: CertificationDefinitionAuthorityErrorCode, message: string) {
    super(message);
    this.name = "CertificationDefinitionAuthorityError";
  }
}

export interface CertificationDefinitionAuthorityOptionsV1 {
  readonly clock?: () => Date;
  readonly busyTimeoutMs?: number;
  /** Migration/testing only. Never enable on a public or operator request path. */
  readonly allowTrustedImports?: boolean;
}

interface DefinitionSetRow {
  readonly tenant_id: string;
  readonly certification_set_id: string;
  readonly revision: number;
  readonly source_contract_id: string;
  readonly source_contract_revision: number;
  readonly source_contract_hash: string;
  readonly dataset_id: string;
  readonly facility_id: string;
  readonly binding_id: string;
  readonly binding_revision: number;
  readonly binding_hash: string;
  readonly effective_from: string;
  readonly effective_to: string | null;
  readonly status: string;
  readonly definition_json: string;
  readonly definition_hash: string;
  readonly registered_by: string;
  readonly registered_at: string;
}

/**
 * Immutable trusted-import and effective-dated selector foundation. It records full executable DQ and
 * reconciliation definitions beside their independently verified lifecycle
 * identities so selection never depends on mutable "current" documents.
 * Caller-supplied DQ/reconciliation maker-checker claims are not production
 * authority; registration is disabled unless allowTrustedImports is explicitly
 * enabled by migration/test composition. Public/operator request code must not
 * expose that option.
 */
export class SqliteCertificationDefinitionAuthorityV1
  implements ModernCertificationDefinitionAuthorityV1
{
  readonly #database: DatabaseSync;
  readonly #activeMappings: ActiveMappingExecutionAuthorityV1;
  readonly #runtime: SqliteHistoricalRuntimeAuthorityV1;
  readonly #clock: () => Date;
  readonly #allowTrustedImports: boolean;
  #closed = false;

  constructor(
    databasePath: string,
    dependencies: {
      readonly governed: GovernedDefinitionV2Resolver;
      readonly runtime: SqliteHistoricalRuntimeAuthorityV1;
    },
    options: CertificationDefinitionAuthorityOptionsV1 = {}
  ) {
    const path = requiredPath(databasePath);
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(path, { enableForeignKeyConstraints: true });
    this.#activeMappings = new ActiveMappingExecutionAuthorityV1(dependencies.governed);
    this.#runtime = dependencies.runtime;
    this.#clock = options.clock ?? (() => new Date());
    this.#allowTrustedImports = options.allowTrustedImports ?? false;
    const timeout = integer(options.busyTimeoutMs ?? 5_000, "busyTimeoutMs", 0, 60_000);
    try {
      this.#database.exec(
        `PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${timeout};`
      );
      migrateSqliteComponent(this.#database, {
        componentName: CERTIFICATION_DEFINITION_AUTHORITY_COMPONENT,
        supportedVersion: CERTIFICATION_DEFINITION_AUTHORITY_SCHEMA_VERSION,
        migrations: CERTIFICATION_DEFINITION_AUTHORITY_MIGRATIONS,
        unsupportedVersionError: (current, supported) =>
          integrity(`Certification-definition schema ${current} is newer than supported ${supported}`)
      });
      this.#verifyIntegrity();
    } catch (error) {
      this.#database.close();
      if (error instanceof CertificationDefinitionAuthorityError) throw error;
      throw integrity("Certification-definition authority initialization failed", error);
    }
  }

  register(
    actorValue: TrustedCertificationDefinitionActorV1,
    inputValue: RegisterCertificationDefinitionSetV1
  ): CertificationDefinitionSetV1 {
    this.#assertOpen();
    const trustedActor = validateActor(actorValue);
    const input = registration(inputValue);
    if (!this.#allowTrustedImports || input.trustedImportOnly !== true) {
      invalid(
        "Direct certification-set import is disabled; durable control-definition and source lifecycle authorities are required"
      );
    }
    const registeredAt = this.#now();
    if (input.scopeBinding.tenantId !== trustedActor.tenantId) invalid("Scope binding belongs to another tenant");
    if (input.scopeBinding.scope.scopeType !== "facility") invalid("Certification definition sets must be facility scoped");
    if (!effectiveOn(input.scopeBinding, input.effectiveFrom)) {
      invalid("Certification window begins outside the immutable scope binding");
    }
    if (input.effectiveTo !== undefined && !effectiveOn(input.scopeBinding, input.effectiveTo)) {
      invalid("Certification window ends outside the immutable scope binding");
    }
    const mapping = this.#activeMappings.resolveFrozenActive({
      tenantId: trustedActor.tenantId,
      definitionVersionId: input.mappingDefinitionVersionId
    });
    if (mappingContainsDimensionLookup(mapping.mappingSpec)) {
      invalid(
        "Mappings with dimension_lookup are disabled until a content-addressed dimension authority is configured"
      );
    }
    if (canonicalJson(mapping.mappingSpec.sourceContract) !== canonicalJson(input.scopeBinding.sourceContract)) {
      invalid("Active mapping does not bind the scope binding's exact source contract");
    }
    ensureWindowContains(mapping.window, input.effectiveFrom, input.effectiveTo, "mapping");

    const runtime = this.#runtime.resolveActivatedRuntime(
      trustedActor.tenantId,
      { runtimeBundleId: input.runtimeBundleId, runtimeBundleHash: input.runtimeBundleHash },
      registeredAt
    );
    if (canonicalJson(runtime.runtime.dictionary) !== canonicalJson(mapping.mappingSpec.dictionaryBundle)) {
      invalid("Activated runtime dictionary does not match the active mapping");
    }
    if (
      runtime.runtime.mappingCompiler.bundleId !== input.compilerCompatibility.bundleId ||
      runtime.runtime.mappingCompiler.version !== input.compilerCompatibility.version ||
      runtime.runtime.mappingCompiler.contentHash !== input.compilerCompatibility.contentHash
    ) {
      invalid("Runtime mapping compiler is incompatible with the certification set");
    }

    const dataQuality = certifiedControl(
      input.dataQuality,
      input.scopeBinding,
      input.effectiveFrom,
      input.effectiveTo,
      trustedActor.actorId,
      registeredAt,
      "data-quality"
    );
    const reconciliation = certifiedControl(
      input.reconciliation,
      input.scopeBinding,
      input.effectiveFrom,
      input.effectiveTo,
      trustedActor.actorId,
      registeredAt,
      "reconciliation"
    );
    const body = {
      contractVersion: 1 as const,
      tenantId: trustedActor.tenantId,
      certificationSetId: input.certificationSetId,
      revision: input.revision,
      sourceContract: input.scopeBinding.sourceContract,
      scopeBinding: input.scopeBinding,
      mappingDefinitionVersionId: input.mappingDefinitionVersionId,
      runtime: {
        runtimeBundleId: input.runtimeBundleId,
        runtimeBundleHash: input.runtimeBundleHash
      },
      dataQuality,
      reconciliation,
      compilerCompatibility: input.compilerCompatibility,
      effectiveFrom: input.effectiveFrom,
      ...(input.effectiveTo === undefined ? {} : { effectiveTo: input.effectiveTo }),
      status: "active" as const,
      registeredBy: trustedActor.actorId,
      registeredAt
    };
    const definition = deepFreeze({ ...body, definitionHash: canonicalHash(body) });
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const existing = this.#database.prepare(
        `SELECT * FROM certification_definition_sets_v1
         WHERE tenant_id = ? AND certification_set_id = ? AND revision = ?`
      ).get(trustedActor.tenantId, input.certificationSetId, input.revision) as DefinitionSetRow | undefined;
      if (existing) {
        const replay = this.#row(existing);
        const replayBody = {
          ...body,
          registeredAt: replay.registeredAt
        };
        const expectedReplay = {
          ...replayBody,
          definitionHash: canonicalHash(replayBody)
        };
        if (canonicalJson(replay) !== canonicalJson(expectedReplay)) {
          conflict("Certification set identity is already bound");
        }
        this.#database.exec("COMMIT");
        return replay;
      }
      const overlap = this.#database.prepare(
        `SELECT 1 FROM certification_definition_sets_v1
         WHERE tenant_id = ? AND source_contract_id = ? AND source_contract_revision = ?
           AND dataset_id = ? AND facility_id = ?
           AND effective_from < COALESCE(?, '9999-12-31')
           AND COALESCE(effective_to, '9999-12-31') > ? LIMIT 1`
      ).get(
        trustedActor.tenantId,
        input.scopeBinding.sourceContract.sourceContractId,
        input.scopeBinding.sourceContract.revision,
        input.scopeBinding.datasetId,
        input.scopeBinding.scope.scopeId,
        input.effectiveTo ?? null,
        input.effectiveFrom
      );
      if (overlap) conflict("Certification selection windows cannot overlap for one exact facility source");
      this.#database.prepare(
        `INSERT INTO certification_definition_sets_v1 (
          tenant_id, certification_set_id, revision, source_contract_id,
          source_contract_revision, source_contract_hash, dataset_id, facility_id,
          binding_id, binding_revision, binding_hash, effective_from, effective_to,
          status, definition_json, definition_hash, registered_by, registered_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        trustedActor.tenantId, input.certificationSetId, input.revision,
        input.scopeBinding.sourceContract.sourceContractId,
        input.scopeBinding.sourceContract.revision,
        input.scopeBinding.sourceContract.sourceContractHash,
        input.scopeBinding.datasetId, input.scopeBinding.scope.scopeId,
        input.scopeBinding.bindingId, input.scopeBinding.revision,
        input.scopeBinding.bindingHash, input.effectiveFrom,
        input.effectiveTo ?? null, "active", canonicalJson(definition),
        definition.definitionHash, trustedActor.actorId, registeredAt
      );
      this.#database.exec("COMMIT");
      return definition;
    } catch (error) {
      try { this.#database.exec("ROLLBACK"); } catch { /* preserve original */ }
      if (error instanceof CertificationDefinitionAuthorityError) throw error;
      throw integrity("Certification definition registration failed", error);
    }
  }

  async resolveForSnapshot(input: {
    readonly tenantId: string;
    readonly sourceContract: DatasetSnapshotV2["sourceContract"];
    readonly asOfDate: string;
  }): Promise<ModernCertificationDefinitionResolutionV1 | undefined> {
    this.#assertOpen();
    const tenantId = identifier(input.tenantId, "tenantId");
    const asOfDate = date(input.asOfDate, "asOfDate");
    const source = sourceReference(input.sourceContract);
    const rows = this.#database.prepare(
      `SELECT * FROM certification_definition_sets_v1
       WHERE tenant_id = ? AND source_contract_id = ? AND source_contract_revision = ?
         AND source_contract_hash = ? AND status = 'active'
         AND effective_from <= ? AND (effective_to IS NULL OR effective_to > ?)
       ORDER BY effective_from DESC LIMIT 2`
    ).all(
      tenantId, source.sourceContractId, source.revision, source.sourceContractHash,
      asOfDate, asOfDate
    ) as unknown as DefinitionSetRow[];
    if (rows.length === 0) return undefined;
    if (rows.length !== 1) throw integrity("Certification selection is ambiguous across facility scopes");
    const definition = this.#row(rows[0]!);
    const mapping = this.#activeMappings.resolveFrozenActive({
      tenantId,
      definitionVersionId: definition.mappingDefinitionVersionId
    });
    this.#verifyExternalAuthorities(definition, mapping, asOfDate);
    return deepFreeze({
      mappingSpec: mapping.mappingSpec,
      mappingWindow: mapping.window,
      runtime: {
        ...definition.runtime,
        window: {
          effectiveFrom: definition.effectiveFrom,
          ...(definition.effectiveTo === undefined ? {} : { effectiveTo: definition.effectiveTo })
        }
      },
      dataQuality: definition.dataQuality.execution,
      reconciliation: definition.reconciliation.execution
    });
  }

  /** Exact facility-aware selection for capture receipts; preferred by composition code. */
  async resolveForBoundSnapshot(input: {
    readonly evidence: BoundCertificationSnapshotEvidenceV1;
  }): Promise<ModernCertificationDefinitionResolutionV1 | undefined> {
    const inputEvidence = boundEvidence(input.evidence);
    const { tenantId, sourceContract, scopeBinding: binding, asOfDate } = inputEvidence;
    const receipt = inputEvidence.extractionReceipt;
    const delivery = inputEvidence.delivery;
    if (
      binding.tenantId !== tenantId ||
      canonicalJson(binding.sourceContract) !== canonicalJson(sourceContract) ||
      receipt.tenantId !== tenantId ||
      receipt.datasetId !== binding.datasetId ||
      receipt.facilityId !== binding.scope.scopeId ||
      receipt.deliveryId.length === 0 ||
      canonicalJson(receipt.sourceContract) !== canonicalJson(sourceContract) ||
      canonicalJson(receipt.scopeBinding) !== canonicalJson({
        bindingId: binding.bindingId,
        revision: binding.revision,
        bindingHash: binding.bindingHash
      }) ||
      receipt.asOfDate !== asOfDate
      || delivery.tenantId !== tenantId
      || delivery.deliveryId !== receipt.deliveryId
      || delivery.deliveryHash !== inputEvidence.deliveryHash
      || delivery.status !== "usable"
      || delivery.datasetId !== binding.datasetId
      || delivery.facilityId !== binding.scope.scopeId
      || canonicalJson(delivery.sourceContract) !== canonicalJson(sourceContract)
      || canonicalJson(delivery.scopeBinding) !== canonicalJson(receipt.scopeBinding)
    ) {
      invalid("Snapshot scope receipt does not match the requested tenant and source contract");
    }
    const row = this.#database.prepare(
      `SELECT * FROM certification_definition_sets_v1
       WHERE tenant_id = ? AND source_contract_id = ? AND source_contract_revision = ?
         AND source_contract_hash = ? AND dataset_id = ? AND facility_id = ?
         AND binding_id = ? AND binding_revision = ? AND binding_hash = ?
         AND effective_from <= ? AND (effective_to IS NULL OR effective_to > ?)
       LIMIT 1`
    ).get(
      tenantId, binding.sourceContract.sourceContractId,
      binding.sourceContract.revision, binding.sourceContract.sourceContractHash,
      binding.datasetId, binding.scope.scopeId, binding.bindingId, binding.revision,
      binding.bindingHash, asOfDate, asOfDate
    ) as DefinitionSetRow | undefined;
    if (!row) return undefined;
    const definition = this.#row(row);
    const mapping = this.#activeMappings.resolveFrozenActive({
      tenantId,
      definitionVersionId: definition.mappingDefinitionVersionId
    });
    this.#verifyExternalAuthorities(definition, mapping, asOfDate);
    return deepFreeze({
      mappingSpec: mapping.mappingSpec,
      mappingWindow: mapping.window,
      runtime: {
        ...definition.runtime,
        window: {
          effectiveFrom: definition.effectiveFrom,
          ...(definition.effectiveTo === undefined ? {} : { effectiveTo: definition.effectiveTo })
        }
      },
      dataQuality: definition.dataQuality.execution,
      reconciliation: definition.reconciliation.execution
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#database.close();
  }

  #verifyExternalAuthorities(
    definition: CertificationDefinitionSetV1,
    mapping: ActiveMappingExecutionV1,
    asOfDate: string
  ): void {
    if (
      canonicalJson(mapping.mappingSpec.sourceContract) !== canonicalJson(definition.sourceContract) ||
      !effectiveOn(definition.scopeBinding, asOfDate)
    ) {
      throw integrity("Certification set no longer matches mapping or scope evidence");
    }
    const runtime = this.#runtime.resolveActivatedRuntime(
      definition.tenantId,
      definition.runtime,
      this.#now()
    ).runtime;
    if (
      canonicalJson(runtime.dictionary) !== canonicalJson(mapping.mappingSpec.dictionaryBundle) ||
      runtime.mappingCompiler.bundleId !== definition.compilerCompatibility.bundleId ||
      runtime.mappingCompiler.version !== definition.compilerCompatibility.version ||
      runtime.mappingCompiler.contentHash !== definition.compilerCompatibility.contentHash
    ) {
      throw integrity("Certification runtime compatibility evidence no longer resolves exactly");
    }
  }

  #row(row: DefinitionSetRow): CertificationDefinitionSetV1 {
    const definition = parseDefinitionSet(JSON.parse(row.definition_json) as unknown);
    if (
      definition.tenantId !== row.tenant_id ||
      definition.certificationSetId !== row.certification_set_id ||
      definition.revision !== row.revision ||
      definition.sourceContract.sourceContractId !== row.source_contract_id ||
      definition.sourceContract.revision !== row.source_contract_revision ||
      definition.sourceContract.sourceContractHash !== row.source_contract_hash ||
      definition.scopeBinding.datasetId !== row.dataset_id ||
      definition.scopeBinding.scope.scopeId !== row.facility_id ||
      definition.scopeBinding.bindingId !== row.binding_id ||
      definition.scopeBinding.revision !== row.binding_revision ||
      definition.scopeBinding.bindingHash !== row.binding_hash ||
      definition.effectiveFrom !== row.effective_from ||
      (definition.effectiveTo ?? null) !== row.effective_to ||
      definition.status !== row.status ||
      definition.definitionHash !== row.definition_hash ||
      definition.registeredBy !== row.registered_by ||
      definition.registeredAt !== row.registered_at
    ) {
      throw integrity("Certification definition set row does not match its hashed document");
    }
    return definition;
  }

  #verifyIntegrity(): void {
    const rows = this.#database.prepare(
      "SELECT * FROM certification_definition_sets_v1 ORDER BY tenant_id, certification_set_id, revision"
    ).all() as unknown as DefinitionSetRow[];
    for (const row of rows) this.#row(row);
  }

  #now(): string {
    const value = this.#clock();
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) invalid("Certification-definition clock is invalid");
    return timestamp(value.toISOString(), "clock");
  }

  #assertOpen(): void {
    if (this.#closed) throw new CertificationDefinitionAuthorityError("STORE_CLOSED", "Authority is closed");
  }
}

function parseDefinitionSet(value: unknown): CertificationDefinitionSetV1 {
  const document = object(value, "CertificationDefinitionSetV1");
  const { definitionHash: rawHash, ...body } = document;
  const definitionHash = hash(String(rawHash), "definitionHash");
  if (canonicalHash(body) !== definitionHash) throw integrity("Certification definition hash failed verification");
  const scopeBinding = parseGovernedDatasetScopeBindingV1(body.scopeBinding);
  const dataQuality = object(body.dataQuality, "dataQuality");
  const reconciliation = object(body.reconciliation, "reconciliation");
  return deepFreeze({
    ...(body as unknown as Omit<CertificationDefinitionSetV1, "scopeBinding" | "definitionHash">),
    scopeBinding,
    dataQuality: {
      identity: definitionIdentity(dataQuality.identity),
      execution: canonicalClone(dataQuality.execution) as unknown as ModernDataQualityDefinitionV1
    },
    reconciliation: {
      identity: definitionIdentity(reconciliation.identity),
      execution: canonicalClone(reconciliation.execution) as unknown as ModernReconciliationDefinitionV1
    },
    definitionHash
  });
}

function registration(value: RegisterCertificationDefinitionSetV1): RegisterCertificationDefinitionSetV1 {
  const effectiveFrom = date(value.effectiveFrom, "effectiveFrom");
  const effectiveTo = value.effectiveTo === undefined ? undefined : date(value.effectiveTo, "effectiveTo");
  if (effectiveTo !== undefined && effectiveTo < effectiveFrom) invalid("effectiveTo cannot precede effectiveFrom");
  return deepFreeze({
    certificationSetId: identifier(value.certificationSetId, "certificationSetId"),
    revision: integer(value.revision, "revision", 1, 1_000_000),
    scopeBinding: parseGovernedDatasetScopeBindingV1(value.scopeBinding),
    mappingDefinitionVersionId: identifier(value.mappingDefinitionVersionId, "mappingDefinitionVersionId"),
    runtimeBundleId: identifier(value.runtimeBundleId, "runtimeBundleId"),
    runtimeBundleHash: hash(value.runtimeBundleHash, "runtimeBundleHash"),
    dataQuality: {
      identity: definitionIdentity(value.dataQuality.identity),
      execution: canonicalClone(value.dataQuality.execution) as unknown as ModernDataQualityDefinitionV1
    },
    reconciliation: {
      identity: definitionIdentity(value.reconciliation.identity),
      execution: canonicalClone(value.reconciliation.execution) as unknown as ModernReconciliationDefinitionV1
    },
    compilerCompatibility: {
      bundleId: identifier(value.compilerCompatibility.bundleId, "compiler bundleId"),
      version: text(value.compilerCompatibility.version, "compiler version", 64),
      contentHash: hash(value.compilerCompatibility.contentHash, "compiler contentHash")
    },
    effectiveFrom,
    ...(effectiveTo === undefined ? {} : { effectiveTo }),
    trustedImportOnly: value.trustedImportOnly === true
      ? true
      : invalid("trustedImportOnly must be explicitly true")
  });
}

function boundEvidence(value: BoundCertificationSnapshotEvidenceV1): BoundCertificationSnapshotEvidenceV1 {
  const extractionReceipt = canonicalClone(value.extractionReceipt) as unknown as ModernSnapshotExtractionReceiptV1;
  const delivery = canonicalClone(value.delivery) as unknown as GovernedSourceDeliveryRecordV1;
  const { receiptHash: _receiptHash, ...receiptBody } = extractionReceipt;
  if (canonicalHash(receiptBody) !== extractionReceipt.receiptHash) {
    invalid("Extraction receipt hash failed verification");
  }
  const { deliveryHash: _deliveryHash, ...deliveryBody } = delivery;
  if (canonicalHash(deliveryBody) !== delivery.deliveryHash) {
    invalid("Source delivery hash failed verification");
  }
  const deliveryHash = hash(value.deliveryHash, "deliveryHash");
  if (deliveryHash !== delivery.deliveryHash) invalid("Bound delivery hash does not match delivery evidence");
  return deepFreeze({
    tenantId: identifier(value.tenantId, "tenantId"),
    sourceContract: sourceReference(value.sourceContract),
    deliveryHash,
    extractionReceipt,
    delivery,
    scopeBinding: parseGovernedDatasetScopeBindingV1(value.scopeBinding),
    asOfDate: date(value.asOfDate, "asOfDate")
  });
}

function certifiedControl<T>(
  value: Readonly<{ identity: CertifiedControlDefinitionIdentityV1; execution: T }>,
  binding: GovernedDatasetScopeBindingV1,
  effectiveFrom: string,
  effectiveTo: string | undefined,
  approvingActorId: string,
  registeredAt: string,
  label: string
): Readonly<{ identity: CertifiedControlDefinitionIdentityV1; execution: T }> {
  const identity = definitionIdentity(value.identity);
  const execution = canonicalClone(value.execution) as unknown as T;
  const document = object(execution, `${label} execution document`);
  if (
    identity.tenantId !== binding.tenantId ||
    identity.datasetId !== binding.datasetId ||
    identity.facilityId !== binding.scope.scopeId ||
    identity.definitionId !== document.definitionId ||
    identity.approvedBy !== approvingActorId ||
    identity.approvedBy === identity.createdBy ||
    identity.approvedAt > registeredAt
  ) {
    invalid(`${label} execution document lacks exact tenant/facility/revision/approval/hash identity`);
  }
  const { definitionHash: _definitionHash, ...identityBody } = identity;
  if (canonicalHash({ identity: identityBody, execution }) !== identity.definitionHash) {
    invalid(`${label} execution definition hash is invalid`);
  }
  const window = object(document.window, `${label} window`);
  ensureWindowContains(
    {
      effectiveFrom: String(window.effectiveFrom),
      ...(window.effectiveTo === undefined ? {} : { effectiveTo: String(window.effectiveTo) })
    },
    effectiveFrom,
    effectiveTo,
    label
  );
  return deepFreeze({ identity, execution });
}

function definitionIdentity(value: unknown): CertifiedControlDefinitionIdentityV1 {
  const item = object(value, "certified control definition identity");
  if (item.status !== "approved") invalid("Certified control definition is not approved");
  return deepFreeze({
    tenantId: identifier(String(item.tenantId), "control tenantId"),
    datasetId: identifier(String(item.datasetId), "control datasetId"),
    facilityId: identifier(String(item.facilityId), "control facilityId"),
    definitionId: identifier(String(item.definitionId), "control definitionId"),
    revision: integer(Number(item.revision), "control revision", 1, 1_000_000),
    status: "approved" as const,
    createdBy: identifier(String(item.createdBy), "control createdBy"),
    approvedBy: identifier(String(item.approvedBy), "control approvedBy"),
    approvedAt: timestamp(String(item.approvedAt), "control approvedAt"),
    definitionHash: hash(String(item.definitionHash), "control definitionHash")
  });
}

function ensureWindowContains(
  window: { readonly effectiveFrom: string; readonly effectiveTo?: string },
  effectiveFrom: string,
  effectiveTo: string | undefined,
  label: string
): void {
  if (
    window.effectiveFrom > effectiveFrom ||
    (window.effectiveTo !== undefined && (effectiveTo === undefined || window.effectiveTo < effectiveTo))
  ) {
    invalid(`${label} effective window does not contain the certification set window`);
  }
}

function effectiveOn(binding: GovernedDatasetScopeBindingV1, dateValue: string): boolean {
  return binding.effectiveFrom <= dateValue &&
    (binding.effectiveTo === undefined || dateValue < binding.effectiveTo);
}

function mappingContainsDimensionLookup(mapping: ActiveMappingExecutionV1["mappingSpec"]): boolean {
  return canonicalJson(mapping.rules).includes('"op":"dimension_lookup"');
}

function sourceReference(value: DatasetSnapshotV2["sourceContract"]): DatasetSnapshotV2["sourceContract"] {
  return deepFreeze({
    sourceContractId: identifier(value.sourceContractId, "sourceContractId"),
    revision: integer(value.revision, "sourceContract revision", 1, 1_000_000),
    sourceContractHash: hash(value.sourceContractHash, "sourceContractHash")
  });
}

function validateActor(value: TrustedCertificationDefinitionActorV1): TrustedCertificationDefinitionActorV1 {
  if (
    value.authority !== "platform_operator" || value.identitySource !== "server_derived"
  ) invalid("Server-derived platform operator identity is required");
  return deepFreeze({
    tenantId: identifier(value.tenantId, "tenantId"),
    actorId: identifier(value.actorId, "actorId"),
    authority: "platform_operator" as const,
    identitySource: "server_derived" as const
  });
}

function canonicalClone(value: unknown): CanonicalJsonValue {
  try { return JSON.parse(canonicalJson(value)) as CanonicalJsonValue; }
  catch { invalid("Execution definition is not canonical JSON"); }
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function requiredPath(value: string): string {
  if (typeof value !== "string" || !value.trim()) invalid("Certification-definition database path is required");
  return value === ":memory:" ? value : resolve(value);
}

function identifier(value: string, label: string): string {
  if (!IdentifierSchema.safeParse(value).success) invalid(`${label} is invalid`);
  return value;
}

function date(value: string, label: string): string {
  if (!IsoDateSchema.safeParse(value).success) invalid(`${label} is invalid`);
  return value;
}

function timestamp(value: string, label: string): string {
  if (!IsoTimestampSchema.safeParse(value).success) invalid(`${label} is invalid`);
  return value;
}

function hash(value: string, label: string): Sha256Hash {
  const parsed = Sha256HashSchema.safeParse(value);
  if (!parsed.success) invalid(`${label} is invalid`);
  return parsed.data;
}

function text(value: string, label: string, maximum: number): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum) invalid(`${label} is invalid`);
  return value;
}

function integer(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalid(`${label} is outside its bound`);
  return value;
}

function invalid(message: string): never {
  throw new CertificationDefinitionAuthorityError("INVALID_INPUT", message);
}

function conflict(message: string): never {
  throw new CertificationDefinitionAuthorityError("CONFLICT", message);
}

function integrity(message: string, cause?: unknown): CertificationDefinitionAuthorityError {
  return new CertificationDefinitionAuthorityError(
    "INTEGRITY_FAILURE",
    cause === undefined ? message : `${message}: ${cause instanceof Error ? cause.message : "unknown failure"}`
  );
}
