import { z } from "zod";

import {
  canonicalHash,
  canonicalJson,
  IdentifierSchema,
  IsoDateSchema,
  IsoTimestampSchema,
  parseGovernedDatasetScopeBindingV1,
  Sha256HashSchema,
  parseHistoricalRuntimeBundleV1,
  parseMappingSpecV2,
  parseSourceContractV1,
  type SnapshotCertificationAttemptV1,
  type CertifiedSnapshotEvidenceRecordV1,
  type DatasetSnapshotV2,
  type GovernedDatasetScopeBindingV1,
  type HistoricalRuntimeBundleV1,
  type HistoricalRuntimeResolver,
  type MappingSpecV2,
  type Sha256Hash
} from "../contracts/index.js";
import {
  createCertifiedSnapshotArtifactMetadataV1,
  createCertifiedSnapshotEvidenceRecordV1,
  parseCertifiedSnapshotEvidenceRecordV1,
  type CertifiedSnapshotArtifactMetadataV1
} from "../contracts/certified-snapshot-evidence-v1.js";
import {
  createCertifiedSnapshotEvidenceRecordV2,
  type CertifiedSnapshotEvidenceRecordV2
} from "../contracts/certified-snapshot-evidence-v2.js";
import type { CertificationArtifactOutboxRecordV1 } from "../contracts/certification-artifact-staging-v1.js";
import {
  createMappingApplicationV1,
  type MappingApplicationV1
} from "../contracts/mapping-v2.js";
import {
  createNormalizedSnapshotArtifactV2,
  parseNormalizedSnapshotArtifactV2
} from "../contracts/normalized-snapshot-artifact-v2.js";
import {
  parseGovernedSourceDeliveryRecordV1,
  type GovernedSourceDeliveryRecordV1,
  type GovernedSourceDeliveryResolutionV1
} from "../contracts/source-delivery-authority-v1.js";
import type { ArtifactStore } from "../control/artifacts.js";
import type { RuntimeActivationProofV1 } from "../control/historical-runtime-authority-v1.js";
import type {
  LifecycleSnapshotCertificationDefinitionAuthorityV1,
  LifecycleSnapshotCertificationResolutionV1
} from "../control/lifecycle-snapshot-certification-definition-authority-v1.js";
import {
  reconcileSegmentsV2,
  runDataQualityV2,
  type DataQualityRuleV2,
  type SegmentedControlTotalV2
} from "../domain/data-quality-v2.js";
import { RepositoryError, type ImmutableRepositoryPort } from "../repositories/ports.js";
import type { CertificationArtifactStagingStoreV1 } from "../repositories/certification-artifact-staging-v1.js";
import type { SnapshotCertificationAttemptStoreV1 } from "../repositories/snapshot-certification-attempts-v1.js";
import {
  executeMappingSpecV2,
  type MappingDimensionLookupV1,
  type MappingSourceScalar
} from "./mapping-v2-executor.js";
import {
  modernSnapshotExtractionReceiptIdV1,
  parseModernSnapshotExtractionReceiptV1,
  type GovernedSourceDeliveryCaptureAuthorityV1,
  type ModernSnapshotExtractionReceiptV1
} from "./modern-snapshot-capture.js";

const CertifySnapshotV2RequestSchema = z
  .object({
    snapshotId: IdentifierSchema
  })
  .strict();

const TrustedCertificationActorV1Schema = z
  .object({
    tenantId: IdentifierSchema,
    actorId: IdentifierSchema,
    authority: z.literal("platform_operator"),
    identitySource: z.literal("server_derived")
  })
  .strict();

const EffectiveWindowV1Schema = z
  .object({
    effectiveFrom: IsoDateSchema,
    effectiveTo: IsoDateSchema.optional()
  })
  .strict()
  .superRefine((value, context) => {
    if (value.effectiveTo !== undefined && value.effectiveFrom > value.effectiveTo) {
      context.addIssue({ code: "custom", path: ["effectiveTo"], message: "cannot precede effectiveFrom" });
    }
  });

const DataQualityRuleV2Schema = z.discriminatedUnion("type", [
  z
    .object({
      ruleId: IdentifierSchema,
      type: z.literal("required"),
      field: z.string().min(1).max(256),
      severity: z.enum(["info", "warning", "error", "critical"]),
      blocking: z.boolean()
    })
    .strict(),
  z
    .object({
      ruleId: IdentifierSchema,
      type: z.literal("unique"),
      field: z.string().min(1).max(256),
      severity: z.enum(["info", "warning", "error", "critical"]),
      blocking: z.boolean()
    })
    .strict(),
  z
    .object({
      ruleId: IdentifierSchema,
      type: z.literal("allowed_values"),
      field: z.string().min(1).max(256),
      values: z.array(z.string().max(4_096)).min(1).max(10_000),
      severity: z.enum(["info", "warning", "error", "critical"]),
      blocking: z.boolean()
    })
    .strict(),
  z
    .object({
      ruleId: IdentifierSchema,
      type: z.literal("decimal_range"),
      field: z.string().min(1).max(256),
      minimum: z.string().optional(),
      maximum: z.string().optional(),
      severity: z.enum(["info", "warning", "error", "critical"]),
      blocking: z.boolean()
    })
    .strict(),
  z
    .object({
      ruleId: IdentifierSchema,
      type: z.literal("equals_sum"),
      field: z.string().min(1).max(256),
      addends: z.array(z.string().min(1).max(256)).min(1).max(32),
      tolerance: z.string(),
      severity: z.enum(["info", "warning", "error", "critical"]),
      blocking: z.boolean()
    })
    .strict()
]);

const DataQualityDefinitionV1Schema = z
  .object({
    definitionId: IdentifierSchema,
    rulesetId: IdentifierSchema,
    mappingSectionId: IdentifierSchema,
    requiredSectionIds: z.array(IdentifierSchema).min(1).max(256),
    rules: z.array(DataQualityRuleV2Schema).min(1).max(1_000),
    balanceField: z.string().min(1).max(256),
    materialBalance: z.string().regex(/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/u),
    window: EffectiveWindowV1Schema
  })
  .strict();

const SegmentedControlTotalV2Schema: z.ZodType<SegmentedControlTotalV2> = z
  .object({
    dimensions: z.record(z.string().min(1).max(256), z.string().max(4_096)),
    rowCount: z.number().int().min(0).max(1_000_000),
    balance: z.string().regex(/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/u),
    currency: z.string().regex(/^[A-Z]{3}$/u)
  })
  .strict();

const ReconciliationControlV1Schema = z
  .object({
    controlId: IdentifierSchema,
    sectionId: IdentifierSchema,
    recordSource: z.enum(["normalized", "source"]),
    dimensions: z.array(z.string().min(1).max(256)).min(1).max(5),
    balanceField: z.string().min(1).max(256),
    currencyField: z.string().min(1).max(256),
    expected: z.array(SegmentedControlTotalV2Schema).min(1).max(100_000),
    balanceTolerance: z.string().regex(/^(?:0|[1-9]\d*)(?:\.\d+)?$/u)
  })
  .strict();

const ReconciliationDefinitionV1Schema = z
  .object({
    definitionId: IdentifierSchema,
    reconciliationId: IdentifierSchema,
    requiredSectionIds: z.array(IdentifierSchema).min(1).max(256),
    controls: z.array(ReconciliationControlV1Schema).min(1).max(256),
    window: EffectiveWindowV1Schema
  })
  .strict()
  .superRefine((value, context) => {
    const required = new Set(value.requiredSectionIds);
    if (required.size !== value.requiredSectionIds.length) {
      context.addIssue({ code: "custom", path: ["requiredSectionIds"], message: "must be unique" });
    }
    const ids = value.controls.map((control) => control.controlId);
    if (new Set(ids).size !== ids.length) {
      context.addIssue({ code: "custom", path: ["controls"], message: "control ids must be unique" });
    }
    for (const sectionId of required) {
      if (!value.controls.some((control) => control.sectionId === sectionId)) {
        context.addIssue({
          code: "custom",
          path: ["controls"],
          message: `required section ${sectionId} must have an executable control`
        });
      }
    }
    for (const [index, control] of value.controls.entries()) {
      if (!required.has(control.sectionId)) {
        context.addIssue({
          code: "custom",
          path: ["controls", index, "sectionId"],
          message: "must name a required section"
        });
      }
    }
  });

const RuntimeActivationV1Schema = z
  .object({
    runtimeBundleId: IdentifierSchema,
    runtimeBundleHash: Sha256HashSchema,
    window: EffectiveWindowV1Schema
  })
  .strict();

export type CertifySnapshotV2Request = Readonly<z.infer<typeof CertifySnapshotV2RequestSchema>>;
interface ResolvedCertifySnapshotV2Request extends CertifySnapshotV2Request {
  readonly mappingApplicationId: string;
  readonly normalizedPopulationId: string;
  readonly certificationManifestId: string;
  readonly idempotencyKey: string;
}
export type TrustedCertificationActorV1 = Readonly<
  z.infer<typeof TrustedCertificationActorV1Schema>
>;
export interface ModernDataQualityDefinitionV1 {
  readonly definitionId: string;
  readonly rulesetId: string;
  readonly mappingSectionId: string;
  readonly requiredSectionIds: readonly string[];
  readonly rules: readonly DataQualityRuleV2[];
  readonly balanceField: string;
  readonly materialBalance: string;
  readonly window: Readonly<z.infer<typeof EffectiveWindowV1Schema>>;
}
export type ModernReconciliationDefinitionV1 = Readonly<
  z.infer<typeof ReconciliationDefinitionV1Schema>
>;

export interface CapturedSourcePopulationV2 {
  readonly tenantId: string;
  readonly snapshotId: string;
  readonly snapshotHash: Sha256Hash;
  readonly sourceContract: DatasetSnapshotV2["sourceContract"];
  readonly sectionId: string;
  readonly extractionHash: Sha256Hash;
  readonly sectionContentHash: Sha256Hash;
  readonly sectionSchemaHash: Sha256Hash;
  readonly controlPopulationHash: Sha256Hash;
  readonly records: readonly Readonly<Record<string, MappingSourceScalar>>[];
}

export interface ModernCertificationDefinitionResolutionV1 {
  readonly mappingSpec: MappingSpecV2;
  readonly mappingWindow: Readonly<z.infer<typeof EffectiveWindowV1Schema>>;
  readonly runtime: {
    readonly runtimeBundleId: string;
    readonly runtimeBundleHash: Sha256Hash;
    readonly window: Readonly<z.infer<typeof EffectiveWindowV1Schema>>;
  };
  readonly dataQuality: ModernDataQualityDefinitionV1;
  readonly reconciliation: ModernReconciliationDefinitionV1;
}

export interface ModernSnapshotSourceEvidenceAuthorityV1 {
  loadSection(input: {
    readonly tenantId: string;
    readonly snapshotId: string;
    readonly sectionId: string;
  }): Promise<CapturedSourcePopulationV2 | undefined>;
}

export interface ModernCertificationDefinitionAuthorityV1 {
  resolveForBoundSnapshot(input: {
    readonly evidence: {
      readonly tenantId: string;
      readonly sourceContract: DatasetSnapshotV2["sourceContract"];
      readonly deliveryHash: Sha256Hash;
      readonly extractionReceipt: ModernSnapshotExtractionReceiptV1;
      readonly delivery: GovernedSourceDeliveryRecordV1;
      readonly scopeBinding: GovernedDatasetScopeBindingV1;
      readonly asOfDate: string;
    };
  }): Promise<ModernCertificationDefinitionResolutionV1 | undefined>;
}

export interface ModernSnapshotExtractionReceiptAuthorityV1 {
  get(
    tenantId: string,
    receiptId: string
  ): Promise<ModernSnapshotExtractionReceiptV1 | undefined>;
}

export interface ModernMappingDimensionAuthorityV1 {
  resolveForMapping(input: {
    readonly tenantId: string;
    readonly mappingSpec: MappingSpecV2;
  }): Promise<readonly MappingDimensionLookupV1[]>;
}

/**
 * Production certification runtime boundary. It resolves activation at the
 * immutable attempt timestamp, then exposes only components proven to belong
 * to that exact runtime. The legacy historical resolver remains available for
 * migration/test fixtures that do not claim lifecycle activation authority.
 */
export interface ActivatedCertificationRuntimeResolverV1 extends HistoricalRuntimeResolver {
  resolveActivatedRuntime(reference: {
    readonly runtimeBundleId: string;
    readonly runtimeBundleHash: Sha256Hash;
  }): {
    readonly runtime: HistoricalRuntimeBundleV1;
    readonly activation: RuntimeActivationProofV1;
  };
}

export interface CertificationRuntimeAuthorityFactoryV1 {
  forCertification(input: {
    readonly tenantId: string;
    readonly certifiedAt: string;
  }): ActivatedCertificationRuntimeResolverV1;
}

export interface ModernSnapshotCertificationServiceDependencies {
  readonly snapshots: Pick<ImmutableRepositoryPort<DatasetSnapshotV2>, "get">;
  readonly receipts: ModernSnapshotExtractionReceiptAuthorityV1;
  readonly sourceDeliveries: GovernedSourceDeliveryCaptureAuthorityV1;
  readonly certifiedEvidence: Pick<
    ImmutableRepositoryPort<CertifiedSnapshotEvidenceRecordV1>,
    "get" | "put"
  >;
  /** Locks certification time and immutable request identity before artifact materialization. */
  readonly attempts: SnapshotCertificationAttemptStoreV1;
  /** Optional crash-safe handoff record binding the normalized artifact to the immutable attempt. */
  readonly artifactStaging?: CertificationArtifactStagingStoreV1;
  readonly sourceEvidence: ModernSnapshotSourceEvidenceAuthorityV1;
  /** Legacy trusted-import authority. Production composition must omit this in favor of lifecycleDefinitions. */
  readonly definitions?: ModernCertificationDefinitionAuthorityV1;
  /**
   * Decision-time governed authority. When configured it is the only
   * definition authority and must provide exact V2 lineage provenance.
   */
  readonly lifecycleDefinitions?: LifecycleSnapshotCertificationDefinitionAuthorityV1;
  readonly runtime: HistoricalRuntimeResolver;
  readonly dimensions: ModernMappingDimensionAuthorityV1;
  readonly artifacts: Pick<ArtifactStore, "getJson" | "putJson">;
  /** Required by production composition; legacy test/migration paths use runtime directly. */
  readonly certificationRuntime?: CertificationRuntimeAuthorityFactoryV1;
  readonly now: () => string;
}

export interface ModernSnapshotCertificationResultV1 {
  readonly evidence: CertifiedSnapshotEvidenceRecordV1;
  /** Present only for lifecycle-governed production certification until V2 repository persistence ships. */
  readonly evidenceV2?: CertifiedSnapshotEvidenceRecordV2;
  readonly replayed: boolean;
}

export type ModernSnapshotCertificationErrorCode =
  | "INVALID_REQUEST"
  | "OPERATOR_REQUIRED"
  | "NOT_FOUND"
  | "INTEGRITY_FAILURE"
  | "INACTIVE_DEFINITION"
  | "MISSING_REQUIRED_EVIDENCE"
  | "DATA_QUALITY_FAILED"
  | "RECONCILIATION_FAILED";

export class ModernSnapshotCertificationError extends Error {
  constructor(readonly code: ModernSnapshotCertificationErrorCode, message: string) {
    super(message);
    this.name = "ModernSnapshotCertificationError";
  }
}

/**
 * Trusted SnapshotV2 certification path. The request is deliberately IDs-only:
 * source rows, hashes, mapping logic, DQ controls, reconciliation totals, actor
 * identity, and timestamps are all reloaded or derived inside this boundary.
 */
export class ModernSnapshotCertificationService {
  readonly #dependencies: ModernSnapshotCertificationServiceDependencies;

  constructor(dependencies: ModernSnapshotCertificationServiceDependencies) {
    this.#dependencies = dependencies;
  }

  async certify(
    requestValue: CertifySnapshotV2Request,
    trustedActorValue: TrustedCertificationActorV1
  ): Promise<ModernSnapshotCertificationResultV1> {
    const publicRequest = parsed(CertifySnapshotV2RequestSchema, requestValue, "certification request");
    const actor = parsed(
      TrustedCertificationActorV1Schema,
      trustedActorValue,
      "trusted certification actor",
      "OPERATOR_REQUIRED"
    );
    const request = resolveCertificationRequest(publicRequest, actor.tenantId);
    const snapshot = await this.#dependencies.snapshots.get(actor.tenantId, request.snapshotId);
    if (!snapshot) fail("NOT_FOUND", "Dataset snapshot was not found in the actor tenant");
    if (snapshot.tenantId !== actor.tenantId || snapshot.snapshotId !== request.snapshotId) {
      fail("INTEGRITY_FAILURE", "Snapshot repository crossed its requested tenant or identity boundary");
    }

    const receiptValue = await this.#dependencies.receipts.get(
      actor.tenantId,
      modernSnapshotExtractionReceiptIdV1(snapshot.snapshotId)
    );
    if (!receiptValue) {
      fail("MISSING_REQUIRED_EVIDENCE", "Immutable extraction receipt was not found");
    }
    const receipt = certificationEvidence(
      () => parseModernSnapshotExtractionReceiptV1(receiptValue),
      "Extraction receipt"
    );
    this.#validateReceipt(receipt, snapshot);

    const attempt = await this.#attempt(request, actor, snapshot);
    const existing = await this.#dependencies.certifiedEvidence.get(
      actor.tenantId,
      request.certificationManifestId
    );
    const lifecycleDefinitions = this.#dependencies.lifecycleDefinitions;
    // Legacy replay deliberately avoids consulting mutable live authority. A
    // lifecycle-governed replay must instead reconstruct its V2 envelope from
    // decision-time durable lineage below.
    if (existing && lifecycleDefinitions === undefined) {
      return this.#replay(request, actor, snapshot, attempt, existing);
    }

    const certifiedAt = attempt.certifiedAt;

    const deliveryValue = await this.#dependencies.sourceDeliveries.resolveGovernedDeliveryForCapture({
      tenantId: actor.tenantId,
      sourceContractId: receipt.sourceContract.sourceContractId,
      deliveryId: receipt.deliveryId
    });
    if (!deliveryValue) {
      fail("MISSING_REQUIRED_EVIDENCE", "Governed source delivery no longer resolves as usable");
    }
    const delivery = this.#validateDeliveryResolution(deliveryValue, receipt, snapshot);

    if (snapshot.knowledge.persistedAt > certifiedAt || snapshot.asOfDate > certifiedAt.slice(0, 10)) {
      fail("INTEGRITY_FAILURE", "Certification cannot precede snapshot evidence");
    }
    const boundEvidence = {
      tenantId: actor.tenantId,
      sourceContract: snapshot.sourceContract,
      deliveryHash: delivery.delivery.deliveryHash,
      extractionReceipt: receipt,
      delivery: delivery.delivery,
      scopeBinding: delivery.scopeBinding,
      asOfDate: snapshot.asOfDate
    };
    let lifecycle: LifecycleSnapshotCertificationResolutionV1 | undefined;
    let resolutionValue: ModernCertificationDefinitionResolutionV1 | undefined;
    if (lifecycleDefinitions === undefined) {
      resolutionValue = await this.#legacyDefinitionResolution(boundEvidence);
    } else {
      lifecycle = await lifecycleDefinitions.resolveForCertificationAttemptDetailed({
        evidence: boundEvidence,
        attempt
      });
      resolutionValue = lifecycle?.resolution;
    }
    if (!resolutionValue) fail("NOT_FOUND", "No governed certification definition set was found");
    const resolution = this.#validateResolution(resolutionValue, snapshot, certifiedAt);
    if (existing) {
      this.#assertEvidenceMatchesResolution(existing, resolution);
      return this.#replay(request, actor, snapshot, attempt, existing, lifecycle);
    }
    this.#requireSections(snapshot, [
      resolution.dataQuality.mappingSectionId,
      ...resolution.dataQuality.requiredSectionIds,
      ...resolution.reconciliation.requiredSectionIds
    ]);

    const sourceSections = new Map<string, CapturedSourcePopulationV2>();
    for (const sectionId of new Set([
      resolution.dataQuality.mappingSectionId,
      ...resolution.dataQuality.requiredSectionIds,
      ...resolution.reconciliation.requiredSectionIds
    ])) {
      const source = await this.#dependencies.sourceEvidence.loadSection({
        tenantId: actor.tenantId,
        snapshotId: snapshot.snapshotId,
        sectionId
      });
      if (!source) {
        fail("MISSING_REQUIRED_EVIDENCE", `Source evidence for required section ${sectionId} was not found`);
      }
      this.#validateSourcePopulation(source, snapshot, sectionId);
      sourceSections.set(sectionId, source);
    }
    const source = sourceSections.get(resolution.dataQuality.mappingSectionId);
    if (!source) fail("MISSING_REQUIRED_EVIDENCE", "Mapped source section evidence was not found");

    const runtime = await this.#resolveRuntime(
      resolution,
      actor.tenantId,
      certifiedAt,
      lifecycleDefinitions !== undefined,
      lifecycle?.governance
    );
    const dimensions = await this.#dependencies.dimensions.resolveForMapping({
      tenantId: actor.tenantId,
      mappingSpec: resolution.mappingSpec
    });
    this.#validateDimensionLookups(resolution.mappingSpec, dimensions);
    const mapped = executeMappingSpecV2({
      spec: resolution.mappingSpec,
      records: source.records,
      dimensions
    });
    if (mapped.inputRowCount !== this.#section(snapshot, source.sectionId).rowCount) {
      fail("INTEGRITY_FAILURE", "Reloaded mapping population does not match its snapshot section row count");
    }

    const mappingApplication = createMappingApplicationV1({
      contractVersion: 1,
      tenantId: actor.tenantId,
      mappingApplicationId: request.mappingApplicationId,
      snapshot: {
        snapshotId: snapshot.snapshotId,
        snapshotHash: snapshot.snapshotHash,
        contentHash: snapshot.hashes.contentHash
      },
      mappingSpec: {
        mappingSpecId: resolution.mappingSpec.mappingSpecId,
        revision: resolution.mappingSpec.revision,
        mappingSpecHash: resolution.mappingSpec.mappingSpecHash
      },
      dictionaryBundle: resolution.mappingSpec.dictionaryBundle,
      runtimeBundle: {
        runtimeBundleId: runtime.runtimeBundleId,
        runtimeBundleHash: runtime.runtimeBundleHash,
        runtimeVersion: runtime.runtimeVersion
      },
      inputPopulationHash: mapped.inputPopulationHash as Sha256Hash,
      outputPopulationHash: mapped.outputPopulationHash as Sha256Hash,
      inputRowCount: mapped.inputRowCount,
      outputRowCount: mapped.outputRowCount,
      rejectedRowCount: mapped.rejectedRowCount,
      appliedBy: actor.actorId,
      appliedAt: certifiedAt
    });
    const normalized = createNormalizedSnapshotArtifactV2({
      contractVersion: 2,
      kind: "normalized_snapshot",
      tenantId: actor.tenantId,
      normalizedPopulationId: request.normalizedPopulationId,
      snapshot: { snapshotId: snapshot.snapshotId, snapshotHash: snapshot.snapshotHash },
      mappingApplication: {
        mappingApplicationId: mappingApplication.mappingApplicationId,
        mappingApplicationHash: mappingApplication.mappingApplicationHash
      },
      records: [...mapped.records],
      createdAt: certifiedAt
    });
    const evaluationRecords = normalizedEvaluationRecords(normalized.records);
    const quality = runDataQualityV2({
      records: evaluationRecords,
      rules: resolution.dataQuality.rules,
      balanceField: resolution.dataQuality.balanceField,
      materialBalance: resolution.dataQuality.materialBalance
    });
    if (
      quality.populationHash !== normalized.populationHash ||
      quality.rowCount !== normalized.rowCount
    ) {
      fail("INTEGRITY_FAILURE", "Data-quality evaluation crossed the normalized population boundary");
    }
    if (quality.publicationDecision !== "publish" || quality.findings.some((finding) => !finding.passed)) {
      fail("DATA_QUALITY_FAILED", "Every declared data-quality control must pass before certification");
    }
    const reconciliationResults = resolution.reconciliation.controls.map((control) => {
      const controlRecords = control.recordSource === "normalized"
        ? evaluationRecords
        : normalizedEvaluationRecords(sourceSections.get(control.sectionId)!.records);
      const result = reconcileSegmentsV2({
        records: controlRecords,
        dimensions: control.dimensions,
        balanceField: control.balanceField,
        currencyField: control.currencyField,
        expected: control.expected,
        balanceTolerance: control.balanceTolerance
      });
      const expectedPopulationHash = control.recordSource === "normalized"
        ? normalized.populationHash
        : sourceSections.get(control.sectionId)!.controlPopulationHash;
      if (
        !result.passed ||
        result.checks.some((check) => !check.passed) ||
        result.checks.some((check) => check.populationHash !== expectedPopulationHash)
      ) {
        fail(
          "RECONCILIATION_FAILED",
          `Declared reconciliation control ${control.controlId} did not pass`
        );
      }
      return Object.freeze({
        controlId: control.controlId,
        sectionId: control.sectionId,
        recordSource: control.recordSource,
        populationHash: expectedPopulationHash,
        resultHash: result.resultHash
      });
    });
    const reconciliationResultHash = canonicalHash({
      schemaVersion: 1,
      reconciliationId: resolution.reconciliation.reconciliationId,
      controls: reconciliationResults
    });

    const stored = this.#dependencies.artifacts.putJson({
      tenantId: actor.tenantId,
      kind: "normalized_snapshot",
      mediaType: "application/json",
      value: normalized
    });
    const loaded = this.#dependencies.artifacts.getJson(actor.tenantId, stored.artifactId);
    const reloadedNormalized = parseNormalizedSnapshotArtifactV2(loaded.value);
    if (canonicalJson(reloadedNormalized) !== canonicalJson(normalized)) {
      fail("INTEGRITY_FAILURE", "Normalized artifact reload did not match the exact mapped payload");
    }
    const artifactMetadata = createCertifiedSnapshotArtifactMetadataV1({
      artifact: reloadedNormalized,
      loadedStoredArtifact: loaded.metadata
    });
    const artifactBindingHash = await this.#prepareArtifactStage({
      request,
      actor,
      attempt,
      artifactMetadata,
      preparedAt: certifiedAt
    });

    const evidence = this.#buildEvidence({
      request,
      actor,
      snapshot,
      mappingSpec: resolution.mappingSpec,
      mappingApplication,
      artifactMetadata,
      normalized: reloadedNormalized,
      quality: {
        rulesetId: resolution.dataQuality.rulesetId,
        rulesetHash: canonicalHash(resolution.dataQuality),
        resultHash: quality.resultHash as Sha256Hash
      },
      reconciliation: {
        reconciliationId: resolution.reconciliation.reconciliationId,
        definitionHash: canonicalHash(resolution.reconciliation),
        resultHash: reconciliationResultHash
      },
      certifiedAt
    });
    const evidenceV2 = lifecycle === undefined
      ? undefined
      : this.#buildEvidenceV2(evidence, attempt, lifecycle.governance);
    try {
      const put = await this.#dependencies.certifiedEvidence.put(evidence, {
        tenantId: actor.tenantId,
        actorId: actor.actorId,
        idempotencyKey: request.idempotencyKey
      });
      const persisted = certificationEvidence(
        () => parseCertifiedSnapshotEvidenceRecordV1(put.record),
        "Persisted certification evidence"
      );
      if (canonicalJson(persisted) !== canonicalJson(evidence)) {
        if (put.replayed) return this.#replay(request, actor, snapshot, attempt, persisted);
        fail("INTEGRITY_FAILURE", "Certification evidence repository returned a substituted record");
      }
      await this.#recordArtifactStageCommit({
        request,
        actor,
        attempt,
        artifactMetadata,
        artifactBindingHash,
        evidence: persisted,
        occurredAt: certifiedAt
      });
      return Object.freeze({
        evidence: persisted,
        ...(evidenceV2 === undefined ? {} : { evidenceV2 }),
        replayed: put.replayed
      });
    } catch (error) {
      if (
        error instanceof RepositoryError &&
        (error.code === "ALREADY_EXISTS" || error.code === "IDEMPOTENCY_CONFLICT")
      ) {
        const raced = await this.#dependencies.certifiedEvidence.get(
          actor.tenantId,
          request.certificationManifestId
        );
        if (raced) {
          this.#assertEvidenceMatchesResolution(raced, resolution);
          return this.#replay(request, actor, snapshot, attempt, raced, lifecycle);
        }
      }
      await this.#recordArtifactStageFailure({
        request,
        actor,
        attempt,
        artifactMetadata,
        artifactBindingHash,
        occurredAt: certifiedAt,
        error
      });
      throw error;
    }
  }

  async #replay(
    request: ResolvedCertifySnapshotV2Request,
    actor: TrustedCertificationActorV1,
    snapshot: DatasetSnapshotV2,
    attempt: SnapshotCertificationAttemptV1,
    existingValue: CertifiedSnapshotEvidenceRecordV1,
    lifecycle?: LifecycleSnapshotCertificationResolutionV1
  ): Promise<ModernSnapshotCertificationResultV1> {
    const evidence = parseCertifiedSnapshotEvidenceRecordV1(existingValue);
    if (
      evidence.tenantId !== actor.tenantId ||
      evidence.certification.certificationManifestId !== request.certificationManifestId ||
      evidence.certification.snapshotId !== request.snapshotId ||
      evidence.certification.snapshotHash !== snapshot.snapshotHash ||
      evidence.certification.mappingApplicationId !== request.mappingApplicationId ||
      evidence.certification.populationId !== request.normalizedPopulationId ||
      evidence.certification.certifiedBy !== actor.actorId
    ) {
      fail("INTEGRITY_FAILURE", "Certification manifest id is already bound to another request or actor");
    }
    const loaded = this.#dependencies.artifacts.getJson(
      actor.tenantId,
      evidence.normalizedArtifact.artifactId
    );
    const artifact = parseNormalizedSnapshotArtifactV2(loaded.value);
    const metadata = createCertifiedSnapshotArtifactMetadataV1({
      artifact,
      loadedStoredArtifact: loaded.metadata
    });
    if (canonicalJson(metadata) !== canonicalJson(evidence.normalizedArtifact)) {
      fail("INTEGRITY_FAILURE", "Replayed certification no longer resolves its exact normalized artifact");
    }
    const artifactBindingHash = this.#artifactBindingHash(request, actor, attempt, metadata);
    await this.#recordArtifactStageCommit({
      request,
      actor,
      attempt,
      artifactMetadata: metadata,
      artifactBindingHash,
      evidence,
      occurredAt: attempt.certifiedAt
    });
    return Object.freeze({
      evidence,
      ...(lifecycle === undefined
        ? {}
        : { evidenceV2: this.#buildEvidenceV2(evidence, attempt, lifecycle.governance) }),
      replayed: true
    });
  }

  async #legacyDefinitionResolution(input: {
    readonly tenantId: string;
    readonly sourceContract: DatasetSnapshotV2["sourceContract"];
    readonly deliveryHash: Sha256Hash;
    readonly extractionReceipt: ModernSnapshotExtractionReceiptV1;
    readonly delivery: GovernedSourceDeliveryRecordV1;
    readonly scopeBinding: GovernedDatasetScopeBindingV1;
    readonly asOfDate: string;
  }): Promise<ModernCertificationDefinitionResolutionV1 | undefined> {
    const definitions = this.#dependencies.definitions;
    if (definitions === undefined) {
      fail(
        "INTEGRITY_FAILURE",
        "Certification requires lifecycle definitions in production or an explicit trusted-import definition authority"
      );
    }
    return definitions.resolveForBoundSnapshot({ evidence: input });
  }

  async #prepareArtifactStage(input: {
    readonly request: ResolvedCertifySnapshotV2Request;
    readonly actor: TrustedCertificationActorV1;
    readonly attempt: SnapshotCertificationAttemptV1;
    readonly artifactMetadata: CertifiedSnapshotArtifactMetadataV1;
    readonly preparedAt: string;
  }): Promise<Sha256Hash | undefined> {
    const staging = this.#dependencies.artifactStaging;
    if (!staging) return undefined;
    const artifactBindingHash = this.#artifactBindingHash(
      input.request,
      input.actor,
      input.attempt,
      input.artifactMetadata
    );
    try {
      const staged = await staging.prepareOrReplay({
        contractVersion: 1,
        tenantId: input.actor.tenantId,
        certificationManifestId: input.request.certificationManifestId,
        attemptHash: input.attempt.attemptHash,
        normalizedArtifact: input.artifactMetadata,
        artifactBindingHash,
        preparedAt: input.preparedAt
      });
      this.#assertArtifactStage(
        staged.record,
        input.request,
        input.actor,
        input.attempt,
        input.artifactMetadata,
        artifactBindingHash
      );
      return artifactBindingHash;
    } catch (error) {
      if (error instanceof ModernSnapshotCertificationError) throw error;
      fail("INTEGRITY_FAILURE", "Certification artifact stage could not be persisted or replayed");
    }
  }

  async #recordArtifactStageCommit(input: {
    readonly request: ResolvedCertifySnapshotV2Request;
    readonly actor: TrustedCertificationActorV1;
    readonly attempt: SnapshotCertificationAttemptV1;
    readonly artifactMetadata: CertifiedSnapshotArtifactMetadataV1;
    readonly artifactBindingHash: Sha256Hash | undefined;
    readonly evidence: CertifiedSnapshotEvidenceRecordV1;
    readonly occurredAt: string;
  }): Promise<void> {
    const staging = this.#dependencies.artifactStaging;
    if (!staging) return;
    if (input.artifactBindingHash === undefined) {
      fail("INTEGRITY_FAILURE", "Certification artifact stage binding is unexpectedly absent");
    }
    try {
      const committed = await staging.recordEvidenceCommitted({
        tenantId: input.actor.tenantId,
        certificationManifestId: input.request.certificationManifestId,
        attemptHash: input.attempt.attemptHash,
        artifactBindingHash: input.artifactBindingHash,
        certificationEvidenceHash: input.evidence.evidenceHash,
        occurredAt: input.occurredAt
      });
      this.#assertArtifactStage(
        committed.record,
        input.request,
        input.actor,
        input.attempt,
        input.artifactMetadata,
        input.artifactBindingHash,
        input.evidence.evidenceHash
      );
    } catch (error) {
      if (error instanceof ModernSnapshotCertificationError) throw error;
      fail("INTEGRITY_FAILURE", "Certification artifact stage commit could not be persisted or verified");
    }
  }

  async #recordArtifactStageFailure(input: {
    readonly request: ResolvedCertifySnapshotV2Request;
    readonly actor: TrustedCertificationActorV1;
    readonly attempt: SnapshotCertificationAttemptV1;
    readonly artifactMetadata: CertifiedSnapshotArtifactMetadataV1;
    readonly artifactBindingHash: Sha256Hash | undefined;
    readonly occurredAt: string;
    readonly error: unknown;
  }): Promise<void> {
    const staging = this.#dependencies.artifactStaging;
    if (!staging) return;
    if (input.artifactBindingHash === undefined) {
      fail("INTEGRITY_FAILURE", "Certification artifact stage binding is unexpectedly absent");
    }
    try {
      const failed = await staging.recordEvidenceFailure({
        tenantId: input.actor.tenantId,
        certificationManifestId: input.request.certificationManifestId,
        attemptHash: input.attempt.attemptHash,
        artifactBindingHash: input.artifactBindingHash,
        failureHash: canonicalHash({
          contractVersion: 1,
          kind: "certification_evidence_persistence_failure",
          errorType: input.error instanceof Error ? input.error.name : typeof input.error
        }),
        occurredAt: input.occurredAt
      });
      this.#assertArtifactStage(
        failed.record,
        input.request,
        input.actor,
        input.attempt,
        input.artifactMetadata,
        input.artifactBindingHash
      );
    } catch (error) {
      if (error instanceof ModernSnapshotCertificationError) throw error;
      fail("INTEGRITY_FAILURE", "Certification artifact failure receipt could not be persisted or verified");
    }
  }

  #artifactBindingHash(
    request: ResolvedCertifySnapshotV2Request,
    actor: TrustedCertificationActorV1,
    attempt: SnapshotCertificationAttemptV1,
    artifactMetadata: CertifiedSnapshotArtifactMetadataV1
  ): Sha256Hash {
    return canonicalHash({
      contractVersion: 1,
      tenantId: actor.tenantId,
      certificationManifestId: request.certificationManifestId,
      attemptHash: attempt.attemptHash,
      normalizedArtifact: artifactMetadata
    });
  }

  #assertArtifactStage(
    record: CertificationArtifactOutboxRecordV1,
    request: ResolvedCertifySnapshotV2Request,
    actor: TrustedCertificationActorV1,
    attempt: SnapshotCertificationAttemptV1,
    artifactMetadata: CertifiedSnapshotArtifactMetadataV1,
    artifactBindingHash: Sha256Hash,
    certificationEvidenceHash?: Sha256Hash
  ): void {
    if (
      record.stage.tenantId !== actor.tenantId ||
      record.stage.certificationManifestId !== request.certificationManifestId ||
      record.stage.attemptHash !== attempt.attemptHash ||
      record.stage.artifactBindingHash !== artifactBindingHash ||
      canonicalJson(record.stage.normalizedArtifact) !== canonicalJson(artifactMetadata) ||
      (certificationEvidenceHash !== undefined &&
        (record.state !== "evidence_committed" ||
          record.certificationEvidenceHash !== certificationEvidenceHash))
    ) {
      fail("INTEGRITY_FAILURE", "Certification artifact stage does not bind the exact attempt, artifact, and evidence");
    }
  }

  async #attempt(
    request: ResolvedCertifySnapshotV2Request,
    actor: TrustedCertificationActorV1,
    snapshot: DatasetSnapshotV2
  ): Promise<SnapshotCertificationAttemptV1> {
    const timestamp = parsed(IsoTimestampSchema, this.#dependencies.now(), "trusted clock");
    try {
      const result = await this.#dependencies.attempts.startOrReplay({
        tenantId: actor.tenantId,
        certificationManifestId: request.certificationManifestId,
        snapshotId: snapshot.snapshotId,
        snapshotHash: snapshot.snapshotHash,
        actorId: actor.actorId,
        requestHash: canonicalHash({
          contractVersion: 1,
          tenantId: actor.tenantId,
          actorId: actor.actorId,
          snapshotId: request.snapshotId,
          mappingApplicationId: request.mappingApplicationId,
          normalizedPopulationId: request.normalizedPopulationId,
          certificationManifestId: request.certificationManifestId,
          idempotencyKey: request.idempotencyKey
        }),
        certifiedAt: timestamp,
        createdAt: timestamp
      });
      return result.attempt;
    } catch {
      fail("INTEGRITY_FAILURE", "Certification attempt receipt could not be persisted or replayed");
    }
  }

  #validateReceipt(
    receipt: ModernSnapshotExtractionReceiptV1,
    snapshot: DatasetSnapshotV2
  ): void {
    if (
      receipt.tenantId !== snapshot.tenantId ||
      receipt.receiptId !== modernSnapshotExtractionReceiptIdV1(snapshot.snapshotId) ||
      receipt.snapshotId !== snapshot.snapshotId ||
      canonicalJson(receipt.sourceContract) !== canonicalJson(snapshot.sourceContract) ||
      receipt.receiptHash !== snapshot.hashes.extractionHash ||
      receipt.asOfDate !== snapshot.asOfDate ||
      canonicalJson(receipt.delivery) !== canonicalJson(snapshot.delivery) ||
      receipt.sourceLocator !== snapshot.sourceLocator ||
      receipt.immutableSourceVersion !== snapshot.immutableSourceVersion ||
      canonicalJson(receipt.knowledge) !== canonicalJson(snapshot.knowledge) ||
      canonicalJson(receipt.watermark) !== canonicalJson(snapshot.watermark) ||
      receipt.hashes.contentHash !== snapshot.hashes.contentHash ||
      receipt.hashes.schemaHash !== snapshot.hashes.schemaHash ||
      receipt.hashes.catalogHash !== snapshot.hashes.catalogHash ||
      receipt.hashes.parserHash !== snapshot.hashes.parserHash ||
      receipt.rowCount !== snapshot.rowCount ||
      receipt.byteCount !== snapshot.byteCount ||
      canonicalJson(receipt.sections) !== canonicalJson(snapshot.sections) ||
      canonicalJson(receipt.correction) !== canonicalJson(snapshot.correction) ||
      receipt.capturedBy !== snapshot.createdBy
    ) {
      fail("INTEGRITY_FAILURE", "Extraction receipt does not exactly reconstruct the immutable snapshot");
    }
  }

  #validateDeliveryResolution(
    resolution: GovernedSourceDeliveryResolutionV1,
    receipt: ModernSnapshotExtractionReceiptV1,
    snapshot: DatasetSnapshotV2
  ): GovernedSourceDeliveryResolutionV1 {
    const delivery = certificationEvidence(
      () => parseGovernedSourceDeliveryRecordV1(resolution.delivery),
      "Governed source delivery"
    );
    const sourceContract = certificationEvidence(
      () => parseSourceContractV1(resolution.sourceContract),
      "Governed source contract"
    );
    const scopeBinding = certificationEvidence(
      () => parseGovernedDatasetScopeBindingV1(resolution.scopeBinding),
      "Governed dataset scope binding"
    );
    const expectedSourceVersionHash = delivery.locator.mode === "postgresql_pull"
      ? delivery.locator.sourceVersionHash
      : delivery.locator.immutableVersionHash;
    if (
      delivery.status !== "usable" ||
      delivery.tenantId !== snapshot.tenantId ||
      delivery.deliveryId !== receipt.deliveryId ||
      delivery.deliveryRevision !== receipt.sourceDelivery.deliveryRevision ||
      delivery.deliveryHash !== receipt.sourceDelivery.deliveryHash ||
      canonicalHash(delivery.locator) !== receipt.sourceDelivery.locatorHash ||
      expectedSourceVersionHash !== receipt.sourceDelivery.sourceVersionHash ||
      canonicalJson(delivery.sourceContract) !== canonicalJson(receipt.sourceContract) ||
      canonicalJson(delivery.scopeBinding) !== canonicalJson(receipt.scopeBinding) ||
      delivery.datasetId !== receipt.datasetId ||
      delivery.facilityId !== receipt.facilityId ||
      sourceContract.tenantId !== snapshot.tenantId ||
      sourceContract.status !== "active" ||
      canonicalJson({
        sourceContractId: sourceContract.sourceContractId,
        revision: sourceContract.revision,
        sourceContractHash: sourceContract.sourceContractHash
      }) !== canonicalJson(receipt.sourceContract) ||
      canonicalJson(sourceContract.delivery) !== canonicalJson(receipt.delivery) ||
      scopeBinding.tenantId !== snapshot.tenantId ||
      scopeBinding.datasetId !== receipt.datasetId ||
      scopeBinding.scope.scopeType !== "facility" ||
      scopeBinding.scope.scopeId !== receipt.facilityId ||
      canonicalJson(scopeBinding.sourceContract) !== canonicalJson(receipt.sourceContract) ||
      canonicalJson({
        bindingId: scopeBinding.bindingId,
        revision: scopeBinding.revision,
        bindingHash: scopeBinding.bindingHash
      }) !== canonicalJson(receipt.scopeBinding)
    ) {
      fail("INTEGRITY_FAILURE", "Governed delivery resolution substituted snapshot source or facility scope");
    }
    return Object.freeze({ delivery, sourceContract, scopeBinding });
  }

  #validateResolution(
    value: ModernCertificationDefinitionResolutionV1,
    snapshot: DatasetSnapshotV2,
    certifiedAt: string
  ): ModernCertificationDefinitionResolutionV1 {
    const mappingSpec = parseMappingSpecV2(value.mappingSpec);
    const mappingWindow = parsed(EffectiveWindowV1Schema, value.mappingWindow, "mapping effective window");
    const runtime = parsed(RuntimeActivationV1Schema, value.runtime, "runtime activation");
    const dataQuality = parsed(
      DataQualityDefinitionV1Schema,
      value.dataQuality,
      "data-quality definition"
    ) as ModernDataQualityDefinitionV1;
    const reconciliation = parsed(
      ReconciliationDefinitionV1Schema,
      value.reconciliation,
      "reconciliation definition"
    );
    if (
      mappingSpec.tenantId !== snapshot.tenantId ||
      canonicalJson(mappingSpec.sourceContract) !== canonicalJson(snapshot.sourceContract)
    ) {
      fail("INTEGRITY_FAILURE", "Activated mapping does not bind the exact tenant and source contract");
    }
    if (mappingSpec.status !== "active" || mappingSpec.approvedAt === undefined) {
      fail("INACTIVE_DEFINITION", "Snapshot certification requires an active approved mapping");
    }
    if (mappingSpec.approvedAt > certifiedAt) {
      fail("INACTIVE_DEFINITION", "Mapping approval cannot follow its application");
    }
    for (const [label, window] of [
      ["mapping", mappingWindow],
      ["runtime", runtime.window],
      ["data-quality", dataQuality.window],
      ["reconciliation", reconciliation.window]
    ] as const) {
      if (!effectiveOn(window, snapshot.asOfDate)) {
        fail("INACTIVE_DEFINITION", `${label} definition is not effective for the snapshot as-of date`);
      }
    }
    return Object.freeze({ mappingSpec, mappingWindow, runtime, dataQuality, reconciliation });
  }

  #requireSections(snapshot: DatasetSnapshotV2, sectionIds: readonly string[]): void {
    for (const sectionId of new Set(sectionIds)) {
      const section = snapshot.sections.find((candidate) => candidate.sectionId === sectionId);
      if (!section || !section.present) {
        fail(
          "MISSING_REQUIRED_EVIDENCE",
          `Required certification section ${sectionId} is absent from immutable snapshot evidence`
        );
      }
    }
  }

  #validateSourcePopulation(
    source: CapturedSourcePopulationV2,
    snapshot: DatasetSnapshotV2,
    sectionId: string
  ): void {
    try {
      canonicalJson(source);
    } catch {
      fail("INTEGRITY_FAILURE", "Captured source population is not canonical evidence");
    }
    if (
      source.tenantId !== snapshot.tenantId ||
      source.snapshotId !== snapshot.snapshotId ||
      source.snapshotHash !== snapshot.snapshotHash ||
      source.sectionId !== sectionId ||
      source.extractionHash !== snapshot.hashes.extractionHash ||
      canonicalJson(source.sourceContract) !== canonicalJson(snapshot.sourceContract)
    ) {
      fail("INTEGRITY_FAILURE", "Captured source population does not bind the exact snapshot lineage");
    }
    const section = this.#section(snapshot, sectionId);
    if (
      source.records.length !== section.rowCount ||
      source.sectionContentHash !== section.contentHash ||
      source.sectionSchemaHash !== section.schemaHash ||
      section.controlPopulationHash === undefined ||
      source.controlPopulationHash !== section.controlPopulationHash ||
      canonicalHash(source.records) !== source.controlPopulationHash
    ) {
      fail("INTEGRITY_FAILURE", "Captured source population did not verify against section controls");
    }
  }

  async #resolveRuntime(
    resolution: ModernCertificationDefinitionResolutionV1,
    tenantId: string,
    certifiedAt: string,
    lifecycleGoverned: boolean,
    governance?: CertifiedSnapshotEvidenceRecordV2["governance"]
  ): Promise<HistoricalRuntimeBundleV1> {
    const reference = {
      runtimeBundleId: resolution.runtime.runtimeBundleId,
      runtimeBundleHash: resolution.runtime.runtimeBundleHash
    };
    const activatedRuntime = this.#dependencies.certificationRuntime?.forCertification({
      tenantId,
      certifiedAt
    });
    if (lifecycleGoverned && activatedRuntime === undefined) {
      fail(
        "INTEGRITY_FAILURE",
        "Lifecycle-governed certification requires a decision-time certification runtime authority"
      );
    }
    const activated = activatedRuntime?.resolveActivatedRuntime(reference);
    const runtime = parseHistoricalRuntimeBundleV1(
      activated?.runtime ?? await this.#dependencies.runtime.resolveRuntimeBundle(reference)
    );
    if (
      runtime.runtimeBundleId !== resolution.runtime.runtimeBundleId ||
      runtime.runtimeBundleHash !== resolution.runtime.runtimeBundleHash ||
      runtime.assembledAt > certifiedAt ||
      canonicalJson(runtime.dictionary) !== canonicalJson(resolution.mappingSpec.dictionaryBundle)
    ) {
      fail("INTEGRITY_FAILURE", "Historical runtime does not match the activated mapping lineage");
    }
    if (
      activated !== undefined &&
      (activated.activation.tenantId !== tenantId ||
        activated.activation.runtimeBundleId !== runtime.runtimeBundleId ||
        activated.activation.runtimeBundleHash !== runtime.runtimeBundleHash ||
        activated.activation.activatedAt > certifiedAt)
    ) {
      fail("INTEGRITY_FAILURE", "Certification runtime activation did not bind the immutable attempt time");
    }
    if (
      lifecycleGoverned &&
      (activated === undefined ||
        governance === undefined ||
        runtime.runtimeBundleId !== governance.runtime.runtimeBundleId ||
        runtime.runtimeVersion !== governance.runtime.runtimeVersion ||
        runtime.runtimeBundleHash !== governance.runtime.runtimeBundleHash ||
        canonicalJson(activated.activation) !== canonicalJson(governance.runtime.activation) ||
        canonicalJson(runtime.dictionary) !== canonicalJson(governance.runtime.dictionary) ||
        canonicalJson(runtime.mappingCompiler) !== canonicalJson(governance.runtime.mappingCompiler))
    ) {
      fail(
        "INTEGRITY_FAILURE",
        "Lifecycle definition and certification runtime authorities did not resolve identical immutable runtime lineage"
      );
    }
    const references = [runtime.dictionary, runtime.mappingCompiler, ...runtime.methodologies];
    if (references.some((reference) => reference.createdAt > runtime.assembledAt)) {
      fail("INTEGRITY_FAILURE", "Historical runtime contains a bundle created after assembly");
    }
    await Promise.all([
      (activatedRuntime ?? this.#dependencies.runtime).resolveDictionary(runtime.dictionary),
      (activatedRuntime ?? this.#dependencies.runtime).resolveBundle(runtime.mappingCompiler),
      ...runtime.methodologies.map((reference) =>
        (activatedRuntime ?? this.#dependencies.runtime).resolveBundle(reference)
      )
    ]);
    return runtime;
  }

  #validateDimensionLookups(
    mappingSpec: MappingSpecV2,
    lookups: readonly MappingDimensionLookupV1[]
  ): void {
    const required = new Set<string>();
    for (const rule of mappingSpec.rules) collectDimensionReferences(rule.expression, required);
    const supplied = new Set<string>();
    for (const lookup of lookups) {
      const key = `${lookup.definitionId}:${lookup.definitionVersion}:${lookup.definitionHash}`;
      if (supplied.has(key)) fail("INTEGRITY_FAILURE", "Dimension authority returned a duplicate lookup");
      supplied.add(key);
    }
    if (canonicalJson([...required].sort()) !== canonicalJson([...supplied].sort())) {
      fail("INTEGRITY_FAILURE", "Dimension authority did not resolve the exact mapping lookup set");
    }
  }

  #section(snapshot: DatasetSnapshotV2, sectionId: string): DatasetSnapshotV2["sections"][number] {
    const section = snapshot.sections.find((candidate) => candidate.sectionId === sectionId);
    if (!section) fail("MISSING_REQUIRED_EVIDENCE", "Mapped source section is absent");
    return section;
  }

  #assertEvidenceMatchesResolution(
    evidenceValue: CertifiedSnapshotEvidenceRecordV1,
    resolution: ModernCertificationDefinitionResolutionV1
  ): void {
    const evidence = parseCertifiedSnapshotEvidenceRecordV1(evidenceValue);
    if (
      evidence.population.dataQuality.rulesetId !== resolution.dataQuality.rulesetId ||
      evidence.population.dataQuality.rulesetHash !== canonicalHash(resolution.dataQuality) ||
      evidence.population.reconciliation.reconciliationId !== resolution.reconciliation.reconciliationId ||
      evidence.population.reconciliation.definitionHash !== canonicalHash(resolution.reconciliation)
    ) {
      fail("INTEGRITY_FAILURE", "Persisted certification evidence does not prove the lifecycle-selected controls ran");
    }
  }

  #buildEvidenceV2(
    evidence: CertifiedSnapshotEvidenceRecordV1,
    attempt: SnapshotCertificationAttemptV1,
    governance: CertifiedSnapshotEvidenceRecordV2["governance"]
  ): CertifiedSnapshotEvidenceRecordV2 {
    try {
      return createCertifiedSnapshotEvidenceRecordV2({
        contractVersion: 2,
        tenantId: evidence.tenantId,
        v1Evidence: evidence,
        certificationAttempt: attempt,
        governance,
        recordedAt: evidence.recordedAt
      });
    } catch {
      fail("INTEGRITY_FAILURE", "Lifecycle authority provenance did not bind the exact certification evidence");
    }
  }

  #buildEvidence(input: {
    readonly request: ResolvedCertifySnapshotV2Request;
    readonly actor: TrustedCertificationActorV1;
    readonly snapshot: DatasetSnapshotV2;
    readonly mappingSpec: MappingSpecV2;
    readonly mappingApplication: MappingApplicationV1;
    readonly artifactMetadata: ReturnType<typeof createCertifiedSnapshotArtifactMetadataV1>;
    readonly normalized: ReturnType<typeof parseNormalizedSnapshotArtifactV2>;
    readonly quality: {
      readonly rulesetId: string;
      readonly rulesetHash: Sha256Hash;
      readonly resultHash: Sha256Hash;
    };
    readonly reconciliation: {
      readonly reconciliationId: string;
      readonly definitionHash: Sha256Hash;
      readonly resultHash: Sha256Hash;
    };
    readonly certifiedAt: string;
  }): CertifiedSnapshotEvidenceRecordV1 {
    const populationBody = {
      contractVersion: 1 as const,
      tenantId: input.actor.tenantId,
      populationId: input.normalized.normalizedPopulationId,
      snapshotId: input.snapshot.snapshotId,
      snapshotHash: input.snapshot.snapshotHash,
      mappingApplicationId: input.mappingApplication.mappingApplicationId,
      mappingApplicationHash: input.mappingApplication.mappingApplicationHash,
      populationHash: input.normalized.populationHash,
      fieldSetHash: input.normalized.fieldSetHash,
      rowCount: input.normalized.rowCount,
      dataQuality: {
        runId: `dq-${canonicalHash(input.request.certificationManifestId).slice(7, 39)}`,
        rulesetId: input.quality.rulesetId,
        rulesetHash: input.quality.rulesetHash,
        resultHash: input.quality.resultHash,
        publicationDecision: "publish" as const,
        blockerCodes: []
      },
      reconciliation: {
        reconciliationId: input.reconciliation.reconciliationId,
        definitionHash: input.reconciliation.definitionHash,
        resultHash: input.reconciliation.resultHash,
        passed: true as const,
        populationHash: input.normalized.populationHash
      },
      certifiedBy: input.actor.actorId,
      certifiedAt: input.certifiedAt
    };
    const population = Object.freeze({
      ...populationBody,
      certificationHash: canonicalHash(populationBody)
    });
    const certificationBody = {
      contractVersion: 1 as const,
      tenantId: input.actor.tenantId,
      certificationManifestId: input.request.certificationManifestId,
      evidenceFormat: "modern_snapshot_v2" as const,
      snapshotId: input.snapshot.snapshotId,
      snapshotHash: input.snapshot.snapshotHash,
      populationId: population.populationId,
      populationCertificationHash: population.certificationHash,
      mappingApplicationId: input.mappingApplication.mappingApplicationId,
      mappingApplicationHash: input.mappingApplication.mappingApplicationHash,
      normalizedArtifactId: input.artifactMetadata.artifactId,
      normalizedArtifactContentHash: input.artifactMetadata.contentHash,
      dataQualityResultHash: population.dataQuality.resultHash,
      reconciliationResultHash: population.reconciliation.resultHash,
      populationHash: population.populationHash,
      rowCount: population.rowCount,
      certifiedBy: population.certifiedBy,
      certifiedAt: population.certifiedAt
    };
    return createCertifiedSnapshotEvidenceRecordV1({
      contractVersion: 1,
      tenantId: input.actor.tenantId,
      certification: {
        ...certificationBody,
        certificationManifestHash: canonicalHash(certificationBody)
      },
      population,
      mappingSpec: input.mappingSpec,
      mappingApplication: input.mappingApplication,
      normalizedArtifact: input.artifactMetadata,
      dataQualityPopulation: {
        populationHash: input.normalized.populationHash,
        fieldSetHash: input.normalized.fieldSetHash,
        rowCount: input.normalized.rowCount
      },
      recordedAt: input.certifiedAt
    });
  }
}

function parsed<T>(
  schema: z.ZodType<T>,
  value: unknown,
  label: string,
  code: ModernSnapshotCertificationErrorCode = "INVALID_REQUEST"
): T {
  const result = schema.safeParse(value);
  if (!result.success) fail(code, `${label} failed strict validation`);
  return result.data;
}

function resolveCertificationRequest(
  request: CertifySnapshotV2Request,
  tenantId: string
): ResolvedCertifySnapshotV2Request {
  const id = (kind: string) =>
    `${kind}-${canonicalHash({
      contractVersion: 1,
      tenantId,
      snapshotId: request.snapshotId,
      kind
    }).slice("sha256:".length, "sha256:".length + 32)}`;
  return Object.freeze({
    snapshotId: request.snapshotId,
    mappingApplicationId: id("mapping"),
    normalizedPopulationId: id("population"),
    certificationManifestId: id("certification"),
    idempotencyKey: id("certify")
  });
}

function effectiveOn(
  window: Readonly<z.infer<typeof EffectiveWindowV1Schema>>,
  asOfDate: string
): boolean {
  return window.effectiveFrom <= asOfDate &&
    (window.effectiveTo === undefined || asOfDate < window.effectiveTo);
}

function certificationEvidence<T>(load: () => T, label: string): T {
  try {
    return load();
  } catch {
    fail("INTEGRITY_FAILURE", `${label} failed canonical integrity validation`);
  }
}

function normalizedEvaluationRecords(
  records: readonly Readonly<Record<string, null | boolean | string | number>>[]
): readonly Readonly<Record<string, null | boolean | string>>[] {
  for (const record of records) {
    if (Object.values(record).some((value) => typeof value === "number")) {
      fail("INTEGRITY_FAILURE", "Normalized mapping output unexpectedly contained a numeric JSON value");
    }
  }
  return records as readonly Readonly<Record<string, null | boolean | string>>[];
}

function collectDimensionReferences(expression: MappingSpecV2["rules"][number]["expression"], found: Set<string>): void {
  if (expression.op === "dimension_lookup") {
    found.add(`${expression.definitionId}:${expression.definitionVersion}:${expression.definitionHash}`);
    collectDimensionReferences(expression.input, found);
    return;
  }
  if (expression.op === "source" || expression.op === "literal") return;
  if (expression.op === "coalesce" || expression.op === "combine") {
    for (const input of expression.inputs) collectDimensionReferences(input, found);
    return;
  }
  if (expression.op === "when") {
    collectConditionDimensionReferences(expression.condition, found);
    collectDimensionReferences(expression.then, found);
    collectDimensionReferences(expression.otherwise, found);
    return;
  }
  collectDimensionReferences(expression.input, found);
}

function collectConditionDimensionReferences(
  condition: Extract<
    MappingSpecV2["rules"][number]["expression"],
    { readonly op: "when" }
  >["condition"],
  found: Set<string>
): void {
  if (condition.op === "equals") {
    collectDimensionReferences(condition.left, found);
    collectDimensionReferences(condition.right, found);
    return;
  }
  if (condition.op === "in" || condition.op === "is_null") {
    collectDimensionReferences(condition.input, found);
    return;
  }
  if (condition.op === "not") {
    collectConditionDimensionReferences(condition.condition, found);
    return;
  }
  for (const nested of condition.conditions) collectConditionDimensionReferences(nested, found);
}

function fail(code: ModernSnapshotCertificationErrorCode, message: string): never {
  throw new ModernSnapshotCertificationError(code, message);
}
