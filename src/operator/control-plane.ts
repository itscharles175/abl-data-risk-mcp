import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readFileSync
} from "node:fs";
import { resolve } from "node:path";
import { TextDecoder } from "node:util";

import type { MonitoringAlertStore } from "../control/alerts.js";
import type { ArtifactStore } from "../control/artifacts.js";
import type {
  GovernedDefinitionAuditEventV2,
  GovernedDefinitionV2Store,
  GovernedDefinitionViewV2
} from "../control/governed-definitions-v2.js";
import type { InputCertificationViewV1 } from "../control/input-certifications.js";
import {
  DefinitionStoreError,
  type DefinitionStore,
  type GovernedDefinition
} from "../control/definitions.js";
import type { ControlStore, JsonValue } from "../control/store.js";
import {
  selectEffectiveBorrowingBasePolicy,
  type ArBorrowingBasePolicyVersion
} from "../domain/borrowing-base.js";
import { DICTIONARY_VERSION } from "../domain/dictionary.js";
import { runDataQuality, type DataQualityProfile } from "../domain/data-quality.js";
import {
  validateFieldMappings,
  type MappingValidationResult,
  type SourceColumn
} from "../domain/mapping.js";
import { evaluateMonitoring, type MonitorDefinition } from "../domain/monitoring.js";
import type { TenantMembershipStore } from "../security/membership-store.js";
import {
  loadLoanTapeFile,
  type LoadLoanTapeFileOptions
} from "../services/file-ingestion.js";
import type { SnapshotIngestionService } from "../services/ingestion.js";
import type { SqlSnapshotExtractionService } from "../services/sql-snapshot-extraction.js";
import type { InputCertificationService } from "../services/input-certification.js";
import type {
  ModernSnapshotCaptureResultV1,
  TrustedModernSnapshotCaptureActorV1
} from "../services/modern-snapshot-capture.js";
import type {
  ModernSnapshotCertificationResultV1,
  TrustedCertificationActorV1
} from "../services/modern-snapshot-certification.js";
import type {
  GovernedDefinitionV2Resolver,
  GovernedDefinitionExecutionReferenceV2
} from "../services/governed-definition-v2-resolver.js";
import {
  alertListInputSchema,
  alertTransitionInputSchema,
  auditListInputSchema,
  boundedJson,
  certifySnapshotV2InputSchema,
  certifySnapshotInputSchema,
  definitionProposeInputSchema,
  definitionTransitionInputSchema,
  fileIngestInputSchema,
  governedDefinitionV2AuditListInputSchema,
  governedDefinitionV2GetInputSchema,
  governedDefinitionV2ListInputSchema,
  governedDefinitionV2ProposeInputSchema,
  governedDefinitionV2SelectEffectiveInputSchema,
  governedDefinitionV2TransitionInputSchema,
  mappingProposeInputSchema,
  mappingTransitionInputSchema,
  membershipChangeInputSchema,
  membershipProposeInputSchema,
  operatorIdentifierSchema,
  OperatorInputError,
  parseStrict,
  putInputArtifactInputSchema,
  extractSqlV2InputSchema,
  inputCertificationCertifySchema,
  inputCertificationProposeSchema,
  sqlExtractInputSchema,
  validateDefinitionDocument,
  validateInputArtifact,
  type AlertListInput,
  type AlertTransitionInput,
  type AuditListInput,
  type CertifySnapshotInput,
  type CertifySnapshotV2Input,
  type DefinitionProposeInput,
  type DefinitionTransitionInput,
  type FileIngestInput,
  type ExtractSqlV2Input,
  type GovernedDefinitionV2AuditListInput,
  type GovernedDefinitionV2GetInput,
  type GovernedDefinitionV2ListInput,
  type GovernedDefinitionV2ProposeInput,
  type GovernedDefinitionV2SelectEffectiveInput,
  type GovernedDefinitionV2TransitionInput,
  type InputArtifactKind,
  type MappingProposeInput,
  type MappingTransitionInput,
  type MembershipChangeInput,
  type MembershipProposeInput,
  type PutInputArtifactInput,
  type SqlExtractInput
} from "./schemas.js";

type ControlPort = Pick<
  ControlStore,
  | "appendAuditEvent"
  | "getDatasetSnapshot"
  | "getMappingVersion"
  | "listAuditEvents"
  | "proposeMappingVersion"
  | "transitionMappingVersion"
>;
type DefinitionPort = Pick<
  DefinitionStore,
  "get" | "listAuditEvents" | "propose" | "selectEffective" | "transition"
>;
type GovernedDefinitionV2Port = Pick<
  GovernedDefinitionV2Store,
  "get" | "list" | "listAuditEvents" | "propose" | "selectEffective" | "transition"
>;
type GovernedDefinitionV2ResolverPort = Pick<GovernedDefinitionV2Resolver, "resolveEffective">;
type ArtifactPort = Pick<ArtifactStore, "putJson">;
type MembershipPort = Pick<TenantMembershipStore, "approve" | "propose" | "revoke">;
type AlertPort = Pick<MonitoringAlertStore, "listAlerts" | "listAuditEvents" | "transitionAlert">;
type IngestionPort = Pick<SnapshotIngestionService, "certifyMappedSnapshot" | "registerDeliveredSnapshot">;
type SqlExtractorPort = Pick<SqlSnapshotExtractionService, "extractAndRegister">;
type InputCertificationPort = Pick<InputCertificationService, "propose" | "certify">;
type ModernSnapshotCapturePort = {
  capture(
    actor: TrustedModernSnapshotCaptureActorV1,
    request: ExtractSqlV2Input,
    options?: { readonly signal?: AbortSignal }
  ): Promise<ModernSnapshotCaptureResultV1>;
};
type ModernSnapshotCertificationPort = {
  certify(
    request: CertifySnapshotV2Input,
    actor: TrustedCertificationActorV1
  ): Promise<ModernSnapshotCertificationResultV1>;
};

export interface OperatorControlPlaneDependencies {
  /**
   * Trusted identity established by the process boundary. Request documents
   * never supply or override this value.
   */
  readonly principal: OperatorPrincipal;
  readonly control: ControlPort;
  readonly definitions: DefinitionPort;
  readonly governedDefinitionsV2?: GovernedDefinitionV2Port;
  readonly governedDefinitionV2Resolver?: GovernedDefinitionV2ResolverPort;
  readonly artifacts: ArtifactPort;
  readonly memberships: MembershipPort;
  readonly alerts: AlertPort;
  readonly ingestion: IngestionPort;
  readonly inputCertification?: InputCertificationPort;
  readonly sqlExtractors?: ReadonlyMap<string, SqlExtractorPort>;
  readonly modernSnapshotCapture?: ModernSnapshotCapturePort;
  readonly modernSnapshotCertification?: ModernSnapshotCertificationPort;
  readonly loadLoanTape?: typeof loadLoanTapeFile;
  readonly readJsonFile?: typeof readBoundedJsonFile;
}

/**
 * Authenticated identity for an operator process or service. The current local
 * CLI is intentionally a privileged global administrator: tenantId values in
 * legacy request documents select resources and are not authentication
 * assertions. Modern IDs-only commands instead require the process boundary to
 * bind tenantId on this trusted principal. A networked administration service
 * must enforce its tenant grants before it constructs or invokes this plane.
 */
export interface OperatorPrincipal {
  readonly principalId: string;
  /** Optional server-derived tenant binding required by modern IDs-only commands. */
  readonly tenantId?: string;
  readonly authenticationMethod: "local_os_account" | "trusted_service_identity";
  readonly authorizationScope: "global_admin";
}

export type OperatorControlPlaneErrorCode =
  | "INVALID_INPUT"
  | "CAPABILITY_NOT_CONFIGURED"
  | "SOURCE_NOT_CONFIGURED"
  | "MAPPING_NOT_READY"
  | "DEFINITION_INVALID"
  | "DEFINITION_NOT_EFFECTIVE"
  | "SNAPSHOT_NOT_FOUND"
  | "SNAPSHOT_MISMATCH";

export class OperatorControlPlaneError extends Error {
  constructor(
    readonly code: OperatorControlPlaneErrorCode,
    message: string
  ) {
    super(message);
    this.name = "OperatorControlPlaneError";
  }
}

export interface OperatorSnapshotSummary {
  readonly snapshotId: string;
  readonly sourceId: string;
  readonly asOfDate: string;
  readonly rowCount: number;
  readonly contentHash: string;
  readonly artifactId: string;
}

export interface OperatorSqlSnapshotSummary extends OperatorSnapshotSummary {
  readonly datasetId: string;
  readonly relationId: string;
  readonly queryFingerprint: string;
  readonly byteLength: number;
}

export interface OperatorModernSnapshotCaptureSummary {
  readonly snapshotId: string;
  readonly deliveryId: string;
  readonly sourceContractId: string;
  readonly receiptId: string;
  readonly snapshotHash: string;
  readonly receiptHash: string;
  readonly asOfDate: string;
  readonly rowCount: number;
  readonly columnCount: number;
  readonly byteCount: number;
  readonly receiptReplayed: boolean;
  readonly snapshotReplayed: boolean;
}

export interface OperatorModernSnapshotCertificationSummary {
  readonly snapshotId: string;
  readonly snapshotHash: string;
  readonly mappingApplicationId: string;
  readonly mappingApplicationHash: string;
  readonly normalizedPopulationId: string;
  readonly populationHash: string;
  readonly certificationManifestId: string;
  readonly certificationManifestHash: string;
  readonly dataQualityResultHash: string;
  readonly reconciliationResultHash: string;
  readonly evidenceHash: string;
  readonly rowCount: number;
  readonly certifiedAt: string;
  readonly replayed: boolean;
}

export interface OperatorMappingSummary {
  readonly mappingVersionId: string;
  readonly mappingKey: string;
  readonly version: number;
  readonly status: string;
  readonly mappingHash: string;
  readonly dictionaryVersion: string;
  readonly validation?: OperatorMappingValidationSummary;
}

export interface OperatorMappingValidationSummary {
  readonly profile: MappingValidationResult["profile"];
  readonly readiness: MappingValidationResult["readiness"];
  readonly errorCodes: readonly string[];
  readonly warningCodes: readonly string[];
  readonly coverage: MappingValidationResult["coverage"];
}

export interface OperatorDefinitionSummary {
  readonly definitionId: string;
  readonly definitionKey: string;
  readonly kind: string;
  readonly version: string;
  readonly status: string;
  readonly effectiveFrom: string;
  readonly effectiveTo: string | null;
  readonly documentHash: string;
}

export interface OperatorGovernedDefinitionV2Summary {
  readonly definitionVersionId: string;
  readonly definitionKey: string;
  readonly kind: string;
  readonly semanticVersion: string;
  readonly status: string;
  readonly lifecycleRevision: number;
  readonly effectiveFrom: string;
  readonly effectiveTo: string | null;
  readonly predecessorDefinitionVersionId: string | null;
  readonly rollbackTargetDefinitionVersionId: string | null;
  readonly proposedBy: string;
  readonly proposedAt: string;
  readonly lastTransitionBy: string;
  readonly lastTransitionAt: string;
  readonly documentHash: string;
  readonly semanticDiffHash: string;
  readonly semanticDiff: {
    readonly beforeHash: string | null;
    readonly afterHash: string;
    readonly changeCount: number;
    readonly changedPaths: readonly string[];
    readonly truncated: boolean;
  };
  readonly impactPreviewHash: string;
  readonly impactPreview: {
    readonly impactLevel: string;
    readonly affectedCapabilities: readonly string[];
    readonly changedPathCount: number;
    readonly rollbackTargetRequired: boolean;
  };
  readonly versionHash: string;
  readonly approval: {
    readonly approvedBy: string;
    readonly approvedAt: string;
    readonly approvalEventHash: string;
  } | null;
}

export interface OperatorEffectiveGovernedDefinitionV2Summary
  extends OperatorGovernedDefinitionV2Summary {
  readonly resolutionVerified: true;
  readonly executionReference: GovernedDefinitionExecutionReferenceV2;
}

export interface OperatorGovernedDefinitionV2AuditSummary {
  readonly sequence: number;
  readonly eventId: string;
  readonly definitionVersionId: string;
  readonly lifecycleRevision: number;
  readonly fromStatus: string | null;
  readonly toStatus: string;
  readonly actor: string;
  readonly occurredAt: string;
  readonly previousEventHash: string | null;
  readonly eventHash: string;
}

export interface OperatorCertificationSummary {
  readonly snapshotId: string;
  readonly mappingVersionId: string;
  readonly dataQualityDefinitionId: string;
  readonly dataQualityRunId: string;
  readonly reconciliationId: string;
  readonly certificationManifestId: string;
  readonly certified: boolean;
  readonly blockerCodes: readonly string[];
  readonly findingCount: number;
  readonly reconciliationPassed: boolean;
  readonly manifestHash: string;
  readonly normalizedArtifactId: string;
}

export interface OperatorInputArtifactSummary {
  readonly inputId: string;
  readonly kind: InputArtifactKind;
  readonly artifactId: string;
  readonly contentHash: string;
  readonly byteLength: number;
  readonly auditSequence: number;
}

export interface OperatorInputCertificationSummary {
  readonly inputId: string;
  readonly inputKind: string;
  readonly status: "proposed" | "certified";
  readonly proposalHash: string;
  readonly certifiedArtifactId?: string;
  readonly envelopeHash?: string;
  readonly lineageHash?: string;
}

export interface OperatorMembershipSummary {
  readonly membershipId: string;
  readonly tenantId: string;
  readonly principalId: string;
  readonly status: string;
}

export interface OperatorAlertSummary {
  readonly alertId: string;
  readonly monitorId: string;
  readonly status: string;
  readonly severity: string;
  readonly scope: { readonly type: string; readonly id: string };
  readonly recurrenceCount: number;
  readonly firstSeenOn: string;
  readonly lastSeenOn: string;
}

export interface OperatorAuditEventSummary {
  readonly sequence: number;
  readonly eventId: string;
  readonly eventType: string;
  readonly entityType: string;
  readonly entityId: string;
  readonly actor: string;
  readonly occurredAt: string;
}

/**
 * Operator-only administration boundary. It is deliberately not referenced by
 * either MCP transport and never returns source records, definition documents,
 * artifact payloads, OAuth subjects, tokens, credentials, or database paths.
 */
export class OperatorControlPlane {
  readonly #dependencies: OperatorControlPlaneDependencies;
  readonly #principal: OperatorPrincipal;
  readonly #loadLoanTape: typeof loadLoanTapeFile;
  readonly #readJsonFile: typeof readBoundedJsonFile;

  constructor(dependencies: OperatorControlPlaneDependencies) {
    this.#dependencies = dependencies;
    this.#principal = validateOperatorPrincipal(dependencies.principal);
    this.#loadLoanTape = dependencies.loadLoanTape ?? loadLoanTapeFile;
    this.#readJsonFile = dependencies.readJsonFile ?? readBoundedJsonFile;
  }

  ingestLoanTape(inputValue: unknown): OperatorSnapshotSummary {
    const input = parseStrict(fileIngestInputSchema, inputValue, "file ingestion request");
    const loaded = this.#loadLoanTape(input.filePath, fileLimits(input));
    let registered: ReturnType<IngestionPort["registerDeliveredSnapshot"]>;
    try {
      registered = this.#dependencies.ingestion.registerDeliveredSnapshot({
        tenantId: input.tenantId,
        snapshotId: input.snapshotId,
        sourceId: input.sourceId,
        asOfDate: input.asOfDate,
        records: loaded.records,
        deliveredBy: this.#principal.principalId,
        idempotencyKey: input.idempotencyKey,
        ...(input.expectedCanonicalContentHash === undefined
          ? {}
          : { expectedCanonicalContentHash: input.expectedCanonicalContentHash })
      });
    } catch (error) {
      if (isDeclaredHashMismatch(error)) {
        throw new OperatorControlPlaneError(
          "SNAPSHOT_MISMATCH",
          "Delivered snapshot content hash did not match the declared hash"
        );
      }
      throw error;
    }
    return snapshotSummary(registered);
  }

  async extractSqlSnapshot(
    inputValue: unknown,
    options: { readonly signal?: AbortSignal } = {}
  ): Promise<OperatorSqlSnapshotSummary> {
    const input = parseStrict(sqlExtractInputSchema, inputValue, "SQL extraction request");
    const extractor = this.#dependencies.sqlExtractors?.get(input.sourceId);
    if (!extractor) {
      throw new OperatorControlPlaneError(
        "SOURCE_NOT_CONFIGURED",
        "The requested trusted SQL snapshot source is not configured"
      );
    }
    let result: Awaited<ReturnType<SqlExtractorPort["extractAndRegister"]>>;
    try {
      result = await extractor.extractAndRegister(
        {
          tenantId: input.tenantId,
          datasetId: input.datasetId,
          snapshotId: input.snapshotId,
          relationId: input.relationId,
          columnIds: input.columnIds,
          ...(input.watermark === undefined ? {} : { watermark: input.watermark }),
          asOfDate: input.asOfDate,
          deliveredBy: this.#principal.principalId,
          idempotencyKey: input.idempotencyKey,
          ...(input.expectedCanonicalContentHash === undefined
            ? {}
            : { expectedCanonicalContentHash: input.expectedCanonicalContentHash })
        },
        options.signal === undefined ? {} : { signal: options.signal }
      );
    } catch (error) {
      if (isDeclaredHashMismatch(error)) {
        throw new OperatorControlPlaneError(
          "SNAPSHOT_MISMATCH",
          "Extracted snapshot content hash did not match the declared hash"
        );
      }
      throw error;
    }
    return {
      ...snapshotSummary(result),
      datasetId: result.extraction.datasetId,
      relationId: result.extraction.relationId,
      queryFingerprint: result.extraction.queryFingerprint,
      byteLength: result.extraction.byteLength
    };
  }

  async extractSqlSnapshotV2(
    inputValue: unknown,
    options: { readonly signal?: AbortSignal } = {}
  ): Promise<OperatorModernSnapshotCaptureSummary> {
    const input: ExtractSqlV2Input = parseStrict(
      extractSqlV2InputSchema,
      inputValue,
      "modern SQL extraction request"
    );
    const capture = this.#dependencies.modernSnapshotCapture;
    const tenantId = this.#principal.tenantId;
    if (capture === undefined || tenantId === undefined) {
      throw new OperatorControlPlaneError(
        "CAPABILITY_NOT_CONFIGURED",
        "Governed modern snapshot capture is not configured"
      );
    }
    const result = await capture.capture(
      {
        tenantId,
        actorId: this.#principal.principalId,
        authority: "platform_operator",
        identitySource: "server_derived"
      },
      input,
      options.signal === undefined ? {} : { signal: options.signal }
    );
    return {
      snapshotId: result.snapshot.snapshotId,
      deliveryId: result.receipt.deliveryId,
      sourceContractId: result.snapshot.sourceContract.sourceContractId,
      receiptId: result.receipt.receiptId,
      snapshotHash: result.snapshot.snapshotHash,
      receiptHash: result.receipt.receiptHash,
      asOfDate: result.snapshot.asOfDate,
      rowCount: result.snapshot.rowCount,
      columnCount: result.receipt.columnCount,
      byteCount: result.receipt.byteCount,
      receiptReplayed: result.receiptReplayed,
      snapshotReplayed: result.snapshotReplayed
    };
  }

  proposeMapping(inputValue: unknown): OperatorMappingSummary {
    const input = parseStrict(mappingProposeInputSchema, inputValue, "mapping proposal");
    const validation = validateFieldMappings(normalizeSourceColumns(input.sourceColumns), input.mappings, input.profile);
    requireReadyMapping(validation);
    const mapping = this.#dependencies.control.proposeMappingVersion({
      tenantId: input.tenantId,
      mappingVersionId: input.mappingVersionId,
      mappingKey: input.mappingKey,
      snapshotId: input.snapshotId,
      dictionaryVersion: DICTIONARY_VERSION,
      mappings: input.mappings,
      proposedBy: this.#principal.principalId,
      idempotencyKey: input.idempotencyKey
    });
    return mappingSummary(mapping, validationSummary(validation));
  }

  transitionMapping(inputValue: unknown): OperatorMappingSummary {
    const input = parseStrict(mappingTransitionInputSchema, inputValue, "mapping transition");
    const current = this.#dependencies.control.getMappingVersion(input.tenantId, input.mappingVersionId);
    if (!current) throw new OperatorControlPlaneError("MAPPING_NOT_READY", "Mapping version was not found");
    let validation: MappingValidationResult | undefined;
    if (input.toStatus === "validated") {
      if (current.dictionaryVersion !== DICTIONARY_VERSION) {
        throw new OperatorControlPlaneError(
          "MAPPING_NOT_READY",
          "Mapping dictionary version does not match this operator release"
        );
      }
      validation = validateFieldMappings(normalizeSourceColumns(input.sourceColumns), current.mappings, input.profile);
      requireReadyMapping(validation);
    }
    const transitioned = this.#dependencies.control.transitionMappingVersion({
      tenantId: input.tenantId,
      mappingVersionId: input.mappingVersionId,
      toStatus: input.toStatus,
      actor: this.#principal.principalId,
      ...(validation === undefined
        ? {}
        : {
            evidence: boundedJson(
              {
                dictionaryVersion: DICTIONARY_VERSION,
                validation: validationSummary(validation)
              },
              "mapping validation evidence",
              128_000
            )
          }),
      idempotencyKey: input.idempotencyKey
    });
    return mappingSummary(
      transitioned,
      validation === undefined ? undefined : validationSummary(validation)
    );
  }

  proposeDefinition(inputValue: unknown): OperatorDefinitionSummary {
    const input = parseStrict(definitionProposeInputSchema, inputValue, "definition proposal");
    const document = validateAndBindDefinition(input);
    const definition = this.#dependencies.definitions.propose({
      tenantId: input.tenantId,
      definitionId: input.definitionId,
      definitionKey: input.definitionKey,
      kind: input.kind,
      version: input.version,
      effectiveFrom: input.effectiveFrom,
      ...(input.effectiveTo === undefined ? {} : { effectiveTo: input.effectiveTo }),
      document,
      proposedBy: this.#principal.principalId,
      idempotencyKey: input.idempotencyKey
    });
    return definitionSummary(definition);
  }

  transitionDefinition(inputValue: unknown): OperatorDefinitionSummary {
    const input = parseStrict(definitionTransitionInputSchema, inputValue, "definition transition");
    const current = this.#dependencies.definitions.get(input.tenantId, input.definitionId);
    if (!current) {
      throw new OperatorControlPlaneError("DEFINITION_INVALID", "Governed definition was not found");
    }
    if (input.toStatus === "validated") validateStoredDefinition(current);
    const evidence = input.evidence === undefined
      ? input.toStatus === "validated"
        ? { validator: "operator-control-plane", schemaVersion: 1 }
        : undefined
      : boundedJson(input.evidence, "definition transition evidence", 128_000);
    const definition = this.#dependencies.definitions.transition({
      tenantId: input.tenantId,
      definitionId: input.definitionId,
      toStatus: input.toStatus,
      actor: this.#principal.principalId,
      ...(evidence === undefined ? {} : { evidence }),
      idempotencyKey: input.idempotencyKey
    });
    return definitionSummary(definition);
  }

  proposeGovernedDefinitionV2(inputValue: unknown): OperatorGovernedDefinitionV2Summary {
    const input = parseStrict(
      governedDefinitionV2ProposeInputSchema,
      inputValue,
      "governed definition v2 proposal"
    );
    const definition = this.#governedDefinitionsV2().propose({
      tenantId: input.tenantId,
      definitionVersionId: input.definitionVersionId,
      definitionKey: input.definitionKey,
      kind: input.kind,
      semanticVersion: input.semanticVersion,
      effectiveFrom: input.effectiveFrom,
      ...(input.effectiveTo === undefined ? {} : { effectiveTo: input.effectiveTo }),
      ...(input.predecessorDefinitionVersionId === undefined
        ? {}
        : { predecessorDefinitionVersionId: input.predecessorDefinitionVersionId }),
      ...(input.rollbackTargetDefinitionVersionId === undefined
        ? {}
        : { rollbackTargetDefinitionVersionId: input.rollbackTargetDefinitionVersionId }),
      document: boundedJson(
        input.document,
        "governed definition v2 document",
        1_000_000
      ),
      proposedBy: this.#principal.principalId,
      idempotencyKey: input.idempotencyKey
    });
    return governedDefinitionV2Summary(definition);
  }

  transitionGovernedDefinitionV2(inputValue: unknown): OperatorGovernedDefinitionV2Summary {
    const input = parseStrict(
      governedDefinitionV2TransitionInputSchema,
      inputValue,
      "governed definition v2 transition"
    );
    const definition = this.#governedDefinitionsV2().transition({
      tenantId: input.tenantId,
      definitionVersionId: input.definitionVersionId,
      toStatus: input.toStatus,
      expectedRevision: input.expectedRevision,
      actor: this.#principal.principalId,
      ...(input.evidence === undefined
        ? {}
        : {
            evidence: boundedJson(
              input.evidence,
              "governed definition v2 transition evidence",
              128_000
            )
          }),
      idempotencyKey: input.idempotencyKey
    });
    return governedDefinitionV2Summary(definition);
  }

  getGovernedDefinitionV2(inputValue: unknown): OperatorGovernedDefinitionV2Summary {
    const input = parseStrict(
      governedDefinitionV2GetInputSchema,
      inputValue,
      "governed definition v2 get request"
    );
    const definition = this.#governedDefinitionsV2().get(
      input.tenantId,
      input.definitionVersionId
    );
    if (definition === undefined) {
      throw new OperatorControlPlaneError(
        "DEFINITION_INVALID",
        "Governed definition v2 version was not found"
      );
    }
    return governedDefinitionV2Summary(definition);
  }

  listGovernedDefinitionsV2(inputValue: unknown): readonly OperatorGovernedDefinitionV2Summary[] {
    const input = parseStrict(
      governedDefinitionV2ListInputSchema,
      inputValue,
      "governed definition v2 list request"
    );
    return this.#governedDefinitionsV2()
      .list(input.tenantId, {
        ...(input.kind === undefined ? {} : { kind: input.kind }),
        ...(input.definitionKey === undefined ? {} : { definitionKey: input.definitionKey }),
        ...(input.limit === undefined ? {} : { limit: input.limit })
      })
      .map(governedDefinitionV2Summary);
  }

  selectEffectiveGovernedDefinitionV2(
    inputValue: unknown
  ): OperatorEffectiveGovernedDefinitionV2Summary {
    const input = parseStrict(
      governedDefinitionV2SelectEffectiveInputSchema,
      inputValue,
      "governed definition v2 effective-selection request"
    );
    const resolved = this.#governedDefinitionV2Resolver().resolveEffective(input);
    const definition = this.#governedDefinitionsV2().get(
      input.tenantId,
      resolved.reference.definitionVersionId
    );
    if (
      definition === undefined ||
      definition.version.versionHash !== resolved.reference.versionHash ||
      definition.version.documentHash !== resolved.reference.documentHash ||
      definition.approvalEvidence?.approvalEventHash !== resolved.reference.approvalEventHash
    ) {
      throw new OperatorControlPlaneError(
        "DEFINITION_INVALID",
        "Resolved governed definition v2 metadata failed integrity binding"
      );
    }
    return {
      ...governedDefinitionV2Summary(definition),
      resolutionVerified: true,
      executionReference: resolved.reference
    };
  }

  listGovernedDefinitionV2Audit(
    inputValue: unknown
  ): readonly OperatorGovernedDefinitionV2AuditSummary[] {
    const input = parseStrict(
      governedDefinitionV2AuditListInputSchema,
      inputValue,
      "governed definition v2 audit request"
    );
    return this.#governedDefinitionsV2()
      .listAuditEvents(input.tenantId, input.afterSequence ?? 0, input.limit ?? 100)
      .map(governedDefinitionV2AuditSummary);
  }

  certifySnapshot(inputValue: unknown): OperatorCertificationSummary {
    const input = parseStrict(certifySnapshotInputSchema, inputValue, "snapshot certification");
    const snapshot = this.#dependencies.control.getDatasetSnapshot(input.tenantId, input.snapshotId);
    if (!snapshot) throw new OperatorControlPlaneError("SNAPSHOT_NOT_FOUND", "Dataset snapshot was not found");
    let definition: GovernedDefinition;
    try {
      definition = this.#dependencies.definitions.selectEffective(
        input.tenantId,
        "data_quality_profile",
        input.dataQualityDefinitionKey,
        snapshot.asOfDate
      );
    } catch (error) {
      if (!(error instanceof DefinitionStoreError) || error.code !== "NOT_FOUND") throw error;
      throw new OperatorControlPlaneError(
        "DEFINITION_NOT_EFFECTIVE",
        "No active data-quality definition is effective for the snapshot"
      );
    }
    const document = validateStoredDefinition(definition) as unknown as DataQualityProfile;
    if (document.expectedAsOfDate !== snapshot.asOfDate) {
      throw new OperatorControlPlaneError(
        "SNAPSHOT_MISMATCH",
        "Data-quality expected date does not match the immutable snapshot"
      );
    }
    const certification = this.#dependencies.ingestion.certifyMappedSnapshot({
      tenantId: input.tenantId,
      snapshotId: input.snapshotId,
      mappingVersionId: input.mappingVersionId,
      dataQualityRunId: input.dataQualityRunId,
      reconciliationId: input.reconciliationId,
      certificationManifestId: input.certificationManifestId,
      dataQualityProfile: document,
      declaredControlTotals: {
        rowCount: input.declaredControlTotals.rowCount,
        balance: input.declaredControlTotals.balance,
        ...(input.declaredControlTotals.currency === undefined
          ? {}
          : { currency: input.declaredControlTotals.currency })
      },
      ...(input.reconciliationTolerance === undefined
        ? {}
        : { reconciliationTolerance: input.reconciliationTolerance }),
      evaluatedAt: input.evaluatedAt,
      codeVersion: input.codeVersion,
      executedBy: this.#principal.principalId,
      idempotencyKey: input.idempotencyKey
    });
    return {
      snapshotId: certification.snapshot.snapshotId,
      mappingVersionId: certification.mappingVersion.mappingVersionId,
      dataQualityDefinitionId: definition.definitionId,
      dataQualityRunId: certification.durableDataQualityRun.runId,
      reconciliationId: certification.reconciliation.reconciliationId,
      certificationManifestId: certification.manifest.manifestId,
      certified: certification.certified,
      blockerCodes: certification.blockerCodes,
      findingCount: certification.durableDataQualityRun.findingCount,
      reconciliationPassed: certification.reconciliation.passed,
      manifestHash: certification.manifest.manifestHash,
      normalizedArtifactId: certification.normalizedArtifact.artifactId
    };
  }

  async certifySnapshotV2(
    inputValue: unknown
  ): Promise<OperatorModernSnapshotCertificationSummary> {
    const input: CertifySnapshotV2Input = parseStrict(
      certifySnapshotV2InputSchema,
      inputValue,
      "modern snapshot certification request"
    );
    const certification = this.#dependencies.modernSnapshotCertification;
    const tenantId = this.#principal.tenantId;
    if (certification === undefined || tenantId === undefined) {
      throw new OperatorControlPlaneError(
        "CAPABILITY_NOT_CONFIGURED",
        "Governed modern snapshot certification is not configured"
      );
    }
    const result = await certification.certify(input, {
      tenantId,
      actorId: this.#principal.principalId,
      authority: "platform_operator",
      identitySource: "server_derived"
    });
    return {
      snapshotId: result.evidence.certification.snapshotId,
      snapshotHash: result.evidence.certification.snapshotHash,
      mappingApplicationId: result.evidence.certification.mappingApplicationId,
      mappingApplicationHash: result.evidence.certification.mappingApplicationHash,
      normalizedPopulationId: result.evidence.certification.populationId,
      populationHash: result.evidence.certification.populationHash,
      certificationManifestId: result.evidence.certification.certificationManifestId,
      certificationManifestHash: result.evidence.certification.certificationManifestHash,
      dataQualityResultHash: result.evidence.certification.dataQualityResultHash,
      reconciliationResultHash: result.evidence.certification.reconciliationResultHash,
      evidenceHash: result.evidence.evidenceHash,
      rowCount: result.evidence.certification.rowCount,
      certifiedAt: result.evidence.certification.certifiedAt,
      replayed: result.replayed
    };
  }

  putInputArtifact(inputValue: unknown): OperatorInputArtifactSummary {
    const input = parseStrict(putInputArtifactInputSchema, inputValue, "input artifact request");
    const value = validateInputArtifact(input.kind, this.#readJsonFile(input.filePath, 8_000_000));
    const snapshotId = requiredStringProperty(value, "snapshotId");
    const asOfDate = requiredStringProperty(value, "asOfDate");
    const snapshot = this.#dependencies.control.getDatasetSnapshot(input.tenantId, snapshotId);
    if (!snapshot) throw new OperatorControlPlaneError("SNAPSHOT_NOT_FOUND", "Dataset snapshot was not found");
    if (snapshot.asOfDate !== asOfDate) {
      throw new OperatorControlPlaneError(
        "SNAPSHOT_MISMATCH",
        "Input artifact date does not match the immutable snapshot"
      );
    }
    const artifact = this.#dependencies.artifacts.putJson({
      tenantId: input.tenantId,
      kind: input.kind,
      mediaType: "application/json",
      value
    });
    const audit = this.#dependencies.control.appendAuditEvent({
      tenantId: input.tenantId,
      eventType: "input_artifact.stored",
      entityType: "input_artifact",
      entityId: input.inputId,
      actor: this.#principal.principalId,
      details: {
        artifactId: artifact.artifactId,
        byteLength: artifact.byteLength,
        contentHash: artifact.contentHash,
        kind: input.kind,
        snapshotId
      },
      idempotencyKey: input.idempotencyKey
    });
    return {
      inputId: input.inputId,
      kind: input.kind,
      artifactId: artifact.artifactId,
      contentHash: artifact.contentHash,
      byteLength: artifact.byteLength,
      auditSequence: audit.sequence
    };
  }

  proposeInputCertification(inputValue: unknown): OperatorInputCertificationSummary {
    const input = parseStrict(
      inputCertificationProposeSchema,
      inputValue,
      "input certification proposal"
    );
    const service = this.#dependencies.inputCertification;
    if (!service) {
      throw new OperatorControlPlaneError(
        "INVALID_INPUT",
        "Input certification service is unavailable"
      );
    }
    return inputCertificationSummary(
      service.propose({
        tenantId: input.tenantId,
        inputId: input.inputId,
        inputKind: input.inputKind,
        candidateArtifactId: input.candidateArtifactId,
        primaryCertificationManifestId: input.primaryCertificationManifestId,
        definitionIds: input.definitionIds,
        purpose: input.purpose,
        declaredControls: {
          rowCount: input.declaredControls.rowCount,
          ...(input.declaredControls.balance === undefined
            ? {}
            : { balance: input.declaredControls.balance }),
          ...(input.declaredControls.currency === undefined
            ? {}
            : { currency: input.declaredControls.currency })
        },
        idempotencyKey: input.idempotencyKey,
        proposedBy: this.#principal.principalId
      })
    );
  }

  certifyInputCertification(inputValue: unknown): OperatorInputCertificationSummary {
    const input = parseStrict(
      inputCertificationCertifySchema,
      inputValue,
      "input certification approval"
    );
    const service = this.#dependencies.inputCertification;
    if (!service) {
      throw new OperatorControlPlaneError(
        "INVALID_INPUT",
        "Input certification service is unavailable"
      );
    }
    return inputCertificationSummary(
      service.certify({
        ...input,
        certifiedBy: this.#principal.principalId
      })
    );
  }

  proposeMembership(inputValue: unknown): OperatorMembershipSummary {
    const input = parseStrict(membershipProposeInputSchema, inputValue, "membership proposal");
    return membershipSummary(
      this.#dependencies.memberships.propose({
        membershipId: input.membershipId,
        issuer: input.issuer,
        subject: input.subject,
        clientId: input.clientId,
        tenantId: input.tenantId,
        principalId: input.principalId,
        ...(input.notBefore === undefined ? {} : { notBefore: input.notBefore }),
        ...(input.expiresAt === undefined ? {} : { expiresAt: input.expiresAt }),
        proposedBy: this.#principal.principalId,
        idempotencyKey: input.idempotencyKey
      })
    );
  }

  approveMembership(inputValue: unknown): OperatorMembershipSummary {
    const input = parseStrict(membershipChangeInputSchema, inputValue, "membership approval");
    return membershipSummary(this.#dependencies.memberships.approve({
      membershipId: input.membershipId,
      actor: this.#principal.principalId,
      idempotencyKey: input.idempotencyKey
    }));
  }

  revokeMembership(inputValue: unknown): OperatorMembershipSummary {
    const input = parseStrict(membershipChangeInputSchema, inputValue, "membership revocation");
    return membershipSummary(this.#dependencies.memberships.revoke({
      membershipId: input.membershipId,
      actor: this.#principal.principalId,
      idempotencyKey: input.idempotencyKey
    }));
  }

  listAlerts(inputValue: unknown): readonly OperatorAlertSummary[] {
    const input = parseStrict(alertListInputSchema, inputValue, "alert list request");
    return this.#dependencies.alerts
      .listAlerts(input.tenantId, {
        ...(input.status === undefined ? {} : { status: input.status }),
        ...(input.limit === undefined ? {} : { limit: input.limit })
      })
      .map(alertSummary);
  }

  transitionAlert(inputValue: unknown): OperatorAlertSummary {
    const input = parseStrict(alertTransitionInputSchema, inputValue, "alert transition");
    const common = {
      tenantId: input.tenantId,
      alertId: input.alertId,
      actor: this.#principal.principalId,
      idempotencyKey: input.idempotencyKey
    };
    const transition = input.action === "acknowledge"
      ? { ...common, action: input.action, ...(input.note === undefined ? {} : { note: input.note }) }
      : input.action === "resolve"
        ? { ...common, action: input.action, resolution: input.resolution }
        : { ...common, action: input.action, reason: input.reason };
    return alertSummary(this.#dependencies.alerts.transitionAlert(transition));
  }

  listAudit(inputValue: unknown): readonly OperatorAuditEventSummary[] {
    const input = parseStrict(auditListInputSchema, inputValue, "audit list request");
    const afterSequence = input.afterSequence ?? 0;
    const limit = input.limit ?? 100;
    if (input.stream === "control") {
      return this.#dependencies.control
        .listAuditEvents(input.tenantId, { afterSequence, limit })
        .map((event) => auditSummary(event));
    }
    if (input.stream === "definitions") {
      return this.#dependencies.definitions
        .listAuditEvents(input.tenantId, afterSequence, limit)
        .map((event) => auditSummary({ ...event, entityType: "definition", entityId: event.definitionId }));
    }
    return this.#dependencies.alerts
      .listAuditEvents(input.tenantId, { afterSequence, limit })
      .map((event) => auditSummary(event));
  }

  #governedDefinitionsV2(): GovernedDefinitionV2Port {
    const authority = this.#dependencies.governedDefinitionsV2;
    if (authority === undefined) {
      throw new OperatorControlPlaneError(
        "DEFINITION_INVALID",
        "Governed definition v2 administration is unavailable"
      );
    }
    return authority;
  }

  #governedDefinitionV2Resolver(): GovernedDefinitionV2ResolverPort {
    const resolver = this.#dependencies.governedDefinitionV2Resolver;
    if (resolver === undefined) {
      throw new OperatorControlPlaneError(
        "DEFINITION_INVALID",
        "Governed definition v2 resolution is unavailable"
      );
    }
    return resolver;
  }
}

function validateOperatorPrincipal(principal: OperatorPrincipal): OperatorPrincipal {
  const principalId = parseStrict(
    operatorIdentifierSchema,
    principal?.principalId,
    "operator principal"
  );
  const tenantId = principal.tenantId === undefined
    ? undefined
    : parseStrict(operatorIdentifierSchema, principal.tenantId, "operator tenant binding");
  if (
    (principal.authenticationMethod !== "local_os_account" &&
      principal.authenticationMethod !== "trusted_service_identity") ||
    principal.authorizationScope !== "global_admin"
  ) {
    throw new OperatorInputError("operator principal is invalid");
  }
  return Object.freeze({
    principalId,
    ...(tenantId === undefined ? {} : { tenantId }),
    authenticationMethod: principal.authenticationMethod,
    authorizationScope: principal.authorizationScope
  });
}

export function readBoundedJsonFile(pathInput: string, maximumBytes = 1_000_000): JsonValue {
  if (
    !pathInput ||
    pathInput.length > 4_096 ||
    /[\u0000\r\n]/.test(pathInput) ||
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1_024 ||
    maximumBytes > 100_000_000
  ) {
    throw new OperatorInputError("JSON file request is invalid");
  }
  const path = resolve(pathInput);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stats = fstatSync(descriptor);
    if (!stats.isFile() || stats.size > maximumBytes) {
      throw new OperatorInputError("JSON file is not a bounded regular file");
    }
    const bytes = readFileSync(descriptor);
    if (bytes.byteLength > maximumBytes) throw new OperatorInputError("JSON file exceeds its byte limit");
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new OperatorInputError("JSON file is not valid UTF-8");
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new OperatorInputError("JSON file is malformed");
    }
    return boundedJson(parsed, "JSON file", maximumBytes);
  } catch (error) {
    if (error instanceof OperatorInputError) throw error;
    throw new OperatorInputError("JSON file could not be opened safely");
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function fileLimits(input: FileIngestInput): LoadLoanTapeFileOptions {
  return {
    ...(input.format === undefined ? {} : { format: input.format }),
    ...(input.limits?.maximumBytes === undefined ? {} : { maximumBytes: input.limits.maximumBytes }),
    ...(input.limits?.maximumRecords === undefined ? {} : { maximumRecords: input.limits.maximumRecords }),
    ...(input.limits?.maximumColumns === undefined ? {} : { maximumColumns: input.limits.maximumColumns }),
    ...(input.limits?.maximumCellCharacters === undefined
      ? {}
      : { maximumCellCharacters: input.limits.maximumCellCharacters })
  };
}

function validationSummary(validation: MappingValidationResult): OperatorMappingValidationSummary {
  return {
    profile: validation.profile,
    readiness: validation.readiness,
    errorCodes: uniqueSorted(validation.errors.map((issue) => issue.code)),
    warningCodes: uniqueSorted(validation.warnings.map((issue) => issue.code)),
    coverage: validation.coverage
  };
}

function requireReadyMapping(validation: MappingValidationResult): void {
  if (!validation.ready) {
    throw new OperatorControlPlaneError(
      "MAPPING_NOT_READY",
      `Mapping validation failed: ${uniqueSorted(validation.errors.map((issue) => issue.code)).join(",")}`
    );
  }
}

function validateAndBindDefinition(input: DefinitionProposeInput): JsonValue {
  const document = validateDefinitionDocument(input.kind, input.document);
  assertDefinitionIdentity(
    input.kind,
    document,
    input.definitionKey,
    input.version,
    input.effectiveFrom,
    input.effectiveTo
  );
  validateDefinitionSemantics(input.kind, document, input.effectiveFrom);
  return document;
}

function validateStoredDefinition(definition: GovernedDefinition): JsonValue {
  const document = validateDefinitionDocument(definition.kind, definition.document);
  assertDefinitionIdentity(
    definition.kind,
    document,
    definition.definitionKey,
    definition.version,
    definition.effectiveFrom,
    definition.effectiveTo ?? undefined
  );
  validateDefinitionSemantics(definition.kind, document, definition.effectiveFrom);
  return document;
}

function validateDefinitionSemantics(
  kind: DefinitionProposeInput["kind"],
  document: JsonValue,
  effectiveFrom: string
): void {
  try {
    if (kind === "data_quality_profile") {
      const profile = document as unknown as DataQualityProfile;
      runDataQuality([], profile, `${profile.expectedAsOfDate}T00:00:00.000Z`);
    } else if (kind === "borrowing_base_policy") {
      selectEffectiveBorrowingBasePolicy(
        [document as unknown as ArBorrowingBasePolicyVersion],
        effectiveFrom
      );
    } else if (kind === "monitor_definition") {
      evaluateMonitoring({
        asOfDate: effectiveFrom,
        scope: { type: "portfolio", id: "definition-validation" },
        dataQualityGate: {
          status: "certified",
          gateId: "definition-validation",
          snapshotId: "definition-validation",
          certifiedAt: `${effectiveFrom}T00:00:00.000Z`,
          blockingFindingCount: 0,
          evidence: []
        },
        monitorDefinitions: [document as unknown as MonitorDefinition],
        observations: []
      });
    }
  } catch {
    throw new OperatorControlPlaneError(
      "DEFINITION_INVALID",
      "Definition document failed deterministic semantic validation"
    );
  }
}

function assertDefinitionIdentity(
  kind: DefinitionProposeInput["kind"],
  document: JsonValue,
  definitionKey: string,
  version: string,
  effectiveFrom: string,
  effectiveTo: string | undefined
): void {
  const record = document as Readonly<Record<string, JsonValue>>;
  const identity = kind === "data_quality_profile"
    ? { key: record.id, version: record.version }
    : kind === "borrowing_base_policy"
      ? {
          key: record.policyId,
          version: record.version,
          effectiveFrom: record.effectiveFrom,
          effectiveTo: record.effectiveTo
        }
      : kind === "monitor_definition"
        ? {
            key: record.monitorId,
            version: record.version,
            effectiveFrom: record.effectiveFrom,
            effectiveTo: record.effectiveTo
          }
        : undefined;
  if (!identity) return;
  if (
    identity.key !== definitionKey ||
    identity.version !== version ||
    (identity.effectiveFrom !== undefined && identity.effectiveFrom !== effectiveFrom) ||
    (identity.effectiveTo !== undefined && identity.effectiveTo !== effectiveTo) ||
    (identity.effectiveTo === undefined && effectiveTo !== undefined && kind !== "data_quality_profile")
  ) {
    throw new OperatorControlPlaneError(
      "DEFINITION_INVALID",
      "Definition envelope identity does not match its document"
    );
  }
}

function requiredStringProperty(value: JsonValue, key: string): string {
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new OperatorControlPlaneError("INVALID_INPUT", "Input artifact must be an object");
  }
  const nested = (value as Readonly<Record<string, JsonValue>>)[key];
  if (typeof nested !== "string") {
    throw new OperatorControlPlaneError("INVALID_INPUT", `Input artifact ${key} is required`);
  }
  return nested;
}

function snapshotSummary(
  registered: ReturnType<IngestionPort["registerDeliveredSnapshot"]>
): OperatorSnapshotSummary {
  return {
    snapshotId: registered.snapshot.snapshotId,
    sourceId: registered.snapshot.sourceId,
    asOfDate: registered.snapshot.asOfDate,
    rowCount: registered.snapshot.rowCount,
    contentHash: registered.snapshot.contentHash,
    artifactId: registered.sourceArtifact.artifactId
  };
}

function mappingSummary(
  mapping: NonNullable<ReturnType<ControlPort["getMappingVersion"]>>,
  validation?: OperatorMappingValidationSummary
): OperatorMappingSummary {
  return {
    mappingVersionId: mapping.mappingVersionId,
    mappingKey: mapping.mappingKey,
    version: mapping.version,
    status: mapping.status,
    mappingHash: mapping.mappingHash,
    dictionaryVersion: mapping.dictionaryVersion,
    ...(validation === undefined ? {} : { validation })
  };
}

function definitionSummary(definition: GovernedDefinition): OperatorDefinitionSummary {
  return {
    definitionId: definition.definitionId,
    definitionKey: definition.definitionKey,
    kind: definition.kind,
    version: definition.version,
    status: definition.status,
    effectiveFrom: definition.effectiveFrom,
    effectiveTo: definition.effectiveTo,
    documentHash: definition.documentHash
  };
}

function governedDefinitionV2Summary(
  definition: GovernedDefinitionViewV2
): OperatorGovernedDefinitionV2Summary {
  const { version } = definition;
  return {
    definitionVersionId: version.definitionVersionId,
    definitionKey: version.definitionKey,
    kind: version.kind,
    semanticVersion: version.semanticVersion,
    status: definition.status,
    lifecycleRevision: definition.lifecycleRevision,
    effectiveFrom: version.effectiveFrom,
    effectiveTo: version.effectiveTo,
    predecessorDefinitionVersionId: version.predecessorDefinitionVersionId,
    rollbackTargetDefinitionVersionId: version.rollbackTargetDefinitionVersionId,
    proposedBy: version.proposedBy,
    proposedAt: version.proposedAt,
    lastTransitionBy: definition.lastTransitionBy,
    lastTransitionAt: definition.lastTransitionAt,
    documentHash: version.documentHash,
    semanticDiffHash: version.semanticDiffHash,
    semanticDiff: {
      beforeHash: version.semanticDiff.beforeHash,
      afterHash: version.semanticDiff.afterHash,
      changeCount: version.semanticDiff.changeCount,
      changedPaths: [...version.semanticDiff.changedPaths],
      truncated: version.semanticDiff.truncated
    },
    impactPreviewHash: version.impactPreviewHash,
    impactPreview: {
      impactLevel: version.impactPreview.impactLevel,
      affectedCapabilities: [...version.impactPreview.affectedCapabilities],
      changedPathCount: version.impactPreview.changedPathCount,
      rollbackTargetRequired: version.impactPreview.rollbackTargetRequired
    },
    versionHash: version.versionHash,
    approval: definition.approvalEvidence === null
      ? null
      : {
          approvedBy: definition.approvalEvidence.approvedBy,
          approvedAt: definition.approvalEvidence.approvedAt,
          approvalEventHash: definition.approvalEvidence.approvalEventHash
        }
  };
}

function governedDefinitionV2AuditSummary(
  event: GovernedDefinitionAuditEventV2
): OperatorGovernedDefinitionV2AuditSummary {
  return {
    sequence: event.sequence,
    eventId: event.eventId,
    definitionVersionId: event.definitionVersionId,
    lifecycleRevision: event.lifecycleRevision,
    fromStatus: event.fromStatus,
    toStatus: event.toStatus,
    actor: event.actor,
    occurredAt: event.occurredAt,
    previousEventHash: event.previousEventHash,
    eventHash: event.eventHash
  };
}

function inputCertificationSummary(
  record: InputCertificationViewV1
): OperatorInputCertificationSummary {
  return {
    inputId: record.inputId,
    inputKind: record.inputKind,
    status: record.status,
    proposalHash: record.proposalHash,
    ...(record.status === "certified"
      ? {
          certifiedArtifactId: record.certifiedArtifactId,
          envelopeHash: record.envelopeHash,
          lineageHash: record.lineageHash
        }
      : {})
  };
}

function membershipSummary(
  membership: ReturnType<MembershipPort["propose"]>
): OperatorMembershipSummary {
  return {
    membershipId: membership.membershipId,
    tenantId: membership.tenantId,
    principalId: membership.principalId,
    status: membership.status
  };
}

function alertSummary(
  alert: ReturnType<AlertPort["transitionAlert"]>
): OperatorAlertSummary {
  return {
    alertId: alert.alertId,
    monitorId: alert.monitorId,
    status: alert.status,
    severity: alert.severity,
    scope: alert.scope,
    recurrenceCount: alert.recurrenceCount,
    firstSeenOn: alert.firstSeenOn,
    lastSeenOn: alert.lastSeenOn
  };
}

function auditSummary(event: {
  readonly sequence: number;
  readonly eventId: string;
  readonly eventType: string;
  readonly entityType: string;
  readonly entityId: string;
  readonly actor: string;
  readonly occurredAt: string;
}): OperatorAuditEventSummary {
  return {
    sequence: event.sequence,
    eventId: event.eventId,
    eventType: event.eventType,
    entityType: event.entityType,
    entityId: event.entityId,
    actor: event.actor,
    occurredAt: event.occurredAt
  };
}

function uniqueSorted(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function isDeclaredHashMismatch(error: unknown): boolean {
  return error instanceof Error &&
    error.message === "Delivered snapshot content hash did not match the operator-declared hash";
}

function normalizeSourceColumns(
  columns: readonly {
    readonly name: string;
    readonly type?: string | undefined;
    readonly description?: string | undefined;
    readonly nullable?: boolean | undefined;
  }[]
): readonly SourceColumn[] {
  return columns.map((column) => ({
    name: column.name,
    ...(column.type === undefined ? {} : { type: column.type }),
    ...(column.description === undefined ? {} : { description: column.description }),
    ...(column.nullable === undefined ? {} : { nullable: column.nullable })
  }));
}

export type {
  AlertListInput,
  AlertTransitionInput,
  AuditListInput,
  CertifySnapshotInput,
  DefinitionProposeInput,
  DefinitionTransitionInput,
  FileIngestInput,
  GovernedDefinitionV2AuditListInput,
  GovernedDefinitionV2GetInput,
  GovernedDefinitionV2ListInput,
  GovernedDefinitionV2ProposeInput,
  GovernedDefinitionV2SelectEffectiveInput,
  GovernedDefinitionV2TransitionInput,
  MappingProposeInput,
  MappingTransitionInput,
  MembershipChangeInput,
  MembershipProposeInput,
  PutInputArtifactInput,
  SqlExtractInput
};
