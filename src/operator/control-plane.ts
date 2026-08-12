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
import {
  alertListInputSchema,
  alertTransitionInputSchema,
  auditListInputSchema,
  boundedJson,
  certifySnapshotInputSchema,
  definitionProposeInputSchema,
  definitionTransitionInputSchema,
  fileIngestInputSchema,
  mappingProposeInputSchema,
  mappingTransitionInputSchema,
  membershipChangeInputSchema,
  membershipProposeInputSchema,
  operatorIdentifierSchema,
  OperatorInputError,
  parseStrict,
  putInputArtifactInputSchema,
  inputCertificationCertifySchema,
  inputCertificationProposeSchema,
  sqlExtractInputSchema,
  validateDefinitionDocument,
  validateInputArtifact,
  type AlertListInput,
  type AlertTransitionInput,
  type AuditListInput,
  type CertifySnapshotInput,
  type DefinitionProposeInput,
  type DefinitionTransitionInput,
  type FileIngestInput,
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
type ArtifactPort = Pick<ArtifactStore, "putJson">;
type MembershipPort = Pick<TenantMembershipStore, "approve" | "propose" | "revoke">;
type AlertPort = Pick<MonitoringAlertStore, "listAlerts" | "listAuditEvents" | "transitionAlert">;
type IngestionPort = Pick<SnapshotIngestionService, "certifyMappedSnapshot" | "registerDeliveredSnapshot">;
type SqlExtractorPort = Pick<SqlSnapshotExtractionService, "extractAndRegister">;
type InputCertificationPort = Pick<InputCertificationService, "propose" | "certify">;

export interface OperatorControlPlaneDependencies {
  /**
   * Trusted identity established by the process boundary. Request documents
   * never supply or override this value.
   */
  readonly principal: OperatorPrincipal;
  readonly control: ControlPort;
  readonly definitions: DefinitionPort;
  readonly artifacts: ArtifactPort;
  readonly memberships: MembershipPort;
  readonly alerts: AlertPort;
  readonly ingestion: IngestionPort;
  readonly inputCertification?: InputCertificationPort;
  readonly sqlExtractors?: ReadonlyMap<string, SqlExtractorPort>;
  readonly loadLoanTape?: typeof loadLoanTapeFile;
  readonly readJsonFile?: typeof readBoundedJsonFile;
}

/**
 * Authenticated identity for an operator process or service. The current local
 * CLI is intentionally a privileged global administrator: tenantId values in
 * request documents select resources and are not authentication assertions.
 * A networked administration service must enforce its tenant grants before it
 * constructs or invokes this control plane.
 */
export interface OperatorPrincipal {
  readonly principalId: string;
  readonly authenticationMethod: "local_os_account" | "trusted_service_identity";
  readonly authorizationScope: "global_admin";
}

export type OperatorControlPlaneErrorCode =
  | "INVALID_INPUT"
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
}

function validateOperatorPrincipal(principal: OperatorPrincipal): OperatorPrincipal {
  const principalId = parseStrict(
    operatorIdentifierSchema,
    principal?.principalId,
    "operator principal"
  );
  if (
    (principal.authenticationMethod !== "local_os_account" &&
      principal.authenticationMethod !== "trusted_service_identity") ||
    principal.authorizationScope !== "global_admin"
  ) {
    throw new OperatorInputError("operator principal is invalid");
  }
  return Object.freeze({
    principalId,
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
  MappingProposeInput,
  MappingTransitionInput,
  MembershipChangeInput,
  MembershipProposeInput,
  PutInputArtifactInput,
  SqlExtractInput
};
