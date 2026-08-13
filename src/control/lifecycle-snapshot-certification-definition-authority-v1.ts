import {
  canonicalJson,
  deepFreeze,
  parseGovernedDatasetScopeBindingV1,
  parseSnapshotCertificationAttemptV1,
  parseSnapshotCertificationDefinitionV1,
  parseSourceContractV1,
  type GovernedDatasetScopeBindingV1,
  type SnapshotCertificationAttemptV1
} from "../contracts/index.js";
import {
  parseGovernedSourceDeliveryRecordV1,
  type GovernedSourceDeliveryRecordV1
} from "../contracts/source-delivery-authority-v1.js";
import {
  CertificationRuntimeAuthorityFactoryV1
} from "./certification-runtime-authority-v1.js";
import {
  HistoricalMappingExecutionAuthorityV1,
  HistoricalMappingExecutionAuthorityV1Error
} from "../services/historical-mapping-execution-authority-v1.js";
import {
  GovernedDefinitionV2Resolver,
  GovernedDefinitionV2ResolverError,
  type GovernedDefinitionExecutionReferenceV2
} from "../services/governed-definition-v2-resolver.js";
import {
  parseModernSnapshotExtractionReceiptV1,
  type ModernSnapshotExtractionReceiptV1
} from "../services/modern-snapshot-capture.js";
import type {
  ModernCertificationDefinitionResolutionV1
} from "../services/modern-snapshot-certification.js";

/**
 * Decision-time-only extension.  The original certification-definition port
 * intentionally has no attempt timestamp/hash, so this authority cannot be
 * wired into it without an explicit service seam.  That prevents a mutable
 * ``now`` selection from silently becoming production authority.
 */
export interface LifecycleSnapshotCertificationDefinitionAuthorityV1 {
  resolveForCertificationAttempt(input: {
    readonly evidence: LifecycleBoundSnapshotCertificationEvidenceV1;
    readonly attempt: SnapshotCertificationAttemptV1;
  }): Promise<ModernCertificationDefinitionResolutionV1 | undefined>;
}

export interface LifecycleBoundSnapshotCertificationEvidenceV1 {
  readonly tenantId: string;
  readonly sourceContract: {
    readonly sourceContractId: string;
    readonly revision: number;
    readonly sourceContractHash: `sha256:${string}`;
  };
  readonly deliveryHash: `sha256:${string}`;
  readonly extractionReceipt: ModernSnapshotExtractionReceiptV1;
  readonly delivery: GovernedSourceDeliveryRecordV1;
  readonly scopeBinding: GovernedDatasetScopeBindingV1;
  readonly asOfDate: string;
}

export type LifecycleSnapshotCertificationDefinitionAuthorityErrorCode =
  | "INVALID_INPUT"
  | "NOT_FOUND"
  | "NOT_ACTIVE_AT_TIME"
  | "INTEGRITY_FAILURE";

export class LifecycleSnapshotCertificationDefinitionAuthorityError extends Error {
  constructor(
    readonly code: LifecycleSnapshotCertificationDefinitionAuthorityErrorCode,
    message: string
  ) {
    super(message);
    this.name = "LifecycleSnapshotCertificationDefinitionAuthorityError";
  }
}

/**
 * Resolves one outer snapshot-certification control from its exact immutable
 * facility binding.  It has no candidate-list API and consumes only governed
 * lifecycle, historical-mapping, and certification-runtime read authorities.
 */
export class LifecycleSnapshotCertificationDefinitionAuthorityV1
  implements LifecycleSnapshotCertificationDefinitionAuthorityV1
{
  constructor(
    readonly dependencies: {
      readonly governed: GovernedDefinitionV2Resolver;
      readonly mappings: HistoricalMappingExecutionAuthorityV1;
      readonly runtime: CertificationRuntimeAuthorityFactoryV1;
    }
  ) {}

  async resolveForCertificationAttempt(inputValue: {
    readonly evidence: LifecycleBoundSnapshotCertificationEvidenceV1;
    readonly attempt: SnapshotCertificationAttemptV1;
  }): Promise<ModernCertificationDefinitionResolutionV1 | undefined> {
    const evidence = boundEvidence(inputValue?.evidence);
    const attempt = attemptEvidence(inputValue?.attempt);
    this.#verifyAttempt(evidence, attempt);

    let control;
    try {
      control = this.dependencies.governed.resolveEffective({
        tenantId: evidence.tenantId,
        kind: "snapshot_certification_control",
        definitionKey: evidence.scopeBinding.bindingId,
        asOfDate: evidence.asOfDate
      });
    } catch (error) {
      return rethrowGoverned(error);
    }
    const definition = parseControl(control.executionDocument);
    if (
      control.reference.kind !== "snapshot_certification_control" ||
      control.reference.definitionKey !== evidence.scopeBinding.bindingId ||
      control.approvalEvidence.approvedAt > attempt.certifiedAt ||
      definition.tenantId !== evidence.tenantId ||
      definition.certificationDefinitionId !== evidence.scopeBinding.bindingId ||
      !effectiveOn(definition.window, evidence.asOfDate)
    ) {
      integrity("Snapshot certification control did not bind the approved facility decision");
    }

    const source = this.#resolveFrozen(
      evidence.tenantId,
      definition.sourceContractExecution.definitionVersionId
    );
    if (!source) return undefined;
    this.#verifyReference(source.reference, definition.sourceContractExecution, "source contract");
    const sourceDocument = parseSourceContractV1(source.executionDocument);
    if (
      sourceDocument.tenantId !== evidence.tenantId ||
      sourceDocument.sourceContractId !== definition.sourceContract.sourceContractId ||
      sourceDocument.revision !== definition.sourceContract.revision ||
      sourceDocument.sourceKey !== definition.sourceContractExecution.definitionKey
    ) {
      integrity("Frozen source-contract lifecycle document did not match the certification control");
    }

    const scope = this.#resolveFrozen(
      evidence.tenantId,
      definition.scopeBindingExecution.definitionVersionId
    );
    if (!scope) return undefined;
    this.#verifyReference(scope.reference, definition.scopeBindingExecution, "scope binding");
    const scopeDocument = parseGovernedDatasetScopeBindingV1(scope.executionDocument);
    if (
      canonicalJson(scopeDocument) !== canonicalJson(definition.scopeBinding) ||
      canonicalJson(scopeDocument) !== canonicalJson(evidence.scopeBinding) ||
      scopeDocument.scope.scopeType !== "facility" ||
      !effectiveOn(scopeDocument, evidence.asOfDate)
    ) {
      integrity("Frozen facility-scope lifecycle document did not match captured delivery evidence");
    }

    let mapping;
    try {
      mapping = this.dependencies.mappings.resolveFrozenAt({
        tenantId: evidence.tenantId,
        definitionVersionId: definition.mappingExecution.definitionVersionId,
        certificationAt: attempt.certifiedAt
      });
    } catch (error) {
      return rethrowMapping(error);
    }
    this.#verifyReference(mapping.reference, definition.mappingExecution, "mapping");
    if (
      mapping.mappingSpec.mappingSpecId !== definition.mappingExecution.mappingSpecId ||
      mapping.mappingSpec.revision !== definition.mappingExecution.mappingSpecRevision ||
      mapping.mappingSpec.mappingSpecHash !== definition.mappingExecution.mappingSpecHash ||
      canonicalJson(mapping.mappingSpec.sourceContract) !== canonicalJson(definition.sourceContract) ||
      canonicalJson(mapping.window) !== canonicalJson(definition.mappingExecution.window) ||
      canonicalJson(mapping.activationEvidence) !== canonicalJson(definition.mappingExecution.activation) ||
      !effectiveOn(mapping.window, evidence.asOfDate)
    ) {
      integrity("Historical mapping authority did not reproduce the certification control lineage");
    }

    let runtime;
    try {
      runtime = this.dependencies.runtime.forCertification({
        tenantId: evidence.tenantId,
        certifiedAt: attempt.certifiedAt
      }).resolveActivatedRuntime({
        runtimeBundleId: definition.runtime.runtimeBundleId,
        runtimeBundleHash: definition.runtime.runtimeBundleHash
      });
    } catch (error) {
      return rethrowRuntime(error);
    }
    if (
      runtime.runtime.runtimeVersion !== definition.runtime.runtimeVersion ||
      canonicalJson(runtime.runtime.dictionary) !== canonicalJson(definition.runtime.dictionary) ||
      canonicalJson(runtime.runtime.mappingCompiler) !== canonicalJson(definition.runtime.mappingCompiler) ||
      canonicalJson(runtime.dictionary.reference) !== canonicalJson(definition.runtime.dictionary) ||
      canonicalJson(runtime.mappingCompiler.reference) !== canonicalJson(definition.runtime.mappingCompiler) ||
      canonicalJson(mapping.mappingSpec.dictionaryBundle) !== canonicalJson(runtime.runtime.dictionary) ||
      runtime.activation.activatedAt > attempt.certifiedAt
    ) {
      integrity("Activated runtime did not exactly match the certification control and mapping lineage");
    }

    return deepFreeze({
      mappingSpec: mapping.mappingSpec,
      mappingWindow: mapping.window,
      runtime: {
        runtimeBundleId: runtime.runtime.runtimeBundleId,
        runtimeBundleHash: runtime.runtime.runtimeBundleHash,
        window: definition.window
      },
      dataQuality: definition.dataQuality,
      reconciliation: definition.certificationReconciliation
    }) as ModernCertificationDefinitionResolutionV1;
  }

  #resolveFrozen(tenantId: string, definitionVersionId: string) {
    try {
      return this.dependencies.governed.resolveFrozen({ tenantId, definitionVersionId });
    } catch (error) {
      rethrowGoverned(error);
    }
  }

  #verifyAttempt(
    evidence: LifecycleBoundSnapshotCertificationEvidenceV1,
    attempt: SnapshotCertificationAttemptV1
  ): void {
    if (
      attempt.tenantId !== evidence.tenantId ||
      attempt.snapshotId !== evidence.extractionReceipt.snapshotId ||
      attempt.certificationManifestId.length === 0 ||
      attempt.certifiedAt < evidence.extractionReceipt.knowledge.persistedAt ||
      evidence.asOfDate > attempt.certifiedAt.slice(0, 10)
    ) {
      invalid("Certification attempt does not bind the captured snapshot decision time");
    }
  }

  #verifyReference(
    actual: GovernedDefinitionExecutionReferenceV2,
    expected: Record<string, unknown>,
    label: string
  ): void {
    for (const key of [
      "definitionVersionId", "definitionKey", "kind", "semanticVersion",
      "versionHash", "documentHash", "approvalEventHash"
    ] as const) {
      if (actual[key] !== expected[key]) integrity(`Frozen ${label} reference was substituted`);
    }
  }
}

function boundEvidence(value: unknown): LifecycleBoundSnapshotCertificationEvidenceV1 {
  if (!value || typeof value !== "object") invalid("Bound snapshot evidence is required");
  const input = value as LifecycleBoundSnapshotCertificationEvidenceV1;
  const receipt = parseReceipt(input.extractionReceipt);
  const delivery = parseDelivery(input.delivery);
  const binding = parseBinding(input.scopeBinding);
  const source = input.sourceContract;
  if (
    typeof input.tenantId !== "string" || typeof input.asOfDate !== "string" ||
    canonicalJson(source) !== canonicalJson(receipt.sourceContract) ||
    input.tenantId !== receipt.tenantId ||
    input.tenantId !== delivery.tenantId ||
    input.tenantId !== binding.tenantId ||
    input.deliveryHash !== delivery.deliveryHash ||
    receipt.deliveryId !== delivery.deliveryId ||
    receipt.sourceDelivery.deliveryHash !== delivery.deliveryHash ||
    receipt.sourceDelivery.deliveryRevision !== delivery.deliveryRevision ||
    receipt.datasetId !== binding.datasetId ||
    receipt.facilityId !== binding.scope.scopeId ||
    receipt.asOfDate !== input.asOfDate ||
    canonicalJson(receipt.scopeBinding) !== canonicalJson({
      bindingId: binding.bindingId,
      revision: binding.revision,
      bindingHash: binding.bindingHash
    }) ||
    canonicalJson(delivery.sourceContract) !== canonicalJson(source) ||
    canonicalJson(binding.sourceContract) !== canonicalJson(source) ||
    canonicalJson(delivery.scopeBinding) !== canonicalJson(receipt.scopeBinding) ||
    delivery.datasetId !== binding.datasetId ||
    delivery.facilityId !== binding.scope.scopeId ||
    delivery.status !== "usable"
  ) {
    invalid("Bound receipt, delivery, source, and facility scope evidence do not match exactly");
  }
  return deepFreeze({ ...input, extractionReceipt: receipt, delivery, scopeBinding: binding });
}

function attemptEvidence(value: unknown): SnapshotCertificationAttemptV1 {
  try {
    return parseSnapshotCertificationAttemptV1(value);
  } catch {
    invalid("Certification attempt hash or decision timestamp is invalid");
  }
}

function parseReceipt(value: unknown): ModernSnapshotExtractionReceiptV1 {
  try { return parseModernSnapshotExtractionReceiptV1(value); } catch { invalid("Extraction receipt is invalid"); }
}

function parseDelivery(value: unknown): GovernedSourceDeliveryRecordV1 {
  try { return parseGovernedSourceDeliveryRecordV1(value); } catch { invalid("Source delivery is invalid"); }
}

function parseBinding(value: unknown): GovernedDatasetScopeBindingV1 {
  try { return parseGovernedDatasetScopeBindingV1(value); } catch { invalid("Scope binding is invalid"); }
}

function parseControl(value: unknown) {
  try { return parseSnapshotCertificationDefinitionV1(value); } catch { integrity("Approved snapshot certification control is invalid"); }
}

function effectiveOn(
  window: { readonly effectiveFrom: string; readonly effectiveTo?: string | undefined },
  date: string
): boolean {
  return window.effectiveFrom <= date && (window.effectiveTo === undefined || date < window.effectiveTo);
}

function rethrowGoverned(error: unknown): undefined {
  if (error instanceof GovernedDefinitionV2ResolverError) {
    if (error.code === "NOT_FOUND" || error.code === "UNAPPROVED") return undefined;
    if (error.code === "INTEGRITY_FAILURE") integrity(error.message);
    invalid(error.message);
  }
  throw error;
}

function rethrowMapping(error: unknown): undefined {
  if (error instanceof HistoricalMappingExecutionAuthorityV1Error) {
    if (error.code === "NOT_FOUND" || error.code === "NOT_ACTIVE_AT_TIME") return undefined;
    if (error.code === "INTEGRITY_FAILURE") integrity(error.message);
    invalid(error.message);
  }
  throw error;
}

function rethrowRuntime(error: unknown): undefined {
  if (error instanceof Error) integrity(`Certification runtime could not be resolved: ${error.message}`);
  integrity("Certification runtime could not be resolved");
}

function invalid(message: string): never {
  throw new LifecycleSnapshotCertificationDefinitionAuthorityError("INVALID_INPUT", message);
}

function integrity(message: string): never {
  throw new LifecycleSnapshotCertificationDefinitionAuthorityError("INTEGRITY_FAILURE", message);
}
