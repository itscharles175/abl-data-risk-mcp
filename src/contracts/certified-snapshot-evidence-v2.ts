import { z } from "zod";

import {
  DictionaryBundleReferenceV1Schema,
  ImmutableBundleReferenceV1Schema
} from "./bundles.js";
import {
  CertifiedSnapshotEvidenceRecordV1Schema,
  parseCertifiedSnapshotEvidenceRecordV1
} from "./certified-snapshot-evidence-v1.js";
import {
  IdentifierSchema,
  IsoDateSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  canonicalJson,
  parseWithSchema
} from "./canonical.js";
import {
  GovernedDatasetScopeBindingV1Schema,
  parseGovernedDatasetScopeBindingV1
} from "./dataset-scope-binding-v1.js";
import {
  parseSnapshotCertificationAttemptV1,
  SnapshotCertificationAttemptV1Schema
} from "./snapshot-certification-attempt-v1.js";
import {
  parseSnapshotCertificationDefinitionV1,
  SnapshotCertificationDefinitionV1Schema
} from "./snapshot-certification-definition-v1.js";

const SourceContractReferenceV1Schema = z
  .object({
    sourceContractId: IdentifierSchema,
    revision: z.number().int().min(1).max(1_000_000),
    sourceContractHash: Sha256HashSchema
  })
  .strict();

const GovernedExecutionReferenceV2Schema = z
  .object({
    definitionVersionId: IdentifierSchema,
    definitionKey: IdentifierSchema,
    kind: z.enum([
      "source_contract",
      "dataset_scope_binding",
      "mapping_spec",
      "snapshot_certification_control"
    ]),
    semanticVersion: z.string().min(1).max(64),
    versionHash: Sha256HashSchema,
    documentHash: Sha256HashSchema,
    approvalEventHash: Sha256HashSchema
  })
  .strict();

const GovernedApprovalEvidenceV2Schema = z
  .object({
    status: z.literal("approved"),
    proposedBy: IdentifierSchema,
    approvedBy: IdentifierSchema,
    approvedAt: IsoTimestampSchema,
    approvalEventHash: Sha256HashSchema
  })
  .strict()
  .superRefine((value, context) => {
    if (value.proposedBy === value.approvedBy) {
      context.addIssue({ code: "custom", path: ["approvedBy"], message: "must differ from proposedBy" });
    }
  });

const LifecycleActivationEvidenceV1Schema = z
  .object({
    status: z.literal("active"),
    lifecycleRevision: z.number().int().min(1).max(1_000_000),
    activatedBy: IdentifierSchema,
    activatedAt: IsoTimestampSchema,
    activationEventHash: Sha256HashSchema
  })
  .strict();

const GovernedSourceContractExecutionReferenceV1Schema = GovernedExecutionReferenceV2Schema.extend({
  kind: z.literal("source_contract"),
  sourceContract: SourceContractReferenceV1Schema
}).strict();

const GovernedScopeBindingExecutionReferenceV1Schema = GovernedExecutionReferenceV2Schema.extend({
  kind: z.literal("dataset_scope_binding"),
  bindingId: IdentifierSchema,
  revision: z.number().int().min(1).max(1_000_000),
  bindingHash: Sha256HashSchema,
  sourceContract: SourceContractReferenceV1Schema
}).strict();

const GovernedMappingExecutionReferenceV1Schema = GovernedExecutionReferenceV2Schema.extend({
  kind: z.literal("mapping_spec"),
  mappingSpecId: IdentifierSchema,
  mappingSpecRevision: z.number().int().min(1).max(1_000_000),
  mappingSpecHash: Sha256HashSchema,
  sourceContract: SourceContractReferenceV1Schema,
  activation: LifecycleActivationEvidenceV1Schema,
  window: z.object({ effectiveFrom: IsoDateSchema, effectiveTo: IsoDateSchema.optional() }).strict()
}).strict();

const RuntimeActivationEvidenceV1Schema = z
  .object({
    tenantId: IdentifierSchema,
    runtimeBundleId: IdentifierSchema,
    runtimeBundleHash: Sha256HashSchema,
    registeredBy: IdentifierSchema,
    registeredAt: IsoTimestampSchema,
    activatedBy: IdentifierSchema,
    activatedAt: IsoTimestampSchema,
    activationHash: Sha256HashSchema
  })
  .strict()
  .superRefine((value, context) => {
    if (value.registeredAt > value.activatedAt) {
      context.addIssue({ code: "custom", path: ["activatedAt"], message: "cannot precede runtime registration" });
    }
  });

const CertificationGovernanceLineageV2Schema = z
  .object({
    control: z
      .object({
        definition: SnapshotCertificationDefinitionV1Schema,
        reference: GovernedExecutionReferenceV2Schema.extend({
          kind: z.literal("snapshot_certification_control")
        }).strict(),
        approval: GovernedApprovalEvidenceV2Schema,
        activation: LifecycleActivationEvidenceV1Schema
      })
      .strict(),
    sourceContract: z
      .object({
        raw: SourceContractReferenceV1Schema,
        execution: GovernedSourceContractExecutionReferenceV1Schema
      })
      .strict(),
    scopeBinding: z
      .object({
        raw: GovernedDatasetScopeBindingV1Schema,
        execution: GovernedScopeBindingExecutionReferenceV1Schema
      })
      .strict(),
    mapping: z
      .object({
        execution: GovernedMappingExecutionReferenceV1Schema,
        activation: LifecycleActivationEvidenceV1Schema
      })
      .strict(),
    runtime: z
      .object({
        runtimeBundleId: IdentifierSchema,
        runtimeVersion: z.string().min(1).max(64),
        runtimeBundleHash: Sha256HashSchema,
        activation: RuntimeActivationEvidenceV1Schema,
        dictionary: DictionaryBundleReferenceV1Schema,
        mappingCompiler: ImmutableBundleReferenceV1Schema.extend({ bundleKind: z.literal("mapping_compiler") }).strict()
      })
      .strict()
  })
  .strict();

const CertifiedSnapshotEvidenceBodyV2Schema = z
  .object({
    contractVersion: z.literal(2),
    tenantId: IdentifierSchema,
    v1Evidence: CertifiedSnapshotEvidenceRecordV1Schema,
    certificationAttempt: SnapshotCertificationAttemptV1Schema,
    governance: CertificationGovernanceLineageV2Schema,
    recordedAt: IsoTimestampSchema
  })
  .strict()
  .superRefine((value, context) => validateBindings(value, context));

export const CertifiedSnapshotEvidenceRecordV2Schema = CertifiedSnapshotEvidenceBodyV2Schema.extend({
  evidenceHash: Sha256HashSchema
}).strict();

export type CertifiedSnapshotEvidenceRecordV2 = Readonly<z.infer<typeof CertifiedSnapshotEvidenceRecordV2Schema>>;
export type CertifiedSnapshotEvidenceRecordV2Input = Readonly<z.input<typeof CertifiedSnapshotEvidenceBodyV2Schema>>;

/**
 * Forward-only evidence envelope for governed certification. It retains an exact,
 * validated V1 record so V1 repositories and readers remain compatible until an
 * explicit V2 repository migration is deployed.
 */
export function createCertifiedSnapshotEvidenceRecordV2(
  input: CertifiedSnapshotEvidenceRecordV2Input
): CertifiedSnapshotEvidenceRecordV2 {
  canonicalJson(input);
  const body = parseWithSchema(CertifiedSnapshotEvidenceBodyV2Schema, input, "CertifiedSnapshotEvidenceRecordV2");
  validateNestedEvidence(body);
  return parseCertifiedSnapshotEvidenceRecordV2({ ...body, evidenceHash: canonicalHash(body) });
}

export function parseCertifiedSnapshotEvidenceRecordV2(value: unknown): CertifiedSnapshotEvidenceRecordV2 {
  canonicalJson(value);
  const parsed = parseWithSchema(CertifiedSnapshotEvidenceRecordV2Schema, value, "CertifiedSnapshotEvidenceRecordV2");
  validateNestedEvidence(parsed);
  const { evidenceHash, ...body } = parsed;
  assertCanonicalHash(body, evidenceHash, "CertifiedSnapshotEvidenceRecordV2");
  return parsed;
}

function validateNestedEvidence(value: z.infer<typeof CertifiedSnapshotEvidenceBodyV2Schema>): void {
  parseCertifiedSnapshotEvidenceRecordV1(value.v1Evidence);
  parseSnapshotCertificationAttemptV1(value.certificationAttempt);
  parseSnapshotCertificationDefinitionV1(value.governance.control.definition);
  parseGovernedDatasetScopeBindingV1(value.governance.scopeBinding.raw);
}

function validateBindings(value: z.infer<typeof CertifiedSnapshotEvidenceBodyV2Schema>, context: z.RefinementCtx): void {
  const evidence = value.v1Evidence;
  const attempt = value.certificationAttempt;
  const governance = value.governance;
  const definition = governance.control.definition;
  const control = governance.control;

  same(value.tenantId, evidence.tenantId, context, ["v1Evidence", "tenantId"]);
  same(value.tenantId, attempt.tenantId, context, ["certificationAttempt", "tenantId"]);
  same(value.tenantId, definition.tenantId, context, ["governance", "control", "definition", "tenantId"]);
  same(value.tenantId, governance.scopeBinding.raw.tenantId, context, ["governance", "scopeBinding", "raw", "tenantId"]);
  same(value.tenantId, governance.runtime.activation.tenantId, context, ["governance", "runtime", "activation", "tenantId"]);
  same(attempt.certificationManifestId, evidence.certification.certificationManifestId, context, ["certificationAttempt", "certificationManifestId"]);
  same(attempt.snapshotId, evidence.certification.snapshotId, context, ["certificationAttempt", "snapshotId"]);
  same(attempt.snapshotHash, evidence.certification.snapshotHash, context, ["certificationAttempt", "snapshotHash"]);
  same(attempt.certifiedAt, evidence.certification.certifiedAt, context, ["certificationAttempt", "certifiedAt"]);
  if (evidence.recordedAt > value.recordedAt) issue(context, ["recordedAt"], "cannot precede retained V1 evidence");

  same(control.reference.definitionKey, definition.certificationDefinitionId, context, ["governance", "control", "reference", "definitionKey"]);
  same(control.reference.semanticVersion, `${definition.revision}.0.0`, context, ["governance", "control", "reference", "semanticVersion"]);
  same(control.reference.documentHash, canonicalHash(definition), context, ["governance", "control", "reference", "documentHash"]);
  same(control.reference.approvalEventHash, control.approval.approvalEventHash, context, ["governance", "control", "approval", "approvalEventHash"]);
  before(control.approval.approvedAt, control.activation.activatedAt, context, ["governance", "control", "activation", "activatedAt"], "cannot precede approval");
  before(control.activation.activatedAt, attempt.certifiedAt, context, ["governance", "control", "activation", "activatedAt"], "cannot follow certification");
  withinWindow(attempt.certifiedAt.slice(0, 10), definition.window, context, ["certificationAttempt", "certifiedAt"], "is outside the control window");

  const source = governance.sourceContract;
  exact(source.raw, definition.sourceContract, context, ["governance", "sourceContract", "raw"], "must match the control raw source identity");
  exact(source.execution, definition.sourceContractExecution, context, ["governance", "sourceContract", "execution"], "must match the control source execution reference");
  same(source.execution.approvalEventHash, definition.sourceContractExecution.approvalEventHash, context, ["governance", "sourceContract", "execution", "approvalEventHash"]);

  const scope = governance.scopeBinding;
  exact(scope.raw, definition.scopeBinding, context, ["governance", "scopeBinding", "raw"], "must match the control raw scope binding");
  exact(scope.execution, definition.scopeBindingExecution, context, ["governance", "scopeBinding", "execution"], "must match the control scope execution reference");

  const mapping = governance.mapping;
  exact(mapping.execution, definition.mappingExecution, context, ["governance", "mapping", "execution"], "must match the control mapping execution reference");
  exact(mapping.activation, definition.mappingExecution.activation, context, ["governance", "mapping", "activation"], "must match the control mapping activation evidence");
  before(mapping.activation.activatedAt, attempt.certifiedAt, context, ["governance", "mapping", "activation", "activatedAt"], "cannot follow certification");
  withinWindow(attempt.certifiedAt.slice(0, 10), definition.mappingExecution.window, context, ["certificationAttempt", "certifiedAt"], "is outside the mapping window");
  same(evidence.mappingSpec.mappingSpecId, definition.mappingExecution.mappingSpecId, context, ["v1Evidence", "mappingSpec", "mappingSpecId"]);
  same(evidence.mappingSpec.revision, definition.mappingExecution.mappingSpecRevision, context, ["v1Evidence", "mappingSpec", "revision"]);
  same(evidence.mappingSpec.mappingSpecHash, definition.mappingExecution.mappingSpecHash, context, ["v1Evidence", "mappingSpec", "mappingSpecHash"]);
  same(evidence.mappingSpec.mappingKey, mapping.execution.definitionKey, context, ["v1Evidence", "mappingSpec", "mappingKey"]);
  exact(evidence.mappingSpec.sourceContract, source.raw, context, ["v1Evidence", "mappingSpec", "sourceContract"], "must match the governed raw source identity");

  const runtime = governance.runtime;
  same(runtime.runtimeBundleId, definition.runtime.runtimeBundleId, context, ["governance", "runtime", "runtimeBundleId"]);
  same(runtime.runtimeVersion, definition.runtime.runtimeVersion, context, ["governance", "runtime", "runtimeVersion"]);
  same(runtime.runtimeBundleHash, definition.runtime.runtimeBundleHash, context, ["governance", "runtime", "runtimeBundleHash"]);
  exact(runtime.dictionary, definition.runtime.dictionary, context, ["governance", "runtime", "dictionary"], "must match the control dictionary");
  exact(runtime.mappingCompiler, definition.runtime.mappingCompiler, context, ["governance", "runtime", "mappingCompiler"], "must match the control mapping compiler");
  same(runtime.activation.runtimeBundleId, runtime.runtimeBundleId, context, ["governance", "runtime", "activation", "runtimeBundleId"]);
  same(runtime.activation.runtimeBundleHash, runtime.runtimeBundleHash, context, ["governance", "runtime", "activation", "runtimeBundleHash"]);
  before(runtime.activation.activatedAt, attempt.certifiedAt, context, ["governance", "runtime", "activation", "activatedAt"], "cannot follow certification");
  exact(evidence.mappingApplication.runtimeBundle, {
    runtimeBundleId: runtime.runtimeBundleId,
    runtimeBundleHash: runtime.runtimeBundleHash,
    runtimeVersion: runtime.runtimeVersion
  }, context, ["v1Evidence", "mappingApplication", "runtimeBundle"], "must match the governed runtime");
  exact(evidence.mappingApplication.dictionaryBundle, runtime.dictionary, context, ["v1Evidence", "mappingApplication", "dictionaryBundle"], "must match the governed dictionary");
  exact(evidence.mappingSpec.dictionaryBundle, runtime.dictionary, context, ["v1Evidence", "mappingSpec", "dictionaryBundle"], "must match the governed dictionary");
}

function withinWindow(
  asOfDate: string,
  window: { readonly effectiveFrom: string; readonly effectiveTo?: string | undefined },
  context: z.RefinementCtx,
  path: readonly PropertyKey[],
  message: string
): void {
  if (asOfDate < window.effectiveFrom || (window.effectiveTo !== undefined && asOfDate >= window.effectiveTo)) issue(context, path, message);
}

function before(
  earlier: string,
  later: string,
  context: z.RefinementCtx,
  path: readonly PropertyKey[],
  message: string
): void {
  if (earlier > later) issue(context, path, message);
}

function same(actual: string | number | undefined, expected: string | number | undefined, context: z.RefinementCtx, path: readonly PropertyKey[]): void {
  if (actual !== expected) issue(context, path, "does not match the authoritative evidence");
}

function exact(actual: unknown, expected: unknown, context: z.RefinementCtx, path: readonly PropertyKey[], message: string): void {
  if (canonicalJson(actual) !== canonicalJson(expected)) issue(context, path, message);
}

function issue(context: z.RefinementCtx, path: readonly PropertyKey[], message: string): void {
  context.addIssue({ code: "custom", path: [...path], message });
}
