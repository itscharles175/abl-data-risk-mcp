import { z } from "zod";

import {
  ContractValidationError,
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  canonicalJson,
  parseWithSchema
} from "./canonical.js";
import {
  CertifiedSnapshotEvidenceRecordV2Schema,
  parseCertifiedSnapshotEvidenceRecordV2,
  type CertifiedSnapshotEvidenceRecordV2
} from "./certified-snapshot-evidence-v2.js";
import {
  CertifiedSnapshotPublicationV1Schema,
  parseCertifiedSnapshotPublicationV1,
  type CertifiedSnapshotPublicationV1
} from "./certified-snapshot-publication-v1.js";

const PublicationReferenceV1Schema = z
  .object({
    publicationId: IdentifierSchema,
    publicationHash: Sha256HashSchema,
    certificationManifestId: IdentifierSchema,
    snapshotId: IdentifierSchema,
    snapshotHash: Sha256HashSchema,
    datasetBindingId: IdentifierSchema,
    datasetBindingHash: Sha256HashSchema,
    mappingApplicationId: IdentifierSchema,
    mappingApplicationHash: Sha256HashSchema,
    /** Exact immutable V1 publication used to derive this reference. */
    record: CertifiedSnapshotPublicationV1Schema
  })
  .strict();

const EvidenceReferenceV2Schema = z
  .object({
    /** The immutable V2-repository record identity: its certification manifest ID. */
    evidenceId: IdentifierSchema,
    evidenceHash: Sha256HashSchema,
    v1EvidenceHash: Sha256HashSchema,
    /** Exact immutable V2 evidence record used to derive all governed references. */
    record: CertifiedSnapshotEvidenceRecordV2Schema
  })
  .strict();

const CertificationAttemptReferenceV1Schema = z
  .object({
    certificationManifestId: IdentifierSchema,
    attemptHash: Sha256HashSchema,
    snapshotId: IdentifierSchema,
    snapshotHash: Sha256HashSchema,
    certifiedAt: IsoTimestampSchema
  })
  .strict();

const ControlReferenceV2Schema = z
  .object({
    definitionVersionId: IdentifierSchema,
    definitionKey: IdentifierSchema,
    versionHash: Sha256HashSchema,
    documentHash: Sha256HashSchema,
    approvalEventHash: Sha256HashSchema,
    activationEventHash: Sha256HashSchema
  })
  .strict();

const ScopeBindingReferenceV2Schema = z
  .object({
    definitionVersionId: IdentifierSchema,
    definitionKey: IdentifierSchema,
    versionHash: Sha256HashSchema,
    documentHash: Sha256HashSchema,
    approvalEventHash: Sha256HashSchema,
    bindingId: IdentifierSchema,
    revision: z.number().int().min(1).max(1_000_000),
    bindingHash: Sha256HashSchema
  })
  .strict();

const MappingReferenceV2Schema = z
  .object({
    definitionVersionId: IdentifierSchema,
    definitionKey: IdentifierSchema,
    versionHash: Sha256HashSchema,
    documentHash: Sha256HashSchema,
    approvalEventHash: Sha256HashSchema,
    activationEventHash: Sha256HashSchema,
    mappingSpecId: IdentifierSchema,
    mappingSpecRevision: z.number().int().min(1).max(1_000_000),
    mappingSpecHash: Sha256HashSchema,
    mappingApplicationId: IdentifierSchema,
    mappingApplicationHash: Sha256HashSchema
  })
  .strict();

const RuntimeReferenceV2Schema = z
  .object({
    runtimeBundleId: IdentifierSchema,
    runtimeVersion: z.string().min(1).max(64),
    runtimeBundleHash: Sha256HashSchema,
    activationHash: Sha256HashSchema,
    dictionaryBundleId: IdentifierSchema,
    dictionaryBundleHash: Sha256HashSchema,
    mappingCompilerBundleId: IdentifierSchema,
    mappingCompilerBundleHash: Sha256HashSchema
  })
  .strict();

const PublicationGovernanceBodyV2Schema = z
  .object({
    certificationAttempt: CertificationAttemptReferenceV1Schema,
    control: ControlReferenceV2Schema,
    scopeBinding: ScopeBindingReferenceV2Schema,
    mapping: MappingReferenceV2Schema,
    runtime: RuntimeReferenceV2Schema
  })
  .strict();

export const PublicationGovernanceV2Schema = PublicationGovernanceBodyV2Schema.extend({
  governanceHash: Sha256HashSchema
}).strict();

export type PublicationGovernanceV2 = Readonly<z.infer<typeof PublicationGovernanceV2Schema>>;

const GovernedCertifiedSnapshotPublicationLinkBodyV2Schema = z
  .object({
    contractVersion: z.literal(2),
    linkId: IdentifierSchema,
    tenantId: IdentifierSchema,
    publication: PublicationReferenceV1Schema,
    evidence: EvidenceReferenceV2Schema,
    governance: PublicationGovernanceV2Schema,
    linkedAt: IsoTimestampSchema
  })
  .strict()
  .superRefine((value, context) => {
    const record = value.evidence.record;
    if (value.governance.certificationAttempt.certificationManifestId !== value.evidence.evidenceId) {
      issue(context, ["evidence", "evidenceId"], "must be the immutable V2 evidence record identity");
    }
    if (value.publication.certificationManifestId !== value.evidence.evidenceId) {
      issue(context, ["publication", "certificationManifestId"], "must match the linked V2 evidence record identity");
    }
    same(value.publication.snapshotId, value.governance.certificationAttempt.snapshotId, context, ["publication", "snapshotId"]);
    same(value.publication.snapshotHash, value.governance.certificationAttempt.snapshotHash, context, ["publication", "snapshotHash"]);
    same(value.publication.datasetBindingId, value.governance.scopeBinding.bindingId, context, ["publication", "datasetBindingId"]);
    same(value.publication.mappingApplicationId, value.governance.mapping.mappingApplicationId, context, ["publication", "mappingApplicationId"]);
    same(value.publication.mappingApplicationHash, value.governance.mapping.mappingApplicationHash, context, ["publication", "mappingApplicationHash"]);
    if (value.governance.certificationAttempt.certifiedAt > value.linkedAt) {
      issue(context, ["linkedAt"], "cannot precede certification");
    }
    same(value.tenantId, value.publication.record.tenantId, context, ["publication", "record", "tenantId"]);
    same(value.tenantId, record.tenantId, context, ["evidence", "record", "tenantId"]);
    same(value.publication.publicationId, value.publication.record.publicationId, context, ["publication", "publicationId"]);
    same(value.publication.publicationHash, value.publication.record.publicationHash, context, ["publication", "publicationHash"]);
    same(value.publication.certificationManifestId, value.publication.record.certification.certificationManifestId, context, ["publication", "certificationManifestId"]);
    same(value.publication.snapshotId, value.publication.record.snapshot.snapshotId, context, ["publication", "snapshotId"]);
    same(value.publication.snapshotHash, value.publication.record.snapshot.snapshotHash, context, ["publication", "snapshotHash"]);
    same(value.publication.datasetBindingId, value.publication.record.datasetBinding.bindingId, context, ["publication", "datasetBindingId"]);
    same(value.publication.datasetBindingHash, value.publication.record.datasetBinding.bindingHash, context, ["publication", "datasetBindingHash"]);
    same(value.publication.mappingApplicationId, value.publication.record.mappingApplication.mappingApplicationId, context, ["publication", "mappingApplicationId"]);
    same(value.publication.mappingApplicationHash, value.publication.record.mappingApplication.mappingApplicationHash, context, ["publication", "mappingApplicationHash"]);
    same(value.evidence.evidenceId, record.certificationAttempt.certificationManifestId, context, ["evidence", "evidenceId"]);
    same(value.evidence.evidenceHash, record.evidenceHash, context, ["evidence", "evidenceHash"]);
    same(value.evidence.v1EvidenceHash, record.v1Evidence.evidenceHash, context, ["evidence", "v1EvidenceHash"]);
    if (value.governance.governanceHash !== canonicalHash(record.governance)) {
      issue(context, ["governance", "governanceHash"], "must hash the exact V2 evidence governance record");
    }
    validateGovernanceReferences(value.governance, record, context);
  });

export const GovernedCertifiedSnapshotPublicationLinkV2Schema =
  GovernedCertifiedSnapshotPublicationLinkBodyV2Schema.extend({ linkHash: Sha256HashSchema }).strict();

export type GovernedCertifiedSnapshotPublicationLinkV2 = Readonly<
  z.infer<typeof GovernedCertifiedSnapshotPublicationLinkV2Schema>
>;

export interface CreateGovernedCertifiedSnapshotPublicationLinkV2Input {
  readonly linkId: string;
  readonly publication: CertifiedSnapshotPublicationV1;
  /** Must be the V2 repository record ID, currently the certification manifest ID. */
  readonly evidenceId: string;
  readonly evidence: CertifiedSnapshotEvidenceRecordV2;
  readonly linkedAt: string;
}

/**
 * Immutable, metadata-only bridge from the existing V1 surveillance publication
 * to the governed V2 certification evidence. The builder accepts whole verified
 * records only so it cannot be used to fabricate a cross-store lineage link from
 * caller-selected hashes.
 */
export function createGovernedCertifiedSnapshotPublicationLinkV2(
  input: CreateGovernedCertifiedSnapshotPublicationLinkV2Input
): GovernedCertifiedSnapshotPublicationLinkV2 {
  canonicalJson(input);
  const publication = parseCertifiedSnapshotPublicationV1(input.publication);
  const evidence = parseCertifiedSnapshotEvidenceRecordV2(input.evidence);
  const evidenceId = parseWithSchema(IdentifierSchema, input.evidenceId, "GovernedCertifiedSnapshotPublicationLinkV2 evidenceId");
  if (evidenceId !== evidence.certificationAttempt.certificationManifestId) {
    invariant("V2 evidence ID must equal its immutable certification manifest record identity");
  }
  const body = parseWithSchema(
    GovernedCertifiedSnapshotPublicationLinkBodyV2Schema,
    {
      contractVersion: 2,
      linkId: input.linkId,
      tenantId: evidence.tenantId,
      publication: publicationReference(publication),
      evidence: {
        evidenceId,
        evidenceHash: evidence.evidenceHash,
        v1EvidenceHash: evidence.v1Evidence.evidenceHash,
        record: evidence
      },
      governance: createPublicationGovernanceV2(evidence),
      linkedAt: input.linkedAt
    },
    "GovernedCertifiedSnapshotPublicationLinkV2"
  );
  validateLinkAgainstRecords(body, publication, evidence);
  return parseGovernedCertifiedSnapshotPublicationLinkV2({ ...body, linkHash: canonicalHash(body) });
}

export function parseGovernedCertifiedSnapshotPublicationLinkV2(value: unknown): GovernedCertifiedSnapshotPublicationLinkV2 {
  canonicalJson(value);
  const parsed = parseWithSchema(
    GovernedCertifiedSnapshotPublicationLinkV2Schema,
    value,
    "GovernedCertifiedSnapshotPublicationLinkV2"
  );
  const { linkHash, ...body } = parsed;
  assertCanonicalHash(body, linkHash, "GovernedCertifiedSnapshotPublicationLinkV2");
  const { governanceHash } = parsed.governance;
  assertCanonicalHash(parsed.evidence.record.governance, governanceHash, "PublicationGovernanceV2");
  const publication = parseCertifiedSnapshotPublicationV1(parsed.publication.record);
  const evidence = parseCertifiedSnapshotEvidenceRecordV2(parsed.evidence.record);
  validateLinkAgainstRecords(parsed, publication, evidence);
  return parsed;
}

function createPublicationGovernanceV2(evidence: CertifiedSnapshotEvidenceRecordV2): PublicationGovernanceV2 {
  const governance = evidence.governance;
  const body = {
    certificationAttempt: {
      certificationManifestId: evidence.certificationAttempt.certificationManifestId,
      attemptHash: evidence.certificationAttempt.attemptHash,
      snapshotId: evidence.certificationAttempt.snapshotId,
      snapshotHash: evidence.certificationAttempt.snapshotHash,
      certifiedAt: evidence.certificationAttempt.certifiedAt
    },
    control: {
      definitionVersionId: governance.control.reference.definitionVersionId,
      definitionKey: governance.control.reference.definitionKey,
      versionHash: governance.control.reference.versionHash,
      documentHash: governance.control.reference.documentHash,
      approvalEventHash: governance.control.reference.approvalEventHash,
      activationEventHash: governance.control.activation.activationEventHash
    },
    scopeBinding: {
      definitionVersionId: governance.scopeBinding.execution.definitionVersionId,
      definitionKey: governance.scopeBinding.execution.definitionKey,
      versionHash: governance.scopeBinding.execution.versionHash,
      documentHash: governance.scopeBinding.execution.documentHash,
      approvalEventHash: governance.scopeBinding.execution.approvalEventHash,
      bindingId: governance.scopeBinding.raw.bindingId,
      revision: governance.scopeBinding.raw.revision,
      bindingHash: governance.scopeBinding.raw.bindingHash
    },
    mapping: {
      definitionVersionId: governance.mapping.execution.definitionVersionId,
      definitionKey: governance.mapping.execution.definitionKey,
      versionHash: governance.mapping.execution.versionHash,
      documentHash: governance.mapping.execution.documentHash,
      approvalEventHash: governance.mapping.execution.approvalEventHash,
      activationEventHash: governance.mapping.activation.activationEventHash,
      mappingSpecId: governance.mapping.execution.mappingSpecId,
      mappingSpecRevision: governance.mapping.execution.mappingSpecRevision,
      mappingSpecHash: governance.mapping.execution.mappingSpecHash,
      mappingApplicationId: evidence.v1Evidence.mappingApplication.mappingApplicationId,
      mappingApplicationHash: evidence.v1Evidence.mappingApplication.mappingApplicationHash
    },
    runtime: {
      runtimeBundleId: governance.runtime.runtimeBundleId,
      runtimeVersion: governance.runtime.runtimeVersion,
      runtimeBundleHash: governance.runtime.runtimeBundleHash,
      activationHash: governance.runtime.activation.activationHash,
      dictionaryBundleId: governance.runtime.dictionary.bundleId,
      dictionaryBundleHash: governance.runtime.dictionary.contentHash,
      mappingCompilerBundleId: governance.runtime.mappingCompiler.bundleId,
      mappingCompilerBundleHash: governance.runtime.mappingCompiler.contentHash
    }
  };
  return parseWithSchema(
    PublicationGovernanceV2Schema,
    { ...body, governanceHash: canonicalHash(evidence.governance) },
    "PublicationGovernanceV2"
  );
}

function publicationReference(publication: CertifiedSnapshotPublicationV1): z.input<typeof PublicationReferenceV1Schema> {
  return {
    publicationId: publication.publicationId,
    publicationHash: publication.publicationHash,
    certificationManifestId: publication.certification.certificationManifestId,
    snapshotId: publication.snapshot.snapshotId,
    snapshotHash: publication.snapshot.snapshotHash,
    datasetBindingId: publication.datasetBinding.bindingId,
    datasetBindingHash: publication.datasetBinding.bindingHash,
    mappingApplicationId: publication.mappingApplication.mappingApplicationId,
    mappingApplicationHash: publication.mappingApplication.mappingApplicationHash,
    record: publication
  };
}

function validateLinkAgainstRecords(
  link: z.infer<typeof GovernedCertifiedSnapshotPublicationLinkBodyV2Schema>,
  publication: CertifiedSnapshotPublicationV1,
  evidence: CertifiedSnapshotEvidenceRecordV2
): void {
  if (publication.tenantId !== evidence.tenantId) invariant("Publication and V2 evidence tenants must match");
  if (publication.certification.certificationManifestId !== evidence.certificationAttempt.certificationManifestId) {
    invariant("Publication and V2 evidence certification manifests must match");
  }
  if (publication.certification.certificationManifestHash !== evidence.v1Evidence.certification.certificationManifestHash) {
    invariant("Publication and retained V1 evidence manifests must be identical");
  }
  if (publication.snapshot.snapshotId !== evidence.certificationAttempt.snapshotId || publication.snapshot.snapshotHash !== evidence.certificationAttempt.snapshotHash) {
    invariant("Publication and V2 evidence snapshots must match");
  }
  if (publication.mappingApplication.mappingApplicationHash !== evidence.v1Evidence.mappingApplication.mappingApplicationHash) {
    invariant("Publication and retained V1 evidence mapping applications must match");
  }
  if (publication.publishedAt < link.governance.certificationAttempt.certifiedAt) {
    invariant("Publication cannot precede the linked certification");
  }
}

function same(
  actual: string,
  expected: string,
  context: z.RefinementCtx,
  path: readonly PropertyKey[],
): void {
  if (actual !== expected) issue(context, path, "does not match the governed evidence");
}

function validateGovernanceReferences(
  governance: PublicationGovernanceV2,
  evidence: CertifiedSnapshotEvidenceRecordV2,
  context: z.RefinementCtx
): void {
  const source = evidence.governance;
  same(governance.certificationAttempt.certificationManifestId, evidence.certificationAttempt.certificationManifestId, context, ["governance", "certificationAttempt", "certificationManifestId"]);
  same(governance.certificationAttempt.attemptHash, evidence.certificationAttempt.attemptHash, context, ["governance", "certificationAttempt", "attemptHash"]);
  same(governance.certificationAttempt.snapshotId, evidence.certificationAttempt.snapshotId, context, ["governance", "certificationAttempt", "snapshotId"]);
  same(governance.certificationAttempt.snapshotHash, evidence.certificationAttempt.snapshotHash, context, ["governance", "certificationAttempt", "snapshotHash"]);
  same(governance.certificationAttempt.certifiedAt, evidence.certificationAttempt.certifiedAt, context, ["governance", "certificationAttempt", "certifiedAt"]);
  same(governance.control.definitionVersionId, source.control.reference.definitionVersionId, context, ["governance", "control", "definitionVersionId"]);
  same(governance.control.definitionKey, source.control.reference.definitionKey, context, ["governance", "control", "definitionKey"]);
  same(governance.control.versionHash, source.control.reference.versionHash, context, ["governance", "control", "versionHash"]);
  same(governance.control.documentHash, source.control.reference.documentHash, context, ["governance", "control", "documentHash"]);
  same(governance.control.approvalEventHash, source.control.reference.approvalEventHash, context, ["governance", "control", "approvalEventHash"]);
  same(governance.control.activationEventHash, source.control.activation.activationEventHash, context, ["governance", "control", "activationEventHash"]);
  same(governance.scopeBinding.definitionVersionId, source.scopeBinding.execution.definitionVersionId, context, ["governance", "scopeBinding", "definitionVersionId"]);
  same(governance.scopeBinding.definitionKey, source.scopeBinding.execution.definitionKey, context, ["governance", "scopeBinding", "definitionKey"]);
  same(governance.scopeBinding.versionHash, source.scopeBinding.execution.versionHash, context, ["governance", "scopeBinding", "versionHash"]);
  same(governance.scopeBinding.documentHash, source.scopeBinding.execution.documentHash, context, ["governance", "scopeBinding", "documentHash"]);
  same(governance.scopeBinding.approvalEventHash, source.scopeBinding.execution.approvalEventHash, context, ["governance", "scopeBinding", "approvalEventHash"]);
  same(governance.scopeBinding.bindingId, source.scopeBinding.raw.bindingId, context, ["governance", "scopeBinding", "bindingId"]);
  same(String(governance.scopeBinding.revision), String(source.scopeBinding.raw.revision), context, ["governance", "scopeBinding", "revision"]);
  same(governance.scopeBinding.bindingHash, source.scopeBinding.raw.bindingHash, context, ["governance", "scopeBinding", "bindingHash"]);
  same(governance.mapping.definitionVersionId, source.mapping.execution.definitionVersionId, context, ["governance", "mapping", "definitionVersionId"]);
  same(governance.mapping.definitionKey, source.mapping.execution.definitionKey, context, ["governance", "mapping", "definitionKey"]);
  same(governance.mapping.versionHash, source.mapping.execution.versionHash, context, ["governance", "mapping", "versionHash"]);
  same(governance.mapping.documentHash, source.mapping.execution.documentHash, context, ["governance", "mapping", "documentHash"]);
  same(governance.mapping.approvalEventHash, source.mapping.execution.approvalEventHash, context, ["governance", "mapping", "approvalEventHash"]);
  same(governance.mapping.activationEventHash, source.mapping.activation.activationEventHash, context, ["governance", "mapping", "activationEventHash"]);
  same(governance.mapping.mappingSpecId, source.mapping.execution.mappingSpecId, context, ["governance", "mapping", "mappingSpecId"]);
  same(String(governance.mapping.mappingSpecRevision), String(source.mapping.execution.mappingSpecRevision), context, ["governance", "mapping", "mappingSpecRevision"]);
  same(governance.mapping.mappingSpecHash, source.mapping.execution.mappingSpecHash, context, ["governance", "mapping", "mappingSpecHash"]);
  same(governance.mapping.mappingApplicationId, evidence.v1Evidence.mappingApplication.mappingApplicationId, context, ["governance", "mapping", "mappingApplicationId"]);
  same(governance.mapping.mappingApplicationHash, evidence.v1Evidence.mappingApplication.mappingApplicationHash, context, ["governance", "mapping", "mappingApplicationHash"]);
  same(governance.runtime.runtimeBundleId, source.runtime.runtimeBundleId, context, ["governance", "runtime", "runtimeBundleId"]);
  same(governance.runtime.runtimeVersion, source.runtime.runtimeVersion, context, ["governance", "runtime", "runtimeVersion"]);
  same(governance.runtime.runtimeBundleHash, source.runtime.runtimeBundleHash, context, ["governance", "runtime", "runtimeBundleHash"]);
  same(governance.runtime.activationHash, source.runtime.activation.activationHash, context, ["governance", "runtime", "activationHash"]);
  same(governance.runtime.dictionaryBundleId, source.runtime.dictionary.bundleId, context, ["governance", "runtime", "dictionaryBundleId"]);
  same(governance.runtime.dictionaryBundleHash, source.runtime.dictionary.contentHash, context, ["governance", "runtime", "dictionaryBundleHash"]);
  same(governance.runtime.mappingCompilerBundleId, source.runtime.mappingCompiler.bundleId, context, ["governance", "runtime", "mappingCompilerBundleId"]);
  same(governance.runtime.mappingCompilerBundleHash, source.runtime.mappingCompiler.contentHash, context, ["governance", "runtime", "mappingCompilerBundleHash"]);
}

function issue(context: z.RefinementCtx, path: readonly PropertyKey[], message: string): void {
  context.addIssue({ code: "custom", path: [...path], message });
}

function invariant(message: string): never {
  throw new ContractValidationError("INVARIANT_VIOLATION", message);
}
