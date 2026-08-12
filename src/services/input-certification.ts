import { Decimal } from "decimal.js";

import { artifactJsonContentHash, type ArtifactStore, type StoredArtifact } from "../control/artifacts.js";
import type { DefinitionStore, GovernedDefinition } from "../control/definitions.js";
import {
  type CertifyInputCertificationInput,
  type InputCertificationKindV1,
  type InputCertificationRecordV1,
  type InputCertificationViewV1,
  InputCertificationStoreError,
  type InputCertificationStore,
  type InputDeclaredControlsV1,
  type InputDefinitionReferenceV1,
  type ProposeInputCertificationInput
} from "../control/input-certifications.js";
import type {
  AnalysisManifest,
  ControlStore,
  DataQualityRun,
  DatasetSnapshot,
  MappingVersion,
  Reconciliation
} from "../control/store.js";
import {
  createCertifiedInputPopulationV1,
  createAnalysisInputLineageV1,
  type CertifiedInputPopulationV1
} from "../contracts/certified-lineage-v1.js";
import {
  createCertifiedOperationInputV1,
  parseCertifiedOperationInputV1,
  type CertifiedOperationInputV1
} from "../contracts/certified-operation-input-v1.js";
import { canonicalHash, canonicalJson, type CanonicalJsonValue, type Sha256Hash } from "../contracts/canonical.js";
import { DICTIONARY_VERSION } from "../domain/dictionary.js";

export interface InputCertificationPrimaryChain {
  readonly manifest: AnalysisManifest;
  readonly snapshot: DatasetSnapshot;
  readonly mapping: MappingVersion;
  readonly dataQuality: DataQualityRun;
  readonly reconciliation: Reconciliation;
  readonly normalizedArtifact: StoredArtifact;
  readonly records: readonly Readonly<Record<string, unknown>>[];
  readonly dataQualityFingerprint: string;
  readonly reconciliationFingerprint: string;
}

export interface ProposeCertifiedInputRequest {
  readonly tenantId: string;
  readonly inputId: string;
  readonly inputKind: InputCertificationKindV1;
  readonly candidateArtifactId: string;
  readonly primaryCertificationManifestId: string;
  readonly definitionIds: readonly string[];
  readonly purpose: string;
  readonly declaredControls: InputDeclaredControlsV1;
  readonly proposedBy: string;
  readonly idempotencyKey: string;
}

export interface CertifyInputRequest {
  readonly tenantId: string;
  readonly inputId: string;
  readonly certifiedBy: string;
  readonly idempotencyKey: string;
}

export interface VerifiedCertifiedInput {
  readonly record: InputCertificationRecordV1;
  readonly envelope: CertifiedOperationInputV1;
  readonly payload: CanonicalJsonValue;
  readonly summary: {
    readonly inputId: string;
    readonly envelopeHash: Sha256Hash;
    readonly lineageHash: Sha256Hash;
    readonly derivationHash: Sha256Hash;
    readonly primaryCertificationHash: Sha256Hash;
    readonly primaryPopulationHash: Sha256Hash;
    readonly sidecarCertificationHash: Sha256Hash;
    readonly sidecarPopulationHash: Sha256Hash;
    readonly dataQualityRunId: string;
    readonly dataQualityResultHash: Sha256Hash;
    readonly reconciliationId: string;
    readonly reconciliationResultHash: Sha256Hash;
    readonly certifiedAt: string;
  };
}

export interface InputCertificationServiceDependencies {
  readonly control: Pick<ControlStore, "getAnalysisManifest" | "getDatasetSnapshot" | "getMappingVersion" | "getDataQualityRun" | "getReconciliation">;
  readonly definitions: Pick<DefinitionStore, "get" | "selectEffective">;
  readonly artifacts: Pick<ArtifactStore, "getJson" | "putJson">;
  readonly inputCertifications: InputCertificationStore;
}

/** Server-side maker/checker assembler for population-bound operation inputs. */
export class InputCertificationService {
  readonly #dependencies: InputCertificationServiceDependencies;
  readonly #clock: () => Date;

  constructor(dependencies: InputCertificationServiceDependencies, clock: () => Date = () => new Date()) {
    this.#dependencies = dependencies;
    this.#clock = clock;
  }

  propose(request: ProposeCertifiedInputRequest) {
    const existing = this.#dependencies.inputCertifications.get(request.tenantId, request.inputId);
    if (existing) {
      if (!proposalIntentMatches(existing, request)) {
        throw new InputCertificationStoreError(
          "IDEMPOTENCY_CONFLICT",
          "Input certification proposal conflicts with its durable request"
        );
      }
      return this.#dependencies.inputCertifications.propose(
        proposalReplayInput(existing, request)
      );
    }
    const candidate = this.#dependencies.artifacts.getJson(request.tenantId, request.candidateArtifactId);
    const expectedCandidateKind = request.inputKind === "borrowing_base" ? "borrowing_base_input" : "monitoring_input";
    if (candidate.metadata.kind !== expectedCandidateKind) fail("Candidate input artifact kind is invalid");
    const payload = canonicalPayload(candidate.value);
    const facts = payloadFacts(request.inputKind, payload);
    const chain = this.loadPrimaryChain(request.tenantId, request.primaryCertificationManifestId);
    assertPayloadSnapshot(facts, chain.snapshot);
    const definitions = loadDefinitions(
      this.#dependencies.definitions,
      request.tenantId,
      request.definitionIds,
      chain.snapshot.asOfDate,
      request.inputKind
    );
    return this.#dependencies.inputCertifications.propose({
      tenantId: request.tenantId,
      inputId: request.inputId,
      inputKind: request.inputKind,
      candidateArtifactId: candidate.metadata.artifactId,
      candidateArtifactHash: prefixed(candidate.metadata.contentHash),
      candidateArtifactKind: candidate.metadata.kind,
      snapshotId: chain.snapshot.snapshotId,
      asOfDate: chain.snapshot.asOfDate,
      purpose: request.purpose,
      primaryCertificationManifestId: request.primaryCertificationManifestId,
      definitionReferences: definitionReferences(definitions),
      declaredControls: request.declaredControls,
      payloadHash: canonicalHash(payload),
      fieldSetHash: facts.fieldSetHash,
      rowCount: facts.rowCount,
      proposedBy: request.proposedBy,
      idempotencyKey: request.idempotencyKey
    });
  }

  certify(request: CertifyInputRequest): InputCertificationRecordV1 {
    const proposal = this.#dependencies.inputCertifications.get(request.tenantId, request.inputId);
    if (!proposal) fail("Input certification proposal was not found");
    if (proposal.status === "certified") {
      return this.#dependencies.inputCertifications.certify(
        certificationReplayInput(proposal, request)
      );
    }
    if (proposal.proposedBy === request.certifiedBy) {
      throw new InputCertificationStoreError(
        "MAKER_CHECKER_VIOLATION",
        "Input certification proposer cannot certify the same input"
      );
    }
    const candidate = this.#dependencies.artifacts.getJson(request.tenantId, proposal.candidateArtifactId);
    if (
      prefixed(candidate.metadata.contentHash) !== proposal.candidateArtifactHash ||
      candidate.metadata.kind !== proposal.candidateArtifactKind
    ) fail("Candidate artifact no longer matches its proposal");
    const payload = canonicalPayload(candidate.value);
    const facts = payloadFacts(proposal.inputKind, payload);
    if (
      canonicalHash(payload) !== proposal.payloadHash ||
      facts.fieldSetHash !== proposal.fieldSetHash ||
      facts.rowCount !== proposal.rowCount
    ) fail("Candidate population no longer matches its proposal");
    const chain = this.loadPrimaryChain(request.tenantId, proposal.primaryCertificationManifestId);
    assertPayloadSnapshot(facts, chain.snapshot);
    const definitions = loadDefinitions(
      this.#dependencies.definitions,
      request.tenantId,
      proposal.definitionReferences.map((reference) => reference.definitionId),
      chain.snapshot.asOfDate,
      proposal.inputKind
    );
    if (canonicalJson(definitionReferences(definitions)) !== canonicalJson(proposal.definitionReferences)) {
      fail("Governed definitions no longer match the proposal");
    }
    const actualControls = sidecarControls(
      proposal.inputKind,
      payload,
      facts.rowCount,
      definitions
    );
    const reconciliation = reconcile(proposal.declaredControls, actualControls);
    if (!reconciliation.passed) fail("Sidecar population did not reconcile to declared controls");
    const dataQuality = sidecarDataQuality(
      proposal.inputKind,
      payload,
      facts,
      definitions,
      chain
    );
    if (dataQuality.blockerCodes.length > 0) fail("Sidecar population failed data-quality certification");
    const primary = primaryPopulation(chain, proposal.purpose);
    const sidecarBody = {
      contractVersion: 1 as const,
      tenantId: request.tenantId,
      populationId: proposal.inputId,
      populationKind: "certified_sidecar" as const,
      purpose: proposal.purpose,
      snapshot: primary.snapshot,
      mappingApplication: primary.mappingApplication,
      populationHash: proposal.payloadHash,
      fieldSetHash: facts.fieldSetHash,
      rowCount: facts.rowCount,
      dataQuality: {
        runId: dataQuality.runId,
        rulesetId: dataQuality.rulesetId,
        rulesetHash: dataQuality.rulesetHash,
        resultHash: dataQuality.resultHash,
        publicationDecision: "publish" as const,
        blockerCodes: []
      },
      reconciliation: {
        reconciliationId: reconciliation.reconciliationId,
        definitionHash: reconciliation.definitionHash,
        resultHash: reconciliation.resultHash,
        passed: true,
        populationHash: proposal.payloadHash
      },
      certificationStatus: "certified" as const,
      certifiedBy: request.certifiedBy,
      certifiedAt: this.#now()
    };
    const sidecar = createCertifiedInputPopulationV1(sidecarBody);
    const derivationHash = canonicalHash({
      inputKind: proposal.inputKind,
      payloadHash: proposal.payloadHash,
      purpose: proposal.purpose,
      primaryCertificationHash: primary.certificationHash,
      sidecarCertificationHash: sidecar.certificationHash,
      definitions: proposal.definitionReferences
    });
    const lineage = createAnalysisInputLineageV1({
      contractVersion: 1,
      tenantId: request.tenantId,
      analysisKind: proposal.inputKind,
      primary,
      sidecars: [sidecar],
      definitions: [...proposal.definitionReferences],
      derivationHash,
      assembledAt: this.#now()
    });
    const envelope = createCertifiedOperationInputV1({
      contractVersion: 1,
      inputKind: proposal.inputKind,
      payload,
      payloadHash: proposal.payloadHash,
      lineage
    });
    const artifactKind = proposal.inputKind === "borrowing_base"
      ? "certified_borrowing_base_input"
      : "certified_monitoring_input";
    const certifiedArtifact = this.#dependencies.artifacts.putJson({
      tenantId: request.tenantId,
      kind: artifactKind,
      mediaType: "application/json",
      value: envelope
    });
    return this.#dependencies.inputCertifications.certify({
      tenantId: request.tenantId,
      inputId: proposal.inputId,
      certifiedArtifactId: certifiedArtifact.artifactId,
      certifiedArtifactHash: prefixed(certifiedArtifact.contentHash),
      certifiedArtifactKind: artifactKind,
      lineageHash: lineage.lineageHash,
      envelopeHash: envelope.envelopeHash,
      derivationHash,
      primaryCertificationHash: primary.certificationHash,
      primaryPopulationHash: primary.populationHash,
      sidecarCertificationHash: sidecar.certificationHash,
      sidecarPopulationHash: sidecar.populationHash,
      dataQualityRunId: dataQuality.runId,
      dataQualityResultHash: dataQuality.resultHash,
      reconciliationId: reconciliation.reconciliationId,
      reconciliationResultHash: reconciliation.resultHash,
      certifiedBy: request.certifiedBy,
      idempotencyKey: request.idempotencyKey
    });
  }

  verify(input: {
    readonly tenantId: string;
    readonly operation: "ar_borrowing_base" | "monitoring";
    readonly purpose: string;
    readonly artifact: StoredArtifact;
    readonly value: unknown;
    readonly chain: InputCertificationPrimaryChain;
    readonly definitions: readonly GovernedDefinition[];
    readonly now: Date;
  }): VerifiedCertifiedInput {
    const envelope = parseCertifiedOperationInputV1(input.value);
    const expectedKind = input.operation === "ar_borrowing_base" ? "borrowing_base" : "monitoring";
    const expectedArtifactKind = expectedKind === "borrowing_base"
      ? "certified_borrowing_base_input"
      : "certified_monitoring_input";
    if (envelope.inputKind !== expectedKind || input.artifact.kind !== expectedArtifactKind) fail("Certified input kind is invalid");
    if (input.artifact.contentHash !== artifactJsonContentHash(envelope)) fail("Certified artifact content hash is invalid");
    if (envelope.lineage.tenantId !== input.tenantId || envelope.lineage.sidecars[0]!.purpose !== input.purpose) {
      fail("Certified input tenant or purpose is invalid");
    }
    if (Date.parse(envelope.lineage.assembledAt) > input.now.getTime()) fail("Certified input assembly time is in the future");
    const sidecar = envelope.lineage.sidecars[0]!;
    const record = this.#dependencies.inputCertifications.get(input.tenantId, sidecar.populationId);
    if (!record || record.status !== "certified") fail("Authoritative input certification was not found");
    const facts = payloadFacts(expectedKind, envelope.payload);
    assertPayloadSnapshot(facts, input.chain.snapshot);
    const primary = primaryPopulation(input.chain, record.purpose);
    const refs = definitionReferences(input.definitions);
    const dataQuality = sidecarDataQuality(
      record.inputKind,
      envelope.payload,
      facts,
      input.definitions,
      input.chain
    );
    const reconciliation = reconcile(
      record.declaredControls,
      sidecarControls(record.inputKind, envelope.payload, facts.rowCount, input.definitions)
    );
    const derivationHash = canonicalHash({
      inputKind: record.inputKind,
      payloadHash: envelope.payloadHash,
      purpose: record.purpose,
      primaryCertificationHash: primary.certificationHash,
      sidecarCertificationHash: sidecar.certificationHash,
      definitions: refs
    });
    if (
      record.certifiedArtifactId !== input.artifact.artifactId ||
      record.certifiedArtifactHash !== prefixed(input.artifact.contentHash) ||
      record.certifiedArtifactKind !== input.artifact.kind ||
      record.envelopeHash !== envelope.envelopeHash ||
      record.lineageHash !== envelope.lineage.lineageHash ||
      record.derivationHash !== derivationHash ||
      envelope.lineage.derivationHash !== derivationHash ||
      canonicalJson(envelope.lineage.primary) !== canonicalJson(primary) ||
      canonicalJson(envelope.lineage.definitions) !== canonicalJson(refs) ||
      canonicalJson(record.definitionReferences) !== canonicalJson(refs) ||
      record.primaryCertificationHash !== primary.certificationHash ||
      record.primaryPopulationHash !== primary.populationHash ||
      record.sidecarCertificationHash !== sidecar.certificationHash ||
      record.sidecarPopulationHash !== envelope.payloadHash ||
      record.dataQualityRunId !== dataQuality.runId ||
      record.dataQualityResultHash !== dataQuality.resultHash ||
      record.reconciliationId !== reconciliation.reconciliationId ||
      record.reconciliationResultHash !== reconciliation.resultHash ||
      !reconciliation.passed ||
      facts.fieldSetHash !== record.fieldSetHash ||
      facts.rowCount !== record.rowCount
    ) fail("Certified input evidence did not match authoritative state");
    return {
      record,
      envelope,
      payload: envelope.payload,
      summary: {
        inputId: record.inputId,
        envelopeHash: record.envelopeHash,
        lineageHash: record.lineageHash,
        derivationHash: record.derivationHash,
        primaryCertificationHash: record.primaryCertificationHash,
        primaryPopulationHash: record.primaryPopulationHash,
        sidecarCertificationHash: record.sidecarCertificationHash,
        sidecarPopulationHash: record.sidecarPopulationHash,
        dataQualityRunId: record.dataQualityRunId,
        dataQualityResultHash: record.dataQualityResultHash,
        reconciliationId: record.reconciliationId,
        reconciliationResultHash: record.reconciliationResultHash,
        certifiedAt: record.certifiedAt
      }
    };
  }

  loadPrimaryChain(tenantId: string, manifestId: string): InputCertificationPrimaryChain {
    const manifest = this.#dependencies.control.getAnalysisManifest(tenantId, manifestId);
    if (!manifest || manifest.analysisType !== "snapshot_certification") {
      fail("Primary certification manifest is invalid");
    }
    const parameters = certificationParameters(manifest.parameters);
    if (!parameters.certified || parameters.blockerCodes.length !== 0) {
      fail("Primary certification manifest did not pass");
    }
    const snapshot = this.#dependencies.control.getDatasetSnapshot(tenantId, manifest.snapshotId);
    const mapping = this.#dependencies.control.getMappingVersion(tenantId, manifest.mappingVersionId);
    const dataQuality = this.#dependencies.control.getDataQualityRun(
      tenantId,
      parameters.dataQualityRunId
    );
    const reconciliation = this.#dependencies.control.getReconciliation(
      tenantId,
      parameters.reconciliationId
    );
    const normalizedEntry = manifest.artifacts.filter((artifact) => artifact.kind === "normalized_snapshot");
    if (!snapshot || !mapping || !dataQuality || !reconciliation || normalizedEntry.length !== 1) fail("Primary certification chain is incomplete");
    const loaded = this.#dependencies.artifacts.getJson(tenantId, normalizedEntry[0]!.artifactId);
    const normalized = normalizedSnapshot(loaded.value);
    if (
      mapping.status !== "active" || mapping.snapshotId !== snapshot.snapshotId ||
      mapping.dictionaryVersion !== DICTIONARY_VERSION ||
      dataQuality.snapshotId !== snapshot.snapshotId ||
      dataQuality.rulesetId !== parameters.dataQualityProfileId ||
      !dataQuality.passed || dataQuality.failedFindingCount !== 0 ||
      reconciliation.snapshotId !== snapshot.snapshotId || !reconciliation.passed ||
      loaded.metadata.kind !== "normalized_snapshot" ||
      loaded.metadata.contentHash !== normalizedEntry[0]!.contentHash ||
      loaded.metadata.uri !== normalizedEntry[0]!.uri ||
      normalized.snapshotId !== snapshot.snapshotId ||
      normalized.mappingVersionId !== mapping.mappingVersionId ||
      normalized.records.length !== snapshot.rowCount
    ) fail("Primary certification chain is not valid");
    const reconciliationDetails = object(reconciliation.details);
    const reconciliationFingerprint = rawHash(reconciliationDetails.fingerprint);
    const expectedQueryHash = canonicalHash({
      snapshotHash: snapshot.contentHash,
      mappingHash: mapping.mappingHash,
      dataQualityFingerprint: normalized.dataQualityFingerprint,
      reconciliationFingerprint
    }).slice(7);
    if (manifest.queryHash !== expectedQueryHash) fail("Primary certification fingerprint is invalid");
    return {
      manifest,
      snapshot,
      mapping,
      dataQuality,
      reconciliation,
      normalizedArtifact: loaded.metadata,
      records: normalized.records,
      dataQualityFingerprint: normalized.dataQualityFingerprint,
      reconciliationFingerprint
    };
  }

  #now(): string {
    const value = this.#clock();
    if (Number.isNaN(value.getTime())) fail("Input-certification clock is invalid");
    return value.toISOString();
  }
}

function proposalIntentMatches(
  record: InputCertificationViewV1,
  request: ProposeCertifiedInputRequest
): boolean {
  return (
    record.tenantId === request.tenantId &&
    record.inputId === request.inputId &&
    record.inputKind === request.inputKind &&
    record.candidateArtifactId === request.candidateArtifactId &&
    record.primaryCertificationManifestId === request.primaryCertificationManifestId &&
    record.purpose === request.purpose &&
    record.proposedBy === request.proposedBy &&
    canonicalJson(record.declaredControls) === canonicalJson(request.declaredControls) &&
    canonicalJson(record.definitionReferences.map((reference) => reference.definitionId).sort()) ===
      canonicalJson([...request.definitionIds].sort())
  );
}

function proposalReplayInput(
  record: InputCertificationViewV1,
  request: ProposeCertifiedInputRequest
): ProposeInputCertificationInput {
  return {
    tenantId: record.tenantId,
    inputId: record.inputId,
    inputKind: record.inputKind,
    candidateArtifactId: record.candidateArtifactId,
    candidateArtifactHash: record.candidateArtifactHash,
    candidateArtifactKind: record.candidateArtifactKind,
    snapshotId: record.snapshotId,
    asOfDate: record.asOfDate,
    purpose: record.purpose,
    primaryCertificationManifestId: record.primaryCertificationManifestId,
    definitionReferences: record.definitionReferences,
    declaredControls: record.declaredControls,
    payloadHash: record.payloadHash,
    fieldSetHash: record.fieldSetHash,
    rowCount: record.rowCount,
    proposedBy: request.proposedBy,
    idempotencyKey: request.idempotencyKey
  };
}

function certificationReplayInput(
  record: InputCertificationRecordV1,
  request: CertifyInputRequest
): CertifyInputCertificationInput {
  return {
    tenantId: record.tenantId,
    inputId: record.inputId,
    certifiedArtifactId: record.certifiedArtifactId,
    certifiedArtifactHash: record.certifiedArtifactHash,
    certifiedArtifactKind: record.certifiedArtifactKind,
    lineageHash: record.lineageHash,
    envelopeHash: record.envelopeHash,
    derivationHash: record.derivationHash,
    primaryCertificationHash: record.primaryCertificationHash,
    primaryPopulationHash: record.primaryPopulationHash,
    sidecarCertificationHash: record.sidecarCertificationHash,
    sidecarPopulationHash: record.sidecarPopulationHash,
    dataQualityRunId: record.dataQualityRunId,
    dataQualityResultHash: record.dataQualityResultHash,
    reconciliationId: record.reconciliationId,
    reconciliationResultHash: record.reconciliationResultHash,
    certifiedBy: request.certifiedBy,
    idempotencyKey: request.idempotencyKey
  };
}

function certificationParameters(value: unknown): {
  readonly dataQualityProfileId: string;
  readonly dataQualityRunId: string;
  readonly reconciliationId: string;
  readonly certified: boolean;
  readonly blockerCodes: readonly string[];
} {
  const parameters = exactObject(
    value,
    [
      "blockerCodes",
      "certified",
      "dataQualityProfileId",
      "dataQualityProfileVersion",
      "dataQualityRunId",
      "evaluatedAt",
      "reconciliationId"
    ],
    "Primary certification parameters"
  );
  string(parameters.dataQualityProfileId);
  string(parameters.dataQualityProfileVersion);
  string(parameters.dataQualityRunId);
  string(parameters.reconciliationId);
  canonicalIsoTimestamp(parameters.evaluatedAt);
  if (typeof parameters.certified !== "boolean") fail("Primary certification decision is invalid");
  const blockerCodes = array(parameters.blockerCodes);
  if (blockerCodes.length > 10_000 || blockerCodes.some((code) => typeof code !== "string" || code.length === 0)) {
    fail("Primary certification blocker codes are invalid");
  }
  return {
    dataQualityProfileId: parameters.dataQualityProfileId as string,
    dataQualityRunId: parameters.dataQualityRunId as string,
    reconciliationId: parameters.reconciliationId as string,
    certified: parameters.certified,
    blockerCodes: blockerCodes as readonly string[]
  };
}

function normalizedSnapshot(value: unknown): {
  readonly snapshotId: string;
  readonly mappingVersionId: string;
  readonly records: readonly Readonly<Record<string, unknown>>[];
  readonly dataQualityFingerprint: string;
} {
  const normalized = exactObject(
    value,
    ["dataQualityFingerprint", "mappingVersionId", "records", "snapshotId"],
    "Normalized snapshot"
  );
  const records = array(normalized.records);
  if (records.length > 1_000_000) fail("Primary normalized population is too large");
  return {
    snapshotId: string(normalized.snapshotId),
    mappingVersionId: string(normalized.mappingVersionId),
    records: records.map((record) => object(record)),
    dataQualityFingerprint: rawHash(normalized.dataQualityFingerprint)
  };
}

function primaryPopulation(chain: InputCertificationPrimaryChain, purpose: string): CertifiedInputPopulationV1 {
  const populationHash = canonicalHash(chain.records);
  const mappingSpecHash = prefixed(chain.mapping.mappingHash);
  const snapshotHash = canonicalHash(chain.snapshot);
  const primary = {
    contractVersion: 1 as const,
    tenantId: chain.snapshot.tenantId,
    populationId: chain.manifest.manifestId,
    populationKind: "canonical_snapshot" as const,
    purpose,
    snapshot: { snapshotId: chain.snapshot.snapshotId, snapshotHash, contentHash: prefixed(chain.snapshot.contentHash) },
    mappingApplication: {
      mappingApplicationId: chain.manifest.manifestId,
      mappingApplicationHash: canonicalHash({
        tenantId: chain.snapshot.tenantId,
        snapshotId: chain.snapshot.snapshotId,
        snapshotHash,
        mappingVersionId: chain.mapping.mappingVersionId,
        mappingHash: chain.mapping.mappingHash,
        normalizedArtifactId: chain.normalizedArtifact.artifactId,
        normalizedArtifactContentHash: chain.normalizedArtifact.contentHash,
        populationHash
      }),
      mappingSpecId: chain.mapping.mappingVersionId,
      mappingSpecHash
    },
    populationHash,
    fieldSetHash: fieldSetHash(chain.records),
    rowCount: chain.records.length,
    dataQuality: {
      runId: chain.dataQuality.runId,
      rulesetId: chain.dataQuality.rulesetId,
      rulesetHash: prefixed(chain.dataQuality.rulesetHash),
      resultHash: canonicalHash(chain.dataQuality),
      publicationDecision: "publish" as const,
      blockerCodes: []
    },
    reconciliation: {
      reconciliationId: chain.reconciliation.reconciliationId,
      definitionHash: canonicalHash({ kind: chain.reconciliation.kind, checks: chain.reconciliation.checks.map((check) => check.checkId) }),
      resultHash: canonicalHash(chain.reconciliation),
      passed: true,
      populationHash
    },
    certificationStatus: "certified" as const,
    certifiedBy: chain.manifest.createdBy,
    certifiedAt: chain.manifest.createdAt
  };
  return createCertifiedInputPopulationV1(primary);
}

function payloadFacts(kind: InputCertificationKindV1, payload: CanonicalJsonValue) {
  const value = object(payload);
  const snapshotId = string(value.snapshotId);
  const asOfDate = string(value.asOfDate);
  const members = kind === "borrowing_base"
    ? [...array(value.receivables), ...array(value.usage)]
    : array(value.observations);
  if (kind === "monitoring") {
    for (const observation of members) {
      const row = object(observation);
      if (string(row.snapshotId) !== snapshotId || string(row.asOfDate) !== asOfDate) fail("Monitoring observations must use the exact certified snapshot");
    }
  }
  return { snapshotId, asOfDate, rowCount: members.length, fieldSetHash: fieldSetHash(members) };
}

function sidecarControls(
  kind: InputCertificationKindV1,
  payload: CanonicalJsonValue,
  rowCount: number,
  definitions: readonly GovernedDefinition[]
): InputDeclaredControlsV1 {
  if (kind === "monitoring") return { rowCount };
  const value = object(payload);
  let balance = new Decimal(0);
  for (const receivable of array(value.receivables)) balance = balance.plus(string(object(receivable).outstandingAmount));
  return { rowCount, balance: balance.toString(), currency: borrowingBaseCurrency(definitions) };
}

function borrowingBaseCurrency(definitions: readonly GovernedDefinition[]): string {
  if (definitions.length !== 1 || definitions[0]!.kind !== "borrowing_base_policy") {
    fail("Borrowing-base controls require one governed policy");
  }
  const currency = string(object(definitions[0]!.document).currencyCode);
  if (!/^[A-Z]{3}$/.test(currency)) fail("Borrowing-base policy currency is invalid");
  return currency;
}

function reconcile(declared: InputDeclaredControlsV1, actual: InputDeclaredControlsV1) {
  const declaredBalance = new Decimal(declared.balance ?? "0");
  const actualBalance = new Decimal(actual.balance ?? "0");
  const result = {
    declared,
    actual,
    rowCountDifference: actual.rowCount - declared.rowCount,
    balanceDifference: actualBalance.minus(declaredBalance).toString(),
    passed:
      actual.rowCount === declared.rowCount &&
      actualBalance.equals(declaredBalance) &&
      actual.currency === declared.currency
  };
  return {
    ...result,
    reconciliationId: `sidecar-recon-${canonicalHash(result).slice(7, 23)}`,
    definitionHash: canonicalHash({ kind: "exact_sidecar_controls_v1" }),
    resultHash: canonicalHash(result)
  };
}

function sidecarDataQuality(
  kind: InputCertificationKindV1,
  payload: CanonicalJsonValue,
  facts: ReturnType<typeof payloadFacts>,
  definitions: readonly GovernedDefinition[],
  chain: InputCertificationPrimaryChain
) {
  const blockerCodes: string[] = [];
  if (facts.rowCount === 0) blockerCodes.push("empty_sidecar_population");
  if (kind === "monitoring") {
    const metricIds = new Set(definitions.map((definition) => string(object(definition.document).metricId)));
    const permittedEvidence = governedEvidence(definitions, chain);
    const canonicalPopulationEvidence = new Set([
      `source_artifact\u0000${chain.normalizedArtifact.artifactId}`
    ]);
    const observedMetricIds = new Set<string>();
    const observationIds = new Set<string>();
    for (const observation of array(object(payload).observations)) {
      const row = object(observation);
      const metricId = string(row.metricId);
      const observationId = string(row.observationId);
      if (!metricIds.has(metricId)) blockerCodes.push("unknown_monitor_metric");
      if (observedMetricIds.has(metricId)) blockerCodes.push("duplicate_monitor_metric");
      if (observationIds.has(observationId)) blockerCodes.push("duplicate_observation_id");
      observedMetricIds.add(metricId);
      observationIds.add(observationId);
      const evidence = array(row.evidence);
      if (!evidence.some((entry) => isGovernedEvidence(entry, canonicalPopulationEvidence))) {
        blockerCodes.push("missing_observation_population_evidence");
      }
      if (evidence.some((entry) => !isGovernedEvidence(entry, permittedEvidence))) {
        blockerCodes.push("untrusted_observation_evidence");
      }
    }
    if ([...metricIds].some((metricId) => !observedMetricIds.has(metricId))) {
      blockerCodes.push("missing_monitor_metric");
    }
  }
  const result = { kind, populationHash: canonicalHash(payload), fieldSetHash: facts.fieldSetHash, rowCount: facts.rowCount, blockerCodes: [...new Set(blockerCodes)].sort() };
  return {
    runId: `sidecar-dq-${canonicalHash(result).slice(7, 23)}`,
    rulesetId: `${kind}-sidecar-dq-v1`,
    rulesetHash: canonicalHash({ kind, version: 1 }),
    resultHash: canonicalHash(result),
    blockerCodes: result.blockerCodes
  };
}

function isGovernedEvidence(value: unknown, permitted: ReadonlySet<string>): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const entry = value as Record<string, unknown>;
  if (canonicalJson(Object.keys(entry).sort()) !== canonicalJson(["id", "kind"])) return false;
  return typeof entry.kind === "string" &&
    typeof entry.id === "string" &&
    permitted.has(`${entry.kind}\u0000${entry.id}`);
}

function governedEvidence(
  definitions: readonly GovernedDefinition[],
  chain: InputCertificationPrimaryChain
): ReadonlySet<string> {
  return new Set([
    `mapping\u0000${chain.mapping.mappingVersionId}`,
    `reconciliation\u0000${chain.reconciliation.reconciliationId}`,
    `source_artifact\u0000${chain.normalizedArtifact.artifactId}`,
    ...definitions.map((definition) => `policy\u0000${definition.definitionId}`)
  ]);
}

function loadDefinitions(
  store: Pick<DefinitionStore, "get" | "selectEffective">,
  tenantId: string,
  definitionIds: readonly string[],
  asOfDate: string,
  inputKind: InputCertificationKindV1
): readonly GovernedDefinition[] {
  if (definitionIds.length < 1 || new Set(definitionIds).size !== definitionIds.length) fail("Definition ids are invalid");
  if (inputKind === "borrowing_base" && definitionIds.length !== 1) {
    fail("Borrowing-base certification requires exactly one policy definition");
  }
  const expectedKind = inputKind === "borrowing_base" ? "borrowing_base_policy" : "monitor_definition";
  return [...definitionIds].sort().map((definitionId) => {
    const definition = store.get(tenantId, definitionId);
    if (!definition || definition.status !== "active" || definition.kind !== expectedKind) {
      fail("Governed definition was not found with the required kind");
    }
    const effective = store.selectEffective(tenantId, definition.kind, definition.definitionKey, asOfDate);
    if (effective.definitionId !== definition.definitionId) fail("Governed definition is not effective");
    assertDefinitionIdentity(definition, inputKind);
    return definition;
  });
}

function assertDefinitionIdentity(
  definition: GovernedDefinition,
  inputKind: InputCertificationKindV1
): void {
  const document = object(definition.document);
  const key = inputKind === "borrowing_base"
    ? string(document.policyId)
    : string(document.monitorId);
  const effectiveTo = document.effectiveTo === undefined ? null : string(document.effectiveTo);
  if (
    key !== definition.definitionKey ||
    string(document.version) !== definition.version ||
    string(document.effectiveFrom) !== definition.effectiveFrom ||
    effectiveTo !== definition.effectiveTo
  ) {
    fail("Governed definition identity does not match its approved document");
  }
}

function definitionReferences(definitions: readonly GovernedDefinition[]): readonly InputDefinitionReferenceV1[] {
  return definitions.map((definition) => ({ definitionId: definition.definitionId, version: definition.version, definitionHash: prefixed(definition.documentHash) }));
}

function assertPayloadSnapshot(facts: ReturnType<typeof payloadFacts>, snapshot: DatasetSnapshot): void {
  if (facts.snapshotId !== snapshot.snapshotId || facts.asOfDate !== snapshot.asOfDate) fail("Sidecar input does not belong to the certified snapshot");
}

function fieldSetHash(values: readonly unknown[]): Sha256Hash {
  const fields = new Set<string>();
  for (const value of values) for (const key of Object.keys(object(value))) fields.add(key);
  return canonicalHash([...fields].sort());
}

function canonicalPayload(value: unknown): CanonicalJsonValue {
  canonicalJson(value);
  return value as CanonicalJsonValue;
}

function prefixed(value: string): Sha256Hash {
  const normalized = value.startsWith("sha256:") ? value : `sha256:${value}`;
  if (!/^sha256:[a-f0-9]{64}$/.test(normalized)) fail("Hash is invalid");
  return normalized as Sha256Hash;
}

function rawHash(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) fail("Hash is invalid");
  return value;
}

function canonicalIsoTimestamp(value: unknown): string {
  if (typeof value !== "string" || value.length > 64) fail("Timestamp is invalid");
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) fail("Timestamp is invalid");
  return value;
}

function exactObject(
  value: unknown,
  expectedKeys: readonly string[],
  label: string
): Record<string, unknown> {
  const record = object(value);
  if (canonicalJson(Object.keys(record).sort()) !== canonicalJson([...expectedKeys].sort())) {
    fail(`${label} contains an unknown or missing field`);
  }
  return record;
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("Expected a JSON object");
  return value as Record<string, unknown>;
}

function array(value: unknown): readonly unknown[] {
  if (!Array.isArray(value)) fail("Expected a JSON array");
  return value;
}

function string(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) fail("Expected a non-empty string");
  return value;
}

function fail(message: string): never {
  throw new Error(message);
}
