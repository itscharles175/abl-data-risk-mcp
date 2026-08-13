import { z } from "zod";

import {
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  canonicalJson,
  deepFreeze,
  parseCertifiedSnapshotPublicationV1,
  parseGovernedDatasetScopeBindingV1,
  parseSourceAccessPolicyV1,
  parseWithSchema,
  type CertifiedSnapshotPublicationV1,
  type Sha256Hash,
  type SourceAccessPolicyV1
} from "../contracts/index.js";
import { MethodologyBundleV1Schema } from "../contracts/governed-definition-v2.js";
import type { SurveillancePublicationDisableEventV1 } from "../control/surveillance-publications.js";
import type {
  BinDefinitionV1,
  CohortDefinitionV1,
  EntityResolutionDefinitionV1,
  MetricDefinitionV1
} from "../domain/surveillance/contracts.js";
import {
  validateBinDefinitionV1,
  validateCohortDefinitionV1,
  validateEntityResolutionDefinitionV1,
  validateMetricDefinitionV1
} from "../domain/surveillance/definitions.js";
import { getCanonicalFieldPolicy } from "../domain/field-policy.js";
import {
  assertVerifiedPrincipalContext,
  principalBinding,
  type VerifiedPrincipalContext
} from "../security/identity.js";
import {
  assertPermitDecision,
  type PermitPolicyDecision,
  type PolicyDecision,
  type PolicyEvaluationRequest,
  type PolicyObligations
} from "../security/policy.js";
import type { ResolvedGovernedDefinitionV2 } from "./governed-definition-v2-resolver.js";
import {
  PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR,
  assertPortfolioSurveillanceMetricCompatibilityV1,
  derivePortfolioSurveillanceRequestedFieldsV1
} from "./operations/portfolio-surveillance-v1.js";
import {
  createPortfolioSurveillanceAuthorizationPreflightV4,
  parsePortfolioSurveillanceAuthorizationPreflightV4,
  portfolioSurveillanceDescriptorBindingV4,
  type PortfolioSurveillanceAuthorizationPreflightV4
} from "./governed-operation-v4.js";

const OPERATION = "portfolio_surveillance_v1" as const;
const POLICY_TOOL_NAME = "abl_run_portfolio_surveillance" as const;
const MINIMUM_SOURCES = 2;
const MAXIMUM_SOURCES = 120;
const MINIMUM_DEFINITIONS = 2;
const MAXIMUM_DEFINITIONS = 256;
const MAXIMUM_LINEAGE_PUBLICATIONS = 1_000;
const MAXIMUM_POLICY_CANDIDATES = 1_000;
const MAXIMUM_METRICS = 1_000;
const MAXIMUM_CELLS = 1_000_000;

const ScopeSchema = z
  .object({
    scopeType: z.enum(["portfolio", "facility"]),
    scopeId: IdentifierSchema
  })
  .strict();

const SourceContractSelectorSchema = z
  .object({
    sourceContractId: IdentifierSchema,
    sourceKey: IdentifierSchema,
    revision: z.number().int().positive().max(1_000_000),
    sourceContractHash: Sha256HashSchema
  })
  .strict();

const DirectSourceRequestSchema = z
  .object({
    kind: z.literal("certification_manifest"),
    certificationManifestId: IdentifierSchema
  })
  .strict();

const RequestSchema = z
  .object({
    contractVersion: z.literal(1),
    operation: z.literal(OPERATION),
    sources: z.array(DirectSourceRequestSchema).min(MINIMUM_SOURCES).max(MAXIMUM_SOURCES),
    definitionVersionIds: z
      .array(IdentifierSchema)
      .min(MINIMUM_DEFINITIONS)
      .max(MAXIMUM_DEFINITIONS)
  })
  .strict()
  .superRefine((value, context) => {
    uniqueIssue(
      value.sources.map(({ certificationManifestId }) => certificationManifestId),
      context,
      ["sources"]
    );
    uniqueIssue(value.definitionVersionIds, context, ["definitionVersionIds"]);
  });

export type PortfolioSurveillanceAuthorizationRequestV1 = Readonly<
  z.infer<typeof RequestSchema>
>;

export interface PortfolioSurveillanceAuthorizationContextV1 {
  readonly principal: VerifiedPrincipalContext;
  readonly purpose: string;
  /** Trusted clock capture used for every metadata and authority lookup. */
  readonly planningCutoff: string;
}

export interface SurveillancePublicationLineageQueryV1 {
  readonly tenantId: string;
  readonly datasetId: string;
  readonly sourceContract: Readonly<z.infer<typeof SourceContractSelectorSchema>>;
  readonly scope: Readonly<z.infer<typeof ScopeSchema>>;
  readonly asOfDate: string;
  readonly publishedThrough: string;
  readonly maximumResults: number;
}

export interface CompletePublicationLineagePageV1 {
  readonly publications: readonly unknown[];
  /** False means terminality cannot be established and must fail closed. */
  readonly complete: boolean;
}

/** Metadata-only catalog capability. It intentionally has no artifact-reading method. */
export interface SurveillancePublicationReadPortV1 {
  get(
    tenantId: string,
    publicationId: string
  ): Promise<unknown | undefined> | unknown | undefined;
  getByCertificationManifest(
    tenantId: string,
    certificationManifestId: string
  ): Promise<unknown | undefined> | unknown | undefined;
  getDisable(
    tenantId: string,
    publicationId: string
  ):
    | Promise<SurveillancePublicationDisableEventV1 | undefined>
    | SurveillancePublicationDisableEventV1
    | undefined;
  listByScopeAsOf(
    query: SurveillancePublicationLineageQueryV1
  ): Promise<CompletePublicationLineagePageV1> | CompletePublicationLineagePageV1;
}

export interface SourceAccessPolicySelectorV1 {
  readonly tenantId: string;
  readonly datasetId: string;
  readonly sourceContract: Readonly<z.infer<typeof SourceContractSelectorSchema>>;
  readonly scope: Readonly<z.infer<typeof ScopeSchema>>;
  readonly purpose: string;
}

export interface CompleteSourceAccessPolicyCandidateSetV1 {
  readonly definitionKeys: readonly string[];
  /** False means uniqueness and overlap cannot be established. */
  readonly complete: boolean;
}

/** Server-governed selector index. Callers never provide a policy id or version id. */
export interface SourceAccessPolicyCandidateIndexV1 {
  listCandidateDefinitionKeys(
    selector: SourceAccessPolicySelectorV1
  ):
    | Promise<CompleteSourceAccessPolicyCandidateSetV1>
    | CompleteSourceAccessPolicyCandidateSetV1;
}

export interface FrozenGovernedDefinitionResolutionPortV1 {
  resolveFrozenDefinition(
    tenantId: string,
    definitionVersionId: string
  ):
    | Promise<ResolvedGovernedDefinitionV2 | undefined>
    | ResolvedGovernedDefinitionV2
    | undefined;
}

export interface EffectiveGovernedDefinitionResolutionPortV1 {
  resolveEffective(input: Readonly<{
    tenantId: string;
    kind: "source_access_policy" | "dataset_scope_binding";
    definitionKey: string;
    asOfDate: string;
  }>):
    | Promise<ResolvedGovernedDefinitionV2 | undefined>
    | ResolvedGovernedDefinitionV2
    | undefined;
}

export interface PortfolioSurveillanceGlobalAuthorizerV1 {
  authorize(
    request: PolicyEvaluationRequest
  ): Promise<PolicyDecision> | PolicyDecision;
}

export interface FrozenSourceAccessPolicyLineageV1 {
  readonly definitionVersionId: string;
  readonly definitionKey: string;
  readonly semanticVersion: string;
  readonly versionHash: Sha256Hash;
  readonly documentHash: Sha256Hash;
  readonly approvalEventHash: Sha256Hash;
  readonly executionDocumentHash: Sha256Hash;
  readonly policyId: string;
  readonly revision: number;
  readonly policyHash: Sha256Hash;
  readonly effectiveFrom: string;
  readonly effectiveTo: string | null;
}

export interface FrozenDatasetScopeBindingLineageV1 {
  readonly definitionVersionId: string;
  readonly definitionKey: string;
  readonly semanticVersion: string;
  readonly versionHash: Sha256Hash;
  readonly documentHash: Sha256Hash;
  readonly approvalEventHash: Sha256Hash;
  readonly executionDocumentHash: Sha256Hash;
  readonly bindingId: string;
  readonly revision: number;
  readonly bindingHash: Sha256Hash;
  readonly effectiveFrom: string;
  readonly effectiveTo: string | null;
}

export interface ResolvedSourceAccessPolicyV1 {
  readonly policy: SourceAccessPolicyV1;
  readonly lineage: FrozenSourceAccessPolicyLineageV1;
}

export type SurveillanceAnalyticalDefinitionKindV1 =
  | "methodology_bundle"
  | "metric_definition"
  | "cohort_definition"
  | "bin_definition"
  | "entity_resolution_definition";

export interface FrozenAnalyticalDefinitionLineageV1 {
  readonly kind: SurveillanceAnalyticalDefinitionKindV1;
  readonly definitionVersionId: string;
  readonly definitionKey: string;
  readonly semanticVersion: string;
  readonly versionHash: Sha256Hash;
  readonly documentHash: Sha256Hash;
  readonly approvalEventHash: Sha256Hash;
  readonly executionDocumentHash: Sha256Hash;
}

export interface TerminalCertifiedPublicationLineageV1 {
  readonly publicationId: string;
  readonly publicationHash: Sha256Hash;
  readonly certificationManifestId: string;
  readonly certificationManifestHash: Sha256Hash;
  readonly certifiedAt: string;
  readonly snapshotId: string;
  readonly snapshotHash: Sha256Hash;
  readonly asOfDate: string;
  readonly datasetId: string;
  readonly datasetBindingId: string;
  readonly sourceContract: Readonly<z.infer<typeof SourceContractSelectorSchema>>;
  readonly scope: Readonly<z.infer<typeof ScopeSchema>>;
  readonly populationHash: Sha256Hash;
  readonly rowCount: number;
  readonly normalizedPopulationId: string;
  readonly mappingApplicationId: string;
  readonly mappingApplicationHash: Sha256Hash;
  readonly normalizedArtifact: Readonly<{
    artifactId: string;
    artifactContractVersion: 2;
    artifactHash: Sha256Hash;
    kind: "normalized_snapshot";
    mediaType: "application/json";
    contentHash: Sha256Hash;
    byteLength: number;
    uri: string;
    metadataHash: Sha256Hash;
    rowCount: number;
    populationHash: Sha256Hash;
    fieldSetHash: Sha256Hash;
  }>;
  readonly lineagePublicationHashes: readonly Sha256Hash[];
  readonly correctionLineageHash: Sha256Hash;
  readonly publishedAt: string;
}

export interface PortfolioSurveillanceAuthorizationDecisionProjectionV1 {
  readonly decisionId: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly policyFingerprint: string;
  readonly principalBinding: string;
  readonly tenantId: string;
  readonly principalId: string;
  readonly toolName: string;
  readonly datasetId: string;
  readonly requestedFields: readonly string[];
  readonly purpose: string;
  readonly evaluatedAtEpochSeconds: number;
  readonly matchedRuleIds: readonly string[];
  readonly obligations: PolicyObligations;
}

export interface PortfolioSurveillanceMetadataPreflightV1 {
  readonly contractVersion: 1;
  readonly operation: typeof OPERATION;
  readonly request: PortfolioSurveillanceAuthorizationRequestV1;
  readonly requestHash: Sha256Hash;
  readonly planningCutoff: string;
  readonly tenantId: string;
  readonly purpose: string;
  readonly publications: readonly TerminalCertifiedPublicationLineageV1[];
  readonly sourceSelectionHash: Sha256Hash;
  readonly sourceIdentityHash: Sha256Hash;
  readonly datasetId: string;
  readonly scopeHash: Sha256Hash;
  readonly sourceAccessPolicies: readonly FrozenSourceAccessPolicyLineageV1[];
  readonly sourceAccessPolicySetHash: Sha256Hash;
  readonly datasetScopeBindings: readonly FrozenDatasetScopeBindingLineageV1[];
  readonly datasetScopeBindingSetHash: Sha256Hash;
  readonly definitions: readonly FrozenAnalyticalDefinitionLineageV1[];
  readonly definitionSetHash: Sha256Hash;
  readonly requestedFields: readonly string[];
  readonly requestedFieldsHash: Sha256Hash;
  readonly requestedAggregateDimensionFields: readonly string[];
  readonly maximumPlannedCells: number;
  readonly maximumDisclosedItems: number;
  readonly minimumMetricCellCount: number;
  readonly authorization: PortfolioSurveillanceAuthorizationDecisionProjectionV1;
  readonly v4Preflight: PortfolioSurveillanceAuthorizationPreflightV4;
  readonly metadataHash: Sha256Hash;
}

export interface AuthorizedPortfolioSurveillancePreflightV1 {
  readonly metadata: PortfolioSurveillanceMetadataPreflightV1;
  /** Nominal runtime object; it cannot be reconstructed from JSON. */
  readonly permit: PermitPolicyDecision;
}

export type PortfolioSurveillanceAccessPreflightErrorCode =
  | "INVALID_REQUEST"
  | "PUBLICATION_NOT_FOUND"
  | "PUBLICATION_SUBSTITUTION"
  | "PUBLICATION_DISABLED"
  | "PUBLICATION_NOT_TERMINAL"
  | "CORRECTION_LINEAGE_INVALID"
  | "SOURCE_SET_MISMATCH"
  | "DEFINITION_NOT_FOUND"
  | "DEFINITION_SUBSTITUTION"
  | "DEFINITION_EVIDENCE_INVALID"
  | "SOURCE_POLICY_NOT_FOUND"
  | "SOURCE_POLICY_AMBIGUOUS"
  | "SOURCE_POLICY_OVERLAP"
  | "SOURCE_POLICY_EVIDENCE_INVALID"
  | "SOURCE_POLICY_COVERAGE_DENIED"
  | "GLOBAL_POLICY_DENIED"
  | "AUTHORIZATION_OBLIGATION_DENIED"
  | "INTEGRITY_FAILURE";

export class PortfolioSurveillanceAccessPreflightError extends Error {
  constructor(
    readonly code: PortfolioSurveillanceAccessPreflightErrorCode,
    message: string
  ) {
    super(message);
    this.name = "PortfolioSurveillanceAccessPreflightError";
  }
}

/**
 * Resolves exactly one currently effective, approved source-access policy
 * from a complete server-governed candidate-key set. Superseded and retired
 * frozen versions are never accepted as present authority.
 */
export class GovernedSourceAccessPolicyDirectoryV1 {
  constructor(
    readonly index: SourceAccessPolicyCandidateIndexV1,
    readonly definitions: EffectiveGovernedDefinitionResolutionPortV1
  ) {}

  async resolveExact(
    selectorValue: SourceAccessPolicySelectorV1,
    planningCutoffValue: string
  ): Promise<ResolvedSourceAccessPolicyV1> {
    const selector = sourcePolicySelector(selectorValue);
    const planningCutoff = parseWithSchema(
      IsoTimestampSchema,
      planningCutoffValue,
      "source policy planning cutoff"
    );
    const asOfDate = planningCutoff.slice(0, 10);
    const candidateSet = await this.index.listCandidateDefinitionKeys(selector);
    if (
      candidateSet === null ||
      typeof candidateSet !== "object" ||
      candidateSet.complete !== true ||
      !Array.isArray(candidateSet.definitionKeys) ||
      candidateSet.definitionKeys.length > MAXIMUM_POLICY_CANDIDATES
    ) {
      fail("SOURCE_POLICY_EVIDENCE_INVALID", "Source-policy candidate index was incomplete or invalid");
    }
    const keys = candidateSet.definitionKeys.map((value) =>
      parseWithSchema(IdentifierSchema, value, "source policy definition key")
    );
    if (new Set(keys).size !== keys.length) {
      fail("SOURCE_POLICY_EVIDENCE_INVALID", "Source-policy candidate index returned duplicate keys");
    }
    const candidates: ResolvedSourceAccessPolicyV1[] = [];
    for (const definitionKey of keys) {
      const resolved = await this.definitions.resolveEffective({
        tenantId: selector.tenantId,
        kind: "source_access_policy",
        definitionKey,
        asOfDate
      });
      if (resolved === undefined) continue;
      candidates.push(
        parseResolvedSourcePolicy(resolved, definitionKey, selector, planningCutoff)
      );
    }
    const effective = candidates.filter(
      ({ policy }) =>
        policy.effectiveFrom <= asOfDate &&
        (policy.effectiveTo === undefined || asOfDate < policy.effectiveTo)
    );
    if (effective.length === 0) {
      fail("SOURCE_POLICY_NOT_FOUND", "No source-access policy is effective at the planning cutoff");
    }
    if (effective.length !== 1) {
      fail("SOURCE_POLICY_AMBIGUOUS", "More than one source-access policy is effective");
    }
    return effective[0]!;
  }
}

export interface PortfolioSurveillanceAuthorizationPreflightDependenciesV1 {
  readonly publications: SurveillancePublicationReadPortV1;
  readonly sourcePolicies: GovernedSourceAccessPolicyDirectoryV1;
  readonly datasetScopeBindings: EffectiveGovernedDefinitionResolutionPortV1;
  readonly analyticalDefinitions: FrozenGovernedDefinitionResolutionPortV1;
  readonly globalAuthorizer: PortfolioSurveillanceGlobalAuthorizerV1;
}

/**
 * Resolves and authorizes metadata only. There is deliberately no normalized
 * artifact, row, connector, SQL, or object-storage read capability in these
 * dependencies.
 */
export class PortfolioSurveillanceAuthorizationPreflightServiceV1 {
  constructor(readonly dependencies: PortfolioSurveillanceAuthorizationPreflightDependenciesV1) {}

  async authorize(
    requestValue: unknown,
    contextValue: PortfolioSurveillanceAuthorizationContextV1
  ): Promise<AuthorizedPortfolioSurveillancePreflightV1> {
    const request = parsePortfolioSurveillanceAuthorizationRequestV1(requestValue);
    const context = authorizationContext(contextValue);
    const publications = await resolveTerminalPublications(
      request,
      context,
      this.dependencies.publications
    );
    const first = publications[0]!;
    const datasetScopeBindings = await resolveDatasetScopeBindings(
      publications,
      context,
      this.dependencies.datasetScopeBindings
    );
    const datasetScopeBindingSetHash = canonicalHash(datasetScopeBindings);
    const definitions = await resolveAnalyticalDefinitions(
      request.definitionVersionIds,
      context.principal.tenantId,
      context.planningCutoff,
      this.dependencies.analyticalDefinitions
    );
    const requestedFields = derivePortfolioSurveillanceRequestedFieldsV1({
      metricDefinitions: definitions.metrics,
      cohortDefinitions: definitions.cohorts,
      binDefinitions: definitions.bins,
      entityResolutionDefinitions: definitions.entityResolutions
    });
    const requestedAggregateDimensionFields = deriveAggregateDimensionFields(definitions.metrics);
    const sourceSelector: SourceAccessPolicySelectorV1 = deepFreeze({
      tenantId: context.principal.tenantId,
      datasetId: first.datasetId,
      sourceContract: first.sourceContract,
      scope: first.scope,
      purpose: context.purpose
    });
    const resolvedSourcePolicy = await this.dependencies.sourcePolicies.resolveExact(
      sourceSelector,
      context.planningCutoff
    );
    assertSourcePolicyCoverage(
      resolvedSourcePolicy.policy,
      requestedFields,
      requestedAggregateDimensionFields
    );
    const sourcePolicies = deepFreeze([resolvedSourcePolicy.lineage]);
    const definitionLineage = definitions.lineage;
    const requestHash = canonicalHash(request);
    const sourceSelectionHash = canonicalHash({
      planningCutoff: context.planningCutoff,
      terminalPublications: publications.map((publication) => ({
        asOfDate: publication.asOfDate,
        certificationManifestHash: publication.certificationManifestHash,
        certificationManifestId: publication.certificationManifestId,
        correctionLineageHash: publication.correctionLineageHash,
        publicationHash: publication.publicationHash,
        publicationId: publication.publicationId,
        snapshotHash: publication.snapshotHash,
        snapshotId: publication.snapshotId
      }))
    });
    const sourceIdentityHash = canonicalHash(
      publications.map((publication) => ({
        datasetId: publication.datasetId,
        source: publication.sourceContract,
        scope: publication.scope
      }))
    );
    const sourceAccessPolicySetHash = canonicalHash(sourcePolicies);
    const definitionSetHash = canonicalHash(definitionLineage);
    const requestedFieldsHash = canonicalHash(requestedFields);
    const maximumPlannedCells = definitions.metrics.reduce(
      (sum, metric) => safeAdd(sum, metric.maximumCells, "metric cell budget"),
      0
    );
    if (maximumPlannedCells < 1 || maximumPlannedCells > MAXIMUM_CELLS) {
      fail("DEFINITION_EVIDENCE_INVALID", "Frozen metrics exceed the operation cell budget");
    }
    const maximumDisclosedItems = safeAdd(
      maximumPlannedCells,
      safeAdd(
        definitions.metrics.length,
        definitions.metrics.length * 4,
        "metric header and warning budget"
      ),
      "maximum disclosed item budget"
    );
    const minimumMetricCellCount = Math.min(
      ...definitions.metrics.map(({ privacy }) => privacy.minimumCellCount)
    );
    const decision = await this.dependencies.globalAuthorizer.authorize({
      principal: context.principal,
      toolName: POLICY_TOOL_NAME,
      dataset: { id: first.datasetId, tenantId: context.principal.tenantId },
      fields: requestedFields,
      purpose: context.purpose,
      nowEpochSeconds: Math.floor(Date.parse(context.planningCutoff) / 1_000)
    });
    try {
      assertPermitDecision(decision);
    } catch {
      fail("GLOBAL_POLICY_DENIED", "Global authorization policy denied portfolio surveillance");
    }
    assertPermitBindings(decision, context, first.datasetId, requestedFields);
    assertAggregateOnlyObligations(
      decision.obligations,
      maximumDisclosedItems,
      minimumMetricCellCount
    );
    const authorization = decisionProjection(decision, context.principal.principalId);
    const v4Preflight = createPortfolioSurveillanceAuthorizationPreflightV4({
      contractVersion: 1,
      operation: OPERATION,
      tenantId: context.principal.tenantId,
      purpose: context.purpose,
      descriptor: portfolioSurveillanceDescriptorBindingV4(),
      requestHash,
      datasetId: first.datasetId,
      scopeHash: canonicalHash(first.scope),
      sourceIdentityHash,
      sourceSelectionHash,
      sourceAccessPolicySetHash,
      datasetScopeBindingSetHash,
      definitionSetHash,
      requestedFields: [...requestedFields],
      requestedFieldsHash,
      planningCutoff: context.planningCutoff,
      maximumPlannedCells,
      minimumMetricCellCount
    });
    const body = {
      contractVersion: 1 as const,
      operation: OPERATION,
      request,
      requestHash,
      planningCutoff: context.planningCutoff,
      tenantId: context.principal.tenantId,
      purpose: context.purpose,
      publications,
      sourceSelectionHash,
      sourceIdentityHash,
      datasetId: first.datasetId,
      scopeHash: canonicalHash(first.scope),
      sourceAccessPolicies: sourcePolicies,
      sourceAccessPolicySetHash,
      datasetScopeBindings,
      datasetScopeBindingSetHash,
      definitions: definitionLineage,
      definitionSetHash,
      requestedFields,
      requestedFieldsHash,
      requestedAggregateDimensionFields,
      maximumPlannedCells,
      maximumDisclosedItems,
      minimumMetricCellCount,
      authorization,
      v4Preflight
    };
    const metadata = parsePortfolioSurveillanceMetadataPreflightV1({
      ...body,
      metadataHash: canonicalHash(body)
    });
    return Object.freeze({ metadata, permit: decision });
  }
}

export function parsePortfolioSurveillanceAuthorizationRequestV1(
  value: unknown
): PortfolioSurveillanceAuthorizationRequestV1 {
  const parsed = parseWithSchema(RequestSchema, value, "PortfolioSurveillanceAuthorizationRequestV1");
  return deepFreeze({
    ...parsed,
    sources: [...parsed.sources].sort(
      (left, right) => compare(left.certificationManifestId, right.certificationManifestId)
    ),
    definitionVersionIds: [...parsed.definitionVersionIds].sort(compare)
  });
}

/** Verifies the canonical/self-hashed metadata projection, not runtime authority. */
export function parsePortfolioSurveillanceMetadataPreflightV1(
  value: unknown
): PortfolioSurveillanceMetadataPreflightV1 {
  const record = strictRecord(value, [
    "authorization",
    "contractVersion",
    "datasetId",
    "datasetScopeBindingSetHash",
    "datasetScopeBindings",
    "definitionSetHash",
    "definitions",
    "maximumPlannedCells",
    "maximumDisclosedItems",
    "metadataHash",
    "minimumMetricCellCount",
    "operation",
    "planningCutoff",
    "publications",
    "purpose",
    "request",
    "requestHash",
    "requestedAggregateDimensionFields",
    "requestedFields",
    "requestedFieldsHash",
    "scopeHash",
    "sourceAccessPolicies",
    "sourceAccessPolicySetHash",
    "sourceIdentityHash",
    "sourceSelectionHash",
    "tenantId",
    "v4Preflight"
  ], "PortfolioSurveillanceMetadataPreflightV1");
  const metadataHash = parseWithSchema(Sha256HashSchema, record.metadataHash, "metadata hash");
  const { metadataHash: _metadataHash, ...body } = record;
  assertCanonicalHash(body, metadataHash, "PortfolioSurveillanceMetadataPreflightV1");
  const request = parsePortfolioSurveillanceAuthorizationRequestV1(record.request);
  const requestHash = parseWithSchema(Sha256HashSchema, record.requestHash, "request hash");
  if (canonicalHash(request) !== requestHash) integrity("Preflight request hash did not verify");
  const v4Preflight = parsePortfolioSurveillanceAuthorizationPreflightV4(record.v4Preflight);
  const tenantId = parseWithSchema(IdentifierSchema, record.tenantId, "tenantId");
  const purpose = parseWithSchema(IdentifierSchema, record.purpose, "purpose");
  const datasetId = parseWithSchema(IdentifierSchema, record.datasetId, "datasetId");
  const planningCutoff = parseWithSchema(IsoTimestampSchema, record.planningCutoff, "planningCutoff");
  const sourceSelectionHash = parseWithSchema(
    Sha256HashSchema,
    record.sourceSelectionHash,
    "sourceSelectionHash"
  );
  const sourceIdentityHash = parseWithSchema(
    Sha256HashSchema,
    record.sourceIdentityHash,
    "sourceIdentityHash"
  );
  const sourceAccessPolicySetHash = parseWithSchema(
    Sha256HashSchema,
    record.sourceAccessPolicySetHash,
    "sourceAccessPolicySetHash"
  );
  const datasetScopeBindingSetHash = parseWithSchema(
    Sha256HashSchema,
    record.datasetScopeBindingSetHash,
    "datasetScopeBindingSetHash"
  );
  const definitionSetHash = parseWithSchema(
    Sha256HashSchema,
    record.definitionSetHash,
    "definitionSetHash"
  );
  const requestedFieldsHash = parseWithSchema(
    Sha256HashSchema,
    record.requestedFieldsHash,
    "requestedFieldsHash"
  );
  const requestedFields = sortedIdentifiers(record.requestedFields, "requestedFields", 1, 2_000);
  const requestedAggregateDimensionFields = sortedIdentifiers(
    record.requestedAggregateDimensionFields,
    "requestedAggregateDimensionFields",
    0,
    256
  );
  const publications = projectionRecords(
    record.publications,
    "publications",
    MINIMUM_SOURCES,
    MAXIMUM_SOURCES
  ) as unknown as readonly TerminalCertifiedPublicationLineageV1[];
  const sourceAccessPolicies = projectionRecords(
    record.sourceAccessPolicies,
    "sourceAccessPolicies",
    1,
    MAXIMUM_POLICY_CANDIDATES
  ) as unknown as readonly FrozenSourceAccessPolicyLineageV1[];
  const datasetScopeBindings = projectionRecords(
    record.datasetScopeBindings,
    "datasetScopeBindings",
    1,
    MAXIMUM_SOURCES
  ) as unknown as readonly FrozenDatasetScopeBindingLineageV1[];
  const definitions = projectionRecords(
    record.definitions,
    "definitions",
    MINIMUM_DEFINITIONS,
    MAXIMUM_DEFINITIONS
  ) as unknown as readonly FrozenAnalyticalDefinitionLineageV1[];
  const maximumPlannedCells = boundedInteger(
    record.maximumPlannedCells,
    "maximumPlannedCells",
    1,
    MAXIMUM_CELLS
  );
  const maximumDisclosedItems = boundedInteger(
    record.maximumDisclosedItems,
    "maximumDisclosedItems",
    1,
    MAXIMUM_CELLS + MAXIMUM_METRICS * 5
  );
  const minimumMetricCellCount = boundedInteger(
    record.minimumMetricCellCount,
    "minimumMetricCellCount",
    1,
    100_000
  );
  const scopeHash = parseWithSchema(Sha256HashSchema, record.scopeHash, "scopeHash");
  const authorization = strictRecord(record.authorization, [
    "datasetId",
    "decisionId",
    "evaluatedAtEpochSeconds",
    "matchedRuleIds",
    "obligations",
    "policyFingerprint",
    "policyId",
    "policyVersion",
    "principalBinding",
    "principalId",
    "purpose",
    "requestedFields",
    "tenantId",
    "toolName"
  ], "authorization projection");
  validatePublicationProjections(publications);
  validateFrozenLineageReferences(sourceAccessPolicies, "source access policy");
  validateFrozenLineageReferences(datasetScopeBindings, "dataset-scope binding");
  validateFrozenLineageReferences(definitions, "analytical definition");
  validateAuthorizationProjection(
    authorization,
    maximumDisclosedItems,
    minimumMetricCellCount
  );
  const metricCount = definitions.filter(({ kind }) => kind === "metric_definition").length;
  const expectedDisclosedItems = safeAdd(
    maximumPlannedCells,
    metricCount * 5,
    "parsed disclosed item budget"
  );
  const expectedSelectionHash = canonicalHash({
    planningCutoff,
    terminalPublications: publications.map((publication) => ({
      asOfDate: publication.asOfDate,
      certificationManifestHash: publication.certificationManifestHash,
      certificationManifestId: publication.certificationManifestId,
      correctionLineageHash: publication.correctionLineageHash,
      publicationHash: publication.publicationHash,
      publicationId: publication.publicationId,
      snapshotHash: publication.snapshotHash,
      snapshotId: publication.snapshotId
    }))
  });
  const expectedSourceIdentityHash = canonicalHash(
    publications.map((publication) => ({
      datasetId: publication.datasetId,
      source: publication.sourceContract,
      scope: publication.scope
    }))
  );
  const requestSourceHash = canonicalHash(
    request.sources.map(({ certificationManifestId }) => certificationManifestId)
  );
  const publicationRequestHash = canonicalHash(
    publications
      .map(({ certificationManifestId }) => certificationManifestId)
      .sort(compare)
  );
  if (
    v4Preflight.tenantId !== tenantId ||
    v4Preflight.purpose !== purpose ||
    v4Preflight.datasetId !== datasetId ||
    v4Preflight.planningCutoff !== planningCutoff ||
    v4Preflight.requestHash !== requestHash ||
    v4Preflight.sourceSelectionHash !== sourceSelectionHash ||
    v4Preflight.sourceIdentityHash !== sourceIdentityHash ||
    v4Preflight.sourceAccessPolicySetHash !== sourceAccessPolicySetHash ||
    v4Preflight.datasetScopeBindingSetHash !== datasetScopeBindingSetHash ||
    v4Preflight.definitionSetHash !== definitionSetHash ||
    v4Preflight.requestedFieldsHash !== requestedFieldsHash ||
    v4Preflight.scopeHash !== scopeHash ||
    v4Preflight.maximumPlannedCells !== maximumPlannedCells ||
    v4Preflight.minimumMetricCellCount !== minimumMetricCellCount ||
    canonicalJson(v4Preflight.requestedFields) !== canonicalJson(requestedFields) ||
    canonicalHash(requestedFields) !== requestedFieldsHash ||
    maximumDisclosedItems !== expectedDisclosedItems ||
    canonicalHash(sourceAccessPolicies) !== sourceAccessPolicySetHash ||
    canonicalHash(datasetScopeBindings) !== datasetScopeBindingSetHash ||
    canonicalHash(definitions) !== definitionSetHash ||
    canonicalHash(definitions.map(({ definitionVersionId }) => definitionVersionId).sort(compare)) !==
      canonicalHash(request.definitionVersionIds) ||
    new Set(datasetScopeBindings.map(({ bindingId }) => bindingId)).size !==
      new Set(publications.map(({ datasetBindingId }) => datasetBindingId)).size ||
    publications.some(
      ({ datasetBindingId }) =>
        !datasetScopeBindings.some(({ bindingId }) => bindingId === datasetBindingId)
    ) ||
    expectedSelectionHash !== sourceSelectionHash ||
    expectedSourceIdentityHash !== sourceIdentityHash ||
    requestSourceHash !== publicationRequestHash ||
    publications.some(
      (publication) =>
        publication.datasetId !== datasetId || canonicalHash(publication.scope) !== scopeHash
    ) ||
    authorization.tenantId !== tenantId ||
    authorization.purpose !== purpose ||
    authorization.datasetId !== datasetId ||
    authorization.toolName !== POLICY_TOOL_NAME ||
    authorization.evaluatedAtEpochSeconds !== Math.floor(Date.parse(planningCutoff) / 1_000) ||
    canonicalJson(authorization.requestedFields) !== canonicalJson(requestedFields) ||
    canonicalJson(v4Preflight.descriptor) !==
      canonicalJson(portfolioSurveillanceDescriptorBindingV4())
  ) {
    integrity("V4 preflight did not match its resolved metadata authority");
  }
  void requestedAggregateDimensionFields;
  return deepFreeze(value as PortfolioSurveillanceMetadataPreflightV1);
}

export function assertAuthorizedPortfolioSurveillancePreflightV1(
  value: AuthorizedPortfolioSurveillancePreflightV1
): void {
  const metadata = parsePortfolioSurveillanceMetadataPreflightV1(value.metadata);
  try {
    assertPermitDecision(value.permit);
  } catch {
    integrity("Portfolio surveillance preflight permit is not runtime-issued");
  }
  const projection = decisionProjection(value.permit, metadata.authorization.principalId);
  if (canonicalJson(projection) !== canonicalJson(metadata.authorization)) {
    integrity("Runtime policy decision did not match its canonical preflight projection");
  }
}

async function resolveTerminalPublications(
  request: PortfolioSurveillanceAuthorizationRequestV1,
  context: Readonly<{
    principal: VerifiedPrincipalContext;
    purpose: string;
    planningCutoff: string;
  }>,
  port: SurveillancePublicationReadPortV1
): Promise<readonly TerminalCertifiedPublicationLineageV1[]> {
  const terminals: TerminalCertifiedPublicationLineageV1[] = [];
  for (const source of request.sources) {
    const byCertificationValue = await port.getByCertificationManifest(
      context.principal.tenantId,
      source.certificationManifestId
    );
    if (byCertificationValue === undefined) {
      fail("PUBLICATION_NOT_FOUND", "Certification manifest publication was not found");
    }
    const byCertification = parsePublication(
      byCertificationValue,
      "PUBLICATION_SUBSTITUTION"
    );
    const directValue = await port.get(
      context.principal.tenantId,
      byCertification.publicationId
    );
    if (directValue === undefined) {
      fail("PUBLICATION_NOT_FOUND", "Derived certified snapshot publication was not found");
    }
    const direct = parsePublication(directValue, "PUBLICATION_SUBSTITUTION");
    if (
      direct.tenantId !== context.principal.tenantId ||
      direct.certification.certificationManifestId !== source.certificationManifestId ||
      byCertification.tenantId !== context.principal.tenantId ||
      byCertification.publicationHash !== direct.publicationHash
    ) {
      fail("PUBLICATION_SUBSTITUTION", "Publication authority substituted tenant or certification evidence");
    }
    assertPublicationAvailableAtCutoff(direct, context.planningCutoff);
    const sourceContract = publishedSourceSelector(direct);
    const page = await port.listByScopeAsOf({
      tenantId: context.principal.tenantId,
      datasetId: direct.datasetId,
      sourceContract,
      scope: direct.scope,
      asOfDate: direct.snapshot.asOfDate,
      publishedThrough: context.planningCutoff,
      maximumResults: MAXIMUM_LINEAGE_PUBLICATIONS
    });
    if (
      page === null ||
      typeof page !== "object" ||
      page.complete !== true ||
      !Array.isArray(page.publications) ||
      page.publications.length < 1 ||
      page.publications.length > MAXIMUM_LINEAGE_PUBLICATIONS
    ) {
      fail("CORRECTION_LINEAGE_INVALID", "Publication lineage query was incomplete or invalid");
    }
    const candidates: CertifiedSnapshotPublicationV1[] = [];
    for (const candidate of page.publications) {
      const parsed = parsePublication(candidate, "CORRECTION_LINEAGE_INVALID");
      assertPublicationMatchesQuery(parsed, direct, sourceContract, context.planningCutoff);
      const disabled = await port.getDisable(context.principal.tenantId, parsed.publicationId);
      if (disabled !== undefined) {
        assertDisableEvent(disabled, parsed);
        if (disabled.disabledAt <= context.planningCutoff) {
          fail("PUBLICATION_DISABLED", "Correction lineage contains a disabled publication");
        }
      }
      candidates.push(parsed);
    }
    const selected = terminalPublication(candidates, direct);
    terminals.push(publicationLineageProjection(selected.terminal, selected.chain));
  }
  const ordered = terminals.sort(
    (left, right) =>
      compare(left.asOfDate, right.asOfDate) ||
      compare(left.certificationManifestId, right.certificationManifestId)
  );
  const dates = new Set<string>();
  const first = ordered[0]!;
  for (const publication of ordered) {
    if (dates.has(publication.asOfDate)) {
      fail("SOURCE_SET_MISMATCH", "Terminal surveillance publications have duplicate as-of dates");
    }
    dates.add(publication.asOfDate);
    if (
      publication.datasetId !== first.datasetId ||
      canonicalJson(publication.sourceContract) !== canonicalJson(first.sourceContract) ||
      canonicalJson(publication.scope) !== canonicalJson(first.scope)
    ) {
      fail("SOURCE_SET_MISMATCH", "Surveillance publications must share dataset, source revision, and scope");
    }
  }
  return deepFreeze(ordered);
}

function terminalPublication(
  candidates: readonly CertifiedSnapshotPublicationV1[],
  requested: CertifiedSnapshotPublicationV1
): Readonly<{
  terminal: CertifiedSnapshotPublicationV1;
  chain: readonly CertifiedSnapshotPublicationV1[];
}> {
  const bySnapshot = new Map<string, CertifiedSnapshotPublicationV1>();
  const childByParent = new Map<string, CertifiedSnapshotPublicationV1>();
  const roots: CertifiedSnapshotPublicationV1[] = [];
  for (const candidate of candidates) {
    const key = snapshotKey(candidate.snapshot.snapshotId, candidate.snapshot.snapshotHash);
    if (bySnapshot.has(key)) {
      fail("CORRECTION_LINEAGE_INVALID", "Correction lineage contains duplicate snapshot identities");
    }
    bySnapshot.set(key, candidate);
    if (candidate.snapshot.correction.kind === "original") roots.push(candidate);
  }
  for (const candidate of candidates) {
    if (candidate.snapshot.correction.kind === "original") continue;
    const parentKey = snapshotKey(
      candidate.snapshot.correction.correctsSnapshotId,
      candidate.snapshot.correction.correctsSnapshotHash
    );
    if (!bySnapshot.has(parentKey)) {
      fail("CORRECTION_LINEAGE_INVALID", "Correction lineage contains a missing or cross-period parent");
    }
    if (childByParent.has(parentKey)) {
      fail("CORRECTION_LINEAGE_INVALID", "Correction lineage contains a fork");
    }
    childByParent.set(parentKey, candidate);
  }
  if (roots.length !== 1) {
    fail("CORRECTION_LINEAGE_INVALID", "Correction lineage must contain exactly one original root");
  }
  const chain: CertifiedSnapshotPublicationV1[] = [];
  const visited = new Set<string>();
  let current = roots[0]!;
  let expectedSequence = 1;
  for (;;) {
    const currentKey = snapshotKey(current.snapshot.snapshotId, current.snapshot.snapshotHash);
    if (visited.has(currentKey)) fail("CORRECTION_LINEAGE_INVALID", "Correction lineage contains a cycle");
    visited.add(currentKey);
    chain.push(current);
    const child = childByParent.get(currentKey);
    if (child === undefined) break;
    if (
      child.snapshot.correction.kind !== "correction" ||
      child.snapshot.correction.correctionSequence !== expectedSequence ||
      current.snapshot.knowledge.persistedAt > child.snapshot.correction.detectedAt ||
      child.snapshot.correction.detectedAt > child.certification.certifiedAt ||
      child.certification.certifiedAt > child.publishedAt
    ) {
      fail(
        "CORRECTION_LINEAGE_INVALID",
        "Correction lineage contains a sequence gap or impossible temporal edge"
      );
    }
    expectedSequence += 1;
    current = child;
  }
  if (visited.size !== candidates.length) {
    fail("CORRECTION_LINEAGE_INVALID", "Correction lineage is disconnected or cyclic");
  }
  if (current.publicationHash !== requested.publicationHash) {
    fail("PUBLICATION_NOT_TERMINAL", "Requested publication is obsolete under correction lineage");
  }
  return deepFreeze({ terminal: current, chain });
}

interface ResolvedAnalyticalDefinitions {
  readonly metrics: readonly MetricDefinitionV1[];
  readonly cohorts: readonly CohortDefinitionV1[];
  readonly bins: readonly BinDefinitionV1[];
  readonly entityResolutions: readonly EntityResolutionDefinitionV1[];
  readonly lineage: readonly FrozenAnalyticalDefinitionLineageV1[];
}

async function resolveAnalyticalDefinitions(
  definitionVersionIds: readonly string[],
  tenantId: string,
  planningCutoff: string,
  port: FrozenGovernedDefinitionResolutionPortV1
): Promise<ResolvedAnalyticalDefinitions> {
  const resolved: ResolvedGovernedDefinitionV2[] = [];
  for (const definitionVersionId of definitionVersionIds) {
    const value = await port.resolveFrozenDefinition(tenantId, definitionVersionId);
    if (value === undefined) {
      fail("DEFINITION_NOT_FOUND", `Frozen analytical definition ${definitionVersionId} was not found`);
    }
    if (value.reference.definitionVersionId !== definitionVersionId) {
      fail("DEFINITION_SUBSTITUTION", "Frozen analytical definition authority substituted an id");
    }
    const parsed = parseResolvedDefinition(value, definitionVersionId);
    if (parsed.approvalEvidence.approvedAt > planningCutoff) {
      fail("DEFINITION_EVIDENCE_INVALID", "Frozen analytical definition was approved after planning cutoff");
    }
    resolved.push(parsed);
  }
  const allowed = new Set<SurveillanceAnalyticalDefinitionKindV1>([
    "methodology_bundle",
    "metric_definition",
    "cohort_definition",
    "bin_definition",
    "entity_resolution_definition"
  ]);
  for (const value of resolved) {
    if (!allowed.has(value.reference.kind as SurveillanceAnalyticalDefinitionKindV1)) {
      fail("DEFINITION_EVIDENCE_INVALID", `Unsupported definition kind ${value.reference.kind}`);
    }
  }
  const methodologyValues = resolved.filter(
    ({ reference }) => reference.kind === "methodology_bundle"
  );
  if (methodologyValues.length !== 1) {
    fail("DEFINITION_EVIDENCE_INVALID", "Exactly one methodology bundle is required");
  }
  const methodology = parseWithSchema(
    MethodologyBundleV1Schema,
    methodologyValues[0]!.executionDocument,
    "portfolio surveillance methodology"
  );
  assertDefinitionIdentity(methodologyValues[0]!, methodology.bundleId, methodology.version);
  const metrics = definitionDocuments<MetricDefinitionV1>(
    resolved,
    "metric_definition",
    validateMetricDefinitionV1,
    tenantId
  );
  if (metrics.length < 1 || metrics.length > MAXIMUM_METRICS) {
    fail("DEFINITION_EVIDENCE_INVALID", "Portfolio surveillance requires 1..1000 metrics");
  }
  for (const metric of metrics) assertPortfolioSurveillanceMetricCompatibilityV1(metric);
  const cohorts = definitionDocuments<CohortDefinitionV1>(
    resolved,
    "cohort_definition",
    validateCohortDefinitionV1,
    tenantId
  );
  const bins = definitionDocuments<BinDefinitionV1>(
    resolved,
    "bin_definition",
    validateBinDefinitionV1,
    tenantId
  );
  const entityResolutions = definitionDocuments<EntityResolutionDefinitionV1>(
    resolved,
    "entity_resolution_definition",
    (value) => validateEntityResolutionDefinitionV1(value, tenantId),
    tenantId
  );
  validateSupportingDefinitionSets(metrics, cohorts, bins, entityResolutions);
  validateMethodologyDefinitionSet(methodology.requiredDefinitionKinds, resolved);
  const lineage = resolved
    .map(analyticalDefinitionLineage)
    .sort(
      (left, right) =>
        compare(left.kind, right.kind) ||
        compare(left.definitionVersionId, right.definitionVersionId)
    );
  if (new Set(lineage.map(({ definitionVersionId }) => definitionVersionId)).size !== lineage.length) {
    fail("DEFINITION_EVIDENCE_INVALID", "Frozen analytical definition ids are not unique");
  }
  return deepFreeze({
    metrics: sortEngineDefinitions(metrics),
    cohorts: sortEngineDefinitions(cohorts),
    bins: sortEngineDefinitions(bins),
    entityResolutions: sortEngineDefinitions(entityResolutions),
    lineage
  });
}

function parseResolvedDefinition(
  value: ResolvedGovernedDefinitionV2,
  expectedDefinitionVersionId: string
): ResolvedGovernedDefinitionV2 {
  if (value === null || typeof value !== "object") {
    fail("DEFINITION_EVIDENCE_INVALID", "Frozen definition evidence is not an object");
  }
  const reference = value.reference;
  const approval = value.approvalEvidence;
  if (
    reference === undefined ||
    approval === undefined ||
    reference.definitionVersionId !== expectedDefinitionVersionId ||
    !IdentifierSchema.safeParse(reference.definitionVersionId).success ||
    !IdentifierSchema.safeParse(reference.definitionKey).success ||
    !Sha256HashSchema.safeParse(reference.versionHash).success ||
    !Sha256HashSchema.safeParse(reference.documentHash).success ||
    !Sha256HashSchema.safeParse(reference.approvalEventHash).success ||
    approval.status !== "approved" ||
    approval.approvalEventHash !== reference.approvalEventHash ||
    approval.proposedBy === approval.approvedBy ||
    !IsoTimestampSchema.safeParse(approval.approvedAt).success
  ) {
    fail("DEFINITION_EVIDENCE_INVALID", "Frozen definition reference or approval evidence is invalid");
  }
  canonicalHash(value.executionDocument);
  return value;
}

function definitionDocuments<T extends { readonly definitionId: string; readonly version: number }>(
  resolved: readonly ResolvedGovernedDefinitionV2[],
  kind: SurveillanceAnalyticalDefinitionKindV1,
  validate: (value: T) => unknown,
  tenantId: string
): readonly T[] {
  return resolved
    .filter(({ reference }) => reference.kind === kind)
    .map((value) => {
      try {
        validate(value.executionDocument as unknown as T);
      } catch {
        fail("DEFINITION_EVIDENCE_INVALID", `Frozen ${kind} failed engine validation`);
      }
      const document = value.executionDocument as unknown as T & {
        readonly approval: Readonly<{
          status: string;
          proposedBy?: string;
          approvedBy?: string;
          approvedAt?: string;
        }>;
        readonly tenantId?: string;
      };
      assertDefinitionIdentity(value, document.definitionId, `${document.version}.0.0`);
      if (
        document.approval.status !== "approved" ||
        document.approval.proposedBy !== value.approvalEvidence.proposedBy ||
        document.approval.approvedBy !== value.approvalEvidence.approvedBy ||
        document.approval.approvedAt !== value.approvalEvidence.approvedAt ||
        (document.tenantId !== undefined && document.tenantId !== tenantId)
      ) {
        fail("DEFINITION_EVIDENCE_INVALID", `Frozen ${kind} execution approval did not verify`);
      }
      assertExecutionDocumentHash(value, document);
      return cloneCanonical(document);
    });
}

function assertDefinitionIdentity(
  value: ResolvedGovernedDefinitionV2,
  definitionKey: string,
  semanticVersion: string
): void {
  if (
    value.reference.definitionKey !== definitionKey ||
    value.reference.semanticVersion !== semanticVersion
  ) {
    fail("DEFINITION_SUBSTITUTION", "Frozen definition logical identity or version was substituted");
  }
}

function assertExecutionDocumentHash(
  value: ResolvedGovernedDefinitionV2,
  document: Readonly<Record<string, unknown>>
): void {
  const direct = canonicalHash(document);
  const neutral = canonicalHash({
    ...document,
    approval: {
      status: "pending_durable_approval",
      authority: "governed_definition_v2_lifecycle"
    }
  });
  if (value.reference.documentHash !== direct && value.reference.documentHash !== neutral) {
    fail("DEFINITION_EVIDENCE_INVALID", "Frozen definition execution document drifted from its hash");
  }
}

function analyticalDefinitionLineage(
  value: ResolvedGovernedDefinitionV2
): FrozenAnalyticalDefinitionLineageV1 {
  return deepFreeze({
    kind: value.reference.kind as SurveillanceAnalyticalDefinitionKindV1,
    definitionVersionId: value.reference.definitionVersionId,
    definitionKey: value.reference.definitionKey,
    semanticVersion: value.reference.semanticVersion,
    versionHash: value.reference.versionHash,
    documentHash: value.reference.documentHash,
    approvalEventHash: value.reference.approvalEventHash,
    executionDocumentHash: canonicalHash(value.executionDocument)
  });
}

function parseResolvedSourcePolicy(
  resolvedValue: ResolvedGovernedDefinitionV2,
  expectedDefinitionKey: string,
  selector: SourceAccessPolicySelectorV1,
  planningCutoff: string
): ResolvedSourceAccessPolicyV1 {
  const resolved = parseResolvedDefinition(
    resolvedValue,
    resolvedValue.reference.definitionVersionId
  );
  if (resolved.reference.kind !== "source_access_policy") {
    fail("SOURCE_POLICY_EVIDENCE_INVALID", "Source-policy index resolved a different definition kind");
  }
  let policy: SourceAccessPolicyV1;
  try {
    policy = parseSourceAccessPolicyV1(resolved.executionDocument);
  } catch {
    fail("SOURCE_POLICY_EVIDENCE_INVALID", "Frozen source-access policy document is invalid");
  }
  if (
    resolved.reference.definitionKey !== expectedDefinitionKey ||
    resolved.reference.definitionKey !== policy.policyId ||
    resolved.reference.semanticVersion !== `${policy.revision}.0.0` ||
    resolved.reference.documentHash !== canonicalHash(policy) ||
    resolved.approvalEvidence.approvedAt > planningCutoff ||
    policy.tenantId !== selector.tenantId ||
    policy.datasetId !== selector.datasetId ||
    canonicalJson({ ...policy.sourceContract, sourceKey: selector.sourceContract.sourceKey }) !==
      canonicalJson(selector.sourceContract) ||
    canonicalJson(policy.scope) !== canonicalJson(selector.scope) ||
    policy.purpose !== selector.purpose
  ) {
    fail("SOURCE_POLICY_EVIDENCE_INVALID", "Frozen source-access policy selector or hash was substituted");
  }
  return deepFreeze({
    policy,
    lineage: {
      definitionVersionId: resolved.reference.definitionVersionId,
      definitionKey: resolved.reference.definitionKey,
      semanticVersion: resolved.reference.semanticVersion,
      versionHash: resolved.reference.versionHash,
      documentHash: resolved.reference.documentHash,
      approvalEventHash: resolved.reference.approvalEventHash,
      executionDocumentHash: canonicalHash(resolved.executionDocument),
      policyId: policy.policyId,
      revision: policy.revision,
      policyHash: policy.policyHash,
      effectiveFrom: policy.effectiveFrom,
      effectiveTo: policy.effectiveTo ?? null
    }
  });
}

function validateSupportingDefinitionSets(
  metrics: readonly MetricDefinitionV1[],
  cohorts: readonly CohortDefinitionV1[],
  bins: readonly BinDefinitionV1[],
  entityResolutions: readonly EntityResolutionDefinitionV1[]
): void {
  const requiredCohorts = new Set<string>();
  const requiredBins = new Set<string>();
  const requiredResolutions = new Set<string>();
  for (const metric of metrics) {
    const config = metric.configuration;
    if (config.kind === "roll_cure") requiredBins.add(config.binDefinitionId);
    if (config.kind === "balance_utilization" && config.cohortDefinitionId !== undefined) {
      requiredCohorts.add(config.cohortDefinitionId);
    }
    if (config.kind === "concentration") {
      if (config.binDefinitionId !== undefined) requiredBins.add(config.binDefinitionId);
      if (config.entityResolutionDefinitionId !== undefined) {
        requiredResolutions.add(config.entityResolutionDefinitionId);
      }
      const fieldPolicy = getCanonicalFieldPolicy(config.dimensionField);
      if (fieldPolicy.directIdentifier && config.entityResolutionDefinitionId === undefined) {
        fail("DEFINITION_EVIDENCE_INVALID", "Identifier concentration requires entity resolution");
      }
      if (fieldPolicy.aggregationEligibility === "allowed" && config.binDefinitionId === undefined) {
        fail("DEFINITION_EVIDENCE_INVALID", "Numeric concentration requires a governed bin");
      }
    }
  }
  exactSet(requiredCohorts, cohorts.map(({ definitionId }) => definitionId), "cohort");
  exactSet(requiredBins, bins.map(({ definitionId }) => definitionId), "bin");
  exactSet(
    requiredResolutions,
    entityResolutions.map(({ definitionId }) => definitionId),
    "entity-resolution"
  );
}

function validateMethodologyDefinitionSet(
  requiredKinds: readonly string[],
  resolved: readonly ResolvedGovernedDefinitionV2[]
): void {
  const executableKinds = new Set(resolved.map(({ reference }) => reference.kind));
  const supported = new Set<string>([
    "metric_definition",
    "cohort_definition",
    "bin_definition",
    "entity_resolution_definition"
  ]);
  if (!requiredKinds.includes("metric_definition")) {
    fail("DEFINITION_EVIDENCE_INVALID", "Methodology must require metric definitions");
  }
  for (const kind of requiredKinds) {
    if (!supported.has(kind) || !executableKinds.has(kind as ResolvedGovernedDefinitionV2["reference"]["kind"])) {
      fail("DEFINITION_EVIDENCE_INVALID", `Methodology requires unavailable kind ${kind}`);
    }
  }
  for (const kind of executableKinds) {
    if (kind !== "methodology_bundle" && !requiredKinds.includes(kind)) {
      fail("DEFINITION_EVIDENCE_INVALID", `Frozen ${kind} is not declared by the methodology`);
    }
  }
}

function deriveAggregateDimensionFields(
  metrics: readonly MetricDefinitionV1[]
): readonly string[] {
  const fields = new Set<string>();
  for (const metric of metrics) {
    const config = metric.configuration;
    if (config.kind === "rating_migration") fields.add(config.ratingField);
    if (
      config.kind === "concentration" &&
      config.binDefinitionId === undefined &&
      config.entityResolutionDefinitionId === undefined
    ) {
      fields.add(config.dimensionField);
    }
    if (config.kind === "period_comparison" && config.dimensionField !== undefined) {
      fields.add(config.dimensionField);
    }
  }
  const result = [...fields].sort(compare);
  for (const field of result) {
    const policy = getCanonicalFieldPolicy(field);
    if (policy.aggregationEligibility !== "bucket_only" || policy.defaultMask !== "none") {
      fail("DEFINITION_EVIDENCE_INVALID", `Dimension ${field} is not eligible for direct aggregation`);
    }
  }
  return deepFreeze(result);
}

function assertSourcePolicyCoverage(
  policy: SourceAccessPolicyV1,
  requestedFields: readonly string[],
  requestedAggregateDimensionFields: readonly string[]
): void {
  const fields = new Set(policy.allowedFields);
  const dimensions = new Set(policy.allowedAggregateDimensionFields);
  if (
    requestedFields.some((field) => !fields.has(field)) ||
    requestedAggregateDimensionFields.some((field) => !dimensions.has(field))
  ) {
    fail(
      "SOURCE_POLICY_COVERAGE_DENIED",
      "Source-access policy does not cover all server-derived fields and dimensions"
    );
  }
}

function assertPermitBindings(
  decision: PermitPolicyDecision,
  context: Readonly<{ principal: VerifiedPrincipalContext; purpose: string; planningCutoff: string }>,
  datasetId: string,
  requestedFields: readonly string[]
): void {
  if (
    decision.tenantId !== context.principal.tenantId ||
    decision.principalBinding !== principalBinding(context.principal) ||
    decision.toolName !== POLICY_TOOL_NAME ||
    decision.datasetId !== datasetId ||
    decision.purpose !== context.purpose ||
    decision.evaluatedAtEpochSeconds !== Math.floor(Date.parse(context.planningCutoff) / 1_000) ||
    canonicalJson(decision.requestedFields) !== canonicalJson(requestedFields)
  ) {
    fail("GLOBAL_POLICY_DENIED", "Global policy decision did not bind the exact preflight context");
  }
}

function assertAggregateOnlyObligations(
  obligations: PolicyObligations,
  maximumDisclosedItems: number,
  minimumMetricCellCount: number
): void {
  if (
    !obligations.requireImmutableSnapshot ||
    obligations.allowRawRows ||
    obligations.allowExport ||
    obligations.rowFilterRefs.length !== 0 ||
    Object.keys(obligations.fieldMasks).length !== 0 ||
    obligations.maxResultRows < maximumDisclosedItems ||
    obligations.minimumCohortSize > minimumMetricCellCount
  ) {
    fail(
      "AUTHORIZATION_OBLIGATION_DENIED",
      "Global policy obligations cannot satisfy aggregate-only portfolio surveillance"
    );
  }
}

function decisionProjection(
  decision: PermitPolicyDecision,
  principalId: string
): PortfolioSurveillanceAuthorizationDecisionProjectionV1 {
  return deepFreeze({
    decisionId: decision.decisionId,
    policyId: decision.policyId,
    policyVersion: decision.policyVersion,
    policyFingerprint: decision.policyFingerprint,
    principalBinding: decision.principalBinding,
    tenantId: decision.tenantId,
    principalId,
    toolName: decision.toolName,
    datasetId: decision.datasetId,
    requestedFields: [...decision.requestedFields],
    purpose: decision.purpose!,
    evaluatedAtEpochSeconds: decision.evaluatedAtEpochSeconds,
    matchedRuleIds: [...decision.matchedRuleIds],
    obligations: decision.obligations
  });
}

function publicationLineageProjection(
  publication: CertifiedSnapshotPublicationV1,
  chain: readonly CertifiedSnapshotPublicationV1[]
): TerminalCertifiedPublicationLineageV1 {
  if (
    publication.certification.evidenceFormat !== "modern_snapshot_v2" ||
    publication.normalizedArtifact.artifactContractVersion !== 2 ||
    publication.normalizedArtifact.artifactHash === undefined
  ) {
    fail(
      "PUBLICATION_SUBSTITUTION",
      "Portfolio surveillance requires a modern normalized artifact identity"
    );
  }
  const lineagePublicationHashes = chain.map(({ publicationHash }) => publicationHash);
  return deepFreeze({
    publicationId: publication.publicationId,
    publicationHash: publication.publicationHash,
    certificationManifestId: publication.certification.certificationManifestId,
    certificationManifestHash: publication.certification.certificationManifestHash,
    certifiedAt: publication.certification.certifiedAt,
    snapshotId: publication.snapshot.snapshotId,
    snapshotHash: publication.snapshot.snapshotHash,
    asOfDate: publication.snapshot.asOfDate,
    datasetId: publication.datasetId,
    datasetBindingId: publication.datasetBinding.bindingId,
    sourceContract: publishedSourceSelector(publication),
    scope: publication.scope,
    populationHash: publication.population.populationHash,
    rowCount: publication.population.rowCount,
    normalizedPopulationId: publication.population.populationId,
    mappingApplicationId: publication.mappingApplication.mappingApplicationId,
    mappingApplicationHash: publication.mappingApplication.mappingApplicationHash,
    normalizedArtifact: {
      artifactId: publication.normalizedArtifact.artifactId,
      artifactContractVersion: publication.normalizedArtifact.artifactContractVersion,
      artifactHash: publication.normalizedArtifact.artifactHash,
      kind: publication.normalizedArtifact.kind,
      mediaType: publication.normalizedArtifact.mediaType,
      contentHash: publication.normalizedArtifact.contentHash,
      byteLength: publication.normalizedArtifact.byteLength,
      uri: publication.normalizedArtifact.uri,
      metadataHash: publication.normalizedArtifact.metadataHash,
      rowCount: publication.normalizedArtifact.rowCount,
      populationHash: publication.normalizedArtifact.populationHash,
      fieldSetHash: publication.normalizedArtifact.fieldSetHash
    },
    lineagePublicationHashes,
    correctionLineageHash: canonicalHash(lineagePublicationHashes),
    publishedAt: publication.publishedAt
  });
}

async function resolveDatasetScopeBindings(
  publications: readonly TerminalCertifiedPublicationLineageV1[],
  context: Readonly<{
    principal: VerifiedPrincipalContext;
    purpose: string;
    planningCutoff: string;
  }>,
  port: EffectiveGovernedDefinitionResolutionPortV1
): Promise<readonly FrozenDatasetScopeBindingLineageV1[]> {
  const result = new Map<string, FrozenDatasetScopeBindingLineageV1>();
  for (const publication of publications) {
    const bindingId = publication.datasetBindingId;
    const resolvedValue = await port.resolveEffective({
      tenantId: context.principal.tenantId,
      kind: "dataset_scope_binding",
      definitionKey: bindingId,
      asOfDate: publication.asOfDate
    });
    if (resolvedValue === undefined) {
      fail("SOURCE_SET_MISMATCH", `Governed dataset-scope binding ${bindingId} is not effective`);
    }
    const resolved = parseResolvedDefinition(
      resolvedValue,
      resolvedValue.reference.definitionVersionId
    );
    if (
      resolved.reference.kind !== "dataset_scope_binding" ||
      resolved.reference.definitionKey !== bindingId ||
      resolved.approvalEvidence.approvedAt > context.planningCutoff
    ) {
      fail("SOURCE_SET_MISMATCH", "Governed dataset-scope binding authority substituted an identity");
    }
    const binding = parseGovernedDatasetScopeBindingV1(resolved.executionDocument);
    if (
      binding.bindingId !== bindingId ||
      binding.tenantId !== context.principal.tenantId ||
      binding.datasetId !== publication.datasetId ||
      canonicalJson(binding.sourceContract) !==
        canonicalJson({
          sourceContractId: publication.sourceContract.sourceContractId,
          revision: publication.sourceContract.revision,
          sourceContractHash: publication.sourceContract.sourceContractHash
        }) ||
      canonicalJson(binding.scope) !== canonicalJson(publication.scope) ||
      binding.effectiveFrom > publication.asOfDate ||
      (binding.effectiveTo !== undefined && publication.asOfDate >= binding.effectiveTo) ||
      resolved.reference.semanticVersion !== `${binding.revision}.0.0` ||
      resolved.reference.documentHash !== canonicalHash(binding)
    ) {
      fail("SOURCE_SET_MISMATCH", "Governed dataset-scope binding did not match publication authority");
    }
    const lineage = deepFreeze({
        definitionVersionId: resolved.reference.definitionVersionId,
        definitionKey: resolved.reference.definitionKey,
        semanticVersion: resolved.reference.semanticVersion,
        versionHash: resolved.reference.versionHash,
        documentHash: resolved.reference.documentHash,
        approvalEventHash: resolved.reference.approvalEventHash,
        executionDocumentHash: canonicalHash(resolved.executionDocument),
        bindingId: binding.bindingId,
        revision: binding.revision,
        bindingHash: binding.bindingHash,
        effectiveFrom: binding.effectiveFrom,
        effectiveTo: binding.effectiveTo ?? null
      });
    result.set(resolved.reference.definitionVersionId, lineage);
  }
  return deepFreeze(
    [...result.values()].sort(
      (left, right) =>
        compare(left.bindingId, right.bindingId) ||
        compare(left.definitionVersionId, right.definitionVersionId)
    )
  );
}

function assertPublicationAvailableAtCutoff(
  publication: CertifiedSnapshotPublicationV1,
  planningCutoff: string
): void {
  if (
    publication.publishedAt > planningCutoff ||
    publication.certification.certifiedAt > planningCutoff ||
    publication.snapshot.knowledge.persistedAt > planningCutoff
  ) {
    fail("PUBLICATION_SUBSTITUTION", "Publication did not exist at the captured planning cutoff");
  }
}

function assertPublicationMatchesQuery(
  publication: CertifiedSnapshotPublicationV1,
  direct: CertifiedSnapshotPublicationV1,
  sourceContract: Readonly<z.infer<typeof SourceContractSelectorSchema>>,
  planningCutoff: string
): void {
  assertPublicationAvailableAtCutoff(publication, planningCutoff);
  if (
    publication.tenantId !== direct.tenantId ||
    publication.datasetId !== direct.datasetId ||
    canonicalJson(publishedSourceSelector(publication)) !== canonicalJson(sourceContract) ||
    canonicalJson(publication.scope) !== canonicalJson(direct.scope) ||
    publication.snapshot.asOfDate !== direct.snapshot.asOfDate
  ) {
    fail("PUBLICATION_SUBSTITUTION", "Publication lineage query crossed tenant, source, scope, or period");
  }
}

function assertDisableEvent(
  event: SurveillancePublicationDisableEventV1,
  publication: CertifiedSnapshotPublicationV1
): void {
  if (
    event.tenantId !== publication.tenantId ||
    event.publicationId !== publication.publicationId ||
    event.publicationHash !== publication.publicationHash ||
    !IsoTimestampSchema.safeParse(event.disabledAt).success
  ) {
    fail("INTEGRITY_FAILURE", "Publication disable authority substituted evidence");
  }
}

function publishedSourceSelector(
  publication: CertifiedSnapshotPublicationV1
): Readonly<z.infer<typeof SourceContractSelectorSchema>> {
  return deepFreeze({
    sourceContractId: publication.sourceContract.sourceContractId,
    sourceKey: publication.sourceContract.sourceKey,
    revision: publication.sourceContract.revision,
    sourceContractHash: publication.sourceContract.sourceContractHash
  });
}

function parsePublication(
  value: unknown,
  code: PortfolioSurveillanceAccessPreflightErrorCode
): CertifiedSnapshotPublicationV1 {
  if (value === undefined) fail(code, "Certified snapshot publication was not found");
  try {
    return parseCertifiedSnapshotPublicationV1(value);
  } catch {
    fail(code, "Certified snapshot publication failed immutable validation");
  }
}

function sourcePolicySelector(value: SourceAccessPolicySelectorV1): SourceAccessPolicySelectorV1 {
  return deepFreeze({
    tenantId: parseWithSchema(IdentifierSchema, value.tenantId, "source policy tenantId"),
    datasetId: parseWithSchema(IdentifierSchema, value.datasetId, "source policy datasetId"),
    sourceContract: parseWithSchema(
      SourceContractSelectorSchema,
      value.sourceContract,
      "source policy source contract"
    ),
    scope: parseWithSchema(ScopeSchema, value.scope, "source policy scope"),
    purpose: parseWithSchema(IdentifierSchema, value.purpose, "source policy purpose")
  });
}

function authorizationContext(
  value: PortfolioSurveillanceAuthorizationContextV1
): Readonly<{ principal: VerifiedPrincipalContext; purpose: string; planningCutoff: string }> {
  assertVerifiedPrincipalContext(value.principal);
  return deepFreeze({
    principal: value.principal,
    purpose: parseWithSchema(IdentifierSchema, value.purpose, "portfolio surveillance purpose"),
    planningCutoff: parseWithSchema(
      IsoTimestampSchema,
      value.planningCutoff,
      "portfolio surveillance planning cutoff"
    )
  });
}

function sortEngineDefinitions<T extends { readonly definitionId: string; readonly version: number }>(
  values: readonly T[]
): readonly T[] {
  return deepFreeze(
    [...values].sort(
      (left, right) =>
        compare(left.definitionId, right.definitionId) || left.version - right.version
    )
  );
}

function cloneCanonical<T>(value: T): T {
  return deepFreeze(JSON.parse(canonicalJson(value)) as T);
}

function exactSet(expected: ReadonlySet<string>, actualValues: readonly string[], label: string): void {
  const actual = new Set(actualValues);
  if (
    actual.size !== actualValues.length ||
    expected.size !== actual.size ||
    [...expected].some((value) => !actual.has(value))
  ) {
    fail("DEFINITION_EVIDENCE_INVALID", `Frozen ${label} definitions do not exactly match metric dependencies`);
  }
}

function strictRecord(
  value: unknown,
  keys: readonly string[],
  label: string
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    integrity(`${label} must be an object`);
  }
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort(compare);
  const expected = [...keys].sort(compare);
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    integrity(`${label} keys did not match its strict contract`);
  }
  return record;
}

function projectionRecords(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number
): readonly Record<string, unknown>[] {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    integrity(`${label} is outside its cardinality bound`);
  }
  for (const [index, candidate] of value.entries()) {
    if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
      integrity(`${label}[${index}] must be an object`);
    }
  }
  canonicalHash(value);
  return value as readonly Record<string, unknown>[];
}

function validatePublicationProjections(
  publications: readonly TerminalCertifiedPublicationLineageV1[]
): void {
  for (const publication of publications) {
    strictRecord(publication, [
      "asOfDate",
      "certificationManifestHash",
      "certificationManifestId",
      "certifiedAt",
      "correctionLineageHash",
      "datasetBindingId",
      "datasetId",
      "lineagePublicationHashes",
      "mappingApplicationHash",
      "mappingApplicationId",
      "normalizedArtifact",
      "normalizedPopulationId",
      "populationHash",
      "publicationHash",
      "publicationId",
      "publishedAt",
      "rowCount",
      "scope",
      "snapshotHash",
      "snapshotId",
      "sourceContract"
    ], "terminal publication projection");
    parseWithSchema(IdentifierSchema, publication.publicationId, "publicationId");
    parseWithSchema(Sha256HashSchema, publication.publicationHash, "publicationHash");
    parseWithSchema(
      IdentifierSchema,
      publication.certificationManifestId,
      "certificationManifestId"
    );
    parseWithSchema(
      Sha256HashSchema,
      publication.certificationManifestHash,
      "certificationManifestHash"
    );
    parseWithSchema(IsoTimestampSchema, publication.certifiedAt, "certifiedAt");
    parseWithSchema(IdentifierSchema, publication.snapshotId, "snapshotId");
    parseWithSchema(Sha256HashSchema, publication.snapshotHash, "snapshotHash");
    parseWithSchema(IdentifierSchema, publication.datasetId, "publication datasetId");
    parseWithSchema(IdentifierSchema, publication.datasetBindingId, "datasetBindingId");
    parseWithSchema(IdentifierSchema, publication.normalizedPopulationId, "normalizedPopulationId");
    parseWithSchema(IdentifierSchema, publication.mappingApplicationId, "mappingApplicationId");
    parseWithSchema(
      Sha256HashSchema,
      publication.mappingApplicationHash,
      "mappingApplicationHash"
    );
    parseWithSchema(ScopeSchema, publication.scope, "publication scope");
    parseWithSchema(SourceContractSelectorSchema, publication.sourceContract, "publication source");
    parseWithSchema(IsoTimestampSchema, publication.publishedAt, "publication publishedAt");
    const artifact = strictRecord(publication.normalizedArtifact, [
      "artifactContractVersion",
      "artifactId",
      "artifactHash",
      "byteLength",
      "contentHash",
      "fieldSetHash",
      "kind",
      "mediaType",
      "metadataHash",
      "populationHash",
      "rowCount",
      "uri"
    ], "terminal publication artifact projection");
    if (
      artifact.artifactContractVersion !== 2 ||
      artifact.kind !== "normalized_snapshot" ||
      artifact.mediaType !== "application/json" ||
      !IdentifierSchema.safeParse(artifact.artifactId).success ||
      !Sha256HashSchema.safeParse(artifact.artifactHash).success ||
      !Sha256HashSchema.safeParse(artifact.contentHash).success ||
      !Sha256HashSchema.safeParse(artifact.metadataHash).success ||
      !Sha256HashSchema.safeParse(artifact.populationHash).success ||
      !Sha256HashSchema.safeParse(artifact.fieldSetHash).success ||
      !Number.isSafeInteger(artifact.byteLength) ||
      (artifact.byteLength as number) < 1 ||
      (artifact.byteLength as number) > 100_000_000 ||
      !Number.isSafeInteger(artifact.rowCount) ||
      (artifact.rowCount as number) < 0 ||
      (artifact.rowCount as number) > 1_000_000 ||
      typeof artifact.uri !== "string" ||
      artifact.uri.length < 1 ||
      artifact.uri.length > 2_048 ||
      artifact.rowCount !== publication.rowCount ||
      artifact.populationHash !== publication.populationHash ||
      publication.certifiedAt > publication.publishedAt
    ) {
      integrity("Terminal publication artifact projection did not verify");
    }
    const lineageHashes = parseWithSchema(
      z.array(Sha256HashSchema).min(1).max(MAXIMUM_LINEAGE_PUBLICATIONS),
      publication.lineagePublicationHashes,
      "correction lineage publication hashes"
    );
    if (
      canonicalHash(lineageHashes) !== publication.correctionLineageHash ||
      lineageHashes.at(-1) !== publication.publicationHash
    ) {
      integrity("Correction lineage projection hash did not verify");
    }
  }
}

function validateFrozenLineageReferences<T extends Readonly<{
  definitionVersionId: unknown;
  definitionKey: unknown;
  versionHash: unknown;
  documentHash: unknown;
  approvalEventHash: unknown;
  executionDocumentHash: unknown;
}>>(
  values: readonly T[],
  label: string
): void {
  for (const value of values) {
    parseWithSchema(IdentifierSchema, value.definitionVersionId, `${label} definitionVersionId`);
    parseWithSchema(IdentifierSchema, value.definitionKey, `${label} definitionKey`);
    parseWithSchema(Sha256HashSchema, value.versionHash, `${label} versionHash`);
    parseWithSchema(Sha256HashSchema, value.documentHash, `${label} documentHash`);
    parseWithSchema(Sha256HashSchema, value.approvalEventHash, `${label} approvalEventHash`);
    parseWithSchema(
      Sha256HashSchema,
      value.executionDocumentHash,
      `${label} executionDocumentHash`
    );
  }
}

function validateAuthorizationProjection(
  authorization: Record<string, unknown>,
  maximumDisclosedItems: number,
  minimumMetricCellCount: number
): void {
  for (const key of [
    "policyId",
    "principalId",
    "tenantId",
    "toolName",
    "datasetId",
    "purpose"
  ]) {
    parseWithSchema(IdentifierSchema, authorization[key], `authorization ${key}`);
  }
  for (const key of ["decisionId", "policyFingerprint", "principalBinding"]) {
    if (typeof authorization[key] !== "string" || !/^[a-f0-9]{64}$/u.test(authorization[key])) {
      integrity(`authorization ${key} is not a bare SHA-256 fingerprint`);
    }
  }
  if (typeof authorization.policyVersion !== "string" || authorization.policyVersion.length > 128) {
    integrity("authorization policyVersion is invalid");
  }
  boundedInteger(
    authorization.evaluatedAtEpochSeconds,
    "authorization evaluatedAtEpochSeconds",
    0,
    Number.MAX_SAFE_INTEGER
  );
  sortedIdentifiers(authorization.requestedFields, "authorization requestedFields", 1, 2_000);
  sortedIdentifiers(authorization.matchedRuleIds, "authorization matchedRuleIds", 1, 10_000);
  const obligations = strictRecord(authorization.obligations, [
    "allowExport",
    "allowRawRows",
    "auditTags",
    "fieldMasks",
    "maxExecutionMs",
    "maxResultBytes",
    "maxResultRows",
    "minimumCohortSize",
    "requireImmutableSnapshot",
    "rowFilterRefs"
  ], "authorization obligations");
  const maxResultRows = boundedInteger(
    obligations.maxResultRows,
    "authorization maxResultRows",
    1,
    Number.MAX_SAFE_INTEGER
  );
  const minimumCohortSize = boundedInteger(
    obligations.minimumCohortSize,
    "authorization minimumCohortSize",
    1,
    Number.MAX_SAFE_INTEGER
  );
  if (
    obligations.requireImmutableSnapshot !== true ||
    obligations.allowRawRows !== false ||
    obligations.allowExport !== false ||
    !Array.isArray(obligations.rowFilterRefs) ||
    obligations.rowFilterRefs.length !== 0 ||
    obligations.fieldMasks === null ||
    typeof obligations.fieldMasks !== "object" ||
    Array.isArray(obligations.fieldMasks) ||
    Object.keys(obligations.fieldMasks).length !== 0 ||
    maxResultRows < maximumDisclosedItems ||
    minimumCohortSize > minimumMetricCellCount
  ) {
    integrity("authorization obligations do not satisfy aggregate-only metadata bounds");
  }
}

function sortedIdentifiers(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number
): readonly string[] {
  const parsed = parseWithSchema(
    z.array(IdentifierSchema).min(minimum).max(maximum),
    value,
    label
  );
  if (
    new Set(parsed).size !== parsed.length ||
    canonicalJson([...parsed].sort(compare)) !== canonicalJson(parsed)
  ) {
    integrity(`${label} must be unique and sorted`);
  }
  return parsed;
}

function boundedInteger(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    integrity(`${label} is outside its integer bound`);
  }
  return value;
}

function snapshotKey(snapshotId: string, snapshotHash: string): string {
  return `${snapshotId}\u0000${snapshotHash}`;
}

function safeAdd(left: number, right: number, label: string): number {
  const result = left + right;
  if (!Number.isSafeInteger(result)) fail("DEFINITION_EVIDENCE_INVALID", `${label} is unsafe`);
  return result;
}

function uniqueIssue(
  values: readonly string[],
  context: z.RefinementCtx,
  path: readonly PropertyKey[]
): void {
  if (new Set(values).size !== values.length) {
    context.addIssue({ code: "custom", path: [...path], message: "must be unique" });
  }
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function fail(code: PortfolioSurveillanceAccessPreflightErrorCode, message: string): never {
  throw new PortfolioSurveillanceAccessPreflightError(code, message);
}

function integrity(message: string): never {
  return fail("INTEGRITY_FAILURE", message);
}

// Compile-time assertion that this preflight remains tied to the registered operation.
void PORTFOLIO_SURVEILLANCE_V1_DESCRIPTOR;
