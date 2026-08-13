import {
  GovernedDefinitionV2Store,
  GovernedDefinitionV2StoreError
} from "../control/governed-definitions-v2.js";
import { SurveillancePublicationCatalog } from "../control/surveillance-publications.js";
import {
  GovernedDefinitionV2Resolver,
  GovernedDefinitionV2ResolverError
} from "./governed-definition-v2-resolver.js";
import type {
  CompletePublicationLineagePageV1,
  CompleteSourceAccessPolicyCandidateSetV1,
  EffectiveGovernedDefinitionResolutionPortV1,
  FrozenGovernedDefinitionResolutionPortV1,
  SourceAccessPolicyCandidateIndexV1,
  SourceAccessPolicySelectorV1,
  SurveillancePublicationLineageQueryV1,
  SurveillancePublicationReadPortV1
} from "./surveillance-access-preflight.js";

const DEFAULT_MAXIMUM_POLICY_CANDIDATES = 1_000;

/**
 * Metadata-only read capability over the immutable publication catalog. The
 * catalog's exact indexed query supplies the completeness proof used by the
 * preflight correction-lineage validator.
 */
export class SurveillancePublicationCatalogReadAdapterV1
implements SurveillancePublicationReadPortV1 {
  constructor(readonly catalog: SurveillancePublicationCatalog) {}

  get(tenantId: string, publicationId: string) {
    return this.catalog.get(tenantId, publicationId);
  }

  getByCertificationManifest(tenantId: string, certificationManifestId: string) {
    return this.catalog.getByCertificationManifest(tenantId, certificationManifestId);
  }

  getDisable(tenantId: string, publicationId: string) {
    return this.catalog.getDisable(tenantId, publicationId);
  }

  listByScopeAsOf(
    query: SurveillancePublicationLineageQueryV1
  ): CompletePublicationLineagePageV1 {
    return this.catalog.listByScopeAsOf(query);
  }
}

/**
 * Discovers policy logical keys from the governed store, never from a caller
 * supplied policy id. A hard bound returns `complete: false` when exceeded so
 * the policy directory cannot silently authorize from a truncated set.
 */
export class GovernedDefinitionSourceAccessPolicyCandidateIndexV1
implements SourceAccessPolicyCandidateIndexV1 {
  readonly maximumCandidates: number;

  constructor(
    readonly store: GovernedDefinitionV2Store,
    maximumCandidates = DEFAULT_MAXIMUM_POLICY_CANDIDATES
  ) {
    if (
      !Number.isSafeInteger(maximumCandidates) ||
      maximumCandidates < 1 ||
      maximumCandidates > DEFAULT_MAXIMUM_POLICY_CANDIDATES
    ) {
      throw new RangeError("maximumCandidates must be an integer from 1 through 1000");
    }
    this.maximumCandidates = maximumCandidates;
  }

  listCandidateDefinitionKeys(
    selector: SourceAccessPolicySelectorV1
  ): CompleteSourceAccessPolicyCandidateSetV1 {
    return this.store.listSourceAccessPolicyCandidateKeys({
      ...selector,
      maximumResults: this.maximumCandidates
    });
  }
}

/** Adapts the resolver's input objects and explicit not-found errors to preflight ports. */
export class GovernedDefinitionV2PreflightResolutionAdapterV1
implements
  FrozenGovernedDefinitionResolutionPortV1,
  EffectiveGovernedDefinitionResolutionPortV1 {
  constructor(readonly resolver: GovernedDefinitionV2Resolver) {}

  resolveFrozenDefinition(tenantId: string, definitionVersionId: string) {
    try {
      return this.resolver.resolveFrozen({ tenantId, definitionVersionId });
    } catch (error) {
      if (isNotFound(error)) return undefined;
      throw error;
    }
  }

  resolveEffective(input: Readonly<{
    tenantId: string;
    kind: "source_access_policy" | "dataset_scope_binding";
    definitionKey: string;
    asOfDate: string;
  }>) {
    try {
      return this.resolver.resolveEffective(input);
    } catch (error) {
      if (isNotFound(error)) return undefined;
      throw error;
    }
  }
}

function isNotFound(error: unknown): boolean {
  return (
    (error instanceof GovernedDefinitionV2StoreError && error.code === "NOT_FOUND") ||
    (error instanceof GovernedDefinitionV2ResolverError && error.code === "NOT_FOUND")
  );
}
