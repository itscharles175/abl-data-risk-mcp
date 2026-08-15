import { parseCertifiedSnapshotPublicationV1 } from "../contracts/index.js";
import type { ArtifactStore } from "../control/artifacts.js";
import type { JobStore } from "../control/jobs.js";
import type { ControlStore } from "../control/store.js";
import type { SqlitePortfolioSurveillanceV4StateStore } from "../repositories/sqlite-portfolio-surveillance-v4-state.js";
import type { TenantMembershipResolver } from "../security/oauth.js";
import type { CompiledAuthorizationPolicy } from "../security/policy.js";
import type { HmacKeyRing } from "../security/signed-plan.js";
import type { SecurityStateStore } from "../security/state-store.js";
import {
  PortfolioSurveillanceWorkflowV4,
  type PortfolioSurveillanceWorkerExecutorV4,
  type PortfolioSurveillanceWorkflowV4Options
} from "./portfolio-surveillance-workflow-v4.js";
import {
  GovernedSourceAccessPolicyDirectoryV1,
  PortfolioSurveillanceAuthorizationPreflightServiceV1,
  type CompletePublicationLineagePageV1,
  type EffectiveGovernedDefinitionResolutionPortV1,
  type FrozenGovernedDefinitionResolutionPortV1,
  type PortfolioSurveillanceGlobalAuthorizerV1,
  type SourceAccessPolicyCandidateIndexV1,
  type SurveillancePublicationLineageQueryV1,
  type SurveillancePublicationReadPortV1
} from "./surveillance-access-preflight.js";
import {
  PortfolioSurveillancePlanMaterializerV1,
  type SurveillanceMaterializationPublicationReadPortV1
} from "./surveillance-materializer.js";
import type { RepositoryBackedSurveillanceSourcePublicationAuthorityV2 } from "./surveillance-production-authority-v2.js";
import {
  V2OnlySurveillancePublicationMaterializationReadAdapter,
  V2OnlySurveillancePublicationReadAdapter,
  type GovernedCertifiedSnapshotPublicationLinkCatalogReadPortV2
} from "./surveillance-publication-v2-read-adapter.js";

export const SINGLE_FACILITY_V2_SURVEILLANCE_EXPOSURE = Object.freeze({
  productionEnabled: false,
  remoteAdvertised: false
} as const);

export type SingleFacilityV2SurveillanceRuntimeErrorCode =
  | "INVALID_CONFIGURATION"
  | "SCOPE_DENIED";

export class SingleFacilityV2SurveillanceRuntimeError extends Error {
  constructor(
    readonly code: SingleFacilityV2SurveillanceRuntimeErrorCode,
    message: string
  ) {
    super(message);
    this.name = "SingleFacilityV2SurveillanceRuntimeError";
  }
}

export interface SingleFacilityV2SurveillanceRuntimeBinding {
  readonly tenantId: string;
  readonly facilityId: string;
}

/** Separate capabilities make a pre-policy artifact read unrepresentable in this composition. */
export interface SingleFacilityV2PublicationAuthorities {
  readonly metadata: Pick<RepositoryBackedSurveillanceSourcePublicationAuthorityV2, "resolveMetadata">;
  readonly artifact: Pick<RepositoryBackedSurveillanceSourcePublicationAuthorityV2, "resolveArtifact">;
}

export interface SingleFacilityV2SurveillanceDefinitionPorts {
  readonly sourcePolicyCandidates: SourceAccessPolicyCandidateIndexV1;
  readonly effective: EffectiveGovernedDefinitionResolutionPortV1;
  readonly frozen: FrozenGovernedDefinitionResolutionPortV1;
}

export interface SingleFacilityV2SurveillanceRuntimeDependencies {
  readonly publicationAuthorities: SingleFacilityV2PublicationAuthorities;
  readonly publicationLinks: GovernedCertifiedSnapshotPublicationLinkCatalogReadPortV2;
  readonly definitions: SingleFacilityV2SurveillanceDefinitionPorts;
  readonly globalAuthorizer: PortfolioSurveillanceGlobalAuthorizerV1;
  readonly artifacts: Pick<ArtifactStore, "getJson" | "putJson">;
  readonly state: SqlitePortfolioSurveillanceV4StateStore;
  readonly control: Pick<ControlStore, "appendAuditEvent" | "listAuditEvents">;
  readonly jobs: JobStore;
  readonly securityState: SecurityStateStore;
  readonly tenantMembershipResolver: TenantMembershipResolver;
  readonly policy: CompiledAuthorizationPolicy;
  readonly keyRing: HmacKeyRing;
  readonly workerExecutor?: PortfolioSurveillanceWorkerExecutorV4;
}

export interface SingleFacilityV2SurveillanceRuntime {
  readonly binding: Readonly<SingleFacilityV2SurveillanceRuntimeBinding>;
  readonly exposure: typeof SINGLE_FACILITY_V2_SURVEILLANCE_EXPOSURE;
  readonly preflightPublications: SurveillancePublicationReadPortV1;
  readonly materializationPublications: SurveillanceMaterializationPublicationReadPortV1;
  readonly sourcePolicies: GovernedSourceAccessPolicyDirectoryV1;
  readonly preflight: PortfolioSurveillanceAuthorizationPreflightServiceV1;
  readonly materializer: PortfolioSurveillancePlanMaterializerV1;
  readonly workflow: PortfolioSurveillanceWorkflowV4;
}

/**
 * Builds a fully runnable local pilot while leaving production and remote
 * exposure disabled. Injected stores and authorities remain caller-owned.
 */
export function composeProductionDisabledSingleFacilityV2SurveillanceRuntime(
  bindingValue: SingleFacilityV2SurveillanceRuntimeBinding,
  dependencies: SingleFacilityV2SurveillanceRuntimeDependencies,
  workflowOptions: PortfolioSurveillanceWorkflowV4Options
): SingleFacilityV2SurveillanceRuntime {
  const binding = runtimeBinding(bindingValue);
  const metadataAdapter = new V2OnlySurveillancePublicationReadAdapter({
    metadataAuthority: dependencies.publicationAuthorities.metadata,
    publicationLinks: dependencies.publicationLinks
  });
  const artifactAdapter = new V2OnlySurveillancePublicationMaterializationReadAdapter({
    artifactAuthority: dependencies.publicationAuthorities.artifact,
    publicationLinks: dependencies.publicationLinks
  });
  const preflightPublications = new SingleFacilityPreflightPublicationFence(
    binding,
    metadataAdapter
  );
  const materializationPublications = new SingleFacilityMaterializationPublicationFence(
    binding,
    artifactAdapter
  );
  const sourcePolicies = new GovernedSourceAccessPolicyDirectoryV1(
    dependencies.definitions.sourcePolicyCandidates,
    dependencies.definitions.effective
  );
  const preflight = new PortfolioSurveillanceAuthorizationPreflightServiceV1({
    publications: preflightPublications,
    sourcePolicies,
    datasetScopeBindings: dependencies.definitions.effective,
    analyticalDefinitions: dependencies.definitions.frozen,
    globalAuthorizer: dependencies.globalAuthorizer
  });
  const materializer = new PortfolioSurveillancePlanMaterializerV1({
    publications: materializationPublications,
    artifacts: dependencies.artifacts,
    analyticalDefinitions: dependencies.definitions.frozen,
    planArtifacts: dependencies.artifacts
  });
  const workflow = new PortfolioSurveillanceWorkflowV4(
    {
      preflight,
      materializer,
      state: dependencies.state,
      control: dependencies.control,
      artifacts: dependencies.artifacts,
      jobs: dependencies.jobs,
      securityState: dependencies.securityState,
      tenantMembershipResolver: dependencies.tenantMembershipResolver,
      policy: dependencies.policy,
      keyRing: dependencies.keyRing,
      ...(dependencies.workerExecutor === undefined
        ? {}
        : { workerExecutor: dependencies.workerExecutor })
    },
    workflowOptions
  );
  return Object.freeze({
    binding,
    exposure: SINGLE_FACILITY_V2_SURVEILLANCE_EXPOSURE,
    preflightPublications,
    materializationPublications,
    sourcePolicies,
    preflight,
    materializer,
    workflow
  });
}

class SingleFacilityPreflightPublicationFence implements SurveillancePublicationReadPortV1 {
  constructor(
    readonly binding: Readonly<SingleFacilityV2SurveillanceRuntimeBinding>,
    readonly delegate: SurveillancePublicationReadPortV1
  ) {}

  async get(tenantId: string, publicationId: string): Promise<unknown | undefined> {
    this.#tenant(tenantId);
    return this.#publication(await this.delegate.get(tenantId, publicationId));
  }

  async getByCertificationManifest(
    tenantId: string,
    certificationManifestId: string
  ): Promise<unknown | undefined> {
    this.#tenant(tenantId);
    return this.#publication(
      await this.delegate.getByCertificationManifest(tenantId, certificationManifestId)
    );
  }

  async getDisable(tenantId: string, publicationId: string) {
    this.#tenant(tenantId);
    return this.delegate.getDisable(tenantId, publicationId);
  }

  async listByScopeAsOf(
    query: SurveillancePublicationLineageQueryV1
  ): Promise<CompletePublicationLineagePageV1> {
    this.#tenant(query.tenantId);
    this.#scope(query.scope);
    const page = await this.delegate.listByScopeAsOf(query);
    for (const publication of page.publications) this.#publication(publication);
    return page;
  }

  #tenant(tenantId: string): void {
    assertTenant(this.binding, tenantId);
  }

  #scope(scope: SurveillancePublicationLineageQueryV1["scope"]): void {
    assertFacility(this.binding, scope);
  }

  #publication(value: unknown | undefined): unknown | undefined {
    return assertPublication(this.binding, value);
  }
}

class SingleFacilityMaterializationPublicationFence
  implements SurveillanceMaterializationPublicationReadPortV1
{
  constructor(
    readonly binding: Readonly<SingleFacilityV2SurveillanceRuntimeBinding>,
    readonly delegate: SurveillanceMaterializationPublicationReadPortV1
  ) {}

  async get(tenantId: string, publicationId: string): Promise<unknown | undefined> {
    assertTenant(this.binding, tenantId);
    return assertPublication(this.binding, await this.delegate.get(tenantId, publicationId));
  }

  async getDisable(tenantId: string, publicationId: string) {
    assertTenant(this.binding, tenantId);
    return this.delegate.getDisable(tenantId, publicationId);
  }
}

function runtimeBinding(
  value: SingleFacilityV2SurveillanceRuntimeBinding
): Readonly<SingleFacilityV2SurveillanceRuntimeBinding> {
  if (!validIdentifier(value?.tenantId) || !validIdentifier(value?.facilityId)) {
    throw new SingleFacilityV2SurveillanceRuntimeError(
      "INVALID_CONFIGURATION",
      "Single-facility runtime requires valid tenant and facility bindings"
    );
  }
  return Object.freeze({ tenantId: value.tenantId, facilityId: value.facilityId });
}

function assertTenant(
  binding: Readonly<SingleFacilityV2SurveillanceRuntimeBinding>,
  tenantId: string
): void {
  if (tenantId !== binding.tenantId) denied("Publication access is outside the bound pilot tenant");
}

function assertFacility(
  binding: Readonly<SingleFacilityV2SurveillanceRuntimeBinding>,
  scope: SurveillancePublicationLineageQueryV1["scope"]
): void {
  if (scope.scopeType !== "facility" || scope.scopeId !== binding.facilityId) {
    denied("Publication access is outside the bound pilot facility");
  }
}

function assertPublication(
  binding: Readonly<SingleFacilityV2SurveillanceRuntimeBinding>,
  value: unknown | undefined
): unknown | undefined {
  if (value === undefined) return undefined;
  let publication;
  try {
    publication = parseCertifiedSnapshotPublicationV1(value);
  } catch {
    denied("Publication access returned malformed evidence at the facility fence");
  }
  if (
    publication.tenantId !== binding.tenantId ||
    publication.scope.scopeType !== "facility" ||
    publication.scope.scopeId !== binding.facilityId
  ) {
    denied("Publication access crossed the bound pilot facility");
  }
  return publication;
}

function validIdentifier(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,511}$/.test(value);
}

function denied(message: string): never {
  throw new SingleFacilityV2SurveillanceRuntimeError("SCOPE_DENIED", message);
}
