import assert from "node:assert/strict";
import { test } from "node:test";

import { canonicalHash } from "../src/contracts/index.js";
import type { GovernedCertifiedSnapshotPublicationLinkV2 } from "../src/contracts/governed-certified-snapshot-publication-link-v2.js";
import { compileAuthorizationPolicy } from "../src/security/policy.js";
import { createHmacKeyRing } from "../src/security/signed-plan.js";
import { PortfolioSurveillanceWorkflowV4 } from "../src/services/portfolio-surveillance-workflow-v4.js";
import {
  SINGLE_FACILITY_V2_SURVEILLANCE_EXPOSURE,
  SingleFacilityV2SurveillanceRuntimeError,
  composeProductionDisabledSingleFacilityV2SurveillanceRuntime,
  type SingleFacilityV2SurveillanceRuntimeDependencies
} from "../src/services/single-facility-v2-surveillance-runtime.js";

const HASH = canonicalHash("single-facility-runtime-test");

test("composition injects distinct preflight and post-policy publication capabilities", () => {
  const fixture = compositionFixture();
  const { runtime } = fixture;

  assert.deepEqual(runtime.binding, { tenantId: "tenant-a", facilityId: "facility-a" });
  assert.equal(runtime.exposure, SINGLE_FACILITY_V2_SURVEILLANCE_EXPOSURE);
  assert.deepEqual(runtime.exposure, { productionEnabled: false, remoteAdvertised: false });
  assert.ok(runtime.workflow instanceof PortfolioSurveillanceWorkflowV4);
  assert.notEqual(runtime.preflightPublications, runtime.materializationPublications);
  assert.equal(runtime.preflight.dependencies.publications, runtime.preflightPublications);
  assert.equal(runtime.materializer.dependencies.publications, runtime.materializationPublications);
});

test("preflight metadata path performs zero artifact reads before permit", async () => {
  const fixture = compositionFixture();

  assert.equal(
    await fixture.runtime.preflightPublications.getByCertificationManifest(
      "tenant-a",
      "certification-a"
    ),
    undefined
  );
  assert.equal(fixture.authorities.metadataCalls, 1);
  assert.equal(fixture.authorities.artifactCalls, 0);
  assert.equal(fixture.artifacts.getCalls, 0);
});

test("post-policy reader rechecks a current disable and delegates correction terminality", async () => {
  const fixture = compositionFixture();

  fixture.links.disabled = true;
  assert.equal(
    await fixture.runtime.materializationPublications.get("tenant-a", "publication-a"),
    undefined
  );
  assert.equal(fixture.authorities.artifactCalls, 0);
  assert.equal(fixture.artifacts.getCalls, 0);

  fixture.links.disabled = false;
  fixture.authorities.nonTerminalCorrection = true;
  assert.equal(
    await fixture.runtime.materializationPublications.get("tenant-a", "publication-a"),
    undefined
  );
  assert.equal(fixture.authorities.artifactCalls, 1);
  assert.equal(fixture.authorities.correctionTerminalityChecks, 1);
  assert.equal(fixture.artifacts.getCalls, 0);
});

test("both publication capabilities fail closed outside the bound tenant and facility", async () => {
  const fixture = compositionFixture();

  await assert.rejects(
    fixture.runtime.preflightPublications.listByScopeAsOf({
      tenantId: "tenant-a",
      datasetId: "dataset-a",
      sourceContract: {
        sourceContractId: "source-a",
        sourceKey: "source-key-a",
        revision: 1,
        sourceContractHash: HASH
      },
      scope: { scopeType: "facility", scopeId: "facility-b" },
      asOfDate: "2026-08-15",
      publishedThrough: "2026-08-15T12:00:00.000Z",
      maximumResults: 10
    }),
    hasRuntimeCode("SCOPE_DENIED")
  );
  await assert.rejects(
    fixture.runtime.materializationPublications.get("tenant-b", "publication-a"),
    hasRuntimeCode("SCOPE_DENIED")
  );
  assert.equal(fixture.links.calls, 0);
});

class PublicationLinks {
  calls = 0;
  disabled = false;

  constructor(readonly link: GovernedCertifiedSnapshotPublicationLinkV2) {}

  getEnabled(tenantId: string, linkId: string) {
    this.calls += 1;
    return !this.disabled && tenantId === "tenant-a" && linkId === this.link.linkId
      ? this.link
      : undefined;
  }

  getByEvidence(tenantId: string, evidenceId: string) {
    this.calls += 1;
    return tenantId === "tenant-a" && evidenceId === "certification-a"
      ? this.link
      : undefined;
  }

  list(tenantId: string) {
    this.calls += 1;
    return tenantId === "tenant-a" ? [this.link] : [];
  }

  getDisable() {
    this.calls += 1;
    return undefined;
  }
}

class PublicationAuthorities {
  metadataCalls = 0;
  artifactCalls = 0;
  correctionTerminalityChecks = 0;
  nonTerminalCorrection = false;

  async resolveMetadata() {
    this.metadataCalls += 1;
    return undefined;
  }

  async resolveArtifact() {
    this.artifactCalls += 1;
    if (this.nonTerminalCorrection) this.correctionTerminalityChecks += 1;
    return undefined;
  }
}

class ArtifactReads {
  getCalls = 0;

  getJson() {
    this.getCalls += 1;
    throw new Error("artifact read was not expected");
  }

  putJson() {
    throw new Error("artifact write was not expected");
  }
}

function compositionFixture() {
  const link = {
    tenantId: "tenant-a",
    linkId: "link-a",
    publication: {
      publicationId: "publication-a",
      certificationManifestId: "certification-a"
    },
    evidence: { evidenceId: "certification-a" }
  } as GovernedCertifiedSnapshotPublicationLinkV2;
  const links = new PublicationLinks(link);
  const authorities = new PublicationAuthorities();
  const artifacts = new ArtifactReads();
  const runtime = composeProductionDisabledSingleFacilityV2SurveillanceRuntime(
    { tenantId: "tenant-a", facilityId: "facility-a" },
    dependencies(links, authorities, artifacts),
    { codeVersion: "test-runtime" }
  );
  return { runtime, links, authorities, artifacts };
}

function dependencies(
  publicationLinks: PublicationLinks,
  publicationAuthorities: PublicationAuthorities,
  artifacts: ArtifactReads
): SingleFacilityV2SurveillanceRuntimeDependencies {
  const never = () => {
    throw new Error("test dependency should not be called");
  };
  return {
    publicationAuthorities: {
      metadata: publicationAuthorities,
      artifact: publicationAuthorities
    },
    publicationLinks,
    definitions: {
      sourcePolicyCandidates: { listCandidateDefinitionKeys: never },
      effective: { resolveEffective: never },
      frozen: { resolveFrozenDefinition: never }
    },
    globalAuthorizer: { authorize: never },
    artifacts,
    state: {} as SingleFacilityV2SurveillanceRuntimeDependencies["state"],
    control: { appendAuditEvent: never, listAuditEvents: never },
    jobs: {} as SingleFacilityV2SurveillanceRuntimeDependencies["jobs"],
    securityState: {} as SingleFacilityV2SurveillanceRuntimeDependencies["securityState"],
    tenantMembershipResolver: { resolveTenantMembership: async () => null },
    policy: compileAuthorizationPolicy({
      id: "test-policy",
      version: "1.0.0",
      defaultObligations: {
        maxResultRows: 100,
        maxResultBytes: 1_000_000,
        maxExecutionMs: 10_000,
        minimumCohortSize: 1,
        requireImmutableSnapshot: true,
        allowRawRows: false,
        allowExport: false,
        rowFilterRefs: [],
        fieldMasks: {},
        auditTags: ["test"]
      },
      rules: [{
        id: "deny-by-default",
        effect: "deny",
        tenantIds: ["*"],
        tools: ["*"],
        datasets: ["*"]
      }]
    }),
    keyRing: createHmacKeyRing(
      [{ id: "test-key", secret: Buffer.alloc(32, 7) }],
      "test-key"
    )
  };
}

function hasRuntimeCode(code: SingleFacilityV2SurveillanceRuntimeError["code"]) {
  return (error: unknown): boolean =>
    error instanceof SingleFacilityV2SurveillanceRuntimeError && error.code === code;
}
