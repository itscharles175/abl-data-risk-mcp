import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import {
  JobHandleRouteCatalogError,
  SqliteJobHandleRouteCatalog
} from "../src/repositories/sqlite-job-handle-route-catalog.js";
import {
  createVerifiedPrincipalContext,
  principalBinding,
  type VerifiedPrincipalContext
} from "../src/security/identity.js";
import {
  CompositeGovernedWorkflowRouter,
  type LegacyRoutedWorkflowApi,
  type RoutedGovernedWorkflowResponse,
  type PortfolioSurveillanceRoutedWorkflowApi
} from "../src/services/composite-governed-workflow-router.js";

const DIRECTORIES: string[] = [];
const LEGACY_HANDLE = `legacy-${"a".repeat(40)}`;
const V4_HANDLE = `surveillance-${"b".repeat(40)}`;
const OBLIGATIONS = Object.freeze([]);

afterEach(() => {
  for (const directory of DIRECTORIES.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("starts register exact opaque handles and every operation routes to its owning lane", async () => {
  const fixture = routerFixture();
  const legacyStarted = await fixture.router.startAuthorized(fixture.principal, {
    operation: "snapshot_stratification",
    certificationManifestId: "cert-1",
    definitionIds: ["definition-1"],
    idempotencyKey: "legacy-idem"
  });
  const v4Started = await fixture.router.startPortfolioSurveillanceAuthorized(
    fixture.principal,
    surveillanceStart("v4-idem")
  );

  assert.equal((legacyStarted.value as { jobHandle: string }).jobHandle, LEGACY_HANDLE);
  assert.equal((v4Started.value as { jobHandle: string }).jobHandle, V4_HANDLE);

  assert.equal((await fixture.router.getJobStatusAuthorized(fixture.principal, LEGACY_HANDLE)).value, "legacy-status");
  assert.equal((await fixture.router.getJobResultAuthorized(fixture.principal, LEGACY_HANDLE)).value, "legacy-result");
  assert.equal((await fixture.router.cancelJobAuthorized(fixture.principal, LEGACY_HANDLE)).value, "legacy-cancel");
  assert.equal((await fixture.router.getJobStatusAuthorized(fixture.principal, V4_HANDLE)).value, "v4-status");
  assert.equal((await fixture.router.getJobResultAuthorized(fixture.principal, V4_HANDLE)).value, "v4-result");
  assert.equal((await fixture.router.cancelJobAuthorized(fixture.principal, V4_HANDLE)).value, "v4-cancel");
  assert.deepEqual(fixture.calls, {
    legacyStart: 1,
    legacyStatus: 1,
    legacyResult: 1,
    legacyCancel: 1,
    v4Start: 1,
    v4Status: 1,
    v4Result: 1,
    v4Cancel: 1
  });
  fixture.close();
});

test("route catalog survives restart without retaining plaintext handles", async () => {
  const directory = temporaryDirectory();
  const databasePath = join(directory, "routes.sqlite");
  const first = routerFixture(databasePath);
  await first.router.startPortfolioSurveillanceAuthorized(first.principal, surveillanceStart("restart-idem"));
  first.close();
  assert.equal(readFileSync(databasePath).includes(Buffer.from(V4_HANDLE)), false);

  const second = routerFixture(databasePath);
  assert.equal((await second.router.getJobStatusAuthorized(second.principal, V4_HANDLE)).value, "v4-status");
  assert.equal(second.calls.legacyStatus, 0);
  assert.equal(second.calls.v4Status, 1);
  second.close();
});

test("unknown and mismatched-principal handles fail closed before either workflow is called", async () => {
  const fixture = routerFixture();
  await fixture.router.startAuthorized(fixture.principal, {
    operation: "snapshot_vintage",
    certificationManifestId: "cert-1",
    definitionIds: ["definition-1"],
    idempotencyKey: "owner-idem"
  });
  const before = { ...fixture.calls };

  await assert.rejects(
    () => fixture.router.getJobStatusAuthorized(fixture.principal, `unknown-${"z".repeat(40)}`),
    (error: unknown) => error instanceof JobHandleRouteCatalogError && error.code === "ROUTE_NOT_FOUND"
  );
  await assert.rejects(
    () => fixture.router.getJobStatusAuthorized(principal("user-2"), LEGACY_HANDLE),
    (error: unknown) => error instanceof JobHandleRouteCatalogError && error.code === "ROUTE_NOT_FOUND"
  );
  assert.deepEqual(fixture.calls, before);
  fixture.close();
});

test("an owning-lane error is returned without probing the other lane", async () => {
  const fixture = routerFixture();
  await fixture.router.startPortfolioSurveillanceAuthorized(fixture.principal, surveillanceStart("failure-idem"));
  fixture.failV4Status = true;

  await assert.rejects(
    () => fixture.router.getJobStatusAuthorized(fixture.principal, V4_HANDLE),
    /v4 status failure/
  );
  assert.equal(fixture.calls.v4Status, 1);
  assert.equal(fixture.calls.legacyStatus, 0);
  fixture.close();
});

test("a handle cannot be reassigned across workflow lanes", () => {
  const catalog = new SqliteJobHandleRouteCatalog(":memory:");
  const owner = fixtureOwner(principal("user-1"));
  catalog.register({ ...owner, jobHandle: LEGACY_HANDLE, lane: "legacy_governed" });
  assert.throws(
    () => catalog.register({ ...owner, jobHandle: LEGACY_HANDLE, lane: "portfolio_surveillance_v4" }),
    (error: unknown) => error instanceof JobHandleRouteCatalogError && error.code === "ROUTE_CONFLICT"
  );
  catalog.close();
});

function routerFixture(databasePath = ":memory:") {
  const calls = {
    legacyStart: 0,
    legacyStatus: 0,
    legacyResult: 0,
    legacyCancel: 0,
    v4Start: 0,
    v4Status: 0,
    v4Result: 0,
    v4Cancel: 0
  };
  const state = { failV4Status: false };
  const response = (value: unknown): RoutedGovernedWorkflowResponse => ({ value, obligations: OBLIGATIONS });
  const legacy: LegacyRoutedWorkflowApi = {
    startAuthorized: (_principal, input) => {
      calls.legacyStart += 1;
      return response({ jobHandle: LEGACY_HANDLE, status: "queued", operation: input.operation });
    },
    getJobStatusAuthorized: () => {
      calls.legacyStatus += 1;
      return response("legacy-status");
    },
    getJobResultAuthorized: () => {
      calls.legacyResult += 1;
      return response("legacy-result");
    },
    cancelJobAuthorized: () => {
      calls.legacyCancel += 1;
      return response("legacy-cancel");
    }
  };
  const portfolioSurveillanceV4: PortfolioSurveillanceRoutedWorkflowApi = {
    startPortfolioSurveillanceAuthorized: () => {
      calls.v4Start += 1;
      return response({ jobHandle: V4_HANDLE, status: "queued", operation: "portfolio_surveillance_v1" });
    },
    getPortfolioSurveillanceJobStatusAuthorized: () => {
      calls.v4Status += 1;
      if (state.failV4Status) throw new Error("v4 status failure");
      return response("v4-status");
    },
    getPortfolioSurveillanceJobResultAuthorized: () => {
      calls.v4Result += 1;
      return response("v4-result");
    },
    cancelPortfolioSurveillanceJobAuthorized: () => {
      calls.v4Cancel += 1;
      return response("v4-cancel");
    }
  };
  const routes = new SqliteJobHandleRouteCatalog(databasePath);
  const router = new CompositeGovernedWorkflowRouter({ legacy, portfolioSurveillanceV4, routes });
  const result = {
    router,
    routes,
    principal: principal("user-1"),
    calls,
    close: () => routes.close(),
    get failV4Status() {
      return state.failV4Status;
    },
    set failV4Status(value: boolean) {
      state.failV4Status = value;
    }
  };
  return result;
}

function surveillanceStart(idempotencyKey: string) {
  return {
    operation: "portfolio_surveillance_v1" as const,
    operationRequest: {
      contractVersion: 1 as const,
      operation: "portfolio_surveillance_v1" as const,
      sources: [{ kind: "certification_manifest" as const, certificationManifestId: "cert-1" }],
      definitionVersionIds: ["metric-1"]
    },
    idempotencyKey,
    purpose: "portfolio surveillance"
  };
}

function principal(subject: string): VerifiedPrincipalContext {
  return createVerifiedPrincipalContext({
    issuer: "https://issuer.example.com/",
    subject,
    principalId: subject,
    tenantId: "tenant-a",
    clientId: "test-client",
    audiences: ["abl-api"],
    resourceIndicators: ["https://mcp.example.test/mcp"],
    scopes: ["abl:all"],
    credentialFingerprint: "a".repeat(64),
    verifiedAtEpochSeconds: 1_786_440_000,
    expiresAtEpochSeconds: 4_000_000_000
  });
}

function fixtureOwner(value: VerifiedPrincipalContext) {
  return {
    tenantId: value.tenantId,
    principalBinding: principalBinding(value)
  };
}

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "job-route-test-"));
  DIRECTORIES.push(directory);
  return directory;
}
