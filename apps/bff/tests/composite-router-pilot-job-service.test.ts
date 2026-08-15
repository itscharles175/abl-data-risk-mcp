import { describe, expect, it } from "vitest";
import {
  createCompositeRouterPilotJobApi,
  type BoundRouterPrincipal,
  type CompositeGovernedWorkflowRouterBridge,
} from "../src/composite-router-pilot-job-service.js";
import {
  PilotJobServiceError,
  type PilotJobActorContext,
  type PilotPortfolioSurveillanceStartInput,
} from "../src/pilot-job-service.js";

const SCOPE = Object.freeze({
  tenantId: "tenant-pilot",
  facilityId: "facility-synthetic-auto-1",
});
const HANDLE = "opaque.job_handle-0123456789";

interface Principal extends BoundRouterPrincipal {
  readonly verified: true;
}

function actor(overrides: Partial<PilotJobActorContext> = {}): PilotJobActorContext {
  return {
    ...SCOPE,
    principalId: "operator-1",
    roles: ["platform_operator"],
    ...overrides,
  };
}

function startInput(): PilotPortfolioSurveillanceStartInput {
  return {
    operation: "portfolio_surveillance_v1",
    operationRequest: {
      contractVersion: 1,
      operation: "portfolio_surveillance_v1",
      sources: [
        { kind: "certification_manifest", certificationManifestId: "cert-june" },
        { kind: "certification_manifest", certificationManifestId: "cert-july" },
      ],
      definitionVersionIds: ["definition-metrics", "definition-methodology"],
    },
    idempotencyKey: "synthetic-auto-july-replay",
    purpose: "monthly_surveillance",
  };
}

function status(statusValue: "queued" | "running" | "cancelled" = "running") {
  return {
    operation: "portfolio_surveillance_v1" as const,
    status: statusValue,
    durableStatus: statusValue === "cancelled" ? "cancelled" : "submitted",
    attemptCount: 1,
    maxAttempts: 3,
    cancellationRequested: statusValue === "cancelled",
    createdAt: "2026-08-15T12:00:00.000Z",
    updatedAt: "2026-08-15T12:00:01.000Z",
    errorCode: null,
    resultAvailable: false,
  };
}

function response(value: unknown) {
  return { value, obligations: [{ allowRawRows: false }, { maxResultRows: 5_000 }] };
}

function bridge(overrides: Partial<CompositeGovernedWorkflowRouterBridge<Principal>> = {}) {
  const calls: { readonly name: string; readonly principal: Principal; readonly value: unknown }[] = [];
  const implementation: CompositeGovernedWorkflowRouterBridge<Principal> = {
    binding: SCOPE,
    startPortfolioSurveillanceAuthorized(principal, input, requestContext) {
      calls.push({ name: "start", principal, value: { input, requestContext } });
      return response({
        jobHandle: HANDLE,
        status: "queued",
        operation: "portfolio_surveillance_v1",
      });
    },
    getJobStatusAuthorized(principal, jobHandle) {
      calls.push({ name: "status", principal, value: jobHandle });
      return response(status());
    },
    getJobResultAuthorized(principal, jobHandle) {
      calls.push({ name: "result", principal, value: jobHandle });
      return response({
        operation: "portfolio_surveillance_v1",
        manifestId: "manifest-1",
        artifactId: "artifact-1",
        resultHash: "a".repeat(64),
        result: { aggregateOnly: true },
      });
    },
    cancelJobAuthorized(principal, jobHandle, requestContext) {
      calls.push({ name: "cancel", principal, value: { jobHandle, requestContext } });
      return response(status("cancelled"));
    },
    ...overrides,
  };
  return { implementation, calls };
}

function api(overrides: Partial<CompositeGovernedWorkflowRouterBridge<Principal>> = {}) {
  const fixture = bridge(overrides);
  let principalFactoryCalls = 0;
  const pilot = createCompositeRouterPilotJobApi({
    bridge: fixture.implementation,
    createVerifiedPrincipal(context): Principal {
      principalFactoryCalls += 1;
      return {
        tenantId: context.tenantId,
        principalId: context.principalId,
        verified: true,
      };
    },
  });
  return {
    ...fixture,
    pilot,
    get principalFactoryCalls() { return principalFactoryCalls; },
  };
}

describe("composite-router pilot job adapter", () => {
  it("binds capability scope and routes start, status, result, and cancel with verified identity", async () => {
    const fixture = api();
    expect(fixture.pilot.scope).toEqual(SCOPE);
    expect(Object.isFrozen(fixture.pilot.scope)).toBe(true);

    const started = await fixture.pilot.service.startPortfolioSurveillance(actor(), startInput());
    const current = await fixture.pilot.service.getJobStatus(actor(), HANDLE);
    const result = await fixture.pilot.service.getJobResult(actor(), HANDLE);
    const cancelled = await fixture.pilot.service.cancelJob(actor(), HANDLE);

    expect(started.value).toMatchObject({ jobHandle: HANDLE, status: "queued" });
    expect(current.value).toMatchObject({ status: "running", durableStatus: "submitted" });
    expect(result.value.result).toEqual({ aggregateOnly: true });
    expect(cancelled.value).toMatchObject({ status: "cancelled", durableStatus: "cancelled" });
    expect(fixture.calls.map(({ name }) => name)).toEqual(["start", "status", "result", "cancel"]);
    expect(fixture.calls.every(({ principal }) =>
      principal.tenantId === SCOPE.tenantId &&
      principal.principalId === "operator-1" &&
      principal.verified
    )).toBe(true);
    const mutationCalls = [fixture.calls[0]!.value, fixture.calls[3]!.value];
    expect(mutationCalls.every((value) =>
      typeof (value as { requestContext: { requestStartedAtMonotonicMs: unknown } })
        .requestContext.requestStartedAtMonotonicMs === "number"
    )).toBe(true);
    expect(JSON.stringify([started, current, result, cancelled])).not.toContain("maxResultRows");
  });

  it("rejects cross-tenant, cross-facility, and unprivileged contexts before identity or router access", async () => {
    const fixture = api();
    for (const context of [
      actor({ tenantId: "tenant-other" }),
      actor({ facilityId: "facility-other" }),
      actor({ roles: ["risk_analyst"] }),
    ]) {
      await expect(fixture.pilot.service.getJobStatus(context, HANDLE)).rejects.toMatchObject({
        status: 403,
        code: "pilot_scope_denied",
        message: "Pilot scope was not authorized",
      });
    }
    expect(fixture.principalFactoryCalls).toBe(0);
    expect(fixture.calls).toEqual([]);
  });

  it("fails closed when the verified principal factory changes tenant or actor binding", async () => {
    const fixture = bridge();
    const pilot = createCompositeRouterPilotJobApi({
      bridge: fixture.implementation,
      createVerifiedPrincipal: (): Principal => ({
        tenantId: "tenant-other",
        principalId: "operator-other",
        verified: true,
      }),
    });
    await expect(pilot.service.getJobStatus(actor(), HANDLE)).rejects.toMatchObject({
      status: 503,
      code: "workflow_contract_violation",
    });
    expect(fixture.calls).toEqual([]);
  });

  it("maps foreign handles and governed failures to sanitized public errors", async () => {
    const upstreamSecret = "source-password-must-not-leak";
    const foreignHandleError = Object.assign(new Error(upstreamSecret), {
      name: "JobHandleRouteCatalogError",
      code: "ROUTE_NOT_FOUND",
    });
    const policyError = Object.assign(new Error(upstreamSecret), {
      name: "PortfolioSurveillanceWorkflowV4Error",
      code: "POLICY_DENIED",
    });
    const fixture = api({
      getJobStatusAuthorized() { throw foreignHandleError; },
      getJobResultAuthorized() { throw policyError; },
    });

    await expect(fixture.pilot.service.getJobStatus(actor(), HANDLE)).rejects.toMatchObject({
      status: 404,
      code: "job_not_found",
      message: "Job was not found",
    });
    await expect(fixture.pilot.service.getJobResult(actor(), HANDLE)).rejects.toMatchObject({
      status: 403,
      code: "permission_denied",
      message: "Pilot operation was denied",
    });
    for (const action of [
      fixture.pilot.service.getJobStatus(actor(), HANDLE),
      fixture.pilot.service.getJobResult(actor(), HANDLE),
    ]) {
      await expect(action).rejects.not.toHaveProperty("message", upstreamSecret);
    }
  });

  it("rejects malformed and secret-bearing router results without disclosing their content", async () => {
    const secret = "must-never-reach-the-browser";
    const malformed = api({
      getJobStatusAuthorized() {
        return response({ ...status(), internalDebug: secret });
      },
      getJobResultAuthorized() {
        return response({
          operation: "portfolio_surveillance_v1",
          manifestId: "manifest-1",
          artifactId: "artifact-1",
          resultHash: "a".repeat(64),
          result: { password: secret },
        });
      },
    });
    for (const action of [
      malformed.pilot.service.getJobStatus(actor(), HANDLE),
      malformed.pilot.service.getJobResult(actor(), HANDLE),
    ]) {
      await expect(action).rejects.toMatchObject({
        status: 503,
        code: "workflow_contract_violation",
      });
      await expect(action).rejects.not.toHaveProperty("message", expect.stringContaining(secret));
    }
  });

  it("validates direct service inputs and leaves unknown failures for the BFF 500 boundary", async () => {
    const unknown = new Error("opaque infrastructure detail");
    const fixture = api({ getJobStatusAuthorized() { throw unknown; } });
    await expect(fixture.pilot.service.getJobStatus(actor(), "short")).rejects.toBeInstanceOf(
      PilotJobServiceError,
    );
    await expect(fixture.pilot.service.startPortfolioSurveillance(actor(), {
      ...startInput(),
      operationRequest: {
        ...startInput().operationRequest,
        sources: [
          { kind: "certification_manifest", certificationManifestId: "cert-june" },
          { kind: "certification_manifest", certificationManifestId: "cert-june" },
        ],
      },
    })).rejects.toMatchObject({ status: 400, code: "invalid_pilot_job" });
    await expect(fixture.pilot.service.getJobStatus(actor(), HANDLE)).rejects.toBe(unknown);
  });
});
