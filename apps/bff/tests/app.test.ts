import request from "supertest";
import { describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { loadBffConfiguration, type BffConfiguration } from "../src/config.js";
import type { AuthorizationRequest, OidcIdentityProvider } from "../src/oidc.js";
import {
  FixtureRiskPlatformAdapter,
  type RiskPlatformAdapter,
} from "../src/platform-adapter.js";
import {
  PilotJobServiceError,
  type PilotJobActorContext,
  type PilotJobServicePort,
  type PilotPortfolioSurveillanceStartInput,
} from "../src/pilot-job-service.js";
import { InMemorySessionStore, type SessionStore } from "../src/session.js";

const ORIGIN = "http://localhost:4173";

function configuration(overrides: Partial<BffConfiguration> = {}): BffConfiguration {
  return {
    authMode: "fixture",
    production: false,
    port: 4300,
    consoleUrl: ORIGIN,
    allowedOrigins: new Set([ORIGIN]),
    secureCookies: false,
    sessionTtlMs: 60 * 60_000,
    stepUpTtlMs: 10 * 60_000,
    oidcTransactionTtlMs: 10 * 60_000,
    oidcTransactionMaxEntries: 4_096,
    oidcLoginWindowMs: 60_000,
    oidcLoginMaxAttempts: 20,
    oidcLoginMaxKeys: 10_000,
    ...overrides,
  };
}

async function login(agent: ReturnType<typeof request.agent>, principalId: string) {
  const response = await agent
    .post("/api/auth/fixture-login")
    .set("origin", ORIGIN)
    .send({ principalId })
    .expect(201);
  return response.body as { readonly csrfToken: string };
}

function explicitSessionStore(): SessionStore {
  const backing = new InMemorySessionStore(60 * 60_000, 10 * 60_000);
  return {
    create: (principal) => backing.create(principal),
    get: (id) => backing.get(id),
    satisfyStepUp: (id) => backing.satisfyStepUp(id),
    delete: (id) => backing.delete(id),
  };
}

function environmentAdapter(): RiskPlatformAdapter {
  const fixture = new FixtureRiskPlatformAdapter();
  return {
    dataMode: "environment",
    async getWorkbenchSection(section) {
      return { ...(await fixture.getWorkbenchSection(section)), sourceMode: "environment" };
    },
    async previewSourceContract(draft) {
      return { ...(await fixture.previewSourceContract(draft)), fixture: false };
    },
  };
}

describe("platform BFF", () => {
  it("labels fixture mode and requires authentication for data", async () => {
    const app = buildApp({ configuration: configuration() });
    const metadata = await request(app).get("/api/v1/meta").expect(200);
    expect(metadata.body).toMatchObject({ backendMode: "fixture", dataMode: "fixture" });
    expect(metadata.body.warning).toContain("No live control-plane");
    await request(app).get("/api/v1/workbench/overview").expect(401);
  });

  it("filters navigation and guards routes by least privilege", async () => {
    const app = buildApp({ configuration: configuration() });
    const analyst = request.agent(app);
    await login(analyst, "demo-analyst");

    const navigation = await analyst.get("/api/v1/navigation").expect(200);
    expect(navigation.body.items.map((item: { readonly id: string }) => item.id)).toEqual([
      "overview",
      "portfolios",
      "facilities",
      "alerts",
    ]);
    await analyst.get("/api/v1/workbench/portfolios").expect(200);
    await analyst.get("/api/v1/workbench/policies").expect(403);
  });

  it("enforces origin, CSRF, step-up, and maker/checker separation", async () => {
    const app = buildApp({ configuration: configuration() });
    const steward = request.agent(app);
    const stewardSession = await login(steward, "demo-steward");
    const action = {
      kind: "mapping_activation",
      targetId: "map-loan-v4",
      reason: "Activate the validated mapping for the August delivery.",
      semanticDiff: { fieldsAdded: 1 },
      rollbackTargetId: "map-loan-v3",
    };

    await steward
      .post("/api/v1/high-risk-actions")
      .set("origin", ORIGIN)
      .send(action)
      .expect(403)
      .expect(({ body }) => expect(body.error.code).toBe("csrf_rejected"));

    await steward
      .post("/api/v1/high-risk-actions")
      .set("origin", "https://attacker.invalid")
      .set("x-csrf-token", stewardSession.csrfToken)
      .send(action)
      .expect(403)
      .expect(({ body }) => expect(body.error.code).toBe("origin_rejected"));

    await steward
      .post("/api/v1/high-risk-actions")
      .set("origin", ORIGIN)
      .set("x-csrf-token", stewardSession.csrfToken)
      .send(action)
      .expect(403)
      .expect(({ body }) => expect(body.error.code).toBe("step_up_required"));

    const steppedUp = await steward
      .post("/api/auth/fixture-step-up")
      .set("origin", ORIGIN)
      .set("x-csrf-token", stewardSession.csrfToken)
      .send({})
      .expect(200);
    expect(steppedUp.body.stepUp.satisfied).toBe(true);

    const proposal = await steward
      .post("/api/v1/high-risk-actions")
      .set("origin", ORIGIN)
      .set("x-csrf-token", stewardSession.csrfToken)
      .send(action)
      .expect(201);

    await steward
      .post(`/api/v1/approvals/${proposal.body.id}/decision`)
      .set("origin", ORIGIN)
      .set("x-csrf-token", stewardSession.csrfToken)
      .send({ decision: "approved", rationale: "I should not be able to approve my own request." })
      .expect(409)
      .expect(({ body }) => expect(body.error.code).toBe("maker_checker_conflict"));

    const reviewer = request.agent(app);
    const reviewerSession = await login(reviewer, "demo-reviewer");
    await reviewer
      .post("/api/auth/fixture-step-up")
      .set("origin", ORIGIN)
      .set("x-csrf-token", reviewerSession.csrfToken)
      .send({})
      .expect(200);
    const decision = await reviewer
      .post(`/api/v1/approvals/${proposal.body.id}/decision`)
      .set("origin", ORIGIN)
      .set("x-csrf-token", reviewerSession.csrfToken)
      .send({ decision: "approved", rationale: "Independent review confirmed the evidence and rollback target." })
      .expect(200);
    expect(decision.body).toMatchObject({ status: "approved", checker: { id: "demo-reviewer" } });
  });

  it("accepts only opaque secret references in strict action payloads", async () => {
    const app = buildApp({ configuration: configuration() });
    const security = request.agent(app);
    const session = await login(security, "demo-security");
    await security
      .post("/api/auth/fixture-step-up")
      .set("origin", ORIGIN)
      .set("x-csrf-token", session.csrfToken)
      .send({})
      .expect(200);

    await security
      .post("/api/v1/high-risk-actions")
      .set("origin", ORIGIN)
      .set("x-csrf-token", session.csrfToken)
      .send({
        kind: "key_rotation",
        targetId: "connector-west",
        reason: "Rotate the connector key before its governed due date.",
        rollbackTargetId: "key-version-5",
        secret: "raw-secret-material",
      })
      .expect(400);

    const accepted = await security
      .post("/api/v1/high-risk-actions")
      .set("origin", ORIGIN)
      .set("x-csrf-token", session.csrfToken)
      .send({
        kind: "key_rotation",
        targetId: "connector-west",
        reason: "Rotate the connector key before its governed due date.",
        rollbackTargetId: "key-version-5",
        secretRef: "secretref://vault/connectors/west#v6",
      })
      .expect(201);
    expect(accepted.body.secretRef).toBe("secretref://vault/connectors/west#v6");
  });

  it("requires the approval capability for the proposal's domain and filters the queue", async () => {
    const app = buildApp({ configuration: configuration() });
    const security = request.agent(app);
    const securitySession = await login(security, "demo-security");
    await security
      .post("/api/auth/fixture-step-up")
      .set("origin", ORIGIN)
      .set("x-csrf-token", securitySession.csrfToken)
      .send({})
      .expect(200);
    const proposal = await security
      .post("/api/v1/high-risk-actions")
      .set("origin", ORIGIN)
      .set("x-csrf-token", securitySession.csrfToken)
      .send({
        kind: "key_rotation",
        targetId: "connector-west",
        reason: "Rotate the governed connector key before its due date.",
        rollbackTargetId: "key-version-5",
        secretRef: "secretref://vault/connectors/west#v6",
      })
      .expect(201);

    const reviewer = request.agent(app);
    const reviewerSession = await login(reviewer, "demo-reviewer");
    await reviewer
      .post("/api/auth/fixture-step-up")
      .set("origin", ORIGIN)
      .set("x-csrf-token", reviewerSession.csrfToken)
      .send({})
      .expect(200);
    const queue = await reviewer.get("/api/v1/approvals").expect(200);
    expect(queue.body.items).toEqual([]);
    await reviewer
      .post(`/api/v1/approvals/${proposal.body.id}/decision`)
      .set("origin", ORIGIN)
      .set("x-csrf-token", reviewerSession.csrfToken)
      .send({ decision: "approved", rationale: "This reviewer lacks key-rotation authority." })
      .expect(403)
      .expect(({ body }) => expect(body.error.code).toBe("permission_denied"));
  });

  it("profiles a source-contract draft without accepting raw credentials", async () => {
    const app = buildApp({ configuration: configuration() });
    const steward = request.agent(app);
    const session = await login(steward, "demo-steward");
    const baseDraft = {
      name: "Primary loan tape",
      deliveryMode: "postgresql",
      sourceLocator: "risk_read.loan_tape",
      watermarkField: "as_of_date",
    };

    await steward
      .post("/api/v1/source-contracts/preview")
      .set("origin", ORIGIN)
      .set("x-csrf-token", session.csrfToken)
      .send({ ...baseDraft, password: "raw-password" })
      .expect(400);

    const preview = await steward
      .post("/api/v1/source-contracts/preview")
      .set("origin", ORIGIN)
      .set("x-csrf-token", session.csrfToken)
      .send({ ...baseDraft, secretRef: "secretref://vault/postgres/risk-reader#v2" })
      .expect(200);
    expect(preview.body).toMatchObject({ fixture: true, nextStep: "propose_activation" });
    expect(preview.body.profile).toHaveLength(4);
    expect(JSON.stringify(preview.body)).not.toContain("raw-password");
  });

  it("sets hardened session cookies when secure-cookie mode is enabled", async () => {
    const app = buildApp({ configuration: configuration({ secureCookies: true }) });
    const response = await request(app)
      .post("/api/auth/fixture-login")
      .set("origin", ORIGIN)
      .send({ principalId: "demo-auditor" })
      .expect(201);
    const cookie = response.headers["set-cookie"]?.[0] as string | undefined;
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Secure");
  });

  it("completes OIDC code plus PKCE login and identity-bound step-up through the adapter", async () => {
    let authorizationRequest: AuthorizationRequest | undefined;
    const oidc: OidcIdentityProvider = {
      async authorizationUrl(input) {
        authorizationRequest = input;
        const url = new URL("https://identity.example.test/authorize");
        url.searchParams.set("state", input.state);
        url.searchParams.set("code_challenge", input.codeChallenge);
        return url;
      },
      async exchangeAuthorizationCode(input) {
        expect(input.codeVerifier.length).toBeGreaterThanOrEqual(43);
        expect(input.nonce).toBe(authorizationRequest?.nonce);
        return {
          id: "oidc-reviewer-7",
          displayName: "OIDC Reviewer",
          email: "reviewer@example.test",
          roles: ["risk_reviewer"],
        };
      },
    };
    const app = buildApp({
      configuration: configuration({
        authMode: "oidc",
        oidc: {
          issuer: "https://identity.example.test/",
          clientId: "abl-console",
          redirectUri: "http://localhost:4300/api/auth/callback",
          scopes: ["openid", "profile", "email", "roles"],
        },
      }),
      oidc,
    });
    const browser = request.agent(app);

    const loginResponse = await browser
      .get(`/api/auth/login?returnTo=${encodeURIComponent("/#/reports")}`)
      .expect(302);
    const authorizationUrl = new URL(loginResponse.headers.location as string);
    expect(authorizationUrl.origin).toBe("https://identity.example.test");
    expect(authorizationUrl.searchParams.get("code_challenge")).toBe(authorizationRequest?.codeChallenge);
    await browser
      .get(`/api/auth/callback?code=code-a&state=${encodeURIComponent(authorizationRequest?.state ?? "")}`)
      .expect(302)
      .expect("location", `${ORIGIN}/#/reports`);
    const authenticated = await browser.get("/api/v1/session").expect(200);
    expect(authenticated.body).toMatchObject({
      principal: { id: "oidc-reviewer-7", roles: ["risk_reviewer"] },
      stepUp: { satisfied: false },
    });

    await browser
      .get(`/api/auth/step-up?returnTo=${encodeURIComponent("/#/approvals")}`)
      .expect(302);
    expect(authorizationRequest?.stepUp).toBe(true);
    await browser
      .get(`/api/auth/callback?code=code-b&state=${encodeURIComponent(authorizationRequest?.state ?? "")}`)
      .expect(302)
      .expect("location", `${ORIGIN}/#/approvals`);
    const steppedUp = await browser.get("/api/v1/session").expect(200);
    expect(steppedUp.body.stepUp.satisfied).toBe(true);
  });

  it("rate-limits OIDC login initiation before allocating unbounded transactions", async () => {
    const oidc: OidcIdentityProvider = {
      async authorizationUrl(input) {
        return new URL(`https://identity.example.test/authorize?state=${input.state}`);
      },
      async exchangeAuthorizationCode() {
        throw new Error("not reached");
      },
    };
    const app = buildApp({
      configuration: configuration({
        authMode: "oidc",
        oidcLoginMaxAttempts: 2,
        oidc: {
          issuer: "https://identity.example.test/",
          clientId: "abl-console",
          redirectUri: "http://localhost:4300/api/auth/callback",
          scopes: ["openid"],
        },
      }),
      oidc,
    });

    await request(app).get("/api/auth/login").expect(302);
    await request(app).get("/api/auth/login").expect(302);
    await request(app)
      .get("/api/auth/login")
      .expect(429)
      .expect("retry-after", "60")
      .expect(({ body }) => expect(body.error.code).toBe("oidc_rate_limited"));
  });

  it("keeps the governed pilot API disabled unless a service is explicitly injected", async () => {
    const app = buildApp({ configuration: configuration() });
    await request(app).get("/api/v1/pilot").expect(401);

    const operator = request.agent(app);
    await login(operator, "demo-operator");
    await operator
      .get("/api/v1/pilot")
      .expect(404)
      .expect(({ body }) => expect(body.error.code).toBe("pilot_api_unavailable"));
  });

  it("derives pilot tenant, facility, and actor scope server-side for every job operation", async () => {
    const calls: {
      readonly name: string;
      readonly context: PilotJobActorContext;
      readonly input?: PilotPortfolioSurveillanceStartInput | string;
    }[] = [];
    const status = {
      operation: "portfolio_surveillance_v1" as const,
      status: "running" as const,
      durableStatus: "submitted",
      attemptCount: 1,
      maxAttempts: 3,
      cancellationRequested: false,
      createdAt: "2026-08-15T12:00:00.000Z",
      updatedAt: "2026-08-15T12:00:01.000Z",
      errorCode: null,
      resultAvailable: false,
    };
    const service: PilotJobServicePort = {
      async startPortfolioSurveillance(context, input) {
        calls.push({ name: "start", context, input });
        return {
          value: {
            jobHandle: "opaque.job_handle-0123456789",
            status: "queued",
            operation: "portfolio_surveillance_v1",
          },
        };
      },
      async getJobStatus(context, jobHandle) {
        calls.push({ name: "status", context, input: jobHandle });
        return { value: status };
      },
      async getJobResult(context, jobHandle) {
        calls.push({ name: "result", context, input: jobHandle });
        return {
          value: {
            operation: "portfolio_surveillance_v1",
            manifestId: "manifest-1",
            artifactId: "artifact-1",
            resultHash: "a".repeat(64),
            result: { aggregateOnly: true },
          },
        };
      },
      async cancelJob(context, jobHandle) {
        calls.push({ name: "cancel", context, input: jobHandle });
        return { value: { ...status, status: "cancelled", cancellationRequested: true } };
      },
    };
    const app = buildApp({
      configuration: configuration(),
      pilotJobs: {
        scope: { tenantId: "tenant-pilot", facilityId: "facility-synthetic-auto-1" },
        service,
      },
    });
    const operator = request.agent(app);
    const session = await login(operator, "demo-operator");

    await operator.get("/api/v1/pilot").expect(200).expect({
      enabled: true,
      scope: { tenantId: "tenant-pilot", facilityId: "facility-synthetic-auto-1" },
      operations: ["portfolio_surveillance_v1"],
    });
    const start = await operator
      .post("/api/v1/pilot/jobs")
      .set("origin", ORIGIN)
      .set("x-csrf-token", session.csrfToken)
      .send({
        certificationManifestIds: ["cert-june", "cert-july"],
        definitionVersionIds: ["definition-metrics", "definition-methodology"],
        idempotencyKey: "synthetic-auto-july-replay",
        purpose: "monthly_surveillance",
      })
      .expect(202);
    expect(start.body).toMatchObject({
      scope: { tenantId: "tenant-pilot", facilityId: "facility-synthetic-auto-1" },
      job: { jobHandle: "opaque.job_handle-0123456789", status: "queued" },
    });
    expect(calls[0]).toEqual({
      name: "start",
      context: {
        tenantId: "tenant-pilot",
        facilityId: "facility-synthetic-auto-1",
        principalId: "demo-operator",
        roles: ["platform_operator"],
      },
      input: {
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
      },
    });

    const handle = "opaque.job_handle-0123456789";
    await operator.get(`/api/v1/pilot/jobs/${handle}/status`).expect(200);
    await operator.get(`/api/v1/pilot/jobs/${handle}/result`).expect(200);
    await operator
      .post(`/api/v1/pilot/jobs/${handle}/cancel`)
      .set("origin", ORIGIN)
      .set("x-csrf-token", session.csrfToken)
      .send({})
      .expect(200);
    expect(calls.slice(1).map(({ name }) => name)).toEqual(["status", "result", "cancel"]);
    expect(calls.slice(1).every(({ context }) =>
      context.tenantId === "tenant-pilot" &&
      context.facilityId === "facility-synthetic-auto-1" &&
      context.principalId === "demo-operator"
    )).toBe(true);
  });

  it("rejects client-supplied scope, requires operator authority, and preserves write protections", async () => {
    const service: PilotJobServicePort = {
      async startPortfolioSurveillance() { throw new Error("must not be called"); },
      async getJobStatus() { throw new Error("must not be called"); },
      async getJobResult() { throw new Error("must not be called"); },
      async cancelJob() { throw new Error("must not be called"); },
    };
    const app = buildApp({
      configuration: configuration(),
      pilotJobs: {
        scope: { tenantId: "tenant-pilot", facilityId: "facility-synthetic-auto-1" },
        service,
      },
    });
    const analyst = request.agent(app);
    await login(analyst, "demo-analyst");
    await analyst.get("/api/v1/pilot").expect(403);

    const operator = request.agent(app);
    const session = await login(operator, "demo-operator");
    const body = {
      certificationManifestIds: ["cert-june", "cert-july"],
      definitionVersionIds: ["definition-metrics", "definition-methodology"],
      idempotencyKey: "synthetic-auto-july-replay",
      purpose: "monthly_surveillance",
      tenantId: "attacker-tenant",
    };
    await operator
      .post("/api/v1/pilot/jobs")
      .set("origin", ORIGIN)
      .set("x-csrf-token", session.csrfToken)
      .send(body)
      .expect(400)
      .expect(({ body: responseBody }) => expect(responseBody.error.code).toBe("invalid_pilot_job"));
    await operator
      .post("/api/v1/pilot/jobs")
      .set("origin", ORIGIN)
      .send({
        certificationManifestIds: ["cert-june", "cert-july"],
        definitionVersionIds: ["definition-metrics", "definition-methodology"],
        idempotencyKey: "synthetic-auto-july-replay",
        purpose: "monthly_surveillance",
      })
      .expect(403)
      .expect(({ body: responseBody }) => expect(responseBody.error.code).toBe("csrf_rejected"));
    await operator
      .post("/api/v1/pilot/jobs/opaque.job_handle-0123456789/cancel")
      .set("origin", "https://attacker.invalid")
      .set("x-csrf-token", session.csrfToken)
      .send({})
      .expect(403)
      .expect(({ body: responseBody }) => expect(responseBody.error.code).toBe("origin_rejected"));
  });

  it("maps only declared pilot service failures to public API errors", async () => {
    const service: PilotJobServicePort = {
      async startPortfolioSurveillance() {
        throw new PilotJobServiceError(409, "idempotency_conflict", "Key is already in use");
      },
      async getJobStatus() {
        throw new PilotJobServiceError(404, "job_not_found", "Job was not found");
      },
      async getJobResult() {
        throw new PilotJobServiceError(409, "result_not_ready", "Result is not ready");
      },
      async cancelJob() {
        throw new PilotJobServiceError(410, "job_terminal", "Job is already terminal");
      },
    };
    const app = buildApp({
      configuration: configuration(),
      pilotJobs: {
        scope: { tenantId: "tenant-pilot", facilityId: "facility-synthetic-auto-1" },
        service,
      },
    });
    const operator = request.agent(app);
    const session = await login(operator, "demo-operator");
    await operator
      .post("/api/v1/pilot/jobs")
      .set("origin", ORIGIN)
      .set("x-csrf-token", session.csrfToken)
      .send({
        certificationManifestIds: ["cert-june", "cert-july"],
        definitionVersionIds: ["definition-metrics", "definition-methodology"],
        idempotencyKey: "synthetic-auto-july-replay",
        purpose: "monthly_surveillance",
      })
      .expect(409)
      .expect(({ body }) => expect(body.error.code).toBe("idempotency_conflict"));
    await operator
      .get("/api/v1/pilot/jobs/opaque.job_handle-0123456789/status")
      .expect(404)
      .expect(({ body }) => expect(body.error.code).toBe("job_not_found"));
    await operator
      .get("/api/v1/pilot/jobs/opaque.job_handle-0123456789/result")
      .expect(409)
      .expect(({ body }) => expect(body.error.code).toBe("result_not_ready"));
    await operator
      .post("/api/v1/pilot/jobs/opaque.job_handle-0123456789/cancel")
      .set("origin", ORIGIN)
      .set("x-csrf-token", session.csrfToken)
      .send({})
      .expect(410)
      .expect(({ body }) => expect(body.error.code).toBe("job_terminal"));
  });

  it("fails closed on missing, unknown, or fixture authentication in production", async () => {
    expect(() => loadBffConfiguration({ NODE_ENV: "production" })).toThrow(
      "BFF_AUTH_MODE=oidc is required in production",
    );
    expect(() => loadBffConfiguration({
      NODE_ENV: "production",
      BFF_AUTH_MODE: "fixture",
    })).toThrow("BFF_AUTH_MODE=oidc is required in production");
    expect(() => loadBffConfiguration({ BFF_AUTH_MODE: "unexpected" })).toThrow(
      "BFF_AUTH_MODE must be either 'fixture' or 'oidc'",
    );
  });

  it("requires explicit non-fixture dependencies and exposes no fixture auth in production", async () => {
    const productionConfiguration = configuration({
      authMode: "oidc",
      production: true,
      secureCookies: true,
      oidc: {
        issuer: "https://identity.example.test/",
        clientId: "abl-console",
        redirectUri: "https://console.example.test/api/auth/callback",
        scopes: ["openid", "profile", "email", "roles"],
      },
    });
    expect(() => buildApp({ configuration: productionConfiguration })).toThrow(
      "Production BFF requires an explicit environment-backed data adapter",
    );
    expect(() => buildApp({
      configuration: productionConfiguration,
      adapter: environmentAdapter(),
    })).toThrow("Production BFF requires an explicit durable session store");
    expect(() => buildApp({
      configuration: productionConfiguration,
      adapter: new FixtureRiskPlatformAdapter(),
      sessions: explicitSessionStore(),
    })).toThrow("Production BFF requires an explicit environment-backed data adapter");

    const app = buildApp({
      configuration: productionConfiguration,
      adapter: environmentAdapter(),
      sessions: explicitSessionStore(),
    });
    await request(app)
      .post("/api/auth/fixture-login")
      .set("origin", ORIGIN)
      .send({ principalId: "demo-operator" })
      .expect(404)
      .expect(({ body }) => expect(body.error.code).toBe("fixture_auth_disabled"));
    await request(app)
      .post("/api/auth/fixture-step-up")
      .set("origin", ORIGIN)
      .send({})
      .expect(404)
      .expect(({ body }) => expect(body.error.code).toBe("fixture_auth_disabled"));
  });

  it("rejects malformed or secret-bearing injected outputs before browser disclosure", async () => {
    const malformedAdapter: RiskPlatformAdapter = {
      dataMode: "environment",
      async getWorkbenchSection(section) {
        return {
          ...(await environmentAdapter().getWorkbenchSection(section)),
          password: "must-never-reach-the-browser",
        } as never;
      },
      async previewSourceContract(draft) {
        return environmentAdapter().previewSourceContract(draft);
      },
    };
    const malformedApp = buildApp({
      configuration: configuration(),
      adapter: malformedAdapter,
    });
    const analyst = request.agent(malformedApp);
    await login(analyst, "demo-analyst");
    const malformedResponse = await analyst.get("/api/v1/workbench/overview").expect(500);
    expect(JSON.stringify(malformedResponse.body)).not.toContain("must-never-reach-the-browser");

    const secretResultService: PilotJobServicePort = {
      async startPortfolioSurveillance() { throw new Error("not reached"); },
      async getJobStatus() { throw new Error("not reached"); },
      async getJobResult() {
        return {
          value: {
            operation: "portfolio_surveillance_v1",
            manifestId: "manifest-1",
            artifactId: "artifact-1",
            resultHash: "a".repeat(64),
            result: { password: "must-never-reach-the-browser" },
          },
        };
      },
      async cancelJob() { throw new Error("not reached"); },
    };
    const secretResultApp = buildApp({
      configuration: configuration(),
      pilotJobs: {
        scope: { tenantId: "tenant-pilot", facilityId: "facility-synthetic-auto-1" },
        service: secretResultService,
      },
    });
    const operator = request.agent(secretResultApp);
    await login(operator, "demo-operator");
    const secretResponse = await operator
      .get("/api/v1/pilot/jobs/opaque.job_handle-0123456789/result")
      .expect(500);
    expect(JSON.stringify(secretResponse.body)).not.toContain("must-never-reach-the-browser");
  });
});
