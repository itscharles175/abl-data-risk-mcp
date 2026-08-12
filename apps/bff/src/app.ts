import { randomBytes, timingSafeEqual } from "node:crypto";
import express, { type Express, type Request, type Response } from "express";
import { z } from "zod";
import {
  ApprovalDecisionSchema,
  HighRiskActionRequestSchema,
  NAVIGATION,
  SectionIdSchema,
  SourceContractDraftSchema,
  hasPermission,
  type BackendMetadata,
  type PlatformPermission,
  type SessionPrincipal,
} from "@abl/platform-contracts";
import {
  ApprovalConflictError,
  ApprovalNotFoundError,
  ApprovalService,
  permissionForAction,
} from "./approvals.js";
import type { BffConfiguration } from "./config.js";
import {
  HttpOidcIdentityProvider,
  OidcLoginRateLimiter,
  OidcTransactionCapacityError,
  OidcTransactionStore,
  createPkcePair,
  type OidcIdentityProvider,
} from "./oidc.js";
import {
  FixtureRiskPlatformAdapter,
  type RiskPlatformAdapter,
} from "./platform-adapter.js";
import {
  InMemorySessionStore,
  OIDC_TRANSACTION_COOKIE,
  SESSION_COOKIE,
  clearCookie,
  parseCookies,
  serializeCookie,
  toSessionView,
  type SessionRecord,
  type SessionStore,
} from "./session.js";

const DEMO_PRINCIPALS: readonly SessionPrincipal[] = [
  { id: "demo-analyst", displayName: "Riley Analyst", email: "analyst@demo.invalid", roles: ["risk_analyst"] },
  { id: "demo-reviewer", displayName: "Morgan Reviewer", email: "reviewer@demo.invalid", roles: ["risk_reviewer"] },
  { id: "demo-steward", displayName: "Casey Steward", email: "steward@demo.invalid", roles: ["data_steward"] },
  { id: "demo-security", displayName: "Avery Security", email: "security@demo.invalid", roles: ["security_admin"] },
  { id: "demo-operator", displayName: "Jordan Operator", email: "operator@demo.invalid", roles: ["platform_operator"] },
  { id: "demo-auditor", displayName: "Taylor Auditor", email: "auditor@demo.invalid", roles: ["auditor"] },
];

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export interface BuildAppOptions {
  readonly configuration: BffConfiguration;
  readonly sessions?: SessionStore;
  readonly approvals?: ApprovalService;
  readonly adapter?: RiskPlatformAdapter;
  readonly oidc?: OidcIdentityProvider;
  readonly now?: () => Date;
}

function fixedTimeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function safeReturnTo(value: unknown): string {
  return typeof value === "string" && value.startsWith("/") && !value.startsWith("//")
    ? value
    : "/";
}

function errorResponse(response: Response, status: number, code: string, message: string): void {
  response.status(status).json({ error: { code, message } });
}

export function buildApp(options: BuildAppOptions): Express {
  const { configuration } = options;
  const now = options.now ?? (() => new Date());
  const sessions =
    options.sessions ??
    new InMemorySessionStore(configuration.sessionTtlMs, configuration.stepUpTtlMs, now);
  const approvals = options.approvals ?? new ApprovalService(now);
  const adapter = options.adapter ?? new FixtureRiskPlatformAdapter();
  const transactions = new OidcTransactionStore(
    now,
    configuration.oidcTransactionTtlMs,
    configuration.oidcTransactionMaxEntries,
  );
  const oidcLoginRateLimiter = new OidcLoginRateLimiter(
    configuration.oidcLoginMaxAttempts,
    configuration.oidcLoginWindowMs,
    configuration.oidcLoginMaxKeys,
    now,
  );
  const oidc =
    options.oidc ??
    (configuration.oidc ? new HttpOidcIdentityProvider(configuration.oidc) : undefined);
  const app = express();

  app.disable("x-powered-by");
  app.use((request, response, next) => {
    response.setHeader("cache-control", "no-store");
    response.setHeader("content-security-policy", "default-src 'none'; frame-ancestors 'none'");
    response.setHeader("referrer-policy", "no-referrer");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("x-frame-options", "DENY");
    response.setHeader("permissions-policy", "camera=(), microphone=(), geolocation=()");
    if (request.path.startsWith("/api/")) response.type("application/json");
    next();
  });
  app.use(express.json({ limit: "64kb", strict: true }));

  const getSession = (request: Request): SessionRecord | undefined => {
    const sessionId = parseCookies(request.headers.cookie)[SESSION_COOKIE];
    return sessionId ? sessions.get(sessionId) : undefined;
  };

  const sessionCookie = (record: SessionRecord): string =>
    serializeCookie(SESSION_COOKIE, record.id, {
      maxAgeSeconds: Math.floor((record.expiresAt.getTime() - now().getTime()) / 1_000),
      secure: configuration.secureCookies,
    });

  const requireSession = (request: Request, response: Response): SessionRecord | undefined => {
    const session = getSession(request);
    if (!session) errorResponse(response, 401, "authentication_required", "Sign in is required");
    return session;
  };

  const requirePermission = (
    session: SessionRecord,
    permission: PlatformPermission,
    response: Response,
  ): boolean => {
    if (!hasPermission(session.principal.roles, permission)) {
      errorResponse(response, 403, "permission_denied", `Missing permission: ${permission}`);
      return false;
    }
    return true;
  };

  const requireOrigin = (request: Request, response: Response): boolean => {
    const origin = request.headers.origin;
    const fetchSite = request.headers["sec-fetch-site"];
    if (!origin || !configuration.allowedOrigins.has(origin) || fetchSite === "cross-site") {
      errorResponse(response, 403, "origin_rejected", "Request origin is not allowed");
      return false;
    }
    return true;
  };

  const requireWriteProtection = (
    request: Request,
    response: Response,
    session: SessionRecord,
  ): boolean => {
    if (SAFE_METHODS.has(request.method)) return true;
    if (!requireOrigin(request, response)) return false;
    const csrfToken = request.header("x-csrf-token");
    if (!csrfToken || !fixedTimeEqual(csrfToken, session.csrfToken)) {
      errorResponse(response, 403, "csrf_rejected", "A valid session-bound CSRF token is required");
      return false;
    }
    return true;
  };

  const requireStepUp = (session: SessionRecord, response: Response): boolean => {
    if ((session.stepUpUntil?.getTime() ?? 0) <= now().getTime()) {
      errorResponse(response, 403, "step_up_required", "Recent step-up authentication is required");
      return false;
    }
    return true;
  };

  const beginOidc = async (
    request: Request,
    response: Response,
    stepUp: boolean,
  ): Promise<void> => {
    if (configuration.authMode !== "oidc" || !oidc) {
      errorResponse(response, 404, "oidc_unavailable", "OIDC is not configured in fixture mode");
      return;
    }
    const rateLimitKey = `${stepUp ? "step-up" : "login"}:${request.ip}`;
    if (!oidcLoginRateLimiter.allow(rateLimitKey)) {
      response.setHeader("retry-after", Math.ceil(configuration.oidcLoginWindowMs / 1_000));
      errorResponse(response, 429, "oidc_rate_limited", "Too many authentication attempts; try again later");
      return;
    }
    const existingSession = stepUp ? requireSession(request, response) : undefined;
    if (stepUp && !existingSession) return;
    const pkce = createPkcePair();
    let transaction;
    try {
      transaction = transactions.create({
        state: randomBytes(32).toString("base64url"),
        nonce: randomBytes(32).toString("base64url"),
        verifier: pkce.verifier,
        returnTo: safeReturnTo(request.query.returnTo),
        stepUp,
        ...(existingSession ? { sessionId: existingSession.id } : {}),
      });
    } catch (error) {
      if (error instanceof OidcTransactionCapacityError) {
        errorResponse(response, 503, "oidc_capacity_exhausted", "Authentication is temporarily unavailable");
        return;
      }
      throw error;
    }
    const authorizationUrl = await oidc.authorizationUrl({
      state: transaction.state,
      nonce: transaction.nonce,
      codeChallenge: pkce.challenge,
      stepUp,
    });
    response.setHeader(
      "set-cookie",
      serializeCookie(OIDC_TRANSACTION_COOKIE, transaction.id, {
        maxAgeSeconds: Math.ceil(configuration.oidcTransactionTtlMs / 1_000),
        secure: configuration.secureCookies,
      }),
    );
    response.redirect(302, authorizationUrl.toString());
  };

  app.get("/health", (_request, response) => {
    response.json({ status: "ok", service: "platform-bff" });
  });

  app.get("/api/v1/meta", (_request, response) => {
    const metadata: BackendMetadata = {
      product: "ABL Portfolio Risk Console",
      backendMode: configuration.authMode,
      dataMode: "fixture",
      warning: "Demonstration data only. No live control-plane or portfolio system is connected.",
    };
    response.json(metadata);
  });

  app.get("/api/auth/login", (request, response, next) => {
    void beginOidc(request, response, false).catch(next);
  });

  app.get("/api/auth/step-up", (request, response, next) => {
    void beginOidc(request, response, true).catch(next);
  });

  app.get("/api/auth/callback", (request, response, next) => {
    void (async () => {
      if (configuration.authMode !== "oidc" || !oidc) {
        errorResponse(response, 404, "oidc_unavailable", "OIDC is not configured");
        return;
      }
      const query = z.object({ code: z.string().min(1), state: z.string().min(1) }).safeParse(request.query);
      if (!query.success) {
        errorResponse(response, 400, "invalid_callback", "OIDC callback parameters are invalid");
        return;
      }
      const transactionId = parseCookies(request.headers.cookie)[OIDC_TRANSACTION_COOKIE];
      const transaction = transactionId
        ? transactions.consume(transactionId, query.data.state)
        : undefined;
      if (!transaction) {
        errorResponse(response, 400, "invalid_transaction", "OIDC transaction is missing, expired, or invalid");
        return;
      }
      const principal = await oidc.exchangeAuthorizationCode({
        code: query.data.code,
        codeVerifier: transaction.verifier,
        nonce: transaction.nonce,
      });
      let session: SessionRecord | undefined;
      if (transaction.stepUp) {
        const current = transaction.sessionId ? sessions.get(transaction.sessionId) : undefined;
        if (!current || current.principal.id !== principal.id) {
          errorResponse(response, 403, "step_up_identity_mismatch", "Step-up identity did not match the session");
          return;
        }
        session = sessions.satisfyStepUp(current.id);
      } else {
        session = sessions.create(principal);
      }
      if (!session) {
        errorResponse(response, 401, "session_expired", "The session expired during authentication");
        return;
      }
      response.setHeader("set-cookie", [
        sessionCookie(session),
        clearCookie(OIDC_TRANSACTION_COOKIE, configuration.secureCookies),
      ]);
      response.redirect(302, `${configuration.consoleUrl}${transaction.returnTo}`);
    })().catch(next);
  });

  app.post("/api/auth/fixture-login", (request, response) => {
    if (configuration.authMode !== "fixture") {
      errorResponse(response, 404, "fixture_auth_disabled", "Fixture authentication is disabled");
      return;
    }
    if (!requireOrigin(request, response)) return;
    const body = z.object({ principalId: z.string().min(1) }).strict().safeParse(request.body);
    const principal = body.success
      ? DEMO_PRINCIPALS.find((candidate) => candidate.id === body.data.principalId)
      : undefined;
    if (!principal) {
      errorResponse(response, 400, "invalid_fixture_principal", "Choose a known fixture principal");
      return;
    }
    const session = sessions.create(principal);
    response.setHeader("set-cookie", sessionCookie(session));
    response.status(201).json(toSessionView(session, now()));
  });

  app.post("/api/auth/fixture-step-up", (request, response) => {
    if (configuration.authMode !== "fixture") {
      errorResponse(response, 404, "fixture_auth_disabled", "Fixture authentication is disabled");
      return;
    }
    const session = requireSession(request, response);
    if (!session || !requireWriteProtection(request, response, session)) return;
    const updated = sessions.satisfyStepUp(session.id);
    if (!updated) {
      errorResponse(response, 401, "session_expired", "Session expired");
      return;
    }
    response.json(toSessionView(updated, now()));
  });

  app.post("/api/auth/logout", (request, response) => {
    const session = requireSession(request, response);
    if (!session || !requireWriteProtection(request, response, session)) return;
    sessions.delete(session.id);
    response.setHeader("set-cookie", clearCookie(SESSION_COOKIE, configuration.secureCookies));
    response.status(204).end();
  });

  app.get("/api/v1/session", (request, response) => {
    const session = requireSession(request, response);
    if (session) response.json(toSessionView(session, now()));
  });

  app.get("/api/v1/navigation", (request, response) => {
    const session = requireSession(request, response);
    if (!session) return;
    response.json({
      items: NAVIGATION.filter((item) => hasPermission(session.principal.roles, item.permission)),
    });
  });

  app.get("/api/v1/workbench/:section", (request, response, next) => {
    void (async () => {
      const session = requireSession(request, response);
      if (!session) return;
      const section = SectionIdSchema.safeParse(request.params.section);
      if (!section.success) {
        errorResponse(response, 404, "section_not_found", "Workbench section was not found");
        return;
      }
      const navigation = NAVIGATION.find((item) => item.id === section.data);
      if (!navigation || !requirePermission(session, navigation.permission, response)) return;
      response.json(await adapter.getWorkbenchSection(section.data));
    })().catch(next);
  });

  app.post("/api/v1/source-contracts/preview", (request, response, next) => {
    void (async () => {
      const session = requireSession(request, response);
      if (
        !session ||
        !requireWriteProtection(request, response, session) ||
        !requirePermission(session, "source:govern", response)
      ) return;
      const parsed = SourceContractDraftSchema.safeParse(request.body);
      if (!parsed.success) {
        errorResponse(response, 400, "invalid_source_contract", "Source contract is invalid or contains credential material");
        return;
      }
      response.json(await adapter.previewSourceContract(parsed.data));
    })().catch(next);
  });

  app.get("/api/v1/approvals", (request, response) => {
    const session = requireSession(request, response);
    if (!session || !requirePermission(session, "approval:review", response)) return;
    response.json({
      items: approvals.list().filter((record) =>
        hasPermission(session.principal.roles, permissionForAction(record.kind, "approve")),
      ),
    });
  });

  app.post("/api/v1/high-risk-actions", (request, response) => {
    const session = requireSession(request, response);
    if (
      !session ||
      !requireWriteProtection(request, response, session) ||
      !requireStepUp(session, response)
    ) return;
    const parsed = HighRiskActionRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      errorResponse(response, 400, "invalid_action", "High-risk action payload is invalid or contains forbidden fields");
      return;
    }
    if (!requirePermission(session, permissionForAction(parsed.data.kind, "propose"), response)) return;
    response.status(201).json(approvals.create(parsed.data, session.principal));
  });

  app.post("/api/v1/approvals/:approvalId/decision", (request, response) => {
    const session = requireSession(request, response);
    if (
      !session ||
      !requireWriteProtection(request, response, session) ||
      !requireStepUp(session, response) ||
      !requirePermission(session, "approval:review", response)
    ) return;
    const approval = approvals.get(request.params.approvalId);
    if (!approval) {
      errorResponse(response, 404, "approval_not_found", "Approval request was not found");
      return;
    }
    if (!requirePermission(session, permissionForAction(approval.kind, "approve"), response)) return;
    const parsed = ApprovalDecisionSchema.safeParse(request.body);
    if (!parsed.success) {
      errorResponse(response, 400, "invalid_decision", "Approval decision payload is invalid");
      return;
    }
    try {
      response.json(approvals.decide(request.params.approvalId, parsed.data, session.principal));
    } catch (error) {
      if (error instanceof ApprovalNotFoundError) {
        errorResponse(response, 404, "approval_not_found", error.message);
      } else if (error instanceof ApprovalConflictError) {
        errorResponse(response, 409, "maker_checker_conflict", error.message);
      } else {
        throw error;
      }
    }
  });

  app.use((_request, response) => {
    errorResponse(response, 404, "not_found", "Route was not found");
  });

  app.use((error: unknown, _request: Request, response: Response, _next: unknown) => {
    const requestId = randomBytes(12).toString("hex");
    console.error("platform-bff request failed", { requestId, error });
    errorResponse(response, 500, "internal_error", `Request failed; reference ${requestId}`);
  });

  return app;
}

export { DEMO_PRINCIPALS };
