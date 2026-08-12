import { randomUUID } from "node:crypto";
import type { Server } from "node:http";

import { toNodeHandler } from "@modelcontextprotocol/node";
import { createMcpHandler, type AuthInfo, type McpServerFactory } from "@modelcontextprotocol/server";
import express, { type NextFunction, type Request, type Response } from "express";

import {
  createBearerChallengeForError,
  createProtectedResourceMetadata,
  OAuthAuthenticationError,
  protectedResourceMetadataUrl,
  type JwtOAuthAuthenticator
} from "../security/oauth.js";
import {
  isVerifiedPrincipalContext,
  principalBinding,
  type VerifiedPrincipalContext
} from "../security/identity.js";

export interface RemoteHttpServerOptions {
  readonly host: string;
  readonly port: number;
  readonly allowedHosts: readonly string[];
  readonly allowedOrigins: readonly string[];
  readonly resource: string;
  readonly authorizationServers: readonly string[];
  readonly scopesSupported: readonly string[];
  readonly resourceName: string;
  readonly resourceDocumentation?: string;
  readonly authenticator: JwtOAuthAuthenticator;
  readonly serverFactory: McpServerFactory;
  readonly readiness: () => Promise<boolean> | boolean;
  readonly rateLimitWindowMs?: number;
  readonly maxRequestsPerWindow?: number;
  readonly maxConcurrentRequests?: number;
  readonly jsonBodyLimit?: string;
}

export interface RemoteHttpServerHandle {
  readonly host: string;
  readonly port: number;
  readonly resourceMetadataUrl: string;
  close(): Promise<void>;
}

/** Starts the authenticated, remote-only Streamable HTTP MCP entry point. */
export async function startRemoteHttp(options: RemoteHttpServerOptions): Promise<RemoteHttpServerHandle> {
  validateRemoteOptions(options);
  const metadataUrl = protectedResourceMetadataUrl(options.resource);
  const metadata = createProtectedResourceMetadata({
    resource: options.resource,
    authorizationServers: options.authorizationServers,
    scopesSupported: options.scopesSupported,
    resourceName: options.resourceName,
    ...(options.resourceDocumentation ? { resourceDocumentation: options.resourceDocumentation } : {})
  });
  const handler = createMcpHandler(options.serverFactory);
  const nodeHandler = toNodeHandler(handler, {
    onerror: () => {
      // The request id emitted by middleware is enough for correlation. Never log request bodies or tokens here.
      process.stderr.write('{"level":"error","event":"mcp_adapter_failure"}\n');
    }
  });
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", false);

  app.get("/healthz", (_request, response) => {
    response.set("Cache-Control", "no-store").status(200).json({ status: "ok" });
  });
  app.get("/readyz", async (_request, response) => {
    try {
      const ready = await options.readiness();
      response
        .set("Cache-Control", "no-store")
        .status(ready ? 200 : 503)
        .json({ status: ready ? "ready" : "not_ready" });
    } catch {
      response.set("Cache-Control", "no-store").status(503).json({ status: "not_ready" });
    }
  });

  const hostGuard = exactHostValidation(options.allowedHosts);
  const originGuard = exactOriginValidation(options.allowedOrigins);
  const metadataPath = new URL(metadataUrl).pathname;
  app.get(metadataPath, hostGuard, originGuard, (_request, response) => {
    response
      .set("Cache-Control", "public, max-age=300")
      .set("Content-Type", "application/json")
      .status(200)
      .json(metadata);
  });

  const rateLimiter = new PrincipalRateLimiter(
    options.maxRequestsPerWindow ?? 120,
    options.rateLimitWindowMs ?? 60_000
  );
  const concurrency = new ConcurrencyGate(options.maxConcurrentRequests ?? 100);
  const jsonParser = express.json({ limit: options.jsonBodyLimit ?? "256kb", type: ["application/json", "application/*+json"] });

  app.all(
    "/mcp",
    hostGuard,
    originGuard,
    requestIdMiddleware,
    concurrency.middleware,
    createAuthenticationMiddleware(options.authenticator, metadataUrl, options.resource),
    rateLimiter.middleware,
    jsonParser,
    (request, response) => {
      response.set("Cache-Control", "no-store");
      void nodeHandler(request, response, request.body);
    }
  );

  app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => {
    if (response.headersSent) return;
    const entityTooLarge =
      Boolean(error && typeof error === "object" && "type" in error && (error as { type?: unknown }).type === "entity.too.large");
    response
      .set("Cache-Control", "no-store")
      .status(entityTooLarge ? 413 : 400)
      .json({ error: entityTooLarge ? "request_too_large" : "invalid_request" });
  });

  const listener = await listen(app, options.host, options.port);
  listener.headersTimeout = 15_000;
  listener.requestTimeout = 30_000;
  listener.keepAliveTimeout = 5_000;
  const address = listener.address();
  const actualPort = typeof address === "object" && address ? address.port : options.port;

  return {
    host: options.host,
    port: actualPort,
    resourceMetadataUrl: metadataUrl,
    close: async () => {
      await handler.close();
      listener.closeIdleConnections?.();
      await new Promise<void>((resolveClose, rejectClose) => {
        listener.close((error) => (error ? rejectClose(error) : resolveClose()));
        listener.closeAllConnections?.();
      });
    }
  };
}

function createAuthenticationMiddleware(
  authenticator: JwtOAuthAuthenticator,
  metadataUrl: string,
  resource: string
) {
  return async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    try {
      const principal = await authenticator.authenticateAuthorizationHeader(request.headers.authorization);
      request.auth = authInfo(principal, resource);
      next();
    } catch (error) {
      const authenticationError =
        error instanceof OAuthAuthenticationError
          ? error
          : new OAuthAuthenticationError(
              "TENANT_RESOLUTION_FAILED",
              "Authentication service is unavailable",
              503,
              "invalid_token"
            );
      response
        .set("Cache-Control", "no-store")
        .set("WWW-Authenticate", createBearerChallengeForError(authenticationError, metadataUrl))
        .status(authenticationError.httpStatus)
        .json({ error: authenticationError.code });
    }
  };
}

function authInfo(principal: VerifiedPrincipalContext, resource: string): AuthInfo {
  return {
    // SDK AuthInfo requires a token-shaped value. Use only the non-reversible fingerprint,
    // never the bearer credential, so handler contexts cannot accidentally leak it.
    token: principal.credentialFingerprint,
    clientId: principal.clientId ?? "unknown-client",
    scopes: [...principal.scopes],
    expiresAt: principal.expiresAtEpochSeconds,
    resource: new URL(resource),
    extra: { verifiedPrincipal: principal }
  };
}

function requestIdMiddleware(request: Request, response: Response, next: NextFunction): void {
  const supplied = request.headers["x-request-id"];
  const requestId =
    typeof supplied === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(supplied) ? supplied : randomUUID();
  response.set("X-Request-Id", requestId);
  response.locals.requestId = requestId;
  next();
}

class PrincipalRateLimiter {
  static readonly MAXIMUM_BUCKETS = 10_000;

  readonly #limit: number;
  readonly #windowMs: number;
  readonly #buckets = new Map<string, { window: number; count: number }>();

  constructor(limit: number, windowMs: number) {
    this.#limit = boundedInteger(limit, "maxRequestsPerWindow", 1, 100_000);
    this.#windowMs = boundedInteger(windowMs, "rateLimitWindowMs", 1_000, 3_600_000);
  }

  readonly middleware = (request: Request, response: Response, next: NextFunction): void => {
    const principal = request.auth?.extra?.verifiedPrincipal;
    if (!isVerifiedPrincipalContext(principal)) {
      response.status(401).json({ error: "missing_authenticated_principal" });
      return;
    }
    const key = principalBinding(principal);
    const now = Date.now();
    const window = Math.floor(now / this.#windowMs);
    const bucket = this.#buckets.get(key);
    if (!bucket && this.#buckets.size >= PrincipalRateLimiter.MAXIMUM_BUCKETS) {
      this.#removeStaleBuckets(window);
      if (this.#buckets.size >= PrincipalRateLimiter.MAXIMUM_BUCKETS) {
        response.set("Retry-After", "1").status(503).json({ error: "rate_limiter_capacity" });
        return;
      }
    }
    const count = bucket?.window === window ? bucket.count + 1 : 1;
    this.#buckets.set(key, { window, count });
    response.set("X-RateLimit-Limit", String(this.#limit));
    response.set("X-RateLimit-Remaining", String(Math.max(0, this.#limit - count)));
    if (count > this.#limit) {
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil(((window + 1) * this.#windowMs - now) / 1_000)
      );
      response
        .set("Retry-After", String(retryAfterSeconds))
        .status(429)
        .json({ error: "rate_limit_exceeded" });
      return;
    }
    next();
  };

  #removeStaleBuckets(window: number): void {
    for (const [bucketKey, candidate] of this.#buckets) {
      if (candidate.window < window) this.#buckets.delete(bucketKey);
    }
  }
}

class ConcurrencyGate {
  readonly #maximum: number;
  #active = 0;

  constructor(maximum: number) {
    this.#maximum = boundedInteger(maximum, "maxConcurrentRequests", 1, 10_000);
  }

  readonly middleware = (_request: Request, response: Response, next: NextFunction): void => {
    if (this.#active >= this.#maximum) {
      response.set("Retry-After", "1").status(503).json({ error: "server_busy" });
      return;
    }
    this.#active += 1;
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      this.#active -= 1;
    };
    response.once("finish", release);
    response.once("close", release);
    next();
  };
}

async function listen(app: express.Express, host: string, port: number): Promise<Server> {
  return await new Promise<Server>((resolveListen, rejectListen) => {
    const listener = app.listen(port, host, () => resolveListen(listener));
    listener.once("error", rejectListen);
  });
}

function validateRemoteOptions(options: RemoteHttpServerOptions): void {
  if (!options.host || /[\u0000-\u001f\u007f]/.test(options.host)) throw new Error("Remote host is invalid");
  boundedInteger(options.port, "port", 0, 65_535);
  if (options.allowedHosts.length === 0) throw new Error("Remote HTTP requires an allowed-host list");
  if (options.allowedOrigins.length === 0) throw new Error("Remote HTTP requires an allowed-origin list");
  for (const host of options.allowedHosts) validateAllowedHost(host);
  for (const origin of options.allowedOrigins) validateAllowedOrigin(origin);
  if (options.maxRequestsPerWindow !== undefined) {
    boundedInteger(options.maxRequestsPerWindow, "maxRequestsPerWindow", 1, 100_000);
  }
  if (options.rateLimitWindowMs !== undefined) {
    boundedInteger(options.rateLimitWindowMs, "rateLimitWindowMs", 1_000, 3_600_000);
  }
  if (options.maxConcurrentRequests !== undefined) {
    boundedInteger(options.maxConcurrentRequests, "maxConcurrentRequests", 1, 10_000);
  }
  const resource = new URL(options.resource);
  if (resource.protocol !== "https:" || resource.hash || resource.username || resource.password) {
    throw new Error("Remote MCP resource must be a credential-free HTTPS URL");
  }
}

function validateAllowedHost(value: string): void {
  if (!value || value !== value.toLowerCase() || value.includes("*") || /[\u0000-\u0020\u007f]/.test(value)) {
    throw new Error("Allowed host is invalid");
  }
  let parsed: URL;
  try {
    parsed = new URL(`https://${value}`);
  } catch {
    throw new Error("Allowed host is invalid");
  }
  if (
    parsed.username ||
    parsed.password ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash ||
    !parsed.host ||
    parsed.host !== value
  ) {
    throw new Error("Allowed host is invalid");
  }
}

function validateAllowedOrigin(value: string): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Allowed origin is invalid");
  }
  if (
    value !== parsed.origin ||
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error("Allowed origin is invalid");
  }
}

function exactHostValidation(allowedHosts: readonly string[]) {
  const allowed = new Set(allowedHosts);
  return (request: Request, response: Response, next: NextFunction): void => {
    const supplied = request.headers.host;
    if (typeof supplied !== "string" || supplied !== supplied.trim()) {
      response.set("Cache-Control", "no-store").status(403).json({ error: "invalid_host" });
      return;
    }
    const normalized = supplied.toLowerCase();
    try {
      validateAllowedHost(normalized);
    } catch {
      response.set("Cache-Control", "no-store").status(403).json({ error: "invalid_host" });
      return;
    }
    if (!allowed.has(normalized)) {
      response.set("Cache-Control", "no-store").status(403).json({ error: "invalid_host" });
      return;
    }
    next();
  };
}

function exactOriginValidation(allowedOrigins: readonly string[]) {
  const allowed = new Set(allowedOrigins);
  return (request: Request, response: Response, next: NextFunction): void => {
    const supplied = request.headers.origin;
    // Non-browser MCP clients do not send Origin. If present, it must be one
    // exact canonical HTTPS origin from the configured allowlist.
    if (supplied === undefined) {
      next();
      return;
    }
    if (typeof supplied !== "string") {
      response.set("Cache-Control", "no-store").status(403).json({ error: "invalid_origin" });
      return;
    }
    try {
      validateAllowedOrigin(supplied);
    } catch {
      response.set("Cache-Control", "no-store").status(403).json({ error: "invalid_origin" });
      return;
    }
    if (!allowed.has(supplied)) {
      response.set("Cache-Control", "no-store").status(403).json({ error: "invalid_origin" });
      return;
    }
    next();
  };
}

function boundedInteger(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}
