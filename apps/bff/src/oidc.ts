import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { z } from "zod";
import {
  PlatformRoleSchema,
  type PlatformRole,
  type SessionPrincipal,
} from "@abl/platform-contracts";
import type { OidcConfiguration } from "./config.js";

const DiscoverySchema = z.object({
  authorization_endpoint: z.string().url(),
  token_endpoint: z.string().url(),
  jwks_uri: z.string().url(),
});

const TokenResponseSchema = z.object({
  id_token: z.string().min(1),
  access_token: z.string().optional(),
  token_type: z.string().optional(),
  expires_in: z.number().optional(),
});

export interface PkcePair {
  readonly verifier: string;
  readonly challenge: string;
}

export interface AuthorizationRequest {
  readonly state: string;
  readonly nonce: string;
  readonly codeChallenge: string;
  readonly stepUp: boolean;
}

export interface OidcIdentityProvider {
  authorizationUrl(request: AuthorizationRequest): Promise<URL>;
  exchangeAuthorizationCode(input: {
    readonly code: string;
    readonly codeVerifier: string;
    readonly nonce: string;
  }): Promise<SessionPrincipal>;
}

export function createPkcePair(): PkcePair {
  const verifier = randomBytes(48).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function extractRoles(claims: Readonly<Record<string, unknown>>): readonly PlatformRole[] {
  const directRoles = Array.isArray(claims.roles) ? claims.roles : [];
  const parsed = directRoles.flatMap((role) => {
    const result = PlatformRoleSchema.safeParse(role);
    return result.success ? [result.data] : [];
  });
  return [...new Set(parsed)];
}

export class HttpOidcIdentityProvider implements OidcIdentityProvider {
  #discovery?: z.infer<typeof DiscoverySchema>;

  public constructor(private readonly configuration: OidcConfiguration) {}

  async #getDiscovery(): Promise<z.infer<typeof DiscoverySchema>> {
    if (this.#discovery) return this.#discovery;
    const discoveryUrl = new URL(".well-known/openid-configuration", `${this.configuration.issuer.replace(/\/$/u, "")}/`);
    const response = await fetch(discoveryUrl, { headers: { accept: "application/json" } });
    if (!response.ok) throw new Error(`OIDC discovery failed with ${response.status}`);
    this.#discovery = DiscoverySchema.parse(await response.json());
    return this.#discovery;
  }

  public async authorizationUrl(request: AuthorizationRequest): Promise<URL> {
    const discovery = await this.#getDiscovery();
    const url = new URL(discovery.authorization_endpoint);
    url.search = new URLSearchParams({
      client_id: this.configuration.clientId,
      redirect_uri: this.configuration.redirectUri,
      response_type: "code",
      scope: this.configuration.scopes.join(" "),
      state: request.state,
      nonce: request.nonce,
      code_challenge: request.codeChallenge,
      code_challenge_method: "S256",
      ...(request.stepUp ? { prompt: "login", max_age: "0" } : {}),
    }).toString();
    return url;
  }

  public async exchangeAuthorizationCode(input: {
    readonly code: string;
    readonly codeVerifier: string;
    readonly nonce: string;
  }): Promise<SessionPrincipal> {
    const discovery = await this.#getDiscovery();
    const response = await fetch(discovery.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: this.configuration.clientId,
        redirect_uri: this.configuration.redirectUri,
        code: input.code,
        code_verifier: input.codeVerifier,
      }),
    });
    if (!response.ok) throw new Error(`OIDC token exchange failed with ${response.status}`);
    const token = TokenResponseSchema.parse(await response.json());
    const jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));
    const verified = await jwtVerify(token.id_token, jwks, {
      issuer: this.configuration.issuer,
      audience: this.configuration.clientId,
    });
    if (typeof verified.payload.nonce !== "string" || !constantTimeEqual(verified.payload.nonce, input.nonce)) {
      throw new Error("OIDC nonce validation failed");
    }
    const subject = z.string().min(1).parse(verified.payload.sub);
    const email = z.string().email().parse(verified.payload.email);
    const displayName =
      typeof verified.payload.name === "string" && verified.payload.name.trim()
        ? verified.payload.name
        : email;
    return {
      id: subject,
      email,
      displayName,
      roles: extractRoles(verified.payload),
    };
  }
}

export interface OidcTransaction {
  readonly id: string;
  readonly state: string;
  readonly nonce: string;
  readonly verifier: string;
  readonly returnTo: string;
  readonly stepUp: boolean;
  readonly sessionId?: string;
  readonly expiresAt: Date;
}

export class OidcTransactionCapacityError extends Error {}

export class OidcTransactionStore {
  readonly #transactions = new Map<string, OidcTransaction>();

  public constructor(
    private readonly now: () => Date = () => new Date(),
    private readonly ttlMs = 10 * 60_000,
    private readonly maxEntries = 4_096,
  ) {
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) throw new Error("OIDC transaction TTL must be a positive integer");
    if (!Number.isSafeInteger(maxEntries) || maxEntries <= 0) throw new Error("OIDC transaction capacity must be a positive integer");
  }

  #sweepExpired(): void {
    const currentTime = this.now().getTime();
    for (const [id, transaction] of this.#transactions) {
      if (transaction.expiresAt.getTime() <= currentTime) this.#transactions.delete(id);
    }
  }

  public get size(): number {
    this.#sweepExpired();
    return this.#transactions.size;
  }

  public create(input: Omit<OidcTransaction, "id" | "expiresAt">): OidcTransaction {
    this.#sweepExpired();
    if (this.#transactions.size >= this.maxEntries) {
      throw new OidcTransactionCapacityError("OIDC transaction capacity is exhausted");
    }
    const transaction: OidcTransaction = {
      ...input,
      id: randomBytes(32).toString("base64url"),
      expiresAt: new Date(this.now().getTime() + this.ttlMs),
    };
    this.#transactions.set(transaction.id, transaction);
    return transaction;
  }

  public consume(id: string, state: string): OidcTransaction | undefined {
    this.#sweepExpired();
    const transaction = this.#transactions.get(id);
    this.#transactions.delete(id);
    if (!transaction || transaction.expiresAt.getTime() <= this.now().getTime()) return undefined;
    return constantTimeEqual(transaction.state, state) ? transaction : undefined;
  }
}

interface RateLimitEntry {
  readonly attempts: number;
  readonly resetsAt: number;
}

export class OidcLoginRateLimiter {
  readonly #entries = new Map<string, RateLimitEntry>();

  public constructor(
    private readonly maxAttempts: number,
    private readonly windowMs: number,
    private readonly maxKeys: number,
    private readonly now: () => Date = () => new Date(),
  ) {
    if (!Number.isSafeInteger(maxAttempts) || maxAttempts <= 0) throw new Error("OIDC login attempt limit must be a positive integer");
    if (!Number.isSafeInteger(windowMs) || windowMs <= 0) throw new Error("OIDC login window must be a positive integer");
    if (!Number.isSafeInteger(maxKeys) || maxKeys <= 0) throw new Error("OIDC login key capacity must be a positive integer");
  }

  #sweepExpired(): void {
    const currentTime = this.now().getTime();
    for (const [key, entry] of this.#entries) {
      if (entry.resetsAt <= currentTime) this.#entries.delete(key);
    }
  }

  public allow(key: string): boolean {
    this.#sweepExpired();
    const current = this.#entries.get(key);
    if (current) {
      if (current.attempts >= this.maxAttempts) return false;
      this.#entries.set(key, { ...current, attempts: current.attempts + 1 });
      return true;
    }
    if (this.#entries.size >= this.maxKeys) return false;
    this.#entries.set(key, {
      attempts: 1,
      resetsAt: this.now().getTime() + this.windowMs,
    });
    return true;
  }

  public get size(): number {
    this.#sweepExpired();
    return this.#entries.size;
  }
}
