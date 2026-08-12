import * as assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import {
  exportJWK,
  generateKeyPair,
  SignJWT,
  UnsecuredJWT,
  type CryptoKey,
  type JSONWebKeySet,
  type JWTPayload,
} from "jose";
import type { FetchImplementation } from "jose/jwks/remote";

import {
  createBearerChallengeForError,
  createBearerWwwAuthenticate,
  createJwtOAuthAuthenticator,
  createProtectedResourceMetadata,
  OAuthAuthenticationError,
  parseBearerAuthorization,
  protectedResourceMetadataUrl,
  type AllowedJwtAlgorithm,
  type TenantMembership,
  type TenantMembershipLookup,
  type TenantMembershipResolver,
} from "../src/security/oauth.js";

const NOW = 1_800_000_000;
const ISSUER = "https://identity.example.test/";
const JWKS_URI = "https://identity.example.test/.well-known/jwks.json";
const AUDIENCE = "abl-mcp";
const RESOURCE = "https://api.example.test/mcp";

interface SigningKey {
  readonly kid: string;
  readonly privateKey: CryptoKey;
  readonly jwk: JsonWebKey;
}

class MemoryMembershipResolver implements TenantMembershipResolver {
  readonly lookups: TenantMembershipLookup[] = [];
  membership: TenantMembership | null = {
    tenantId: "tenant-a",
    principalId: "principal-a",
  };
  failure: Error | undefined;

  async resolveTenantMembership(lookup: TenantMembershipLookup): Promise<TenantMembership | null> {
    this.lookups.push(lookup);
    if (this.failure) throw this.failure;
    return this.membership;
  }
}

async function signingKey(kid: string): Promise<SigningKey> {
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  const exported = await exportJWK(publicKey);
  return {
    kid,
    privateKey,
    jwk: { ...exported, kid, alg: "RS256", use: "sig" },
  };
}

function payload(overrides: JWTPayload = {}): JWTPayload {
  return {
    iss: ISSUER,
    sub: "subject-a",
    aud: AUDIENCE,
    resource: RESOURCE,
    client_id: "codex-client",
    scope: "analysis:run data:read",
    amr: ["pwd", "mfa"],
    iat: NOW - 10,
    exp: NOW + 300,
    ...overrides,
  };
}

async function signedToken(
  key: SigningKey,
  overrides: JWTPayload = {},
  header: Readonly<Record<string, string>> = {
    alg: "RS256",
    kid: key.kid,
    typ: "at+jwt",
  },
): Promise<string> {
  return new SignJWT(payload(overrides)).setProtectedHeader(header).sign(key.privateKey);
}

function createHarness(
  initialJwks: JSONWebKeySet,
  resolver = new MemoryMembershipResolver(),
): {
  readonly authenticate: ReturnType<typeof createJwtOAuthAuthenticator>;
  readonly resolver: MemoryMembershipResolver;
  readonly fetchCount: () => number;
  setJwks(jwks: JSONWebKeySet): void;
} {
  let jwks = initialJwks;
  let count = 0;
  const fetcher: FetchImplementation = async (url, options) => {
    assert.equal(url, JWKS_URI);
    assert.equal(options.method, "GET");
    count += 1;
    return new Response(JSON.stringify(jwks), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const authenticate = createJwtOAuthAuthenticator(
    {
      issuers: [
        {
          issuer: ISSUER,
          jwksUri: JWKS_URI,
          audiences: [AUDIENCE],
          resources: [RESOURCE],
          algorithms: ["RS256"],
          remoteJwks: {
            timeoutDurationMs: 1_000,
            cooldownDurationMs: 0,
            cacheMaxAgeMs: 600_000,
          },
        },
      ],
      tenantMembershipResolver: resolver,
    },
    {
      jwksFetch: fetcher,
      now: () => new Date(NOW * 1_000),
    },
  );
  return {
    authenticate,
    resolver,
    fetchCount: () => count,
    setJwks(next): void {
      jwks = next;
    },
  };
}

function expectOAuthCode(code: OAuthAuthenticationError["code"]): (error: unknown) => boolean {
  return (error: unknown): boolean =>
    error instanceof OAuthAuthenticationError && error.code === code;
}

test("verifies allowlisted JWTs, hashes credentials, and resolves tenant membership server-side", async () => {
  const key = await signingKey("key-a");
  const token = await signedToken(key);
  const harness = createHarness({ keys: [key.jwk] });

  const principal = await harness.authenticate.authenticateAuthorizationHeader(`Bearer ${token}`);

  assert.equal(principal.issuer, ISSUER);
  assert.equal(principal.subject, "subject-a");
  assert.equal(principal.principalId, "principal-a");
  assert.equal(principal.tenantId, "tenant-a");
  assert.equal(principal.clientId, "codex-client");
  assert.deepEqual(principal.audiences, [AUDIENCE]);
  assert.deepEqual(principal.resourceIndicators, [RESOURCE]);
  assert.deepEqual(principal.scopes, ["analysis:run", "data:read"]);
  assert.deepEqual(principal.authenticationMethods, ["mfa", "pwd"]);
  assert.equal(principal.credentialFingerprint, createHash("sha256").update(token).digest("hex"));
  assert.equal(harness.resolver.lookups.length, 1);
  const lookup = harness.resolver.lookups[0]!;
  assert.equal(lookup.issuer, ISSUER);
  assert.equal(lookup.subject, "subject-a");
  assert.equal(lookup.clientId, "codex-client");
  assert.equal("tenantId" in lookup, false);
  assert.equal("token" in lookup, false);
  assert.doesNotMatch(JSON.stringify(lookup), new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.doesNotMatch(JSON.stringify(principal), new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("jose remote JWKS resolver caches keys and reloads once for rotation", async () => {
  const first = await signingKey("key-1");
  const second = await signingKey("key-2");
  const harness = createHarness({ keys: [first.jwk] });
  const firstToken = await signedToken(first);

  await harness.authenticate.authenticateAuthorizationHeader(`Bearer ${firstToken}`);
  await harness.authenticate.authenticateAuthorizationHeader(`Bearer ${firstToken}`);
  assert.equal(harness.fetchCount(), 1, "known keys should come from jose's JWKS cache");

  harness.setJwks({ keys: [second.jwk] });
  const secondToken = await signedToken(second);
  await harness.authenticate.authenticateAuthorizationHeader(`Bearer ${secondToken}`);
  await harness.authenticate.authenticateAuthorizationHeader(`Bearer ${secondToken}`);
  assert.equal(harness.fetchCount(), 2, "a new kid should cause one rotation-aware reload");
});

test("rejects unsecured and symmetric-algorithm confusion tokens before membership resolution", async () => {
  const key = await signingKey("key-a");
  const harness = createHarness({ keys: [key.jwk] });
  const unsecured = new UnsecuredJWT(payload()).encode();
  const symmetric = await new SignJWT(payload())
    .setProtectedHeader({ alg: "HS256", kid: key.kid, typ: "at+jwt" })
    .sign(new TextEncoder().encode("a sufficiently long symmetric test secret"));

  await assert.rejects(
    harness.authenticate.authenticateAuthorizationHeader(`Bearer ${unsecured}`),
    expectOAuthCode("INVALID_TOKEN"),
  );
  await assert.rejects(
    harness.authenticate.authenticateAuthorizationHeader(`Bearer ${symmetric}`),
    expectOAuthCode("INVALID_TOKEN"),
  );
  assert.equal(harness.resolver.lookups.length, 0);
});

test("rejects wrong issuer, audience, resource, expiration, and not-before claims", async () => {
  const key = await signingKey("key-a");
  const cases: readonly [JWTPayload, OAuthAuthenticationError["code"]][] = [
    [{ iss: "https://attacker.example.test/" }, "UNKNOWN_ISSUER"],
    [{ aud: "another-api" }, "INVALID_TOKEN"],
    [{ resource: "https://another.example.test/mcp" }, "INVALID_RESOURCE"],
    [{ exp: NOW - 1 }, "INVALID_TOKEN"],
    [{ nbf: NOW + 1 }, "INVALID_TOKEN"],
  ];

  for (const [claims, expectedCode] of cases) {
    const harness = createHarness({ keys: [key.jwk] });
    const token = await signedToken(key, claims);
    await assert.rejects(
      harness.authenticate.authenticateAuthorizationHeader(`Bearer ${token}`),
      expectOAuthCode(expectedCode),
    );
    assert.equal(harness.resolver.lookups.length, 0);
  }
});

test("fails closed for absent membership, resolver outage, and missing client identity", async () => {
  const key = await signingKey("key-a");
  const token = await signedToken(key);

  const deniedResolver = new MemoryMembershipResolver();
  deniedResolver.membership = null;
  const denied = createHarness({ keys: [key.jwk] }, deniedResolver);
  await assert.rejects(
    denied.authenticate.authenticateAuthorizationHeader(`Bearer ${token}`),
    expectOAuthCode("TENANT_MEMBERSHIP_DENIED"),
  );

  const failedResolver = new MemoryMembershipResolver();
  failedResolver.failure = new Error(`do not expose ${token}`);
  const failed = createHarness({ keys: [key.jwk] }, failedResolver);
  await assert.rejects(
    failed.authenticate.authenticateAuthorizationHeader(`Bearer ${token}`),
    expectOAuthCode("TENANT_RESOLUTION_FAILED"),
  );

  const missingClientToken = await signedToken(key, { client_id: undefined, azp: undefined });
  const missingClient = createHarness({ keys: [key.jwk] });
  await assert.rejects(
    missingClient.authenticate.authenticateAuthorizationHeader(`Bearer ${missingClientToken}`),
    expectOAuthCode("MISSING_REQUIRED_CLAIM"),
  );
});

test("Bearer parsing rejects ambiguity and authentication errors redact tokens", async () => {
  const key = await signingKey("key-a");
  const token = await signedToken(key, { aud: "wrong-audience" });
  const harness = createHarness({ keys: [key.jwk] });

  assert.equal(parseBearerAuthorization(`bearer ${token}`), token);
  assert.throws(() => parseBearerAuthorization(undefined), expectOAuthCode("MISSING_BEARER_TOKEN"));
  assert.throws(
    () => parseBearerAuthorization([`Bearer ${token}`]),
    expectOAuthCode("MALFORMED_AUTHORIZATION"),
  );
  assert.throws(
    () => parseBearerAuthorization(`Basic ${token}`),
    expectOAuthCode("MALFORMED_AUTHORIZATION"),
  );
  assert.throws(
    () => parseBearerAuthorization(`Bearer ${token}, Bearer ${token}`),
    expectOAuthCode("MALFORMED_AUTHORIZATION"),
  );
  assert.throws(
    () => parseBearerAuthorization(`Bearer a.b.${"c".repeat(2_000)}`, 1_024),
    expectOAuthCode("TOKEN_TOO_LARGE"),
  );

  let captured: unknown;
  try {
    await harness.authenticate.authenticateAuthorizationHeader(`Bearer ${token}`);
  } catch (error) {
    captured = error;
  }
  assert.ok(captured instanceof OAuthAuthenticationError);
  assert.doesNotMatch(captured.message, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.doesNotMatch(captured.stack ?? "", new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.doesNotMatch(JSON.stringify(captured), new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("rejects insecure issuer configuration and HMAC allowlists", () => {
  const resolver = new MemoryMembershipResolver();
  assert.throws(
    () =>
      createJwtOAuthAuthenticator({
        issuers: [
          {
            issuer: ISSUER,
            jwksUri: "http://identity.example.test/jwks",
            audiences: [AUDIENCE],
            resources: [RESOURCE],
            algorithms: ["RS256"],
          },
        ],
        tenantMembershipResolver: resolver,
      }),
    expectOAuthCode("INVALID_AUTHENTICATOR_CONFIGURATION"),
  );
  assert.throws(
    () =>
      createJwtOAuthAuthenticator({
        issuers: [
          {
            issuer: ISSUER,
            jwksUri: JWKS_URI,
            audiences: [AUDIENCE],
            resources: [RESOURCE],
            algorithms: ["HS256"] as unknown as AllowedJwtAlgorithm[],
          },
        ],
        tenantMembershipResolver: resolver,
      }),
    expectOAuthCode("INVALID_AUTHENTICATOR_CONFIGURATION"),
  );
});

test("builds RFC 9728 metadata, well-known URL, and token-free Bearer challenges", () => {
  const metadata = createProtectedResourceMetadata({
    resource: RESOURCE,
    authorizationServers: [ISSUER],
    scopesSupported: ["analysis:run", "data:read"],
    resourceName: "ABL MCP",
    resourceDocumentation: "https://docs.example.test/abl-mcp",
  });
  assert.deepEqual(metadata, {
    resource: RESOURCE,
    authorization_servers: [ISSUER],
    bearer_methods_supported: ["header"],
    scopes_supported: ["analysis:run", "data:read"],
    resource_name: "ABL MCP",
    resource_documentation: "https://docs.example.test/abl-mcp",
  });
  const discovery = protectedResourceMetadataUrl(RESOURCE);
  assert.equal(discovery, "https://api.example.test/.well-known/oauth-protected-resource/mcp");
  assert.equal(
    createBearerWwwAuthenticate({
      resourceMetadataUrl: discovery,
      realm: "abl",
      error: "invalid_token",
      scope: ["data:read"],
    }),
    `Bearer resource_metadata="${discovery}", realm="abl", error="invalid_token", scope="data:read"`,
  );
  const denied = new OAuthAuthenticationError(
    "TENANT_MEMBERSHIP_DENIED",
    "Access is not authorized",
    403,
    "insufficient_scope",
  );
  assert.equal(
    createBearerChallengeForError(denied, discovery),
    `Bearer resource_metadata="${discovery}", error="insufficient_scope"`,
  );
});

test("classifies malformed token scopes as invalid credentials, not server configuration", async () => {
  const key = await signingKey("key-a");
  const token = await signedToken(key, { scope: ["data:read", "bad scope"] });
  const harness = createHarness({ keys: [key.jwk] });
  await assert.rejects(
    harness.authenticate.authenticateAuthorizationHeader(`Bearer ${token}`),
    expectOAuthCode("INVALID_TOKEN"),
  );
  assert.equal(harness.resolver.lookups.length, 0);
});
