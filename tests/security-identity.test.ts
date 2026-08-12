import * as assert from "node:assert/strict";
import { test } from "node:test";

import {
  assertActivePrincipal,
  assertVerifiedPrincipalContext,
  createVerifiedPrincipalContext,
  hasAllScopes,
  IdentityContextError,
  isVerifiedPrincipalContext,
  principalBinding,
  requireScopes,
  type VerifiedIdentityAttestation,
} from "../src/security/identity.js";

const NOW = 1_700_000_000;

function attestation(
  overrides: Partial<VerifiedIdentityAttestation> = {},
): VerifiedIdentityAttestation {
  return {
    issuer: "https://identity.example.test",
    subject: "oauth-subject-123",
    principalId: "analyst-123",
    tenantId: "tenant-a",
    clientId: "codex-client",
    audiences: ["abl-api", "abl-api"],
    resourceIndicators: ["https://mcp.example.test/mcp", "https://mcp.example.test/mcp"],
    scopes: ["data:read", "analysis:run", "data:read"],
    credentialFingerprint: "a".repeat(64),
    verifiedAtEpochSeconds: NOW,
    expiresAtEpochSeconds: NOW + 600,
    authenticationMethods: ["mfa", "pwd"],
    ...overrides,
  };
}

test("verified identity context is nominal, normalized, and principal-bound", () => {
  const context = createVerifiedPrincipalContext(attestation());
  assert.equal(isVerifiedPrincipalContext(context), true);
  assert.deepEqual(context.audiences, ["abl-api"]);
  assert.deepEqual(context.resourceIndicators, ["https://mcp.example.test/mcp"]);
  assert.deepEqual(context.scopes, ["analysis:run", "data:read"]);
  assert.deepEqual(context.authenticationMethods, ["mfa", "pwd"]);
  assert.equal(Object.isFrozen(context), true);
  assert.equal(Object.isFrozen(context.scopes), true);

  const refreshed = createVerifiedPrincipalContext(
    attestation({
      scopes: ["analysis:run", "data:read", "export:result"],
      credentialFingerprint: "b".repeat(64),
      verifiedAtEpochSeconds: NOW + 30,
      expiresAtEpochSeconds: NOW + 900,
    }),
  );
  assert.equal(principalBinding(refreshed), principalBinding(context));

  const roundTripped = JSON.parse(JSON.stringify(context)) as unknown;
  assert.equal(isVerifiedPrincipalContext(roundTripped), false);
  assert.throws(
    () => assertVerifiedPrincipalContext(roundTripped),
    (error: unknown) =>
      error instanceof IdentityContextError && error.code === "UNVERIFIED_IDENTITY_CONTEXT",
  );
});

test("identity lifetime and scopes fail closed", () => {
  const context = createVerifiedPrincipalContext(
    attestation({ notBeforeEpochSeconds: NOW + 10 }),
  );
  assert.throws(
    () => assertActivePrincipal(context, NOW),
    (error: unknown) =>
      error instanceof IdentityContextError && error.code === "IDENTITY_NOT_YET_VALID",
  );
  assert.doesNotThrow(() => assertActivePrincipal(context, NOW + 10));
  assert.throws(
    () => assertActivePrincipal(context, NOW + 600),
    (error: unknown) => error instanceof IdentityContextError && error.code === "IDENTITY_EXPIRED",
  );

  assert.equal(hasAllScopes(context, ["analysis:run", "data:read"]), true);
  assert.equal(hasAllScopes(context, ["analysis:run", "export:result"]), false);
  assert.throws(
    () => requireScopes(context, ["export:result"]),
    (error: unknown) => error instanceof IdentityContextError && error.code === "MISSING_SCOPE",
  );
});

test("identity attestation rejects malformed fingerprints and incoherent lifetimes", () => {
  assert.throws(
    () => createVerifiedPrincipalContext(attestation({ credentialFingerprint: "raw-token" })),
    (error: unknown) =>
      error instanceof IdentityContextError && error.code === "INVALID_VERIFICATION_ATTESTATION",
  );
  assert.throws(
    () =>
      createVerifiedPrincipalContext(
        attestation({ expiresAtEpochSeconds: NOW }),
      ),
    (error: unknown) =>
      error instanceof IdentityContextError && error.code === "INVALID_VERIFICATION_ATTESTATION",
  );
});
