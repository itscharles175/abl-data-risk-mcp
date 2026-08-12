import * as assert from "node:assert/strict";
import { test } from "node:test";

import { createVerifiedPrincipalContext } from "../src/security/identity.js";
import {
  compileAuthorizationPolicy,
  evaluatePolicy,
  type PermitPolicyDecision,
} from "../src/security/policy.js";
import {
  createHmacKeyRing,
  issueExecutionPlan,
  issuePrincipalBoundHandle,
  SignedArtifactError,
  verifyExecutionPlan,
  verifyPrincipalBoundHandle,
  type ReplayDefense,
  type ReplayRecord,
} from "../src/security/signed-plan.js";

const NOW = 1_700_000_000;
const SCHEMA_FINGERPRINT = "1".repeat(64);
const PARAMETER_FINGERPRINT = "2".repeat(64);
const SNAPSHOT_FINGERPRINT = "3".repeat(64);

function principal(subject = "subject-1") {
  return createVerifiedPrincipalContext({
    issuer: "https://identity.example.test",
    subject,
    principalId: subject,
    tenantId: "tenant-a",
    clientId: "codex-client",
    audiences: ["abl-api"],
    resourceIndicators: ["https://mcp.example.test/mcp"],
    scopes: ["analysis:run", "data:read"],
    credentialFingerprint: "a".repeat(64),
    verifiedAtEpochSeconds: NOW,
    expiresAtEpochSeconds: NOW + 600,
  });
}

function permit(identity = principal()): PermitPolicyDecision {
  const policy = compileAuthorizationPolicy({
    id: "abl-production",
    version: "1",
    defaultObligations: {
      maxResultRows: 200,
      maxResultBytes: 1_000_000,
      maxExecutionMs: 10_000,
      minimumCohortSize: 10,
      requireImmutableSnapshot: true,
      allowRawRows: false,
      allowExport: false,
      rowFilterRefs: ["tenant-boundary"],
      fieldMasks: {},
      auditTags: ["data-access"],
    },
    rules: [
      {
        id: "permit-stratification",
        effect: "permit",
        tenantIds: ["tenant-a"],
        tools: ["abl_run_stratification"],
        datasets: ["loan-tape"],
        fields: ["risk_rating"],
        requiredScopes: ["analysis:run", "data:read"],
      },
    ],
  });
  const decision = evaluatePolicy(policy, {
    principal: identity,
    toolName: "abl_run_stratification",
    dataset: { id: "loan-tape", tenantId: "tenant-a" },
    fields: ["risk_rating"],
    nowEpochSeconds: NOW,
  });
  assert.equal(decision.effect, "permit");
  return decision as PermitPolicyDecision;
}

function keyRing() {
  return createHmacKeyRing(
    [
      { id: "old", secret: new Uint8Array(32).fill(4) },
      { id: "current", secret: new Uint8Array(32).fill(7) },
    ],
    "current",
  );
}

class MemoryReplayDefense implements ReplayDefense {
  readonly records: ReplayRecord[] = [];
  readonly #seen = new Set<string>();

  consumeOnce(record: ReplayRecord): boolean {
    if (this.#seen.has(record.replayKey)) return false;
    this.#seen.add(record.replayKey);
    this.records.push(record);
    return true;
  }
}

test("signed execution plan binds identity, permit, fingerprints, expiry, and replay nonce", async () => {
  const identity = principal();
  const authorization = permit(identity);
  const issued = issueExecutionPlan(keyRing(), {
    principal: identity,
    authorization,
    spec: {
      operation: "stratification-v1",
      parameterFingerprint: PARAMETER_FINGERPRINT,
      schemaFingerprint: SCHEMA_FINGERPRINT,
      snapshotFingerprint: SNAPSHOT_FINGERPRINT,
    },
    ttlSeconds: 60,
    nowEpochSeconds: NOW,
    nonce: "n".repeat(32),
  });
  assert.match(issued.token, /^ablp1\.current\./);
  assert.equal(issued.claims.policyFingerprint, authorization.policyFingerprint);
  assert.equal(issued.claims.schemaFingerprint, SCHEMA_FINGERPRINT);
  assert.equal(issued.claims.snapshotFingerprint, SNAPSHOT_FINGERPRINT);

  const replay = new MemoryReplayDefense();
  const verified = await verifyExecutionPlan(keyRing(), issued.token, identity, replay, {
    nowEpochSeconds: NOW + 1,
    clockSkewSeconds: 0,
    expected: {
      toolName: "abl_run_stratification",
      datasetId: "loan-tape",
      operation: "stratification-v1",
      parameterFingerprint: PARAMETER_FINGERPRINT,
      schemaFingerprint: SCHEMA_FINGERPRINT,
      policyFingerprint: authorization.policyFingerprint,
      snapshotFingerprint: SNAPSHOT_FINGERPRINT,
    },
  });
  assert.equal(verified.planId, issued.planId);
  assert.equal(replay.records.length, 1);

  await assert.rejects(
    verifyExecutionPlan(keyRing(), issued.token, identity, replay, {
      nowEpochSeconds: NOW + 2,
      clockSkewSeconds: 0,
    }),
    (error: unknown) =>
      error instanceof SignedArtifactError && error.code === "REPLAY_DETECTED",
  );
});

test("execution plan rejects wrong identity, tampering, expiry, and context mismatch before replay", async () => {
  const identity = principal();
  const issued = issueExecutionPlan(keyRing(), {
    principal: identity,
    authorization: permit(identity),
    spec: {
      operation: "stratification-v1",
      parameterFingerprint: PARAMETER_FINGERPRINT,
      schemaFingerprint: SCHEMA_FINGERPRINT,
      snapshotFingerprint: SNAPSHOT_FINGERPRINT,
    },
    ttlSeconds: 60,
    nowEpochSeconds: NOW,
    nonce: "x".repeat(32),
  });

  await assert.rejects(
    verifyExecutionPlan(keyRing(), issued.token, principal("subject-2"), new MemoryReplayDefense(), {
      nowEpochSeconds: NOW + 1,
      clockSkewSeconds: 0,
    }),
    (error: unknown) =>
      error instanceof SignedArtifactError && error.code === "IDENTITY_MISMATCH",
  );

  const segments = issued.token.split(".");
  const signature = segments[3] ?? "";
  segments[3] = `${signature.slice(0, -1)}${signature.endsWith("A") ? "B" : "A"}`;
  await assert.rejects(
    verifyExecutionPlan(keyRing(), segments.join("."), identity, new MemoryReplayDefense(), {
      nowEpochSeconds: NOW + 1,
      clockSkewSeconds: 0,
    }),
    (error: unknown) =>
      error instanceof SignedArtifactError && error.code === "INVALID_ARTIFACT",
  );

  const shortSignature = issued.token.replace(/\.[^.]+$/, ".A");
  await assert.rejects(
    verifyExecutionPlan(keyRing(), shortSignature, identity, new MemoryReplayDefense(), {
      nowEpochSeconds: NOW + 1,
      clockSkewSeconds: 0,
    }),
    (error: unknown) =>
      error instanceof SignedArtifactError && error.code === "INVALID_ARTIFACT",
  );

  await assert.rejects(
    verifyExecutionPlan(keyRing(), issued.token, identity, new MemoryReplayDefense(), {
      nowEpochSeconds: NOW + 60,
      clockSkewSeconds: 0,
    }),
    (error: unknown) =>
      error instanceof SignedArtifactError && error.code === "ARTIFACT_EXPIRED",
  );

  const replay = new MemoryReplayDefense();
  await assert.rejects(
    verifyExecutionPlan(keyRing(), issued.token, identity, replay, {
      nowEpochSeconds: NOW + 1,
      clockSkewSeconds: 0,
      expected: { schemaFingerprint: "f".repeat(64) },
    }),
    (error: unknown) =>
      error instanceof SignedArtifactError && error.code === "EXPECTATION_MISMATCH",
  );
  assert.equal(replay.records.length, 0);
});

test("opaque result and job handles contain no identity and verify only for their principal", () => {
  const identity = principal();
  const issued = issuePrincipalBoundHandle(keyRing(), {
    kind: "result",
    principal: identity,
    ttlSeconds: 120,
    nowEpochSeconds: NOW,
    handleId: "h".repeat(32),
  });
  assert.match(issued.handle, /^ablh1\.current\.r\./);
  assert.doesNotMatch(issued.handle, /tenant-a|subject-1|analyst/);

  const record = verifyPrincipalBoundHandle(keyRing(), issued.handle, identity, {
    nowEpochSeconds: NOW + 1,
    clockSkewSeconds: 0,
    expectedKind: "result",
  });
  assert.equal(record.handleId, "h".repeat(32));
  assert.equal(record.kind, "result");

  assert.throws(
    () =>
      verifyPrincipalBoundHandle(keyRing(), issued.handle, principal("subject-2"), {
        nowEpochSeconds: NOW + 1,
        clockSkewSeconds: 0,
      }),
    (error: unknown) =>
      error instanceof SignedArtifactError && error.code === "INVALID_ARTIFACT",
  );
  assert.throws(
    () =>
      verifyPrincipalBoundHandle(keyRing(), issued.handle, identity, {
        nowEpochSeconds: NOW + 1,
        clockSkewSeconds: 0,
        expectedKind: "job",
      }),
    (error: unknown) =>
      error instanceof SignedArtifactError && error.code === "EXPECTATION_MISMATCH",
  );
  assert.throws(
    () =>
      verifyPrincipalBoundHandle(keyRing(), issued.handle, identity, {
        nowEpochSeconds: NOW + 120,
        clockSkewSeconds: 0,
      }),
    (error: unknown) =>
      error instanceof SignedArtifactError && error.code === "ARTIFACT_EXPIRED",
  );
});
