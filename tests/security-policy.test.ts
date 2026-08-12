import * as assert from "node:assert/strict";
import { test } from "node:test";

import {
  createVerifiedPrincipalContext,
  type VerifiedPrincipalContext,
} from "../src/security/identity.js";
import {
  assertPermitDecision,
  compileAuthorizationPolicy,
  evaluatePolicy,
  PolicyValidationError,
  type AuthorizationPolicyDocument,
  type PolicyObligations,
} from "../src/security/policy.js";

const NOW = 1_700_000_000;

const DEFAULT_OBLIGATIONS: PolicyObligations = {
  maxResultRows: 1_000,
  maxResultBytes: 1_000_000,
  maxExecutionMs: 15_000,
  minimumCohortSize: 10,
  requireImmutableSnapshot: false,
  allowRawRows: false,
  allowExport: true,
  rowFilterRefs: ["tenant-boundary"],
  fieldMasks: { risk_rating: "hash" },
  auditTags: ["data-access"],
};

function principal(
  overrides: { tenantId?: string; principalId?: string; subject?: string; scopes?: readonly string[] } = {},
): VerifiedPrincipalContext {
  return createVerifiedPrincipalContext({
    issuer: "https://identity.example.test",
    subject: overrides.subject ?? "subject-1",
    principalId: overrides.principalId ?? "analyst-1",
    tenantId: overrides.tenantId ?? "tenant-a",
    clientId: "codex-client",
    audiences: ["abl-api"],
    resourceIndicators: ["https://mcp.example.test/mcp"],
    scopes: overrides.scopes ?? ["analysis:run", "data:read"],
    credentialFingerprint: "a".repeat(64),
    verifiedAtEpochSeconds: NOW,
    expiresAtEpochSeconds: NOW + 600,
  });
}

function document(): AuthorizationPolicyDocument {
  return {
    id: "abl-production",
    version: "2026-08-11.1",
    defaultObligations: DEFAULT_OBLIGATIONS,
    rules: [
      {
        id: "permit-balance",
        effect: "permit",
        tenantIds: ["tenant-a"],
        tools: ["abl_run_stratification"],
        datasets: ["loan-tape"],
        fields: ["outstanding_balance"],
        requiredScopes: ["data:read", "analysis:run"],
        obligations: {
          maxResultRows: 500,
          rowFilterRefs: ["portfolio-entitlement"],
          fieldMasks: { outstanding_balance: "tokenize" },
        },
      },
      {
        id: "permit-risk",
        effect: "permit",
        tenantIds: ["tenant-a"],
        tools: ["abl_run_stratification"],
        datasets: ["loan-tape"],
        fields: ["risk_rating"],
        requiredScopes: ["analysis:run", "data:read"],
        obligations: {
          maxResultRows: 200,
          maxExecutionMs: 5_000,
          minimumCohortSize: 25,
          requireImmutableSnapshot: true,
          allowExport: false,
          fieldMasks: { risk_rating: "partial" },
          auditTags: ["sensitive-aggregate"],
        },
      },
      {
        id: "deny-ssn",
        effect: "deny",
        tenantIds: ["tenant-a"],
        tools: ["*"],
        datasets: ["loan-tape"],
        fields: ["ssn"],
      },
    ],
  };
}

test("policy permits covered fields and merges the strictest obligations", () => {
  const policy = compileAuthorizationPolicy(document());
  const decision = evaluatePolicy(policy, {
    principal: principal(),
    toolName: "abl_run_stratification",
    dataset: { id: "loan-tape", tenantId: "tenant-a" },
    fields: ["risk_rating", "outstanding_balance"],
    nowEpochSeconds: NOW + 1,
  });

  assert.equal(decision.effect, "permit");
  if (decision.effect !== "permit") return;
  assert.deepEqual(decision.matchedRuleIds, ["permit-balance", "permit-risk"]);
  assert.equal(decision.obligations.maxResultRows, 200);
  assert.equal(decision.obligations.maxExecutionMs, 5_000);
  assert.equal(decision.obligations.minimumCohortSize, 25);
  assert.equal(decision.obligations.requireImmutableSnapshot, true);
  assert.equal(decision.obligations.allowRawRows, false);
  assert.equal(decision.obligations.allowExport, false);
  assert.deepEqual(decision.obligations.rowFilterRefs, [
    "portfolio-entitlement",
    "tenant-boundary",
  ]);
  assert.deepEqual(decision.obligations.auditTags, ["data-access", "sensitive-aggregate"]);
  assert.deepEqual(decision.obligations.fieldMasks, {
    outstanding_balance: "tokenize",
    risk_rating: "hash",
  });
  assert.doesNotThrow(() => assertPermitDecision(decision));

  const copied = JSON.parse(JSON.stringify(decision));
  assert.throws(
    () => assertPermitDecision(copied),
    (error: unknown) =>
      error instanceof PolicyValidationError && error.code === "UNISSUED_POLICY_DECISION",
  );
});

test("policy denies cross-tenant, missing-scope, uncovered-field, and explicit-deny requests", () => {
  const policy = compileAuthorizationPolicy(document());
  const base = {
    toolName: "abl_run_stratification",
    dataset: { id: "loan-tape", tenantId: "tenant-a" },
    nowEpochSeconds: NOW + 1,
  } as const;

  const crossTenant = evaluatePolicy(policy, {
    ...base,
    principal: principal({ tenantId: "tenant-b" }),
    fields: ["risk_rating"],
  });
  assert.equal(crossTenant.effect, "deny");
  assert.equal(crossTenant.effect === "deny" ? crossTenant.reasons[0]?.code : undefined, "CROSS_TENANT");

  const missingScope = evaluatePolicy(policy, {
    ...base,
    principal: principal({ scopes: ["data:read"] }),
    fields: ["risk_rating"],
  });
  assert.equal(missingScope.effect, "deny");
  assert.equal(missingScope.effect === "deny" ? missingScope.reasons[0]?.code : undefined, "MISSING_SCOPE");

  const uncovered = evaluatePolicy(policy, {
    ...base,
    principal: principal(),
    fields: ["borrower_name"],
  });
  assert.equal(uncovered.effect, "deny");
  assert.equal(uncovered.effect === "deny" ? uncovered.reasons[0]?.code : undefined, "FIELD_NOT_PERMITTED");

  const explicit = evaluatePolicy(policy, {
    ...base,
    principal: principal(),
    fields: ["ssn"],
  });
  assert.equal(explicit.effect, "deny");
  assert.equal(explicit.effect === "deny" ? explicit.reasons[0]?.code : undefined, "EXPLICIT_DENY");
});

test("policy compilation is order-stable and rejects scope-conditioned denies", () => {
  const first = compileAuthorizationPolicy(document());
  const reversedDocument = document();
  const second = compileAuthorizationPolicy({
    ...reversedDocument,
    defaultObligations: {
      ...reversedDocument.defaultObligations,
      rowFilterRefs: [...reversedDocument.defaultObligations.rowFilterRefs].reverse(),
      auditTags: [...reversedDocument.defaultObligations.auditTags].reverse(),
    },
    rules: [...reversedDocument.rules]
      .reverse()
      .map((rule) => ({
        ...rule,
        tenantIds: [...rule.tenantIds].reverse(),
        tools: [...rule.tools].reverse(),
        datasets: [...rule.datasets].reverse(),
        ...(rule.fields === undefined ? {} : { fields: [...rule.fields].reverse() }),
        ...(rule.requiredScopes === undefined
          ? {}
          : { requiredScopes: [...rule.requiredScopes].reverse() }),
      })),
  });
  assert.equal(second.fingerprint, first.fingerprint);

  const bad = document();
  assert.throws(
    () =>
      compileAuthorizationPolicy({
        ...bad,
        rules: [
          {
            id: "bad-deny",
            effect: "deny",
            tenantIds: ["tenant-a"],
            tools: ["*"],
            datasets: ["*"],
            requiredScopes: ["admin"],
          },
        ],
      }),
    (error: unknown) =>
      error instanceof PolicyValidationError && error.code === "INVALID_POLICY",
  );
});
