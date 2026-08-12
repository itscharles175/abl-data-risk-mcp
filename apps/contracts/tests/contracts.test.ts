import { describe, expect, it } from "vitest";
import {
  HighRiskActionRequestSchema,
  OpaqueSecretRefSchema,
  SourceContractDraftSchema,
  permissionsForRoles,
} from "../src/index.js";

describe("platform contracts", () => {
  it("accepts opaque secret references and rejects raw secrets", () => {
    expect(OpaqueSecretRefSchema.safeParse("secretref://vault/abl/client-7#v3").success).toBe(true);
    expect(OpaqueSecretRefSchema.safeParse("my-production-password").success).toBe(false);
  });

  it("uses strict high-risk action requests", () => {
    const parsed = HighRiskActionRequestSchema.safeParse({
      kind: "key_rotation",
      targetId: "connector-7",
      reason: "Rotate the connector credential on schedule.",
      rollbackTargetId: "key-version-2",
      secret: "must-not-pass",
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects secret-like material recursively while permitting opaque references", () => {
    const baseAction = {
      kind: "key_rotation",
      targetId: "connector-7",
      reason: "Rotate the connector credential on schedule.",
      rollbackTargetId: "key-version-2",
    } as const;
    expect(HighRiskActionRequestSchema.safeParse({
      ...baseAction,
      semanticDiff: { connector: { authentication: { apiKey: "raw-key-material" } } },
    }).success).toBe(false);
    expect(HighRiskActionRequestSchema.safeParse({
      ...baseAction,
      semanticDiff: { connector: { authentication: { secretRef: "secretref://vault/abl/client-7#v3" } } },
    }).success).toBe(true);
    expect(HighRiskActionRequestSchema.safeParse({
      ...baseAction,
      semanticDiff: { endpoint: "postgresql://risk:cleartext@db.example.test/abl" },
    }).success).toBe(false);
  });

  it("deduplicates permissions across roles", () => {
    const permissions = permissionsForRoles(["risk_analyst", "risk_reviewer"]);
    expect(permissions.filter((permission) => permission === "portfolio:read")).toHaveLength(1);
    expect(permissions).toContain("approval:review");
  });

  it("requires opaque credentials for connected source contracts", () => {
    expect(SourceContractDraftSchema.safeParse({
      name: "Primary loan tape",
      deliveryMode: "postgresql",
      sourceLocator: "risk_read.loan_tape",
      watermarkField: "as_of_date",
    }).success).toBe(false);
    expect(SourceContractDraftSchema.safeParse({
      name: "Primary loan tape",
      deliveryMode: "postgresql",
      sourceLocator: "risk_read.loan_tape",
      secretRef: "secretref://vault/postgres/risk-reader#v2",
      watermarkField: "as_of_date",
    }).success).toBe(true);
    expect(SourceContractDraftSchema.safeParse({
      name: "Primary loan tape",
      deliveryMode: "postgresql",
      sourceLocator: "postgresql://risk:cleartext@db.example.test/abl",
      secretRef: "secretref://vault/postgres/risk-reader#v2",
      notes: "password=hunter2",
    }).success).toBe(false);
  });
});
