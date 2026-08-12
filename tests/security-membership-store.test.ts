import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import {
  TenantMembershipStore,
  TenantMembershipStoreError
} from "../src/security/membership-store.js";

const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "abl-memberships-"));
  directories.push(directory);
  return new TenantMembershipStore(join(directory, "control.sqlite"), {
    clock: () => new Date("2026-08-11T12:00:00Z")
  });
}

const lookup = {
  issuer: "https://issuer.example.com/",
  subject: "user-123",
  clientId: "codex-client",
  audiences: ["abl-api"],
  resourceIndicators: ["https://mcp.example.com/mcp"],
  scopes: ["analysis:run"],
  credentialFingerprint: "a".repeat(64)
};

test("only maker-checker approved memberships resolve", async () => {
  const store = fixture();
  store.propose({
    membershipId: "membership-1",
    issuer: lookup.issuer,
    subject: lookup.subject,
    clientId: lookup.clientId,
    tenantId: "tenant-a",
    principalId: "analyst-a",
    proposedBy: "identity-admin-a",
    idempotencyKey: "propose-1"
  });
  assert.equal(await store.resolveTenantMembership(lookup), null);
  assert.throws(
    () => store.approve({ membershipId: "membership-1", actor: "identity-admin-a", idempotencyKey: "approve-self" }),
    (error: unknown) => error instanceof TenantMembershipStoreError && error.code === "MAKER_CHECKER_VIOLATION"
  );
  store.approve({ membershipId: "membership-1", actor: "identity-admin-b", idempotencyKey: "approve-1" });
  assert.deepEqual(await store.resolveTenantMembership(lookup), { tenantId: "tenant-a", principalId: "analyst-a" });
  store.revoke({ membershipId: "membership-1", actor: "identity-admin-b", idempotencyKey: "revoke-1" });
  assert.equal(await store.resolveTenantMembership(lookup), null);
  store.close();
});

test("issuer subject and client tuple cannot ambiguously span tenants", () => {
  const store = fixture();
  const base = {
    membershipId: "membership-1",
    issuer: lookup.issuer,
    subject: lookup.subject,
    clientId: lookup.clientId,
    tenantId: "tenant-a",
    principalId: "analyst-a",
    proposedBy: "identity-admin-a",
    idempotencyKey: "propose-1"
  };
  store.propose(base);
  assert.throws(
    () => store.propose({ ...base, membershipId: "membership-2", tenantId: "tenant-b", idempotencyKey: "propose-2" }),
    (error: unknown) => error instanceof TenantMembershipStoreError && error.code === "CONFLICT"
  );
  store.close();
});
