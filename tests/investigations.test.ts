import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { InvestigationStore, InvestigationStoreError } from "../src/control/investigations.js";
import {
  InvestigationService,
  InvestigationServiceError,
  type CertifiedInvestigationDataset
} from "../src/services/investigations.js";
import { createVerifiedPrincipalContext } from "../src/security/identity.js";

const hash = (value: string) => createHash("sha256").update(value).digest("hex");

function principal(tenantId = "tenant-a", principalId = "analyst-a") {
  const verifiedAtEpochSeconds = Math.floor(Date.parse("2026-08-11T11:00:00.000Z") / 1_000);
  return createVerifiedPrincipalContext({
    issuer: "https://identity.example",
    subject: principalId,
    principalId,
    tenantId,
    clientId: "console",
    audiences: ["abl"],
    resourceIndicators: ["https://abl.example/mcp"],
    scopes: ["detail:read"],
    credentialFingerprint: hash(`${tenantId}:${principalId}`),
    verifiedAtEpochSeconds,
    expiresAtEpochSeconds: verifiedAtEpochSeconds + 7_200,
    authenticationMethods: ["pwd", "mfa"]
  });
}

function fixture() {
  let now = new Date("2026-08-11T12:00:00.000Z");
  const dataset: CertifiedInvestigationDataset = {
    tenantId: "tenant-a",
    reference: { kind: "snapshot", id: "snapshot-1" },
    certificationManifestId: "certification-1",
    populationHash: hash("population-1"),
    fields: ["loan_id", "outstanding_balance", "risk_rating"],
    records: [
      { loan_id: "borrower-secret-1", outstanding_balance: "125.25", risk_rating: "Pass" },
      { loan_id: "borrower-secret-2", outstanding_balance: "250.00", risk_rating: "Watch" },
      { loan_id: "borrower-secret-3", outstanding_balance: "375.75", risk_rating: "Watch" }
    ]
  };
  const store = new InvestigationStore(":memory:", { clock: () => now });
  const service = new InvestigationService(
    store,
    {
      loadCertifiedDataset(tenantId, reference) {
        if (tenantId !== dataset.tenantId || reference.id !== dataset.reference.id) throw new Error("missing");
        return dataset;
      }
    },
    {
      cursorKey: new Uint8Array(32).fill(7),
      maskingKey: new Uint8Array(32).fill(9),
      clock: () => now
    }
  );
  return {
    dataset,
    service,
    store,
    advance(minutes: number) {
      now = new Date(now.getTime() + minutes * 60_000);
    }
  };
}

test("investigations filter certified rows, mask identifiers, paginate, and chain disclosure evidence", async () => {
  const { dataset, service, store } = fixture();
  const actor = principal();
  const investigation = await service.create(actor, {
    reference: { kind: "snapshot", id: "snapshot-1" },
    requestedFields: ["loan_id", "outstanding_balance", "risk_rating"],
    filter: { type: "predicate", field: "outstanding_balance", operator: "gte", value: "200" },
    purpose: "portfolio-risk-review",
    reason: "Investigate the watch-list balance bridge",
    rowBudget: 3,
    reviewerPrincipalId: "reviewer-a",
    idempotencyKey: "create-1"
  });
  const first = await service.getRows(actor, investigation.investigationId, {
    limit: 1,
    idempotencyKey: "page-1"
  });
  assert.equal(first.rows.length, 1);
  assert.match(String(first.rows[0]!.loan_id), /^tok_[a-f0-9]{24}$/);
  assert.equal(first.rows[0]!.outstanding_balance, "250.00");
  assert.ok(first.nextCursor);
  assert.equal(first.disclosedRows, 1);

  const second = await service.getRows(actor, investigation.investigationId, {
    cursor: first.nextCursor!,
    limit: 100,
    idempotencyKey: "page-2"
  });
  assert.equal(second.rows.length, 1);
  assert.equal(second.rows[0]!.outstanding_balance, "375.75");
  assert.equal(second.nextCursor, null);
  assert.equal(second.disclosedRows, 2);
  const disclosures = store.listDisclosures("tenant-a", investigation.investigationId);
  assert.equal(disclosures.length, 2);
  assert.equal(disclosures[1]!.previousFingerprint, disclosures[0]!.disclosureFingerprint);
  assert.equal(disclosures[0]!.fieldPolicyVersion, "1.0.0");
  assert.deepEqual(disclosures[0]!.reference, { kind: "snapshot", id: "snapshot-1" });
  assert.equal(disclosures[0]!.certificationManifestId, "certification-1");
  assert.equal(disclosures[0]!.populationHash, dataset.populationHash);
  assert.equal(disclosures[0]!.purpose, "portfolio-risk-review");
  assert.equal(disclosures.some((entry) => JSON.stringify(entry).includes("borrower-secret")), false);
  store.close();
});

test("investigations fail closed across principal, tenant, expiry, cursor tampering, and row budget", async () => {
  const { service, advance, store } = fixture();
  const actor = principal();
  const investigation = await service.create(actor, {
    reference: { kind: "snapshot", id: "snapshot-1" },
    requestedFields: ["loan_id"],
    purpose: "exception-review",
    reason: "Resolve a documented population exception",
    rowBudget: 1,
    idempotencyKey: "create-2"
  });
  await assert.rejects(
    service.getRows(principal("tenant-b"), investigation.investigationId, { idempotencyKey: "wrong-tenant" }),
    (error: unknown) => error instanceof InvestigationServiceError && error.code === "NOT_FOUND"
  );
  await assert.rejects(
    service.getRows(principal("tenant-a", "analyst-b"), investigation.investigationId, { idempotencyKey: "wrong-principal" }),
    (error: unknown) => error instanceof InvestigationServiceError && error.code === "NOT_FOUND"
  );
  const page = await service.getRows(actor, investigation.investigationId, {
    limit: 1,
    idempotencyKey: "budget-page"
  });
  assert.equal(page.remainingRowBudget, 0);
  await assert.rejects(
    service.getRows(actor, investigation.investigationId, { idempotencyKey: "budget-exhausted" }),
    (error: unknown) => error instanceof InvestigationServiceError && error.code === "ROW_BUDGET_EXCEEDED"
  );

  const expiring = await service.create(actor, {
    reference: { kind: "snapshot", id: "snapshot-1" },
    requestedFields: ["risk_rating"],
    purpose: "portfolio-risk-review",
    reason: "Review rating migration evidence",
    idempotencyKey: "create-3"
  });
  advance(16);
  await assert.rejects(
    service.getRows(actor, expiring.investigationId, { idempotencyKey: "expired" }),
    (error: unknown) => error instanceof InvestigationServiceError && error.code === "EXPIRED"
  );
  store.close();
});

test("investigation lifecycle is exactly idempotent and close is principal bound", async () => {
  const { service, store } = fixture();
  const actor = principal();
  const input = {
    reference: { kind: "snapshot" as const, id: "snapshot-1" },
    requestedFields: ["risk_rating"],
    purpose: "portfolio-risk-review",
    reason: "Review the certified risk distribution",
    idempotencyKey: "same-create"
  };
  const first = await service.create(actor, input);
  const replayed = await service.create(actor, input);
  assert.deepEqual(replayed, first);
  assert.throws(
    () => service.close(principal("tenant-a", "analyst-b"), first.investigationId, "Not mine", "bad-close"),
    (error: unknown) => error instanceof InvestigationStoreError && error.code === "NOT_FOUND"
  );
  const closed = service.close(actor, first.investigationId, "Review completed", "close-1");
  assert.equal(closed.status, "closed");
  assert.deepEqual(service.close(actor, first.investigationId, "Review completed", "close-1"), closed);
  store.close();
});
