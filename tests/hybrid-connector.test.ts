import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";

import { ConnectorAgent, type ConnectorExecutionResultV1, type ConnectorOutboundSession } from "../src/hybrid/connector-agent.js";
import {
  ConnectorProtocolError,
  createConnectorSigningKey,
  createConnectorVerificationKey,
  issueConnectorPlan,
  verifyConnectorPlan,
  type ConnectorPlanReplayRecord
} from "../src/hybrid/connector-protocol.js";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const HASH_C = "c".repeat(64);
const NOW = 1_786_500_000;

function keys() {
  const pair = generateKeyPairSync("ed25519");
  return {
    signer: createConnectorSigningKey("central-1", pair.privateKey),
    verifier: createConnectorVerificationKey("central-1", pair.publicKey)
  };
}

function replay() {
  const seen = new Set<string>();
  return {
    records: [] as ConnectorPlanReplayRecord[],
    consumeOnce(record: ConnectorPlanReplayRecord) {
      this.records.push(record);
      if (seen.has(record.replayKey)) return false;
      seen.add(record.replayKey);
      return true;
    }
  };
}

function extractionOperation() {
  return {
    action: "extract" as const,
    sourceContractId: "loans-v2",
    sourceContractHash: HASH_A,
    adapterDefinitionId: "pg-client-vpc",
    adapterDefinitionHash: HASH_B,
    deliveryMode: "full" as const,
    maximumRows: 100_000,
    maximumBytes: 1_000_000,
    maximumExecutionMs: 30_000
  };
}

test("Ed25519 connector plans bind tenant, connector, policy, operation, expiry, and consume once", async () => {
  const key = keys();
  const defense = replay();
  const issued = issueConnectorPlan(key.signer, {
    tenantId: "tenant-a",
    connectorId: "connector-a",
    operation: extractionOperation(),
    policyHash: HASH_C,
    ttlSeconds: 120,
    nowEpochSeconds: NOW,
    nonce: "nonce-a"
  });
  const claims = await verifyConnectorPlan(
    [key.verifier],
    issued.token,
    { tenantId: "tenant-a", connectorId: "connector-a" },
    defense,
    { nowEpochSeconds: NOW }
  );
  assert.equal(claims.planId, issued.claims.planId);
  assert.equal(claims.operation.action, "extract");
  await assert.rejects(
    verifyConnectorPlan(
      [key.verifier],
      issued.token,
      { tenantId: "tenant-a", connectorId: "connector-a" },
      defense,
      { nowEpochSeconds: NOW }
    ),
    (error: unknown) => error instanceof ConnectorProtocolError && error.code === "PLAN_REPLAYED"
  );
});

test("connector plans fail closed on tampering, binding mismatch, unsafe properties, and expiry", async () => {
  const key = keys();
  const issued = issueConnectorPlan(key.signer, {
    tenantId: "tenant-a",
    connectorId: "connector-a",
    operation: extractionOperation(),
    policyHash: HASH_C,
    ttlSeconds: 10,
    nowEpochSeconds: NOW,
    nonce: "nonce-b"
  });
  const tampered = `${issued.token.slice(0, -1)}${issued.token.endsWith("A") ? "B" : "A"}`;
  await assert.rejects(
    verifyConnectorPlan([key.verifier], tampered, { tenantId: "tenant-a", connectorId: "connector-a" }, replay(), { nowEpochSeconds: NOW }),
    (error: unknown) => error instanceof ConnectorProtocolError && error.code === "INVALID_SIGNATURE"
  );
  await assert.rejects(
    verifyConnectorPlan([key.verifier], issued.token, { tenantId: "tenant-b", connectorId: "connector-a" }, replay(), { nowEpochSeconds: NOW }),
    (error: unknown) => error instanceof ConnectorProtocolError && error.code === "PLAN_BINDING_MISMATCH"
  );
  await assert.rejects(
    verifyConnectorPlan([key.verifier], issued.token, { tenantId: "tenant-a", connectorId: "connector-a" }, replay(), { nowEpochSeconds: NOW + 100 }),
    (error: unknown) => error instanceof ConnectorProtocolError && error.code === "PLAN_EXPIRED"
  );
  assert.throws(
    () => issueConnectorPlan(key.signer, {
      tenantId: "tenant-a",
      connectorId: "connector-a",
      operation: { ...extractionOperation(), sql: "select * from loans" } as ReturnType<typeof extractionOperation>,
      policyHash: HASH_C,
      ttlSeconds: 10,
      nowEpochSeconds: NOW
    }),
    (error: unknown) => error instanceof ConnectorProtocolError && error.code === "INVALID_INPUT"
  );
});

test("outbound-only agent verifies mutual TLS peer and permits only aggregate extraction receipts", async () => {
  const key = keys();
  const issued = issueConnectorPlan(key.signer, {
    tenantId: "tenant-a",
    connectorId: "connector-a",
    operation: extractionOperation(),
    policyHash: HASH_C,
    ttlSeconds: 120,
    nowEpochSeconds: NOW
  });
  const submitted: ConnectorExecutionResultV1[] = [];
  let closed = 0;
  const session: ConnectorOutboundSession = {
    peer: { authenticated: true, serverSpkiHash: HASH_A },
    async receivePlan() { return issued.token; },
    async submitResult(result) { submitted.push(result); },
    async submitFailure() { assert.fail("valid result must not fail"); },
    async close() { closed += 1; }
  };
  const agent = new ConnectorAgent({
    configuration: {
      tenantId: "tenant-a",
      connectorId: "connector-a",
      clientIdentityRef: "secret-manager/connector-a-mtls",
      trustedServerSpkiHashes: [HASH_A]
    },
    verificationKeys: [key.verifier],
    replayDefense: replay(),
    transport: { async connect() { return session; } },
    executor: {
      async execute(claims) {
        return {
          action: "extract",
          tenantId: claims.tenantId,
          connectorId: claims.connectorId,
          planId: claims.planId,
          artifactId: "client-artifact-a",
          artifactContentHash: HASH_A,
          snapshotId: "snapshot-a",
          schemaHash: HASH_B,
          rowCount: 42,
          byteCount: 512,
          sectionalControlHash: HASH_C
        };
      }
    },
    clock: () => new Date(NOW * 1_000)
  });
  assert.equal(await agent.pollOnce(), "processed");
  assert.equal(submitted.length, 1);
  assert.equal(submitted[0]?.action, "extract");
  assert.equal(closed, 1);
  assert.equal("listen" in agent, false);
});

test("investigation egress rejects extra fields, unredacted values, oversized pages, and wrong populations", async () => {
  const key = keys();
  const operation = {
    action: "investigate" as const,
    investigationId: "investigation-a",
    snapshotId: "snapshot-a",
    certificationManifestId: "certification-a",
    populationHash: HASH_A,
    purposeHash: HASH_B,
    requestedFields: ["loan_id", "current_balance"],
    masks: { loan_id: "redact" as const, current_balance: "none" as const },
    filter: null,
    rowOffset: 0,
    rowLimit: 2,
    maximumBytes: 4_096,
    maximumExecutionMs: 5_000
  };
  const issued = issueConnectorPlan(key.signer, {
    tenantId: "tenant-a",
    connectorId: "connector-a",
    operation,
    policyHash: HASH_C,
    ttlSeconds: 60,
    nowEpochSeconds: NOW
  });
  const failures: string[] = [];
  const agent = new ConnectorAgent({
    configuration: {
      tenantId: "tenant-a",
      connectorId: "connector-a",
      clientIdentityRef: "secret-manager/connector-a-mtls",
      trustedServerSpkiHashes: [HASH_A]
    },
    verificationKeys: [key.verifier],
    replayDefense: replay(),
    transport: {
      async connect() {
        return {
          peer: { authenticated: true as const, serverSpkiHash: HASH_A },
          async receivePlan() { return issued.token; },
          async submitResult() { assert.fail("unsafe detail must not be submitted"); },
          async submitFailure(failure) { failures.push(failure.code); },
          async close() {}
        };
      }
    },
    executor: {
      async execute(claims) {
        return {
          action: "investigate",
          tenantId: claims.tenantId,
          connectorId: claims.connectorId,
          planId: claims.planId,
          investigationId: "investigation-a",
          populationHash: HASH_A,
          rows: [{ loan_id: "raw-identifier", current_balance: "100", extra_secret: "no" }],
          nextOffset: 1
        };
      }
    },
    clock: () => new Date(NOW * 1_000)
  });
  assert.equal(await agent.pollOnce(), "rejected");
  assert.deepEqual(failures, ["RESULT_POLICY_VIOLATION"]);
});
