import assert from "node:assert/strict";
import { test } from "node:test";

import { runOperatorCli, type OperatorCliIo } from "../src/operator/cli.js";
import {
  OperatorControlPlane,
  OperatorControlPlaneError,
  type OperatorControlPlaneDependencies,
  type OperatorPrincipal
} from "../src/operator/control-plane.js";
import { OperatorInputError } from "../src/operator/schemas.js";
import { ModernSnapshotCaptureError } from "../src/services/modern-snapshot-capture.js";

const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const HASH_C = `sha256:${"c".repeat(64)}`;
const HASH_D = `sha256:${"d".repeat(64)}`;

function unreachable<T>(label: string): T {
  return new Proxy(
    {},
    {
      get: () => () => {
        throw new Error(`Unexpected dependency call: ${label}`);
      }
    }
  ) as T;
}

function principal(tenantBound = true): OperatorPrincipal {
  return {
    principalId: "trusted-operator",
    ...(tenantBound ? { tenantId: "tenant-a" } : {}),
    authenticationMethod: "trusted_service_identity",
    authorizationScope: "global_admin"
  };
}

function dependencies(
  overrides: Partial<OperatorControlPlaneDependencies> = {}
): OperatorControlPlaneDependencies {
  return {
    principal: principal(),
    control: unreachable("control"),
    definitions: unreachable("definitions"),
    artifacts: unreachable("artifacts"),
    memberships: unreachable("memberships"),
    alerts: unreachable("alerts"),
    ingestion: unreachable("ingestion"),
    ...overrides
  };
}

function captureResult() {
  return {
    receipt: {
      deliveryId: "delivery-001",
      receiptId: "derived-snapshot-001:extraction",
      receiptHash: HASH_B,
      columnCount: 25,
      byteCount: 42_000,
      sourceLocator: "postgresql://private-source/secret-table",
      capturedBy: "trusted-operator"
    },
    snapshot: {
      snapshotId: "derived-snapshot-001",
      sourceContract: { sourceContractId: "source-contract-001" },
      snapshotHash: HASH_A,
      asOfDate: "2021-10-31",
      rowCount: 33_698
    },
    receiptReplayed: false,
    snapshotReplayed: false
  } as unknown as Awaited<
    ReturnType<NonNullable<OperatorControlPlaneDependencies["modernSnapshotCapture"]>["capture"]>
  >;
}

function certificationResult() {
  return {
    evidence: {
      certification: {
        snapshotId: "derived-snapshot-001",
        snapshotHash: HASH_A,
        mappingApplicationId: "server-mapping-001",
        mappingApplicationHash: HASH_B,
        populationId: "server-population-001",
        populationHash: HASH_C,
        certificationManifestId: "server-manifest-001",
        certificationManifestHash: HASH_D,
        dataQualityResultHash: HASH_A,
        reconciliationResultHash: HASH_B,
        rowCount: 33_698,
        certifiedAt: "2026-08-13T18:00:00.000Z",
        certifiedBy: "trusted-operator",
        normalizedArtifactId: "private-artifact-id"
      },
      mappingSpec: { privateDefinition: "must-not-leak" },
      normalizedArtifact: { uri: "abl-artifact://private-locator" },
      evidenceHash: HASH_C
    },
    replayed: false
  } as unknown as Awaited<
    ReturnType<NonNullable<OperatorControlPlaneDependencies["modernSnapshotCertification"]>["certify"]>
  >;
}

test("modern capture accepts only source and delivery ids and derives trusted actor identity", async () => {
  let capturedActor: unknown;
  let capturedRequest: unknown;
  const plane = new OperatorControlPlane(
    dependencies({
      modernSnapshotCapture: {
        capture: async (actor, request) => {
          capturedActor = actor;
          capturedRequest = request;
          return captureResult();
        }
      }
    })
  );

  const summary = await plane.extractSqlSnapshotV2({
    sourceContractId: "source-contract-001",
    deliveryId: "delivery-001"
  });

  assert.deepEqual(capturedRequest, {
    sourceContractId: "source-contract-001",
    deliveryId: "delivery-001"
  });
  assert.deepEqual(capturedActor, {
    tenantId: "tenant-a",
    actorId: "trusted-operator",
    authority: "platform_operator",
    identitySource: "server_derived"
  });
  assert.equal(summary.snapshotId, "derived-snapshot-001");
  const serialized = JSON.stringify(summary);
  assert.equal(serialized.includes("private-source"), false);
  assert.equal(serialized.includes("trusted-operator"), false);

  await assert.rejects(
    plane.extractSqlSnapshotV2({
      sourceContractId: "source-contract-001",
      deliveryId: "delivery-001",
      snapshotId: "caller-selected-snapshot"
    }),
    OperatorInputError
  );
});

test("modern certification accepts only snapshot id and returns certified metadata only", async () => {
  let certificationActor: unknown;
  let certificationRequest: unknown;
  const plane = new OperatorControlPlane(
    dependencies({
      modernSnapshotCertification: {
        certify: async (request, actor) => {
          certificationRequest = request;
          certificationActor = actor;
          return certificationResult();
        }
      }
    })
  );

  const summary = await plane.certifySnapshotV2({ snapshotId: "derived-snapshot-001" });

  assert.deepEqual(certificationRequest, { snapshotId: "derived-snapshot-001" });
  assert.deepEqual(certificationActor, {
    tenantId: "tenant-a",
    actorId: "trusted-operator",
    authority: "platform_operator",
    identitySource: "server_derived"
  });
  assert.equal(summary.certificationManifestId, "server-manifest-001");
  const serialized = JSON.stringify(summary);
  assert.equal(serialized.includes("trusted-operator"), false);
  assert.equal(serialized.includes("private-artifact"), false);
  assert.equal(serialized.includes("private-locator"), false);
  assert.equal(serialized.includes("privateDefinition"), false);

  await assert.rejects(
    plane.certifySnapshotV2({
      snapshotId: "derived-snapshot-001",
      certificationManifestId: "caller-selected-manifest"
    }),
    OperatorInputError
  );
});

test("modern commands fail closed when their port or trusted tenant binding is absent", async () => {
  const withoutPorts = new OperatorControlPlane(dependencies());
  await assert.rejects(
    withoutPorts.extractSqlSnapshotV2({
      sourceContractId: "source-contract-001",
      deliveryId: "delivery-001"
    }),
    (error: unknown) =>
      error instanceof OperatorControlPlaneError && error.code === "CAPABILITY_NOT_CONFIGURED"
  );
  await assert.rejects(
    withoutPorts.certifySnapshotV2({ snapshotId: "derived-snapshot-001" }),
    (error: unknown) =>
      error instanceof OperatorControlPlaneError && error.code === "CAPABILITY_NOT_CONFIGURED"
  );

  let called = false;
  const withoutTenant = new OperatorControlPlane(
    dependencies({
      principal: principal(false),
      modernSnapshotCapture: {
        capture: async () => {
          called = true;
          return captureResult();
        }
      }
    })
  );
  await assert.rejects(
    withoutTenant.extractSqlSnapshotV2({
      sourceContractId: "source-contract-001",
      deliveryId: "delivery-001"
    }),
    (error: unknown) =>
      error instanceof OperatorControlPlaneError && error.code === "CAPABILITY_NOT_CONFIGURED"
  );
  assert.equal(called, false);
});

test("CLI dispatches modern commands and redacts missing-capability details", async () => {
  const calls: string[] = [];
  const plane = new OperatorControlPlane(
    dependencies({
      modernSnapshotCapture: {
        capture: async () => {
          calls.push("capture");
          return captureResult();
        }
      },
      modernSnapshotCertification: {
        certify: async () => {
          calls.push("certify");
          return certificationResult();
        }
      }
    })
  );
  const output = captureIo();
  assert.equal(
    await runOperatorCli(["extract-sql-v2", "--request", "ignored.json"], plane, output.io, {
      readRequest: () => ({
        sourceContractId: "source-contract-001",
        deliveryId: "delivery-001"
      })
    }),
    0
  );
  assert.equal(
    await runOperatorCli(["certify-snapshot-v2", "--request", "ignored.json"], plane, output.io, {
      readRequest: () => ({ snapshotId: "derived-snapshot-001" })
    }),
    0
  );
  assert.deepEqual(calls, ["capture", "certify"]);

  const failure = captureIo();
  const unconfigured = new OperatorControlPlane(dependencies());
  assert.equal(
    await runOperatorCli(["certify-snapshot-v2", "--request", "ignored.json"], unconfigured, failure.io, {
      readRequest: () => ({ snapshotId: "derived-snapshot-001" })
    }),
    3
  );
  assert.equal(failure.stderr.length, 1);
  assert.deepEqual(JSON.parse(failure.stderr[0]!), {
    error: {
      code: "CAPABILITY_NOT_CONFIGURED",
      message: "Governed operator capability is not configured"
    },
    ok: false
  });
});

test("CLI preserves declared modern failure codes without leaking trusted evidence details", async () => {
  const plane = new OperatorControlPlane(
    dependencies({
      modernSnapshotCapture: {
        capture: async () => {
          throw new ModernSnapshotCaptureError(
            "EXTRACTION_SUBSTITUTION",
            "private connector, object key, source hash, and database relation"
          );
        }
      }
    })
  );
  const output = captureIo();

  assert.equal(
    await runOperatorCli(["extract-sql-v2", "--request", "ignored.json"], plane, output.io, {
      readRequest: () => ({
        sourceContractId: "source-contract-001",
        deliveryId: "delivery-001"
      })
    }),
    3
  );
  assert.deepEqual(JSON.parse(output.stderr[0]!), {
    error: {
      code: "EXTRACTION_SUBSTITUTION",
      message: "Governed operator operation was rejected"
    },
    ok: false
  });
  assert.equal(output.stderr[0]!.includes("private connector"), false);
  assert.equal(output.stderr[0]!.includes("object key"), false);
  assert.equal(output.stderr[0]!.includes("source hash"), false);
  assert.equal(output.stderr[0]!.includes("database relation"), false);
});

function captureIo(): {
  readonly io: OperatorCliIo;
  readonly stdout: string[];
  readonly stderr: string[];
} {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    stdout,
    stderr,
    io: {
      stdout: (line) => stdout.push(line),
      stderr: (line) => stderr.push(line)
    }
  };
}
