import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import type {
  GovernedCertifiedSnapshotPublicationLinkV2,
  GovernedSourceDeliveryRecordV1
} from "../src/contracts/index.js";
import { canonicalHash } from "../src/contracts/canonical.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import { HistoricalRuntimeAuthorityError, SqliteHistoricalRuntimeAuthorityV1 } from "../src/control/historical-runtime-authority-v1.js";
import { runOperatorCli } from "../src/operator/cli.js";
import {
  OperatorControlPlane,
  type OperatorControlPlaneDependencies,
  type OperatorPrincipal
} from "../src/operator/control-plane.js";
import { OperatorInputError } from "../src/operator/schemas.js";

const HASH_A = `sha256:${"a".repeat(64)}` as const;
const HASH_B = `sha256:${"b".repeat(64)}` as const;
const HASH_C = `sha256:${"c".repeat(64)}` as const;
const HASH_D = `sha256:${"d".repeat(64)}` as const;
const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("source-delivery commands bind tenant and actor at the trusted process boundary", async () => {
  const calls: Array<Readonly<Record<string, unknown>>> = [];
  const delivery = deliveryRecord();
  const resolution = {
    delivery,
    sourceContract: {},
    scopeBinding: {}
  };
  const plane = operatorPlane("operator-maker", {
    sourceDeliveryRegistration: {
      register: async (actor, input) => {
        calls.push({ operation: "register", actor, input });
        return { resolution, replayed: false };
      }
    } as unknown as OperatorControlPlaneDependencies["sourceDeliveryRegistration"],
    sourceDeliveryAdministration: {
      disable: (actor: unknown, input: unknown) => {
        calls.push({ operation: "disable", actor, input });
        return {
          resolution: {
            ...resolution,
            delivery: { ...delivery, deliveryRevision: 2, status: "disabled", statusReason: "bad_source" }
          },
          replayed: false
        };
      },
      resolveDeliveryStatus: async (input: unknown) => {
        calls.push({ operation: "get", input });
        return {
          contractVersion: 1,
          tenantId: "tenant-a",
          deliveryId: "delivery-1",
          deliveryRevision: 1,
          deliveryHash: HASH_A,
          datasetId: "dataset-a",
          facilityId: "facility-a",
          sourceContract: {
            sourceContractId: "source-a",
            revision: 1,
            sourceContractHash: HASH_B
          },
          scopeBinding: { bindingId: "binding-a", revision: 1, bindingHash: HASH_C },
          mode: "object_storage",
          format: "xlsx",
          sourceObservedAt: "2026-08-01T00:00:00.000Z",
          receivedAt: "2026-08-01T00:01:00.000Z",
          status: "usable",
          recordedAt: "2026-08-01T00:02:00.000Z"
        };
      },
      listAudit: (tenantId: string) => [{
        contractVersion: 1,
        tenantId,
        tenantSequence: 1,
        eventId: "event-1",
        eventType: "source_delivery_registered",
        deliveryId: "delivery-1",
        deliveryRevision: 1,
        deliveryHash: HASH_A,
        actorId: "operator-maker",
        identitySource: "server_derived",
        occurredAt: "2026-08-01T00:02:00.000Z",
        previousEventHash: null,
        eventHash: HASH_D
      }]
    } as unknown as OperatorControlPlaneDependencies["sourceDeliveryAdministration"]
  });

  await assert.rejects(
    () => plane.registerSourceDelivery({
      tenantId: "tenant-b",
      deliveryId: "delivery-1",
      sourceContractDefinitionVersionId: "source-definition-1",
      datasetScopeBindingDefinitionVersionId: "binding-definition-1",
      idempotencyKey: "delivery-register-1"
    }),
    OperatorInputError
  );

  const registered = await plane.registerSourceDelivery({
    deliveryId: "delivery-1",
    sourceContractDefinitionVersionId: "source-definition-1",
    datasetScopeBindingDefinitionVersionId: "binding-definition-1",
    idempotencyKey: "delivery-register-1"
  });
  assert.equal(registered.status, "usable");
  assert.equal(JSON.stringify(registered).includes("private/source.xlsx"), false);
  assert.equal(JSON.stringify(registered).includes("immutable-version-secret"), false);
  assert.deepEqual((calls[0]?.actor as Record<string, unknown>), {
    tenantId: "tenant-a",
    actorId: "operator-maker",
    authority: "platform_operator",
    identitySource: "server_derived"
  });

  const status = await plane.getSourceDelivery({ deliveryId: "delivery-1" });
  assert.equal(status.sourceContractId, "source-a");
  assert.deepEqual(calls[1]?.input, { tenantId: "tenant-a", deliveryId: "delivery-1" });

  const disabled = plane.disableSourceDelivery({
    deliveryId: "delivery-1",
    reasonCode: "bad_source",
    idempotencyKey: "delivery-disable-1"
  });
  assert.equal(disabled.status, "disabled");
  assert.equal(disabled.statusReason, "bad_source");

  const audit = plane.listSourceDeliveryAudit({ afterSequence: 0, limit: 10 });
  assert.equal(audit.length, 1);
  assert.equal("identitySource" in audit[0]!, false);
});

test("historical runtime commands form an IDs-only maker/checker chain with bounded audit", () => {
  const directory = tempDirectory("operator-runtime-governance-");
  const artifacts = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "test-key",
    keys: { "test-key": Buffer.alloc(32, 19) }
  });
  const authority = new SqliteHistoricalRuntimeAuthorityV1(
    join(directory, "runtime.sqlite"),
    artifacts,
    { clock: () => new Date("2026-08-15T12:00:00.000Z") }
  );
  const maker = operatorPlane("runtime-maker", { historicalRuntimeAdministration: authority });
  const checker = operatorPlane("runtime-checker", { historicalRuntimeAdministration: authority });

  const dictionaryPath = join(directory, "dictionary.json");
  const compilerPath = join(directory, "compiler.json");
  const methodologyPath = join(directory, "methodology.json");
  const dictionaryContent = {
    dictionary: { fields: [{ id: "loan_id" }] },
    fieldPolicy: { missingValues: "preserve" }
  };
  writeFileSync(dictionaryPath, JSON.stringify(dictionaryContent));
  writeFileSync(compilerPath, JSON.stringify({ compiler: "mapping-v2" }));
  writeFileSync(methodologyPath, JSON.stringify({ methodology: "surveillance-v1" }));

  maker.registerHistoricalBundle({
    bundleKind: "dictionary",
    bundleId: "dictionary-1",
    version: "1.0.0",
    mediaType: "application/json",
    createdAt: "2026-08-15T11:00:00.000Z",
    filePath: dictionaryPath,
    dictionaryVersion: "1.0.0",
    dictionaryHash: canonicalHash(dictionaryContent.dictionary),
    fieldPolicyVersion: "1.0.0",
    fieldPolicyHash: canonicalHash(dictionaryContent.fieldPolicy),
    idempotencyKey: "register-dictionary-1"
  });
  const compiler = maker.registerHistoricalBundle({
    bundleKind: "mapping_compiler",
    bundleId: "compiler-1",
    version: "1.0.0",
    mediaType: "application/json",
    createdAt: "2026-08-15T11:00:00.000Z",
    filePath: compilerPath,
    idempotencyKey: "register-compiler-1"
  });
  maker.registerHistoricalBundle({
    bundleKind: "methodology",
    bundleId: "methodology-1",
    version: "1.0.0",
    mediaType: "application/json",
    createdAt: "2026-08-15T11:00:00.000Z",
    filePath: methodologyPath,
    idempotencyKey: "register-methodology-1"
  });
  assert.equal("artifactId" in compiler, false);

  const runtime = maker.registerHistoricalRuntime({
    runtimeBundleId: "runtime-1",
    runtimeVersion: "1.0.0",
    dictionary: { bundleId: "dictionary-1", version: "1.0.0" },
    mappingCompiler: { bundleId: "compiler-1", version: "1.0.0" },
    methodologies: [{ bundleId: "methodology-1", version: "1.0.0" }],
    assembledAt: "2026-08-15T11:30:00.000Z",
    idempotencyKey: "register-runtime-1"
  });
  assert.equal(runtime.runtimeBundleId, "runtime-1");
  assert.equal(JSON.stringify(runtime).includes("artifactId"), false);

  assert.throws(
    () => maker.activateHistoricalRuntime({
      runtimeBundleId: runtime.runtimeBundleId,
      runtimeBundleHash: runtime.runtimeBundleHash,
      idempotencyKey: "self-activate-runtime-1"
    }),
    (error: unknown) =>
      error instanceof HistoricalRuntimeAuthorityError && error.code === "MAKER_CHECKER_VIOLATION"
  );
  const activated = checker.activateHistoricalRuntime({
    runtimeBundleId: runtime.runtimeBundleId,
    runtimeBundleHash: runtime.runtimeBundleHash,
    idempotencyKey: "activate-runtime-1"
  });
  assert.equal(activated.registeredBy, "runtime-maker");
  assert.equal(activated.activatedBy, "runtime-checker");

  const tail = checker.listHistoricalRuntimeAudit({ afterSequence: 3, limit: 2 });
  assert.deepEqual(tail.map((event) => event.eventType), ["runtime_registered", "runtime_activated"]);
  assert.deepEqual(tail.map((event) => event.tenantSequence), [4, 5]);
  authority.close();
});

test("publication v2 commands are IDs-only, redacted, disable-aware, and reachable through the CLI", async () => {
  const calls: Array<Readonly<Record<string, unknown>>> = [];
  const link = publicationLink();
  const plane = operatorPlane("publication-operator", {
    governedPublicationV2Writer: {
      publish: async (request: unknown, actor: string) => {
        calls.push({ operation: "publish", request, actor });
        return link;
      }
    } as unknown as OperatorControlPlaneDependencies["governedPublicationV2Writer"],
    governedPublicationV2Catalog: {
      get: (tenantId: string, linkId: string) => {
        calls.push({ operation: "get", tenantId, linkId });
        return link;
      },
      getDisable: () => undefined,
      disable: (input: Readonly<Record<string, unknown>>) => {
        calls.push({ operation: "disable", input });
        return {
          tenantId: "tenant-a",
          linkId: "publication-link-1",
          linkHash: HASH_A,
          reasonCode: "superseded",
          reason: "private disable explanation",
          disabledBy: "publication-operator",
          disabledAt: "2026-08-15T12:30:00.000Z"
        };
      },
      listAuditEvents: () => [{
        sequence: 1,
        tenantSequence: 1,
        tenantId: "tenant-a",
        eventId: "publication-event-1",
        eventType: "governed_certified_snapshot_publication_link_v2.recorded",
        linkId: "publication-link-1",
        actor: "publication-operator",
        details: { privateLocator: "do-not-return" },
        occurredAt: "2026-08-15T12:00:00.000Z",
        previousEventHash: null,
        eventHash: HASH_D
      }]
    } as unknown as OperatorControlPlaneDependencies["governedPublicationV2Catalog"]
  });

  const stdout: string[] = [];
  const stderr: string[] = [];
  const exitCode = await runOperatorCli(
    ["publish-snapshot-v2", "--request", "request.json"],
    plane,
    { stdout: (line) => stdout.push(line), stderr: (line) => stderr.push(line) },
    {
      readRequest: () => ({
        linkId: "publication-link-1",
        certificationManifestId: "certification-1",
        idempotencyKey: "publish-1"
      })
    }
  );
  assert.equal(exitCode, 0);
  assert.equal(stderr.length, 0);
  assert.equal(stdout[0]?.includes("privateLocator"), false);
  assert.deepEqual(calls[0]?.request, {
    tenantId: "tenant-a",
    linkId: "publication-link-1",
    certificationManifestId: "certification-1",
    idempotencyKey: "publish-1"
  });
  assert.equal(calls[0]?.actor, "publication-operator");

  const disabled = plane.disablePublicationV2({
    linkId: "publication-link-1",
    expectedLinkHash: HASH_A,
    reasonCode: "superseded",
    reason: "private disable explanation",
    idempotencyKey: "disable-publication-1"
  });
  assert.equal("reason" in disabled, false);
  assert.deepEqual((calls[1]?.input as Record<string, unknown>).disabledBy, "publication-operator");
  assert.deepEqual((calls[1]?.input as Record<string, unknown>).tenantId, "tenant-a");

  const fetched = plane.getPublicationV2({ linkId: "publication-link-1" });
  assert.equal(fetched.enabled, true);
  assert.equal(JSON.stringify(fetched).includes("private publication payload"), false);
  const audit = plane.listPublicationV2Audit({ afterSequence: 0, limit: 10 });
  assert.equal("details" in audit[0]!, false);
});

function operatorPlane(
  principalId: string,
  governance: Partial<OperatorControlPlaneDependencies>
): OperatorControlPlane {
  return new OperatorControlPlane({
    principal: principal(principalId),
    control: unreachable("control"),
    definitions: unreachable("definitions"),
    artifacts: unreachable("artifacts"),
    memberships: unreachable("memberships"),
    alerts: unreachable("alerts"),
    ingestion: unreachable("ingestion"),
    ...governance
  });
}

function principal(principalId: string): OperatorPrincipal {
  return {
    principalId,
    tenantId: "tenant-a",
    authenticationMethod: "trusted_service_identity",
    authorizationScope: "global_admin"
  };
}

function unreachable<T>(label: string): T {
  return new Proxy({}, {
    get: () => () => {
      throw new Error(`Unexpected dependency call: ${label}`);
    }
  }) as T;
}

function tempDirectory(prefix: string): string {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  directories.push(directory);
  return directory;
}

function deliveryRecord(): GovernedSourceDeliveryRecordV1 {
  return {
    contractVersion: 1,
    tenantId: "tenant-a",
    deliveryId: "delivery-1",
    deliveryRevision: 1,
    deliveryHash: HASH_A,
    datasetId: "dataset-a",
    facilityId: "facility-a",
    sourceContract: {
      sourceContractId: "source-a",
      revision: 1,
      sourceContractHash: HASH_B
    },
    scopeBinding: { bindingId: "binding-a", revision: 1, bindingHash: HASH_C },
    locator: {
      mode: "object_storage",
      format: "xlsx",
      connectorId: "connector-a",
      bucket: "private-bucket",
      objectKey: "private/source.xlsx",
      immutableVersionId: "immutable-version-secret",
      immutableVersionHash: HASH_B,
      contentHash: HASH_C,
      byteCount: 100
    },
    sourceObservedAt: "2026-08-01T00:00:00.000Z",
    receivedAt: "2026-08-01T00:01:00.000Z",
    status: "usable",
    recordedBy: "operator-maker",
    identitySource: "server_derived",
    recordedAt: "2026-08-01T00:02:00.000Z",
    previousDeliveryHash: null
  };
}

function publicationLink(): GovernedCertifiedSnapshotPublicationLinkV2 {
  return {
    tenantId: "tenant-a",
    linkId: "publication-link-1",
    linkHash: HASH_A,
    publication: {
      publicationId: "publication-link-1",
      publicationHash: HASH_B,
      snapshotId: "snapshot-1",
      snapshotHash: HASH_C,
      privatePayload: "private publication payload"
    },
    evidence: { evidenceId: "certification-1", evidenceHash: HASH_D },
    governance: { governanceHash: HASH_B },
    linkedAt: "2026-08-15T12:00:00.000Z"
  } as unknown as GovernedCertifiedSnapshotPublicationLinkV2;
}
