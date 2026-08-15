import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import { canonicalHash } from "../src/contracts/canonical.js";
import { parseDatasetSnapshotV2 } from "../src/contracts/dataset-snapshot-v2.js";
import {
  createGovernedDatasetScopeBindingV1,
  type GovernedDatasetScopeBindingV1
} from "../src/contracts/dataset-scope-binding-v1.js";
import { createSourceContractV1, type SourceContractV1 } from "../src/contracts/source-contract-v1.js";
import type {
  GovernedSourceDeliveryLocatorV1,
  RegisterGovernedSourceDeliveryV1,
  TrustedSourceDeliveryActorV1
} from "../src/contracts/source-delivery-authority-v1.js";
import {
  SQLITE_SOURCE_DELIVERY_AUTHORITY_COMPONENT,
  SourceDeliveryAuthorityError,
  SqliteSourceDeliveryAuthorityV1
} from "../src/control/source-delivery-authority-v1.js";
import { InMemoryImmutableRepository } from "../src/repositories/in-memory.js";
import type { GovernedDatasetSnapshotCommitRepositoryV1 } from "../src/repositories/governed-snapshot-commit.js";
import {
  ModernSnapshotCaptureServiceV1,
  type ModernSnapshotExtractionReceiptV1
} from "../src/services/modern-snapshot-capture.js";
import {
  GovernedSourceDeliveryRegistrationError,
  GovernedSourceDeliveryRegistrationServiceV1
} from "../src/services/governed-source-delivery-registration.js";
import type { ResolvedGovernedDefinitionV2 } from "../src/services/governed-definition-v2-resolver.js";

const OBSERVED_AT = "2026-08-01T23:55:00.000Z";
const RECEIVED_AT = "2026-08-02T00:00:00.000Z";
const RECORDED_AT = "2026-08-02T00:05:00.000Z";

test("registers exact governed evidence and exposes only redacted IDs/status outside trusted extraction", async () => {
  const fixture = authorityFixture();
  try {
    const source = sourceContract("tenant-a", "postgresql");
    const binding = scopeBinding(source);
    const registration = registerInput(source, binding, postgresqlLocator(source));
    const result = fixture.authority.register(actor("tenant-a"), registration);

    assert.equal(result.replayed, false);
    assert.equal(result.resolution.delivery.status, "usable");
    assert.equal(result.resolution.delivery.recordedBy, "operator-1");
    assert.equal(result.resolution.delivery.identitySource, "server_derived");

    const status = await fixture.authority.resolveDeliveryStatus({
      tenantId: "tenant-a",
      deliveryId: registration.deliveryId
    });
    assert.equal(status?.status, "usable");
    assert.equal(status?.mode, "postgresql_pull");
    assert.equal(status?.format, "sql_rows");
    assert.equal("locator" in (status as object), false);
    assert.equal(JSON.stringify(status).includes("servicing"), false);
    assert.equal(JSON.stringify(status).includes("kms/postgres/readonly"), false);

    const activated = await fixture.authority.resolveActivatedSourceContract({
      tenantId: "tenant-a",
      sourceContractId: source.sourceContractId
    });
    assert.equal(activated?.sourceContractHash, source.sourceContractHash);
    const resolvedBinding = await fixture.authority.resolveGovernedDatasetScopeBinding({
      tenantId: "tenant-a",
      sourceContract: source,
      deliveryId: registration.deliveryId
    });
    assert.equal(resolvedBinding?.bindingHash, binding.bindingHash);

    const trusted = await fixture.authority.resolveTrustedDeliveryForExtraction({
      tenantId: "tenant-a",
      deliveryId: registration.deliveryId,
      sourceContract: source,
      scopeBinding: binding
    });
    assert.equal(trusted?.delivery.locator.mode, "postgresql_pull");
    assert.equal(
      trusted?.delivery.locator.mode === "postgresql_pull" ? trusted.delivery.locator.relation : undefined,
      "loan_tape"
    );

    assert.equal(
      await fixture.authority.resolveDeliveryStatus({ tenantId: "tenant-b", deliveryId: registration.deliveryId }),
      undefined
    );
    assert.equal(
      await fixture.authority.resolveActivatedSourceContract({
        tenantId: "tenant-b",
        sourceContractId: source.sourceContractId
      }),
      undefined
    );
    assert.throws(
      () => fixture.authority.resolveDeliveryStatus({
          tenantId: "tenant-a",
          deliveryId: registration.deliveryId,
          objectKey: "caller/substitution.xlsx"
        } as never),
      (error: unknown) => authorityError(error, "INVALID_ARGUMENT")
    );

    const audit = fixture.authority.listAudit("tenant-a");
    assert.equal(audit.length, 1);
    assert.equal(audit[0]?.tenantSequence, 1);
    assert.equal(audit[0]?.previousEventHash, null);
    assert.match(audit[0]?.eventHash ?? "", /^sha256:[a-f0-9]{64}$/);

    fixture.authority.close();
    const reopened = new SqliteSourceDeliveryAuthorityV1(fixture.databasePath, {
      clock: () => new Date(RECORDED_AT)
    });
    assert.equal(
      (await reopened.resolveDeliveryStatus({
        tenantId: "tenant-a",
        deliveryId: registration.deliveryId
      }))?.deliveryHash,
      result.resolution.delivery.deliveryHash
    );
    reopened.close();
  } finally {
    fixture.cleanup();
  }
});

test("the authority composes directly with IDs-only modern capture and preflights trusted extraction metadata", async () => {
  const fixture = authorityFixture();
  try {
    const source = sourceContract("tenant-a", "postgresql");
    const binding = scopeBinding(source);
    const registration = registerInput(source, binding, postgresqlLocator(source));
    fixture.authority.register(actor("tenant-a"), registration);
    const receipts = new InMemoryImmutableRepository<ModernSnapshotExtractionReceiptV1>(
      "delivery-authority-capture-receipts",
      (record) => record.receiptId
    );
    const snapshotRecords = new InMemoryImmutableRepository<ReturnType<typeof parseDatasetSnapshotV2>>(
      "delivery-authority-capture-snapshots",
      (record) => record.snapshotId,
      (record) => {
        parseDatasetSnapshotV2(record);
      }
    );
    const snapshots: GovernedDatasetSnapshotCommitRepositoryV1 = {
      put: (record, context) => snapshotRecords.put(record, context),
      get: (tenantId, recordId) => snapshotRecords.get(tenantId, recordId),
      list: (tenantId, page) => snapshotRecords.list(tenantId, page),
      commitGovernedCapture: (record, _lineage, context) => snapshotRecords.put(record, context)
    };
    const snapshotId = modernSnapshotId(registration.deliveryId);
    const service = new ModernSnapshotCaptureServiceV1({
      sourceDeliveries: fixture.authority,
      extraction: {
        extract: async (input) => {
          const delivery = await fixture.authority.resolveTrustedDeliveryForExtraction({
            tenantId: input.tenantId,
            deliveryId: input.deliveryId,
            sourceContract: input.sourceContract,
            scopeBinding: input.scopeBinding
          });
          assert.ok(delivery);
          assert.equal(delivery.delivery.locator.mode, "postgresql_pull");
          return {
            tenantId: input.tenantId,
            datasetId: input.datasetId,
            facilityId: input.facilityId,
            snapshotId: input.snapshotId,
            deliveryId: input.deliveryId,
            asOfDate: "2026-07-31",
            knowledge: {
              sourceObservedAt: delivery.delivery.sourceObservedAt,
              extractedAt: "2026-08-13T12:01:00.000Z",
              receivedAt: "2026-08-13T12:02:00.000Z"
            },
            watermark: { mode: "none" },
            hashes: {
              contentHash: hash("capture-content"),
              schemaHash: hash("capture-schema"),
              profileHash: hash("capture-profile"),
              catalogHash: hash("capture-catalog"),
              parserHash: canonicalHash({
                parserId: input.sourceContract.parserPolicy.parserId,
                parserVersion: input.sourceContract.parserPolicy.parserVersion,
                optionsHash: input.sourceContract.parserPolicy.optionsHash
              })
            },
            rowCount: 2,
            columnCount: 2,
            byteCount: 512,
            elapsedMs: 100,
            sections: [
              {
                sectionId: "loans",
                required: true,
                present: true,
                rowCount: 2,
                contentHash: hash("capture-section-content"),
                schemaHash: hash("capture-section-schema"),
                controlPopulationHash: hash("capture-section-population")
              }
            ],
            correction: { kind: "original" }
          };
        }
      },
      receipts,
      snapshots,
      now: () => "2026-08-13T12:03:00.000Z"
    });

    const captured = await service.capture(actor("tenant-a"), {
      sourceContractId: source.sourceContractId,
      deliveryId: registration.deliveryId
    });
    assert.equal(captured.snapshot.snapshotId, snapshotId);
    assert.equal(captured.snapshot.sourceContract.sourceContractHash, source.sourceContractHash);
    assert.equal(captured.receipt.scopeBinding.bindingHash, binding.bindingHash);
  } finally {
    fixture.cleanup();
  }
});

test("lifecycle-backed registration accepts only governed version IDs and trusted delivery material", async () => {
  const fixture = authorityFixture();
  try {
    // This is the resolver's immutable execution projection: it contains
    // lifecycle approval evidence as `approved`, not a caller-asserted active
    // source document.
    const source = sourceContract("tenant-a", "postgresql", "approved");
    const binding = scopeBinding(source);
    const sourceResolution = resolvedDefinition("source-v1", "source_contract", "loan-tape", source);
    const bindingResolution = resolvedDefinition(
      "binding-v1",
      "dataset_scope_binding",
      binding.bindingId,
      binding
    );
    let materialLoads = 0;
    const service = new GovernedSourceDeliveryRegistrationServiceV1({
      definitions: {
        resolveFrozen: ({ definitionVersionId }) => {
          if (definitionVersionId === "source-v1") return sourceResolution;
          if (definitionVersionId === "binding-v1") return bindingResolution;
          throw new Error("unexpected definition version");
        },
        resolveEffective: ({ kind, definitionKey, asOfDate }) => {
          assert.equal(asOfDate, "2026-08-01");
          if (kind === "source_contract" && definitionKey === "loan-tape") return sourceResolution;
          if (kind === "dataset_scope_binding" && definitionKey === binding.bindingId) return bindingResolution;
          throw new Error("unexpected effective definition");
        }
      },
      deliveryMaterial: {
        resolveForRegistration: async ({ tenantId, deliveryId }) => {
          materialLoads += 1;
          assert.equal(tenantId, "tenant-a");
          assert.equal(deliveryId, "delivery-governed-2026-08");
          return {
            locator: postgresqlLocator(source),
            sourceObservedAt: OBSERVED_AT,
            receivedAt: RECEIVED_AT
          };
        }
      },
      catalog: fixture.authority
    });

    const result = await service.register(actor("tenant-a"), {
      deliveryId: "delivery-governed-2026-08",
      sourceContractDefinitionVersionId: "source-v1",
      datasetScopeBindingDefinitionVersionId: "binding-v1",
      idempotencyKey: "governed-delivery-registration"
    });
    assert.equal(result.replayed, false);
    assert.equal(result.resolution.delivery.sourceContract.sourceContractHash, source.sourceContractHash);
    assert.equal(result.resolution.delivery.scopeBinding.bindingHash, binding.bindingHash);
    assert.equal(materialLoads, 1);

    await assert.rejects(
      () =>
        service.register(
          { tenantId: "tenant-a", actorId: "forged", authority: "platform_operator" } as never,
          {
            deliveryId: "delivery-actor-smuggle",
            sourceContractDefinitionVersionId: "source-v1",
            datasetScopeBindingDefinitionVersionId: "binding-v1",
            idempotencyKey: "governed-delivery-actor-smuggle"
          }
        ),
      (error: unknown) => registrationError(error, "INVALID_INPUT")
    );
    assert.equal(materialLoads, 1);

    await assert.rejects(
      () =>
        service.register(actor("tenant-a"), {
          deliveryId: "delivery-governed-2026-08",
          sourceContractDefinitionVersionId: "binding-v1",
          datasetScopeBindingDefinitionVersionId: "binding-v1",
          idempotencyKey: "governed-delivery-wrong-kind"
        }),
      (error: unknown) => registrationError(error, "INTEGRITY_FAILURE")
    );
    fixture.authority.close();
  } finally {
    fixture.cleanup();
  }
});

test("idempotency replay is exact, conflicts fail closed, and immutable source versions are tenant-scoped unique", () => {
  const fixture = authorityFixture();
  try {
    const source = sourceContract("tenant-a", "object_xlsx");
    const binding = scopeBinding(source);
    const locator = objectLocator(source);
    const registration = registerInput(source, binding, locator);
    const first = fixture.authority.register(actor("tenant-a"), registration);
    const replay = fixture.authority.register(actor("tenant-a"), registration);
    assert.equal(replay.replayed, true);
    assert.equal(replay.resolution.delivery.deliveryHash, first.resolution.delivery.deliveryHash);

    assert.throws(
      () => fixture.authority.register(actor("tenant-a"), { ...registration, deliveryId: "delivery-other" }),
      (error: unknown) => authorityError(error, "IDEMPOTENCY_CONFLICT")
    );
    assert.throws(
      () =>
        fixture.authority.register(actor("tenant-a"), {
          ...registration,
          deliveryId: "delivery-other",
          idempotencyKey: "register-other",
          locator: { ...locator, contentHash: hash("substituted-content") }
        }),
      (error: unknown) => authorityError(error, "ALREADY_EXISTS")
    );

    const sourceB = sourceContract("tenant-b", "object_xlsx");
    const bindingB = scopeBinding(sourceB);
    const tenantB = fixture.authority.register(
      actor("tenant-b"),
      registerInput(sourceB, bindingB, objectLocator(sourceB))
    );
    assert.equal(tenantB.resolution.delivery.tenantId, "tenant-b");
    assert.notEqual(tenantB.resolution.delivery.deliveryHash, first.resolution.delivery.deliveryHash);
  } finally {
    fixture.cleanup();
  }
});

test("disable is append-only, blocks capture authorities, and preserves exact historical replay", async () => {
  const fixture = authorityFixture();
  try {
    const source = sourceContract("tenant-a", "postgresql");
    const binding = scopeBinding(source);
    const registration = registerInput(source, binding, postgresqlLocator(source));
    const registered = fixture.authority.register(actor("tenant-a"), registration);
    fixture.setNow("2026-08-02T01:00:00.000Z");
    const disabled = fixture.authority.disable(actor("tenant-a"), {
      deliveryId: registration.deliveryId,
      reasonCode: "source_retracted",
      idempotencyKey: "disable-delivery"
    });
    assert.equal(disabled.resolution.delivery.status, "disabled");
    assert.equal(disabled.resolution.delivery.deliveryRevision, 2);
    assert.equal(disabled.resolution.delivery.previousDeliveryHash, registered.resolution.delivery.deliveryHash);

    assert.equal(
      await fixture.authority.resolveGovernedDatasetScopeBinding({
        tenantId: "tenant-a",
        sourceContract: source,
        deliveryId: registration.deliveryId
      }),
      undefined
    );
    assert.equal(
      await fixture.authority.resolveTrustedDeliveryForExtraction({
        tenantId: "tenant-a",
        deliveryId: registration.deliveryId,
        sourceContract: source,
        scopeBinding: binding
      }),
      undefined
    );

    const registrationReplay = fixture.authority.register(actor("tenant-a"), registration);
    assert.equal(registrationReplay.replayed, true);
    assert.equal(registrationReplay.resolution.delivery.status, "usable");
    assert.equal(registrationReplay.resolution.delivery.deliveryRevision, 1);
    const disableReplay = fixture.authority.disable(actor("tenant-a"), {
      deliveryId: registration.deliveryId,
      reasonCode: "source_retracted",
      idempotencyKey: "disable-delivery"
    });
    assert.equal(disableReplay.replayed, true);
    assert.equal(disableReplay.resolution.delivery.deliveryRevision, 2);
    assert.throws(
      () =>
        fixture.authority.disable(actor("tenant-a"), {
          deliveryId: registration.deliveryId,
          reasonCode: "second_disable",
          idempotencyKey: "disable-again"
        }),
      (error: unknown) => authorityError(error, "DELIVERY_DISABLED")
    );

    const events = fixture.authority.listAudit("tenant-a");
    assert.equal(events.length, 2);
    assert.equal(events[1]?.previousEventHash, events[0]?.eventHash);
    assert.equal(events[1]?.occurredAt, "2026-08-02T01:00:00.000Z");
  } finally {
    fixture.cleanup();
  }
});

test("exact source-contract and scope-binding revisions remain immutable while only the latest active revision resolves", async () => {
  const fixture = authorityFixture();
  try {
    const sourceV1 = sourceContract("tenant-a", "postgresql", "active", 1);
    const bindingV1 = scopeBinding(sourceV1);
    const registrationV1 = registerInput(sourceV1, bindingV1, postgresqlLocator(sourceV1));
    fixture.authority.register(actor("tenant-a"), registrationV1);

    const sourceV2 = sourceContract("tenant-a", "postgresql", "active", 2);
    const bindingV2 = scopeBinding(sourceV2);
    const registrationV2 = {
      ...registerInput(sourceV2, bindingV2, postgresqlLocator(sourceV2)),
      deliveryId: "delivery-2026-09",
      idempotencyKey: "register-delivery-v2",
      sourceObservedAt: "2026-09-01T23:55:00.000Z",
      receivedAt: "2026-09-02T00:00:00.000Z"
    };
    fixture.setNow("2026-09-02T00:05:00.000Z");
    fixture.authority.register(actor("tenant-a"), registrationV2);

    const active = await fixture.authority.resolveActivatedSourceContract({
      tenantId: "tenant-a",
      sourceContractId: sourceV1.sourceContractId
    });
    assert.equal(active?.revision, 2);
    assert.equal(
      await fixture.authority.resolveGovernedDatasetScopeBinding({
        tenantId: "tenant-a",
        sourceContract: sourceV1,
        deliveryId: registrationV1.deliveryId
      }),
      undefined
    );
    assert.equal(
      (await fixture.authority.resolveGovernedDatasetScopeBinding({
        tenantId: "tenant-a",
        sourceContract: sourceV2,
        deliveryId: registrationV2.deliveryId
      }))?.revision,
      2
    );

    fixture.authority.close();
    const reopened = new SqliteSourceDeliveryAuthorityV1(fixture.databasePath, {
      clock: () => new Date("2026-09-02T00:05:00.000Z")
    });
    assert.equal(
      (await reopened.resolveDeliveryStatus({ tenantId: "tenant-a", deliveryId: registrationV1.deliveryId }))
        ?.sourceContract.revision,
      1
    );
    assert.equal(
      (await reopened.resolveDeliveryStatus({ tenantId: "tenant-a", deliveryId: registrationV2.deliveryId }))
        ?.sourceContract.revision,
      2
    );
    reopened.close();
  } finally {
    fixture.cleanup();
  }
});

test("registration requires executable exact effective governance and matching immutable locators", () => {
  const cases: readonly {
    readonly label: string;
    readonly build: () => RegisterGovernedSourceDeliveryV1;
  }[] = [
    {
      label: "proposed source",
      build: () => {
        const active = sourceContract("tenant-a", "postgresql", "active");
        const { sourceContractHash: _sourceContractHash, ...body } = active;
        const { approvedBy: _approvedBy, approvedAt: _approvedAt, ...proposedBody } = body;
        const source = createSourceContractV1({
          ...proposedBody,
          status: "proposed"
        });
        return registerInput(source, scopeBinding(source), postgresqlLocator(source));
      }
    },
    {
      label: "substituted binding source hash",
      build: () => {
        const source = sourceContract("tenant-a", "postgresql");
        const binding = createGovernedDatasetScopeBindingV1({
          ...scopeBindingBody(source),
          sourceContract: { ...scopeBindingBody(source).sourceContract, sourceContractHash: hash("wrong-source") }
        });
        return registerInput(source, binding, postgresqlLocator(source));
      }
    },
    {
      label: "object key outside pattern",
      build: () => {
        const source = sourceContract("tenant-a", "object_xlsx");
        const locator = objectLocator(source, "other/outside.xlsx");
        return registerInput(source, scopeBinding(source), locator);
      }
    },
    {
      label: "object version hash substitution",
      build: () => {
        const source = sourceContract("tenant-a", "object_xlsx");
        return registerInput(source, scopeBinding(source), {
          ...objectLocator(source),
          immutableVersionHash: hash("wrong-version")
        });
      }
    },
    {
      label: "managed upload is outside modern capture",
      build: () => {
        const source = sourceContract("tenant-a", "object_xlsx");
        return {
          ...registerInput(source, scopeBinding(source), objectLocator(source)),
          locator: {
            mode: "managed_upload",
            format: "xlsx",
            managedObjectId: "upload-1",
            immutableVersionId: "version-1",
            immutableVersionHash: hash("version-1"),
            contentHash: hash("content"),
            byteCount: 10
          } as never
        };
      }
    }
  ];

  for (const entry of cases) {
    const fixture = authorityFixture();
    try {
      assert.throws(
        () => fixture.authority.register(actor("tenant-a"), entry.build()),
        (error: unknown) => authorityError(error, "INVALID_ARGUMENT"),
        entry.label
      );
    } finally {
      fixture.cleanup();
    }
  }
});

test("chronology and effectivity fail closed, including tenant audit clock rollback", () => {
  const source = sourceContract("tenant-a", "postgresql");
  const binding = scopeBinding(source);
  const locator = postgresqlLocator(source);

  for (const registration of [
    { ...registerInput(source, binding, locator), sourceObservedAt: "2026-08-02T00:01:00.000Z" },
    { ...registerInput(source, binding, locator), receivedAt: "2026-08-02T00:06:00.000Z" },
    {
      ...registerInput(source, binding, locator),
      sourceObservedAt: "2025-12-31T23:59:59.000Z",
      receivedAt: "2026-01-01T00:00:00.000Z"
    }
  ]) {
    const fixture = authorityFixture();
    try {
      assert.throws(
        () => fixture.authority.register(actor("tenant-a"), registration),
        (error: unknown) => authorityError(error, "INVALID_ARGUMENT")
      );
    } finally {
      fixture.cleanup();
    }
  }

  const fixture = authorityFixture();
  try {
    const registration = registerInput(source, binding, locator);
    fixture.authority.register(actor("tenant-a"), registration);
    fixture.setNow("2026-08-02T00:04:59.000Z");
    assert.throws(
      () =>
        fixture.authority.disable(actor("tenant-a"), {
          deliveryId: registration.deliveryId,
          reasonCode: "clock_test",
          idempotencyKey: "disable-clock-test"
        }),
      (error: unknown) => authorityError(error, "CLOCK_ROLLBACK")
    );
  } finally {
    fixture.cleanup();
  }
});

test("immutable triggers reject mutation and reopen verifies delivery, audit, and idempotency tampering", () => {
  const triggerCases = [
    {
      name: "delivery",
      drop: "DROP TRIGGER source_delivery_authority_records_v1_no_update",
      tamper: "UPDATE source_delivery_authority_records_v1 SET dataset_id = 'tampered'",
      recreate: `CREATE TRIGGER source_delivery_authority_records_v1_no_update
        BEFORE UPDATE ON source_delivery_authority_records_v1
        BEGIN SELECT RAISE(ABORT, 'source delivery records are immutable'); END;`
    },
    {
      name: "audit",
      drop: "DROP TRIGGER source_delivery_authority_audit_v1_no_update",
      tamper: "UPDATE source_delivery_authority_audit_v1 SET actor_id = 'attacker'",
      recreate: `CREATE TRIGGER source_delivery_authority_audit_v1_no_update
        BEFORE UPDATE ON source_delivery_authority_audit_v1
        BEGIN SELECT RAISE(ABORT, 'source-delivery audit events are immutable'); END;`
    },
    {
      name: "idempotency",
      drop: "DROP TRIGGER source_delivery_authority_idempotency_v1_no_update",
      tamper: "UPDATE source_delivery_authority_idempotency_v1 SET idempotency_key = 'attacker-key'",
      recreate: `CREATE TRIGGER source_delivery_authority_idempotency_v1_no_update
        BEFORE UPDATE ON source_delivery_authority_idempotency_v1
        BEGIN SELECT RAISE(ABORT, 'source-delivery idempotency receipts are immutable'); END;`
    }
  ] as const;

  for (const entry of triggerCases) {
    const fixture = authorityFixture(entry.name);
    try {
      const source = sourceContract("tenant-a", "postgresql");
      fixture.authority.register(
        actor("tenant-a"),
        registerInput(source, scopeBinding(source), postgresqlLocator(source))
      );
      fixture.authority.close();
      const attacker = new DatabaseSync(fixture.databasePath, { enableForeignKeyConstraints: true });
      assert.throws(
        () => attacker.exec("UPDATE source_delivery_authority_records_v1 SET dataset_id = 'blocked'"),
        /source delivery records are immutable/
      );
      attacker.exec(`${entry.drop}; ${entry.tamper}; ${entry.recreate}`);
      attacker.close();
      assert.throws(
        () => new SqliteSourceDeliveryAuthorityV1(fixture.databasePath),
        (error: unknown) => authorityError(error, "INTEGRITY_FAILURE")
      );
    } finally {
      fixture.cleanup();
    }
  }
});

test("component migration refuses a newer source-delivery schema receipt", () => {
  const directory = mkdtempSync(join(tmpdir(), "source-delivery-newer-"));
  const databasePath = join(directory, "authority.sqlite");
  try {
    const database = new DatabaseSync(databasePath);
    database.exec(`
      CREATE TABLE component_schema_versions (
        component_name TEXT PRIMARY KEY CHECK (
          length(component_name) BETWEEN 1 AND 128
        ),
        schema_version INTEGER NOT NULL CHECK (schema_version > 0)
      ) STRICT;
      INSERT INTO component_schema_versions (component_name, schema_version)
      VALUES ('${SQLITE_SOURCE_DELIVERY_AUTHORITY_COMPONENT}', 2);
    `);
    database.close();
    assert.throws(
      () => new SqliteSourceDeliveryAuthorityV1(databasePath),
      (error: unknown) =>
        authorityError(error, "INTEGRITY_FAILURE") && /newer than supported/.test((error as Error).message)
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function authorityFixture(suffix = "base") {
  const directory = mkdtempSync(join(tmpdir(), `source-delivery-${suffix}-`));
  const databasePath = join(directory, "authority.sqlite");
  let now = RECORDED_AT;
  let event = 0;
  const authority = new SqliteSourceDeliveryAuthorityV1(databasePath, {
    clock: () => new Date(now),
    eventId: () => `event-${++event}`
  });
  return {
    authority,
    databasePath,
    setNow(value: string) {
      now = value;
    },
    cleanup() {
      authority.close();
      rmSync(directory, { recursive: true, force: true });
    }
  };
}

function actor(tenantId: string): TrustedSourceDeliveryActorV1 {
  return {
    tenantId,
    actorId: "operator-1",
    authority: "platform_operator",
    identitySource: "server_derived"
  };
}

function sourceContract(
  tenantId: string,
  kind: "postgresql" | "object_xlsx" | "object_parquet",
  status: "active" | "approved" = "active",
  revision = 1
): SourceContractV1 {
  const delivery = kind === "postgresql"
    ? {
        mode: "postgresql_pull" as const,
        connectorId: "postgres-primary",
        credentialRef: "kms/postgres/readonly",
        catalog: "risk",
        schema: "servicing",
        relation: "loan_tape"
      }
    : {
        mode: "object_storage" as const,
        format: kind === "object_xlsx" ? "xlsx" as const : "parquet" as const,
        connectorId: "object-primary",
        credentialRef: "kms/object/readonly",
        bucket: "loan-tapes",
        keyPattern: kind === "object_xlsx" ? "synthetic-auto/*.xlsx" : "synthetic-auto/*.parquet",
        immutableVersionRequired: true as const
      };
  const parserPolicy = kind === "postgresql"
    ? {
        format: "sql_rows" as const,
        parserId: "postgres-exact-v1",
        parserVersion: "1.0.0",
        optionsHash: hash("parser-options"),
        exactDecimalMode: "string" as const,
        timezone: "UTC" as const
      }
    : kind === "object_xlsx"
      ? {
          format: "xlsx" as const,
          parserId: "xlsx-safe-v1",
          parserVersion: "1.0.0",
          optionsHash: hash("parser-options"),
          rejectMacros: true as const,
          rejectExternalLinks: true as const,
          rejectFormulaCells: true as const,
          dateSystem: "reject_mixed" as const,
          exactDecimalMode: "string" as const
        }
      : {
          format: "parquet" as const,
          parserId: "parquet-safe-v1",
          parserVersion: "1.0.0",
          optionsHash: hash("parser-options"),
          exactDecimalMode: "string" as const,
          timezone: "UTC" as const,
          rejectSchemaMerging: true
        };
  return createSourceContractV1({
    contractVersion: 1,
    tenantId,
    sourceContractId: "loan-tape-source",
    sourceKey: "loan-tape",
    revision,
    status,
    delivery,
    schemaPolicy: {
      columns: [
        { sourceName: "assetNumber", ordinal: 0, nativeType: "text", nullable: false, required: true },
        { sourceName: "actualEndBalance", ordinal: 1, nativeType: "decimal", nullable: false, required: true }
      ],
      allowUnknownColumns: false,
      requireStableOrdinals: true
    },
    parserPolicy,
    extractionPolicy: {
      mode: "full",
      readOnly: true,
      maximumRows: 100_000,
      maximumColumns: 100,
      maximumBytes: 1_000_000_000,
      timeoutMs: 30_000,
      cursorRows: 5_000
    },
    sections: [
      {
        sectionId: "loans",
        required: true,
        selector: "Loan Tape",
        keyFields: ["assetNumber"],
        minimumRows: 1
      }
    ],
    effectiveFrom: "2026-01-01",
    createdBy: "steward-1",
    createdAt: "2026-01-02T00:00:00.000Z",
    approvedBy: "reviewer-1",
    approvedAt: "2026-01-03T00:00:00.000Z"
  });
}

function scopeBindingBody(source: SourceContractV1) {
  return {
    contractVersion: 1 as const,
    tenantId: source.tenantId,
    bindingId: "loan-tape-facility-binding",
    revision: source.revision,
    datasetId: "dataset-loans",
    sourceContract: {
      sourceContractId: source.sourceContractId,
      revision: source.revision,
      sourceContractHash: source.sourceContractHash
    },
    scope: { scopeType: "facility" as const, scopeId: "facility-auto-1" },
    effectiveFrom: "2026-01-01"
  };
}

function scopeBinding(source: SourceContractV1): GovernedDatasetScopeBindingV1 {
  return createGovernedDatasetScopeBindingV1(scopeBindingBody(source));
}

function postgresqlLocator(source: SourceContractV1): GovernedSourceDeliveryLocatorV1 {
  assert.equal(source.delivery.mode, "postgresql_pull");
  return {
    mode: "postgresql_pull",
    connectorId: source.delivery.connectorId,
    catalog: source.delivery.catalog,
    schema: source.delivery.schema,
    relation: source.delivery.relation,
    relationIdentityHash: canonicalHash({
      connectorId: source.delivery.connectorId,
      catalog: source.delivery.catalog ?? null,
      schema: source.delivery.schema,
      relation: source.delivery.relation
    }),
    sourceVersionHash: hash(`postgres-repeatable-read-version:${source.revision}`)
  };
}

function objectLocator(
  source: SourceContractV1,
  objectKey = "synthetic-auto/reference-2021-10.xlsx"
): GovernedSourceDeliveryLocatorV1 {
  assert.equal(source.delivery.mode, "object_storage");
  const immutableVersionId = "s3-version-0001";
  return {
    mode: "object_storage",
    format: source.delivery.format,
    connectorId: source.delivery.connectorId,
    bucket: source.delivery.bucket,
    objectKey,
    immutableVersionId,
    immutableVersionHash: canonicalHash({
      connectorId: source.delivery.connectorId,
      bucket: source.delivery.bucket,
      objectKey,
      immutableVersionId
    }),
    contentHash: hash("object-content"),
    byteCount: 42_000
  };
}

function registerInput(
  source: SourceContractV1,
  binding: GovernedDatasetScopeBindingV1,
  locator: GovernedSourceDeliveryLocatorV1
): RegisterGovernedSourceDeliveryV1 {
  return {
    deliveryId: "delivery-2026-08",
    sourceContract: source,
    scopeBinding: binding,
    locator,
    sourceObservedAt: OBSERVED_AT,
    receivedAt: RECEIVED_AT,
    idempotencyKey: "register-delivery"
  };
}

function hash(label: string) {
  return canonicalHash({ label });
}

function resolvedDefinition(
  definitionVersionId: string,
  kind: "source_contract" | "dataset_scope_binding",
  definitionKey: string,
  executionDocument: unknown
): ResolvedGovernedDefinitionV2 {
  return {
    reference: {
      definitionVersionId,
      definitionKey,
      kind,
      semanticVersion: "1.0.0",
      versionHash: hash(`${definitionVersionId}-version`),
      documentHash: hash(`${definitionVersionId}-document`),
      approvalEventHash: hash(`${definitionVersionId}-approval`)
    },
    approvalEvidence: {
      status: "approved",
      proposedBy: "maker-1",
      approvedBy: "checker-1",
      approvedAt: "2026-07-31T00:00:00.000Z",
      approvalEventHash: hash(`${definitionVersionId}-approval`)
    },
    executionDocument: executionDocument as never
  };
}

function modernSnapshotId(deliveryId: string): string {
  return `snapshot-${canonicalHash({
    contractVersion: 1,
    tenantId: "tenant-a",
    sourceContractId: "loan-tape-source",
    deliveryId
  }).slice("sha256:".length, "sha256:".length + 32)}`;
}

function authorityError(error: unknown, code: SourceDeliveryAuthorityError["code"]): boolean {
  assert.ok(error instanceof SourceDeliveryAuthorityError);
  assert.equal(error.code, code);
  return true;
}

function registrationError(
  error: unknown,
  code: GovernedSourceDeliveryRegistrationError["code"]
): boolean {
  assert.ok(error instanceof GovernedSourceDeliveryRegistrationError);
  assert.equal(error.code, code);
  return true;
}
