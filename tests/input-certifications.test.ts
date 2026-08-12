import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, test } from "node:test";

import { MonitoringAlertStore } from "../src/control/alerts.js";
import { DefinitionStore } from "../src/control/definitions.js";
import {
  INPUT_CERTIFICATION_STORE_COMPONENT,
  INPUT_CERTIFICATION_STORE_SCHEMA_VERSION,
  InputCertificationStore,
  InputCertificationStoreError,
  type CertifyInputCertificationInput,
  type ProposeInputCertificationInput
} from "../src/control/input-certifications.js";
import { ControlStore } from "../src/control/store.js";
import { canonicalHash } from "../src/contracts/canonical.js";

const temporaryDirectories: string[] = [];
const FIXED_TIME = "2026-08-12T12:00:00.000Z";

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("input certification is durable, tenant-scoped, immutable, and exactly idempotent", () => {
  const databasePath = temporaryDatabasePath("input-certifications.sqlite");
  const store = new InputCertificationStore(databasePath, { clock: fixedClock });
  const proposalInput = proposalFixture();

  const proposed = store.propose(proposalInput);
  assert.deepEqual(store.propose(proposalInput), proposed);
  assert.equal(proposed.status, "proposed");
  assert.equal(proposed.primaryCertificationManifestId, proposalInput.primaryCertificationManifestId);
  assert.deepEqual(
    proposed.definitionReferences.map((reference) => reference.definitionId),
    ["bbc-methodology", "eligibility-policy"]
  );
  assert.match(proposed.proposalHash, /^sha256:[a-f0-9]{64}$/);
  assert.equal(store.get("tenant-b", proposed.inputId), undefined);
  assert.equal(store.listAuditEvents("tenant-a").length, 1, "an exact replay cannot duplicate audit evidence");

  assert.throws(
    () =>
      store.propose({
        ...proposalInput,
        rowCount: 4,
        declaredControls: { ...proposalInput.declaredControls, rowCount: 4 }
      }),
    (error: unknown) => storeError(error, "IDEMPOTENCY_CONFLICT")
  );

  const certificationInput = certificationFixture(proposed.payloadHash);
  assert.throws(
    () => store.certify({ ...certificationInput, certifiedBy: proposed.proposedBy }),
    (error: unknown) => storeError(error, "MAKER_CHECKER_VIOLATION")
  );
  const certified = store.certify(certificationInput);
  assert.deepEqual(store.certify(certificationInput), certified);
  assert.equal(certified.status, "certified");
  assert.equal(certified.proposalHash, proposed.proposalHash);
  assert.equal(certified.sidecarPopulationHash, proposed.payloadHash);
  assert.equal(certified.certifiedAt, FIXED_TIME);
  assert.equal(store.listAuditEvents("tenant-a").length, 2);
  assert.deepEqual(store.get("tenant-a", proposed.inputId), certified);
  store.close();

  const reopened = new InputCertificationStore(databasePath, { clock: fixedClock });
  assert.deepEqual(reopened.get("tenant-a", proposed.inputId), certified);
  assert.deepEqual(reopened.list("tenant-a"), [certified]);
  reopened.close();

  const database = new DatabaseSync(databasePath, { enableForeignKeyConstraints: true });
  const version = database
    .prepare("SELECT schema_version FROM component_schema_versions WHERE component_name = ?")
    .get(INPUT_CERTIFICATION_STORE_COMPONENT) as unknown as { readonly schema_version: number };
  assert.equal(version.schema_version, INPUT_CERTIFICATION_STORE_SCHEMA_VERSION);
  assert.throws(
    () =>
      database
        .prepare("UPDATE input_certification_proposals SET row_count = 99 WHERE tenant_id = ? AND input_id = ?")
        .run("tenant-a", proposed.inputId),
    /input certification proposals are immutable/
  );
  assert.throws(
    () =>
      database
        .prepare("DELETE FROM input_certifications WHERE tenant_id = ? AND input_id = ?")
        .run("tenant-a", proposed.inputId),
    /input certifications are immutable/
  );
  assert.throws(
    () => database.prepare("DELETE FROM input_certification_audit_events WHERE tenant_id = ?").run("tenant-a"),
    /input certification audit is append-only/
  );
  database.close();
});

test("certification rejects wrong artifact kinds, population drift, and maker/checker bypass atomically", () => {
  const store = new InputCertificationStore(":memory:", { clock: fixedClock });
  const proposed = store.propose(proposalFixture());
  const certification = certificationFixture(proposed.payloadHash);

  assert.throws(
    () => store.certify({ ...certification, certifiedArtifactKind: "certified_monitoring_input" }),
    (error: unknown) => storeError(error, "INVALID_INPUT")
  );
  assert.throws(
    () => store.certify({ ...certification, sidecarPopulationHash: canonicalHash("drifted population") }),
    (error: unknown) => storeError(error, "INVALID_INPUT")
  );
  assert.equal(store.get(proposed.tenantId, proposed.inputId)?.status, "proposed");
  assert.equal(store.listAuditEvents(proposed.tenantId).length, 1);

  const certified = store.certify(certification);
  assert.throws(
    () => store.certify({ ...certification, certifiedArtifactHash: canonicalHash("replacement"), idempotencyKey: "replace" }),
    (error: unknown) => storeError(error, "ILLEGAL_TRANSITION")
  );
  assert.deepEqual(store.get(certified.tenantId, certified.inputId), certified);
  store.close();
});

test("input-certification schema attestation coexists with shared audit components", () => {
  const databasePath = temporaryDatabasePath("shared.sqlite");
  new ControlStore(databasePath).close();
  new MonitoringAlertStore(databasePath).close();
  new DefinitionStore(databasePath).close();
  new InputCertificationStore(databasePath).close();
  new InputCertificationStore(databasePath).close();

  const database = new DatabaseSync(databasePath);
  const components = database
    .prepare("SELECT component_name FROM component_schema_versions ORDER BY component_name")
    .all() as unknown as readonly { readonly component_name: string }[];
  assert.equal(components.some((row) => row.component_name === INPUT_CERTIFICATION_STORE_COMPONENT), true);
  assert.equal(tableExists(database, "audit_events"), true, "control and alert stores share their audit table");
  assert.equal(tableExists(database, "input_certification_audit_events"), true);
  database.exec("DROP INDEX input_certification_audit_tenant_sequence");
  database.close();

  assert.throws(() => new InputCertificationStore(databasePath), /failed attestation/);
});

test("a newer input-certification component version is rejected before domain DDL", () => {
  const databasePath = temporaryDatabasePath("newer.sqlite");
  const seed = new InputCertificationStore(databasePath);
  seed.close();
  const database = new DatabaseSync(databasePath);
  database
    .prepare("UPDATE component_schema_versions SET schema_version = ? WHERE component_name = ?")
    .run(INPUT_CERTIFICATION_STORE_SCHEMA_VERSION + 1, INPUT_CERTIFICATION_STORE_COMPONENT);
  database.close();

  assert.throws(
    () => new InputCertificationStore(databasePath),
    (error: unknown) => storeError(error, "CONFLICT") && /newer than supported/.test(String(error))
  );
});

function proposalFixture(): ProposeInputCertificationInput {
  const payloadHash = canonicalHash({ availability: "920.25", facilityId: "facility-1", rowCount: 3 });
  return {
    tenantId: "tenant-a",
    inputId: "sidecar-certification-1",
    inputKind: "borrowing_base",
    candidateArtifactId: "candidate-artifact-1",
    candidateArtifactHash: canonicalHash("candidate artifact"),
    candidateArtifactKind: "borrowing_base_input",
    snapshotId: "snapshot-1",
    asOfDate: "2026-08-11",
    purpose: "certify borrowing-base sidecar for governed analysis",
    primaryCertificationManifestId: "analysis-manifest-1",
    definitionReferences: [
      {
        definitionId: "eligibility-policy",
        version: "2",
        definitionHash: canonicalHash("eligibility-policy-v2")
      },
      {
        definitionId: "bbc-methodology",
        version: "1",
        definitionHash: canonicalHash("bbc-methodology-v1")
      }
    ],
    declaredControls: { rowCount: 3, balance: "1000.25", currency: "USD" },
    payloadHash,
    fieldSetHash: canonicalHash(["availability", "facilityId", "rowCount"]),
    rowCount: 3,
    proposedBy: "maker",
    idempotencyKey: "propose-sidecar-1"
  };
}

function certificationFixture(sidecarPopulationHash: CertifyInputCertificationInput["sidecarPopulationHash"]): CertifyInputCertificationInput {
  return {
    tenantId: "tenant-a",
    inputId: "sidecar-certification-1",
    certifiedArtifactId: "certified-artifact-1",
    certifiedArtifactHash: canonicalHash("certified artifact"),
    certifiedArtifactKind: "certified_borrowing_base_input",
    lineageHash: canonicalHash("lineage"),
    envelopeHash: canonicalHash("envelope"),
    derivationHash: canonicalHash("derivation"),
    primaryCertificationHash: canonicalHash("primary certification"),
    primaryPopulationHash: canonicalHash("primary population"),
    sidecarCertificationHash: canonicalHash("sidecar certification"),
    sidecarPopulationHash,
    dataQualityRunId: "sidecar-dq-1",
    dataQualityResultHash: canonicalHash("sidecar dq result"),
    reconciliationId: "sidecar-reconciliation-1",
    reconciliationResultHash: canonicalHash("sidecar reconciliation result"),
    certifiedBy: "checker",
    idempotencyKey: "certify-sidecar-1"
  };
}

function temporaryDatabasePath(name: string): string {
  const directory = mkdtempSync(join(tmpdir(), "abl-input-certifications-"));
  temporaryDirectories.push(directory);
  return join(directory, name);
}

function fixedClock(): Date {
  return new Date(FIXED_TIME);
}

function storeError(error: unknown, code: InputCertificationStoreError["code"]): boolean {
  return error instanceof InputCertificationStoreError && error.code === code;
}

function tableExists(database: DatabaseSync, table: string): boolean {
  return database.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(table) !== undefined;
}
