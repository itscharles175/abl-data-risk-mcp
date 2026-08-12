import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, test } from "node:test";

import {
  ALERT_STORE_COMPONENT,
  ALERT_STORE_SCHEMA_VERSION,
  MonitoringAlertStore,
  MonitoringAlertStoreError
} from "../src/control/alerts.js";
import {
  DEFINITION_STORE_COMPONENT,
  DEFINITION_STORE_SCHEMA_VERSION,
  DefinitionStore,
  DefinitionStoreError
} from "../src/control/definitions.js";
import {
  JOB_STORE_COMPONENT,
  JOB_STORE_SCHEMA_VERSION,
  JobStore,
  JobStoreError
} from "../src/control/jobs.js";
import {
  CONTROL_STORE_COMPONENT,
  CONTROL_STORE_SCHEMA_VERSION,
  ControlStore,
  ControlStoreError
} from "../src/control/store.js";
import {
  migrateSqliteComponent,
  SQLITE_COMPONENT_SCHEMA_REGISTRY
} from "../src/infrastructure/sqlite-component-schema.js";
import {
  TENANT_MEMBERSHIP_STORE_COMPONENT,
  TENANT_MEMBERSHIP_STORE_SCHEMA_VERSION,
  TenantMembershipStore,
  TenantMembershipStoreError
} from "../src/security/membership-store.js";
import {
  SECURITY_STATE_STORE_COMPONENT,
  SECURITY_STATE_STORE_SCHEMA_VERSION,
  SecurityStateStore,
  SecurityStateStoreError
} from "../src/security/state-store.js";

interface ClosableStore {
  close(): void;
}

interface ComponentCase {
  readonly componentName: string;
  readonly schemaVersion: number;
  readonly firstDomainTable: string;
  readonly open: (databasePath: string) => ClosableStore;
  readonly isUnsupportedVersion: (error: unknown) => boolean;
}

const COMPONENTS: readonly ComponentCase[] = [
  {
    componentName: CONTROL_STORE_COMPONENT,
    schemaVersion: CONTROL_STORE_SCHEMA_VERSION,
    firstDomainTable: "dataset_snapshots",
    open: (path) => new ControlStore(path),
    isUnsupportedVersion: (error) =>
      error instanceof ControlStoreError && error.code === "CONFLICT"
  },
  {
    componentName: ALERT_STORE_COMPONENT,
    schemaVersion: ALERT_STORE_SCHEMA_VERSION,
    firstDomainTable: "monitoring_runs",
    open: (path) => new MonitoringAlertStore(path),
    isUnsupportedVersion: (error) =>
      error instanceof MonitoringAlertStoreError && error.code === "UNSUPPORTED_SCHEMA"
  },
  {
    componentName: DEFINITION_STORE_COMPONENT,
    schemaVersion: DEFINITION_STORE_SCHEMA_VERSION,
    firstDomainTable: "governed_definitions",
    open: (path) => new DefinitionStore(path),
    isUnsupportedVersion: (error) =>
      error instanceof DefinitionStoreError && error.code === "CONFLICT"
  },
  {
    componentName: JOB_STORE_COMPONENT,
    schemaVersion: JOB_STORE_SCHEMA_VERSION,
    firstDomainTable: "jobs",
    open: (path) => new JobStore(path),
    isUnsupportedVersion: (error) =>
      error instanceof JobStoreError && error.code === "INVALID_INPUT"
  },
  {
    componentName: SECURITY_STATE_STORE_COMPONENT,
    schemaVersion: SECURITY_STATE_STORE_SCHEMA_VERSION,
    firstDomainTable: "consumed_plans",
    open: (path) => new SecurityStateStore(path),
    isUnsupportedVersion: (error) =>
      error instanceof SecurityStateStoreError && error.code === "INVALID_INPUT"
  },
  {
    componentName: TENANT_MEMBERSHIP_STORE_COMPONENT,
    schemaVersion: TENANT_MEMBERSHIP_STORE_SCHEMA_VERSION,
    firstDomainTable: "oauth_tenant_memberships",
    open: (path) => new TenantMembershipStore(path),
    isUnsupportedVersion: (error) =>
      error instanceof TenantMembershipStoreError && error.code === "CONFLICT"
  }
];

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("all durable stores initialize and reopen with independent component versions in one database", () => {
  const databasePath = temporaryDatabasePath("shared.sqlite");
  const seed = new DatabaseSync(databasePath);
  seed.exec("PRAGMA user_version = 73");
  seed.close();

  for (const component of COMPONENTS) component.open(databasePath).close();
  for (const component of COMPONENTS) component.open(databasePath).close();

  const database = new DatabaseSync(databasePath);
  const rows = database
    .prepare(
      `SELECT component_name, schema_version
         FROM component_schema_versions
        ORDER BY component_name`
    )
    .all() as unknown as readonly {
    readonly component_name: string;
    readonly schema_version: number;
  }[];
  assert.deepEqual(
    rows.map((row) => ({
      component_name: row.component_name,
      schema_version: row.schema_version
    })),
    COMPONENTS.map((component) => ({
      component_name: component.componentName,
      schema_version: component.schemaVersion
    })).sort((left, right) => left.component_name.localeCompare(right.component_name))
  );
  const pragma = database.prepare("PRAGMA user_version").get() as unknown as {
    readonly user_version: number;
  };
  assert.equal(pragma.user_version, 73, "component migrations must not claim database-global user_version");
  assert.equal(
    tableExists(database, "monitoring_store_metadata"),
    false,
    "the retired singleton metadata table must not be created in a fresh database"
  );
  database.close();
});

for (const component of COMPONENTS) {
  test(`${component.componentName} rejects a newer component schema before creating domain tables`, () => {
    const databasePath = temporaryDatabasePath(`${component.componentName}.sqlite`);
    const database = new DatabaseSync(databasePath);
    createCanonicalRegistry(database);
    database
      .prepare(
        "INSERT INTO component_schema_versions (component_name, schema_version) VALUES (?, ?)"
      )
      .run(component.componentName, component.schemaVersion + 1);
    database.close();

    assert.throws(
      () => component.open(databasePath),
      (error: unknown) => component.isUnsupportedVersion(error) && /newer than supported/.test(String(error))
    );

    const inspected = new DatabaseSync(databasePath);
    assert.equal(tableExists(inspected, component.firstDomainTable), false);
    const version = inspected
      .prepare(
        "SELECT schema_version FROM component_schema_versions WHERE component_name = ?"
      )
      .get(component.componentName) as unknown as { readonly schema_version: number };
    assert.equal(version.schema_version, component.schemaVersion + 1);
    inspected.close();
  });
}

for (const component of COMPONENTS) {
  test(`${component.componentName} rejects unreceipted pre-existing component objects transactionally`, () => {
    const databasePath = temporaryDatabasePath(`${component.componentName}-unreceipted.sqlite`);
    const database = new DatabaseSync(databasePath);
    database.exec(`CREATE TABLE ${component.firstDomainTable} (attacker_marker TEXT) STRICT;`);
    database.close();

    assert.throws(
      () => component.open(databasePath),
      /unreceipted pre-existing object/
    );

    const inspected = new DatabaseSync(databasePath);
    assert.equal(tableExists(inspected, SQLITE_COMPONENT_SCHEMA_REGISTRY), false);
    assert.equal(tableExists(inspected, component.firstDomainTable), true);
    inspected.close();
  });

  test(`${component.componentName} attests registered schema objects on every open`, () => {
    const databasePath = temporaryDatabasePath(`${component.componentName}-tampered.sqlite`);
    component.open(databasePath).close();
    const database = new DatabaseSync(databasePath);
    database.exec(`DROP TABLE ${component.firstDomainTable};`);
    database.close();

    assert.throws(
      () => component.open(databasePath),
      /failed attestation/
    );

    const inspected = new DatabaseSync(databasePath);
    const version = inspected
      .prepare("SELECT schema_version FROM component_schema_versions WHERE component_name = ?")
      .get(component.componentName) as unknown as { readonly schema_version: number };
    assert.equal(version.schema_version, component.schemaVersion);
    assert.equal(tableExists(inspected, component.firstDomainTable), false);
    inspected.close();
  });
}

test("component initialization rolls back both partial DDL and its version receipt", () => {
  const databasePath = temporaryDatabasePath("rollback.sqlite");
  const database = new DatabaseSync(databasePath);

  assert.throws(
    () =>
      migrateSqliteComponent(database, {
        componentName: "abl.rollback-test",
        supportedVersion: 1,
        migrations: [
          {
            version: 1,
            sql: "CREATE TABLE partial_component_state (id INTEGER PRIMARY KEY) STRICT; SELECT * FROM missing_table;"
          }
        ],
        unsupportedVersionError: () => new Error("unsupported")
      }),
    /no such table/
  );
  assert.equal(tableExists(database, "partial_component_state"), false);
  assert.equal(tableExists(database, SQLITE_COMPONENT_SCHEMA_REGISTRY), false);
  database.close();
});

test("fully attested legacy monitoring schema is adopted without replaying v1 DDL", () => {
  const databasePath = temporaryDatabasePath("legacy-alert-canonical.sqlite");
  new MonitoringAlertStore(databasePath).close();
  const database = new DatabaseSync(databasePath);
  database
    .prepare("DELETE FROM component_schema_versions WHERE component_name = ?")
    .run(ALERT_STORE_COMPONENT);
  database.exec(`
    CREATE TABLE monitoring_store_metadata (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      schema_version INTEGER NOT NULL CHECK (schema_version > 0)
    ) STRICT;
    INSERT INTO monitoring_store_metadata (singleton, schema_version) VALUES (1, 1);
  `);
  database.close();

  const store = new MonitoringAlertStore(databasePath);
  store.close();

  const inspected = new DatabaseSync(databasePath);
  const version = inspected
    .prepare("SELECT schema_version FROM component_schema_versions WHERE component_name = ?")
    .get(ALERT_STORE_COMPONENT) as unknown as { readonly schema_version: number };
  assert.equal(version.schema_version, ALERT_STORE_SCHEMA_VERSION);
  assert.equal(tableExists(inspected, "monitoring_runs"), true);
  inspected.close();
});

test("legacy monitoring marker cannot adopt a weak component schema", () => {
  const databasePath = temporaryDatabasePath("legacy-alert-weak.sqlite");
  const database = new DatabaseSync(databasePath);
  database.exec(`
    CREATE TABLE monitoring_store_metadata (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      schema_version INTEGER NOT NULL CHECK (schema_version > 0)
    ) STRICT;
    INSERT INTO monitoring_store_metadata (singleton, schema_version) VALUES (1, 1);
    CREATE TABLE monitoring_runs (legacy_marker TEXT PRIMARY KEY) STRICT;
  `);
  database.close();

  assert.throws(
    () => new MonitoringAlertStore(databasePath),
    /failed attestation/
  );

  const inspected = new DatabaseSync(databasePath);
  assert.equal(tableExists(inspected, SQLITE_COMPONENT_SCHEMA_REGISTRY), false);
  assert.deepEqual(
    (inspected.prepare("PRAGMA table_info(monitoring_runs)").all() as unknown as readonly { readonly name: string }[])
      .map((column) => column.name),
    ["legacy_marker"]
  );
  inspected.close();
});

test("a weak component registry cannot authorize a job schema version", () => {
  const databasePath = temporaryDatabasePath("weak-registry.sqlite");
  const database = new DatabaseSync(databasePath);
  database.exec(`
    CREATE TABLE component_schema_versions (
      component_name TEXT PRIMARY KEY,
      schema_version INTEGER NOT NULL
    );
    INSERT INTO component_schema_versions (component_name, schema_version)
    VALUES ('${JOB_STORE_COMPONENT}', ${JOB_STORE_SCHEMA_VERSION});
  `);
  database.close();

  assert.throws(() => new JobStore(databasePath), /registry is not canonical/);
  const inspected = new DatabaseSync(databasePath);
  assert.equal(tableExists(inspected, "jobs"), false);
  inspected.close();
});

test("a registry trigger cannot inject job state during component receipt insertion", () => {
  const databasePath = temporaryDatabasePath("registry-job-injection.sqlite");
  const database = new DatabaseSync(databasePath);
  createCanonicalRegistry(database);
  database.exec(`
    CREATE TRIGGER inject_job_from_registry
    AFTER INSERT ON "COMPONENT_SCHEMA_VERSIONS"
    WHEN NEW.component_name = '${JOB_STORE_COMPONENT}'
    BEGIN
      INSERT INTO jobs (
        tenant_id, job_id, tool_name, dataset_id, request_hash, request_json,
        requested_by, status, attempt_count, max_attempts, created_at,
        updated_at, available_at, claimed_by, claim_token_hash,
        lease_expires_at, cancellation_requested, result_handle, error_code
      ) VALUES (
        'attacker-tenant', 'injected-job', 'injected-tool', NULL, 'attacker-hash', '{}',
        'attacker', 'queued', 0, 1, '2026-08-11T00:00:00.000Z',
        '2026-08-11T00:00:00.000Z', '2026-08-11T00:00:00.000Z', NULL, NULL,
        NULL, 0, NULL, NULL
      );
    END;
  `);
  database.close();

  assert.throws(() => new JobStore(databasePath), /registry is not canonical/);
  const inspected = new DatabaseSync(databasePath);
  assert.equal(tableExists(inspected, "jobs"), false);
  const receipt = inspected
    .prepare("SELECT 1 AS present FROM component_schema_versions WHERE component_name = ?")
    .get(JOB_STORE_COMPONENT) as { readonly present: number } | undefined;
  assert.equal(receipt, undefined);
  inspected.close();
});

test("a registry RAISE(IGNORE) trigger cannot suppress component receipts", () => {
  const databasePath = temporaryDatabasePath("registry-ignore-receipt.sqlite");
  const database = new DatabaseSync(databasePath);
  createCanonicalRegistry(database);
  database.exec(`
    CREATE TRIGGER suppress_job_receipt
    BEFORE INSERT ON component_schema_versions
    WHEN NEW.component_name = '${JOB_STORE_COMPONENT}'
    BEGIN
      SELECT RAISE(IGNORE);
    END;
  `);
  database.close();

  assert.throws(() => new JobStore(databasePath), /registry is not canonical/);
  const inspected = new DatabaseSync(databasePath);
  assert.equal(tableExists(inspected, "jobs"), false);
  const receipt = inspected
    .prepare("SELECT 1 AS present FROM component_schema_versions WHERE component_name = ?")
    .get(JOB_STORE_COMPONENT) as { readonly present: number } | undefined;
  assert.equal(receipt, undefined);
  inspected.close();
});

test("an explicit index attached to the component registry is rejected", () => {
  const databasePath = temporaryDatabasePath("registry-explicit-index.sqlite");
  const database = new DatabaseSync(databasePath);
  createCanonicalRegistry(database);
  database.exec(`
    CREATE INDEX registry_version_lookup
      ON "COMPONENT_SCHEMA_VERSIONS" (schema_version);
  `);
  database.close();

  assert.throws(() => new JobStore(databasePath), /registry is not canonical/);
  const inspected = new DatabaseSync(databasePath);
  assert.equal(tableExists(inspected, "jobs"), false);
  inspected.close();
});

test("a registered weak jobs table cannot suppress v1 DDL", () => {
  const databasePath = temporaryDatabasePath("weak-jobs.sqlite");
  const database = new DatabaseSync(databasePath);
  createCanonicalRegistry(database);
  database
    .prepare("INSERT INTO component_schema_versions (component_name, schema_version) VALUES (?, ?)")
    .run(JOB_STORE_COMPONENT, JOB_STORE_SCHEMA_VERSION);
  database.exec(`
    CREATE TABLE jobs (tenant_id TEXT, job_id TEXT) STRICT;
    CREATE TRIGGER jobs_no_delete BEFORE DELETE ON jobs BEGIN SELECT 1; END;
  `);
  database.close();

  assert.throws(() => new JobStore(databasePath), /failed attestation/);
  const inspected = new DatabaseSync(databasePath);
  assert.equal(tableExists(inspected, "job_idempotency"), false);
  assert.deepEqual(
    (inspected.prepare("PRAGMA table_info(jobs)").all() as unknown as readonly { readonly name: string }[])
      .map((column) => column.name),
    ["tenant_id", "job_id"]
  );
  inspected.close();
});

test("registered job triggers are attested on every reopen", () => {
  const databasePath = temporaryDatabasePath("weak-job-trigger.sqlite");
  new JobStore(databasePath).close();
  const database = new DatabaseSync(databasePath);
  database.exec(`
    DROP TRIGGER jobs_no_delete;
    CREATE TRIGGER jobs_no_delete BEFORE DELETE ON jobs BEGIN SELECT 1; END;
  `);
  database.close();

  assert.throws(() => new JobStore(databasePath), /failed attestation for 'jobs_no_delete'/);
});

test("unexpected triggers attached to registered job tables are rejected", () => {
  const databasePath = temporaryDatabasePath("unexpected-job-trigger.sqlite");
  new JobStore(databasePath).close();
  const database = new DatabaseSync(databasePath);
  database.exec(`
    CREATE TRIGGER attacker_jobs_insert
    AFTER INSERT ON jobs BEGIN SELECT 1; END;
  `);
  database.close();

  assert.throws(() => new JobStore(databasePath), /unexpected trigger 'attacker_jobs_insert'/);
});

test("a registered jobs table cannot be shadowed by a same-named trigger", () => {
  const databasePath = temporaryDatabasePath("cross-type-job-name.sqlite");
  new JobStore(databasePath).close();
  const database = new DatabaseSync(databasePath);
  database.exec(`
    CREATE TRIGGER "JOBS"
    AFTER INSERT ON "JOBS" BEGIN
      UPDATE jobs SET status = 'failed' WHERE job_id = NEW.job_id;
    END;
  `);
  database.close();

  assert.throws(
    () => new JobStore(databasePath),
    /unexpected trigger 'JOBS' sharing an expected object name/
  );
});

test("central component attestation preserves duplicate cross-type identities", () => {
  const databasePath = temporaryDatabasePath("cross-type-central.sqlite");
  const options = {
    componentName: "test.cross-type",
    supportedVersion: 1,
    migrations: [{
      version: 1,
      sql: "CREATE TABLE owned_records (record_id TEXT PRIMARY KEY) STRICT;"
    }],
    unsupportedVersionError: (current: number, supported: number) =>
      new Error(`unsupported ${current} > ${supported}`)
  } as const;
  const database = new DatabaseSync(databasePath);
  migrateSqliteComponent(database, options);
  database.exec(`
    CREATE TRIGGER owned_records
    AFTER INSERT ON owned_records BEGIN SELECT 1; END;
  `);

  assert.throws(
    () => migrateSqliteComponent(database, options),
    /unexpected trigger 'owned_records' sharing an expected object name/
  );
  database.close();
});

test("unreceipted shared audit tables must match canonical cross-component DDL", () => {
  const databasePath = temporaryDatabasePath("weak-shared-audit.sqlite");
  const database = new DatabaseSync(databasePath);
  database.exec(`CREATE TABLE audit_events (sequence INTEGER PRIMARY KEY) STRICT;`);
  database.close();

  assert.throws(() => new ControlStore(databasePath), /shared object 'audit_events' is not canonical/);
  const inspected = new DatabaseSync(databasePath);
  assert.equal(tableExists(inspected, SQLITE_COMPONENT_SCHEMA_REGISTRY), false);
  assert.equal(tableExists(inspected, "dataset_snapshots"), false);
  inspected.close();
});

test("legacy monitoring metadata rejects a newer unsupported version", () => {
  const databasePath = temporaryDatabasePath("legacy-alert-newer.sqlite");
  const database = new DatabaseSync(databasePath);
  database.exec(`
    CREATE TABLE monitoring_store_metadata (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      schema_version INTEGER NOT NULL CHECK (schema_version > 0)
    ) STRICT;
    INSERT INTO monitoring_store_metadata (singleton, schema_version) VALUES (1, 2);
  `);
  database.close();

  assert.throws(
    () => new MonitoringAlertStore(databasePath),
    (error: unknown) =>
      error instanceof MonitoringAlertStoreError &&
      error.code === "UNSUPPORTED_SCHEMA" &&
      /newer than supported/.test(error.message)
  );

  const inspected = new DatabaseSync(databasePath);
  assert.equal(tableExists(inspected, SQLITE_COMPONENT_SCHEMA_REGISTRY), false);
  inspected.close();
});

function temporaryDatabasePath(filename: string): string {
  const directory = mkdtempSync(join(tmpdir(), "abl-component-schema-"));
  temporaryDirectories.push(directory);
  return join(directory, filename);
}

function tableExists(database: DatabaseSync, tableName: string): boolean {
  const row = database
    .prepare("SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ?")
    .get(tableName) as { readonly present: number } | undefined;
  return row?.present === 1;
}

function createCanonicalRegistry(database: DatabaseSync): void {
  database.exec(`
    CREATE TABLE component_schema_versions (
      component_name TEXT PRIMARY KEY CHECK (
        length(component_name) BETWEEN 1 AND 128
      ),
      schema_version INTEGER NOT NULL CHECK (schema_version > 0)
    ) STRICT;
  `);
}
