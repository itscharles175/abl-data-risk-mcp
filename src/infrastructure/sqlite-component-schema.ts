import { DatabaseSync } from "node:sqlite";

export const SQLITE_COMPONENT_SCHEMA_REGISTRY = "component_schema_versions" as const;

export interface SqliteComponentMigration {
  /** The schema version produced by this migration. Versions must be contiguous from one. */
  readonly version: number;
  readonly sql: string;
}

export interface SqliteComponentSchemaOptions {
  readonly componentName: string;
  readonly supportedVersion: number;
  readonly migrations: readonly SqliteComponentMigration[];
  /**
   * Object identities intentionally shared with another component. A missing
   * component receipt may reuse one of these objects only when its type and
   * canonical sqlite_master DDL exactly match this component's migration.
   * Every other object produced by the migrations is exclusively owned.
   */
  readonly sharedObjects?: readonly SqliteSchemaObjectIdentity[];
  /** Detects a pre-registry schema version while the migration transaction is held. */
  readonly legacyVersion?: (database: DatabaseSync) => number | undefined;
  readonly unsupportedVersionError: (currentVersion: number, supportedVersion: number) => Error;
}

interface ComponentVersionRow {
  readonly schema_version: number;
}

const COMPONENT_SCHEMA_REGISTRY_SQL = `
CREATE TABLE IF NOT EXISTS component_schema_versions (
  component_name TEXT PRIMARY KEY CHECK (
    length(component_name) BETWEEN 1 AND 128
  ),
  schema_version INTEGER NOT NULL CHECK (schema_version > 0)
) STRICT;
`;

export type SqliteSchemaObjectType = "table" | "index" | "trigger";

export interface SqliteSchemaObjectIdentity {
  readonly type: SqliteSchemaObjectType;
  readonly name: string;
}

export const SQLITE_SHARED_AUDIT_OBJECTS = Object.freeze([
  { type: "table", name: "audit_events" },
  { type: "index", name: "audit_events_tenant_sequence" },
  { type: "trigger", name: "audit_events_no_update" },
  { type: "trigger", name: "audit_events_no_delete" },
  { type: "table", name: "idempotency_records" },
  { type: "trigger", name: "idempotency_records_no_update" },
  { type: "trigger", name: "idempotency_records_no_delete" }
] as const satisfies readonly SqliteSchemaObjectIdentity[]);

interface SqliteSchemaObject {
  readonly type: SqliteSchemaObjectType;
  readonly name: string;
  readonly tableName: string;
  readonly sql: string;
}

interface ExpectedComponentSchemas {
  readonly final: ReadonlyMap<string, SqliteSchemaObject>;
  readonly byVersion: ReadonlyMap<number, ReadonlyMap<string, SqliteSchemaObject>>;
}

/**
 * Atomically initializes or migrates one component in a potentially shared
 * SQLite database. Component versions deliberately do not use PRAGMA
 * user_version, which is database-global and cannot safely represent several
 * independently deployed stores.
 */
export function migrateSqliteComponent(
  database: DatabaseSync,
  options: SqliteComponentSchemaOptions
): void {
  validateOptions(options);
  const expected = buildExpectedSchemas(options);
  const sharedObjects = new Set(
    (options.sharedObjects ?? []).map((object) => schemaObjectKey(object.type, object.name))
  );
  const migrationByVersion = new Map(
    options.migrations.map((migration) => [migration.version, migration] as const)
  );

  database.exec("BEGIN IMMEDIATE");
  try {
    ensureCanonicalRegistry(database);
    let row = database
      .prepare(
        `SELECT schema_version
           FROM component_schema_versions
          WHERE component_name = ?`
      )
      .get(options.componentName) as ComponentVersionRow | undefined;
    if (!row && options.legacyVersion) {
      const legacyVersion = options.legacyVersion(database);
      if (legacyVersion !== undefined) {
        if (!Number.isSafeInteger(legacyVersion) || legacyVersion < 1) {
          throw new Error(`SQLite component '${options.componentName}' has an invalid legacy schema version`);
        }
        if (legacyVersion > options.supportedVersion) {
          throw options.unsupportedVersionError(legacyVersion, options.supportedVersion);
        }
        assertSchemaMatches(
          database,
          options.componentName,
          expected.byVersion.get(legacyVersion),
          `legacy schema version ${legacyVersion}`
        );
        insertComponentVersion(database, options.componentName, legacyVersion);
        row = { schema_version: legacyVersion };
      }
    }
    if (!row) {
      assertNoUnreceiptedExclusiveObjects(database, options.componentName, expected.final, sharedObjects);
    }
    const currentVersion = row?.schema_version ?? 0;
    if (!Number.isSafeInteger(currentVersion) || currentVersion < 0) {
      throw new Error(`SQLite component '${options.componentName}' has invalid schema metadata`);
    }
    if (currentVersion > options.supportedVersion) {
      throw options.unsupportedVersionError(currentVersion, options.supportedVersion);
    }
    if (currentVersion > 0) {
      assertSchemaMatches(
        database,
        options.componentName,
        expected.byVersion.get(currentVersion),
        `registered schema version ${currentVersion}`
      );
    }

    for (let nextVersion = currentVersion + 1; nextVersion <= options.supportedVersion; nextVersion += 1) {
      const migration = migrationByVersion.get(nextVersion);
      if (!migration) {
        throw new Error(
          `SQLite component '${options.componentName}' has no migration for schema version ${nextVersion}`
        );
      }
      database.exec(migration.sql);
      assertSchemaMatches(
        database,
        options.componentName,
        expected.byVersion.get(nextVersion),
        `migrated schema version ${nextVersion}`
      );
      database
        .prepare(
          `INSERT INTO component_schema_versions (component_name, schema_version)
           VALUES (?, ?)
           ON CONFLICT (component_name) DO UPDATE
             SET schema_version = excluded.schema_version`
        )
        .run(options.componentName, nextVersion);
    }
    database.exec("COMMIT");
  } catch (error) {
    try {
      database.exec("ROLLBACK");
    } catch {
      // Preserve the migration failure if SQLite has already closed the transaction.
    }
    throw error;
  }
}

function ensureCanonicalRegistry(database: DatabaseSync): void {
  const existing = readSchemaObject(database, "table", SQLITE_COMPONENT_SCHEMA_REGISTRY);
  if (existing === undefined) {
    database.exec(COMPONENT_SCHEMA_REGISTRY_SQL);
  }
  const actual = readSchemaObject(database, "table", SQLITE_COMPONENT_SCHEMA_REGISTRY);
  const expected: SqliteSchemaObject = {
    type: "table",
    name: SQLITE_COMPONENT_SCHEMA_REGISTRY,
    tableName: SQLITE_COMPONENT_SCHEMA_REGISTRY,
    // sqlite_master canonicalizes CREATE TABLE IF NOT EXISTS to CREATE TABLE.
    sql: normalizeSql(COMPONENT_SCHEMA_REGISTRY_SQL).replace(
      /^CREATE TABLE IF NOT EXISTS /,
      "CREATE TABLE "
    )
  };
  const schemaObjects = [...readComponentObjects(database).values()];
  const sameNamedObjects = schemaObjects.filter(
    (object) =>
      sqliteIdentifierKey(object.name) === sqliteIdentifierKey(SQLITE_COMPONENT_SCHEMA_REGISTRY)
  );
  const explicitAttachedObjects = schemaObjects.filter(
    (object) =>
      (object.type === "index" || object.type === "trigger") &&
      sqliteIdentifierKey(object.tableName) === sqliteIdentifierKey(SQLITE_COMPONENT_SCHEMA_REGISTRY)
  );
  if (
    !actual ||
    !sameSchemaObject(actual, expected) ||
    sameNamedObjects.length !== 1 ||
    explicitAttachedObjects.length !== 0
  ) {
    throw new Error("SQLite component schema registry is not canonical");
  }
}

function insertComponentVersion(database: DatabaseSync, componentName: string, version: number): void {
  database
    .prepare(
      `INSERT INTO component_schema_versions (component_name, schema_version)
       VALUES (?, ?)`
    )
    .run(componentName, version);
}

function buildExpectedSchemas(options: SqliteComponentSchemaOptions): ExpectedComponentSchemas {
  const reference = new DatabaseSync(":memory:");
  const byVersion = new Map<number, ReadonlyMap<string, SqliteSchemaObject>>();
  try {
    for (const migration of [...options.migrations].sort((left, right) => left.version - right.version)) {
      reference.exec(migration.sql);
      byVersion.set(migration.version, readComponentObjects(reference));
    }
  } finally {
    reference.close();
  }
  const final = byVersion.get(options.supportedVersion);
  if (!final || final.size === 0) {
    throw new Error(`SQLite component '${options.componentName}' migration creates no schema objects`);
  }
  for (const sharedObject of options.sharedObjects ?? []) {
    if (!final.has(schemaObjectKey(sharedObject.type, sharedObject.name))) {
      throw new Error(
        `SQLite component '${options.componentName}' declares unknown shared ${sharedObject.type} '${sharedObject.name}'`
      );
    }
  }
  return { final, byVersion };
}

function assertNoUnreceiptedExclusiveObjects(
  database: DatabaseSync,
  componentName: string,
  expectedObjects: ReadonlyMap<string, SqliteSchemaObject>,
  sharedObjects: ReadonlySet<string>
): void {
  for (const expected of expectedObjects.values()) {
    const identity = schemaObjectKey(expected.type, expected.name);
    const actual = readSchemaObject(database, expected.type, expected.name);
    if (!actual) continue;
    if (!sharedObjects.has(identity)) {
      throw new Error(
        `SQLite component '${componentName}' has unreceipted pre-existing object '${expected.name}'`
      );
    }
    if (!sameSchemaObject(actual, expected)) {
      throw new Error(
        `SQLite component '${componentName}' shared object '${expected.name}' is not canonical`
      );
    }
  }
  assertNoUnexpectedAttachedObjects(
    database,
    componentName,
    expectedObjects,
    "unreceipted schema"
  );
}

function assertSchemaMatches(
  database: DatabaseSync,
  componentName: string,
  expectedObjects: ReadonlyMap<string, SqliteSchemaObject> | undefined,
  label: string
): void {
  if (!expectedObjects) {
    throw new Error(`SQLite component '${componentName}' has no attestation for ${label}`);
  }
  for (const expected of expectedObjects.values()) {
    const actual = readSchemaObject(database, expected.type, expected.name);
    if (!actual || !sameSchemaObject(actual, expected)) {
      throw new Error(
        `SQLite component '${componentName}' ${label} failed attestation for '${expected.name}'`
      );
    }
  }
  assertNoUnexpectedAttachedObjects(database, componentName, expectedObjects, label);
}

function assertNoUnexpectedAttachedObjects(
  database: DatabaseSync,
  componentName: string,
  expectedObjects: ReadonlyMap<string, SqliteSchemaObject>,
  label: string
): void {
  const expectedTables = new Set(
    [...expectedObjects.values()]
      .filter((object) => object.type === "table")
      .map((object) => sqliteIdentifierKey(object.name))
  );
  const expectedNames = new Set(
    [...expectedObjects.values()].map((object) => sqliteIdentifierKey(object.name))
  );
  for (const actual of readComponentObjects(database).values()) {
    const actualIdentity = schemaObjectKey(actual.type, actual.name);
    if (expectedNames.has(sqliteIdentifierKey(actual.name)) && !expectedObjects.has(actualIdentity)) {
      throw new Error(
        `SQLite component '${componentName}' ${label} has unexpected ${actual.type} '${actual.name}' sharing an expected object name`
      );
    }
    if (
      (actual.type === "index" || actual.type === "trigger") &&
      expectedTables.has(sqliteIdentifierKey(actual.tableName)) &&
      !expectedObjects.has(actualIdentity)
    ) {
      throw new Error(
        `SQLite component '${componentName}' ${label} has unexpected ${actual.type} '${actual.name}'`
      );
    }
  }
}

function readComponentObjects(database: DatabaseSync): ReadonlyMap<string, SqliteSchemaObject> {
  const rows = database
    .prepare(
      `SELECT type, name, tbl_name, sql
         FROM sqlite_master
        WHERE type IN ('table', 'index', 'trigger')
          AND name NOT LIKE 'sqlite_%'
          AND sql IS NOT NULL
        ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 ELSE 2 END, name`
    )
    .all() as unknown as readonly {
    readonly type: SqliteSchemaObjectType;
    readonly name: string;
    readonly tbl_name: string;
    readonly sql: string;
  }[];
  return new Map(
    rows.map((row) => [
      schemaObjectKey(row.type, row.name),
      {
        type: row.type,
        name: row.name,
        tableName: row.tbl_name,
        sql: normalizeSql(row.sql)
      }
    ] as const)
  );
}

function readSchemaObject(
  database: DatabaseSync,
  type: SqliteSchemaObjectType,
  name: string
): SqliteSchemaObject | undefined {
  const row = database
    .prepare(
      `SELECT type, name, tbl_name, sql
         FROM sqlite_master
        WHERE type = ? AND name = ? COLLATE NOCASE`
    )
    .get(type, name) as {
    readonly type: SqliteSchemaObjectType;
    readonly name: string;
    readonly tbl_name: string;
    readonly sql: string | null;
  } | undefined;
  if (!row || row.sql === null) return undefined;
  return {
    type: row.type,
    name: row.name,
    tableName: row.tbl_name,
    sql: normalizeSql(row.sql)
  };
}

function schemaObjectKey(type: SqliteSchemaObjectType, name: string): string {
  return `${type}\u0000${sqliteIdentifierKey(name)}`;
}

function sqliteIdentifierKey(name: string): string {
  return name.replace(/[A-Z]/g, (character) => character.toLowerCase());
}

function sameSchemaObject(actual: SqliteSchemaObject, expected: SqliteSchemaObject): boolean {
  return actual.type === expected.type &&
    actual.name === expected.name &&
    actual.tableName === expected.tableName &&
    actual.sql === expected.sql;
}

function normalizeSql(sql: string): string {
  return sql.replace(/\s+/g, " ").trim().replace(/;$/, "");
}

function validateOptions(options: SqliteComponentSchemaOptions): void {
  if (!/^[a-z][a-z0-9._-]{0,127}$/.test(options.componentName)) {
    throw new Error("SQLite component name is invalid");
  }
  if (!Number.isSafeInteger(options.supportedVersion) || options.supportedVersion < 1) {
    throw new Error("SQLite supported schema version must be a positive integer");
  }
  const versions = new Set<number>();
  const sharedObjects = new Set<string>();
  for (const object of options.sharedObjects ?? []) {
    const identity = schemaObjectKey(object.type, object.name);
    if (
      !["table", "index", "trigger"].includes(object.type) ||
      !/^[a-z][a-z0-9_]{0,127}$/.test(object.name) ||
      sharedObjects.has(identity)
    ) {
      throw new Error(`SQLite shared-object registry for '${options.componentName}' is invalid`);
    }
    sharedObjects.add(identity);
  }
  for (const migration of options.migrations) {
    if (
      !Number.isSafeInteger(migration.version) ||
      migration.version < 1 ||
      migration.version > options.supportedVersion ||
      versions.has(migration.version) ||
      !migration.sql.trim()
    ) {
      throw new Error(`SQLite migration registry for '${options.componentName}' is invalid`);
    }
    versions.add(migration.version);
  }
  for (let version = 1; version <= options.supportedVersion; version += 1) {
    if (!versions.has(version)) {
      throw new Error(
        `SQLite component '${options.componentName}' has no migration for schema version ${version}`
      );
    }
  }
}
