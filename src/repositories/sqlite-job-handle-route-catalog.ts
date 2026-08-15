import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { migrateSqliteComponent } from "../infrastructure/sqlite-component-schema.js";

export const JOB_HANDLE_ROUTE_CATALOG_COMPONENT = "abl.job-handle-route-catalog" as const;
export const JOB_HANDLE_ROUTE_CATALOG_SCHEMA_VERSION = 1 as const;

export type GovernedJobLane = "legacy_governed" | "portfolio_surveillance_v4";

export interface JobHandleRouteOwner {
  readonly tenantId: string;
  readonly principalBinding: string;
}

export interface JobHandleRouteRegistration extends JobHandleRouteOwner {
  readonly jobHandle: string;
  readonly lane: GovernedJobLane;
}

export interface JobHandleRouteCatalog {
  register(input: JobHandleRouteRegistration): GovernedJobLane;
  resolve(input: JobHandleRouteOwner & { readonly jobHandle: string }): GovernedJobLane;
}

export class JobHandleRouteCatalogError extends Error {
  constructor(
    readonly code: "INVALID_INPUT" | "ROUTE_CONFLICT" | "ROUTE_NOT_FOUND",
    message: string
  ) {
    super(message);
    this.name = "JobHandleRouteCatalogError";
  }
}

/** Durable, digest-only ownership catalog for opaque job handles. */
export class SqliteJobHandleRouteCatalog implements JobHandleRouteCatalog {
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;

  constructor(
    databasePath: string,
    options: { readonly busyTimeoutMs?: number; readonly clock?: () => Date } = {}
  ) {
    if (!databasePath.trim()) invalid("Job-handle route catalog path is required");
    const absolute = resolve(databasePath);
    if (databasePath !== ":memory:") mkdirSync(dirname(absolute), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(databasePath === ":memory:" ? databasePath : absolute);
    this.#clock = options.clock ?? (() => new Date());
    const busyTimeoutMs = boundedInteger(options.busyTimeoutMs ?? 5_000, "busyTimeoutMs", 0, 60_000);
    try {
      this.#database.exec(
        `PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${busyTimeoutMs};`
      );
      migrateSqliteComponent(this.#database, {
        componentName: JOB_HANDLE_ROUTE_CATALOG_COMPONENT,
        supportedVersion: JOB_HANDLE_ROUTE_CATALOG_SCHEMA_VERSION,
        migrations: [{ version: 1, sql: JOB_HANDLE_ROUTE_SCHEMA }],
        unsupportedVersionError: (current, supported) =>
          new JobHandleRouteCatalogError(
            "INVALID_INPUT",
            `Job-handle route schema ${current} is newer than supported version ${supported}`
          )
      });
    } catch (error) {
      this.#database.close();
      throw error;
    }
  }

  register(input: JobHandleRouteRegistration): GovernedJobLane {
    const route = validatedRoute(input);
    const registeredAt = this.#nowIso();
    this.#database
      .prepare(
        `INSERT OR IGNORE INTO job_handle_routes (
           handle_digest, tenant_id, principal_binding, lane, registered_at
         ) VALUES (?, ?, ?, ?, ?)`
      )
      .run(route.handleDigest, route.tenantId, route.principalBinding, route.lane, registeredAt);
    const persisted = this.#row(route.handleDigest);
    if (
      !persisted ||
      persisted.tenant_id !== route.tenantId ||
      persisted.principal_binding !== route.principalBinding ||
      persisted.lane !== route.lane
    ) {
      throw new JobHandleRouteCatalogError(
        "ROUTE_CONFLICT",
        "Opaque job handle is already owned by another workflow route"
      );
    }
    return persisted.lane;
  }

  resolve(input: JobHandleRouteOwner & { readonly jobHandle: string }): GovernedJobLane {
    const owner = validatedOwner(input);
    const persisted = this.#row(handleDigest(input.jobHandle));
    if (
      !persisted ||
      persisted.tenant_id !== owner.tenantId ||
      persisted.principal_binding !== owner.principalBinding
    ) {
      throw new JobHandleRouteCatalogError(
        "ROUTE_NOT_FOUND",
        "Opaque job handle did not authorize a workflow route"
      );
    }
    return persisted.lane;
  }

  close(): void {
    this.#database.close();
  }

  #row(handleDigestValue: string): JobHandleRouteRow | undefined {
    return this.#database
      .prepare(
        `SELECT handle_digest, tenant_id, principal_binding, lane, registered_at
           FROM job_handle_routes
          WHERE handle_digest = ?`
      )
      .get(handleDigestValue) as JobHandleRouteRow | undefined;
  }

  #nowIso(): string {
    const value = this.#clock();
    if (!Number.isFinite(value.getTime())) invalid("Job-handle route catalog clock is invalid");
    return value.toISOString();
  }
}

interface JobHandleRouteRow {
  readonly handle_digest: string;
  readonly tenant_id: string;
  readonly principal_binding: string;
  readonly lane: GovernedJobLane;
  readonly registered_at: string;
}

function validatedRoute(input: JobHandleRouteRegistration): {
  readonly handleDigest: string;
  readonly tenantId: string;
  readonly principalBinding: string;
  readonly lane: GovernedJobLane;
} {
  const owner = validatedOwner(input);
  if (input.lane !== "legacy_governed" && input.lane !== "portfolio_surveillance_v4") {
    invalid("Workflow route lane is invalid");
  }
  return Object.freeze({
    handleDigest: handleDigest(input.jobHandle),
    tenantId: owner.tenantId,
    principalBinding: owner.principalBinding,
    lane: input.lane
  });
}

function validatedOwner(input: JobHandleRouteOwner): JobHandleRouteOwner {
  const tenantId = identifier(input.tenantId, "tenantId");
  const principalBinding = hash(input.principalBinding, "principalBinding");
  return Object.freeze({ tenantId, principalBinding });
}

function handleDigest(jobHandle: string): string {
  if (typeof jobHandle !== "string" || jobHandle.length < 20 || jobHandle.length > 1_024) {
    invalid("Opaque job handle is invalid");
  }
  return createHash("sha256")
    .update("aegis-ledger:job-handle-route:v1\0", "utf8")
    .update(jobHandle, "utf8")
    .digest("hex");
}

function identifier(value: string, field: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 256 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(value)
  ) {
    invalid(`${field} is invalid`);
  }
  return value;
}

function hash(value: string, field: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) invalid(`${field} is invalid`);
  return value;
}

function boundedInteger(value: number, field: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalid(`${field} is invalid`);
  return value;
}

function invalid(message: string): never {
  throw new JobHandleRouteCatalogError("INVALID_INPUT", message);
}

const JOB_HANDLE_ROUTE_SCHEMA = `
CREATE TABLE job_handle_routes (
  handle_digest TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  principal_binding TEXT NOT NULL,
  lane TEXT NOT NULL CHECK (lane IN ('legacy_governed', 'portfolio_surveillance_v4')),
  registered_at TEXT NOT NULL
) STRICT;

CREATE INDEX job_handle_routes_owner_idx
  ON job_handle_routes (tenant_id, principal_binding, registered_at);
`;
