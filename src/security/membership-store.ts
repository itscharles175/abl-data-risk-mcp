import { createHash, randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { migrateSqliteComponent } from "../infrastructure/sqlite-component-schema.js";
import type {
  TenantMembership,
  TenantMembershipLookup,
  TenantMembershipResolver
} from "./oauth.js";

export const TENANT_MEMBERSHIP_STORE_COMPONENT = "abl.tenant-membership-store" as const;
export const TENANT_MEMBERSHIP_STORE_SCHEMA_VERSION = 1 as const;

export type MembershipStatus = "proposed" | "active" | "revoked";

export interface ProposeTenantMembershipInput {
  readonly membershipId: string;
  readonly issuer: string;
  readonly subject: string;
  readonly clientId: string;
  readonly tenantId: string;
  readonly principalId: string;
  readonly notBefore?: string;
  readonly expiresAt?: string;
  readonly proposedBy: string;
  readonly idempotencyKey: string;
}

export interface ChangeTenantMembershipInput {
  readonly membershipId: string;
  readonly actor: string;
  readonly idempotencyKey: string;
}

export interface TenantMembershipRecord {
  readonly membershipId: string;
  readonly issuer: string;
  readonly subject: string;
  readonly clientId: string;
  readonly tenantId: string;
  readonly principalId: string;
  readonly notBefore: string | null;
  readonly expiresAt: string | null;
  readonly status: MembershipStatus;
  readonly proposedBy: string;
  readonly proposedAt: string;
  readonly approvedBy: string | null;
  readonly approvedAt: string | null;
  readonly revokedBy: string | null;
  readonly revokedAt: string | null;
}

export interface TenantMembershipStoreOptions {
  readonly clock?: () => Date;
  readonly busyTimeoutMs?: number;
}

export class TenantMembershipStoreError extends Error {
  constructor(
    readonly code:
      | "INVALID_INPUT"
      | "NOT_FOUND"
      | "CONFLICT"
      | "IDEMPOTENCY_CONFLICT"
      | "MAKER_CHECKER_VIOLATION"
      | "ILLEGAL_TRANSITION",
    message: string
  ) {
    super(message);
    this.name = "TenantMembershipStoreError";
  }
}

/** Fixed-schema, server-side OAuth membership directory and maker/checker workflow. */
export class TenantMembershipStore implements TenantMembershipResolver {
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;

  constructor(databasePath: string, options: TenantMembershipStoreOptions = {}) {
    if (!databasePath.trim()) throw invalid("Membership database path is required");
    const absolute = resolve(databasePath);
    if (databasePath !== ":memory:") mkdirSync(dirname(absolute), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(databasePath === ":memory:" ? databasePath : absolute);
    this.#clock = options.clock ?? (() => new Date());
    const busyTimeout = boundedInteger(options.busyTimeoutMs ?? 5_000, "busyTimeoutMs", 0, 60_000);
    try {
      this.#database.exec(`PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${busyTimeout};`);
      migrateSqliteComponent(this.#database, {
        componentName: TENANT_MEMBERSHIP_STORE_COMPONENT,
        supportedVersion: TENANT_MEMBERSHIP_STORE_SCHEMA_VERSION,
        migrations: [{ version: 1, sql: MEMBERSHIP_SCHEMA }],
        unsupportedVersionError: (current, supported) =>
          new TenantMembershipStoreError(
            "CONFLICT",
            `Tenant-membership schema ${current} is newer than supported version ${supported}`
          )
      });
    } catch (error) {
      this.#database.close();
      throw error;
    }
  }

  propose(input: ProposeTenantMembershipInput): TenantMembershipRecord {
    validateProposal(input);
    const normalizedInput = {
      ...input,
      issuer: httpsUrl(input.issuer, "issuer"),
      ...(input.notBefore === undefined ? {} : { notBefore: timestamp(input.notBefore, "notBefore") }),
      ...(input.expiresAt === undefined ? {} : { expiresAt: timestamp(input.expiresAt, "expiresAt") })
    };
    const requestHash = hashJson(normalizedInput);
    return this.#transaction(() => {
      const replay = this.#replay("membership.propose", normalizedInput.idempotencyKey, requestHash);
      if (replay) return this.#required(replay);
      if (this.get(normalizedInput.membershipId)) throw new TenantMembershipStoreError("CONFLICT", "Membership id already exists");
      const tuple = this.#database
        .prepare(
          `SELECT membership_id FROM oauth_tenant_memberships
            WHERE issuer = ? AND subject = ? AND client_id = ? AND status != 'revoked'`
        )
        .get(normalizedInput.issuer, normalizedInput.subject, normalizedInput.clientId) as { membership_id: string } | undefined;
      if (tuple) throw new TenantMembershipStoreError("CONFLICT", "Issuer, subject, and client already have a membership");
      const now = this.#now();
      this.#database
        .prepare(
          `INSERT INTO oauth_tenant_memberships (
             membership_id, issuer, subject, client_id, tenant_id, principal_id,
             not_before, expires_at, status, proposed_by, proposed_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?, ?)`
        )
        .run(
          normalizedInput.membershipId,
          normalizedInput.issuer,
          normalizedInput.subject,
          normalizedInput.clientId,
          normalizedInput.tenantId,
          normalizedInput.principalId,
          normalizedInput.notBefore ?? null,
          normalizedInput.expiresAt ?? null,
          normalizedInput.proposedBy,
          now
        );
      this.#audit(normalizedInput.membershipId, "membership.proposed", normalizedInput.proposedBy, now);
      this.#receipt(
        "membership.propose",
        normalizedInput.idempotencyKey,
        requestHash,
        normalizedInput.membershipId,
        now
      );
      return this.#required(normalizedInput.membershipId);
    });
  }

  approve(input: ChangeTenantMembershipInput): TenantMembershipRecord {
    return this.#change(input, "active");
  }

  revoke(input: ChangeTenantMembershipInput): TenantMembershipRecord {
    return this.#change(input, "revoked");
  }

  get(membershipId: string): TenantMembershipRecord | undefined {
    identifier(membershipId, "membership id");
    const row = this.#database
      .prepare("SELECT * FROM oauth_tenant_memberships WHERE membership_id = ?")
      .get(membershipId) as MembershipRow | undefined;
    return row ? membershipRow(row) : undefined;
  }

  listForTenant(tenantId: string): readonly TenantMembershipRecord[] {
    identifier(tenantId, "tenant id");
    const rows = this.#database
      .prepare("SELECT * FROM oauth_tenant_memberships WHERE tenant_id = ? ORDER BY membership_id")
      .all(tenantId) as unknown as MembershipRow[];
    return rows.map(membershipRow);
  }

  async resolveTenantMembership(lookup: TenantMembershipLookup): Promise<TenantMembership | null> {
    const issuer = httpsUrl(lookup.issuer, "issuer");
    const subject = text(lookup.subject, "subject", 512);
    const clientId = text(lookup.clientId, "client id", 512);
    const now = this.#now();
    const rows = this.#database
      .prepare(
        `SELECT * FROM oauth_tenant_memberships
          WHERE issuer = ? AND subject = ? AND client_id = ? AND status = 'active'
            AND (not_before IS NULL OR not_before <= ?)
            AND (expires_at IS NULL OR expires_at > ?)
          LIMIT 2`
      )
      .all(issuer, subject, clientId, now, now) as unknown as MembershipRow[];
    if (rows.length !== 1) return null;
    return Object.freeze({ tenantId: rows[0]!.tenant_id, principalId: rows[0]!.principal_id });
  }

  close(): void {
    this.#database.close();
  }

  #change(input: ChangeTenantMembershipInput, target: "active" | "revoked"): TenantMembershipRecord {
    identifier(input.membershipId, "membership id");
    identifier(input.actor, "actor");
    identifier(input.idempotencyKey, "idempotency key");
    const operation = target === "active" ? "membership.approve" : "membership.revoke";
    const requestHash = hashJson(input);
    return this.#transaction(() => {
      const replay = this.#replay(operation, input.idempotencyKey, requestHash);
      if (replay) return this.#required(replay);
      const current = this.#required(input.membershipId);
      if (input.actor === current.proposedBy) {
        throw new TenantMembershipStoreError("MAKER_CHECKER_VIOLATION", "Membership proposer cannot approve or revoke it");
      }
      if ((target === "active" && current.status !== "proposed") || (target === "revoked" && current.status !== "active")) {
        throw new TenantMembershipStoreError("ILLEGAL_TRANSITION", `Cannot transition membership from ${current.status} to ${target}`);
      }
      const now = this.#now();
      if (target === "active") {
        this.#database
          .prepare(
            `UPDATE oauth_tenant_memberships
                SET status = 'active', approved_by = ?, approved_at = ?
              WHERE membership_id = ? AND status = 'proposed'`
          )
          .run(input.actor, now, input.membershipId);
      } else {
        this.#database
          .prepare(
            `UPDATE oauth_tenant_memberships
                SET status = 'revoked', revoked_by = ?, revoked_at = ?
              WHERE membership_id = ? AND status = 'active'`
          )
          .run(input.actor, now, input.membershipId);
      }
      this.#audit(input.membershipId, target === "active" ? "membership.approved" : "membership.revoked", input.actor, now);
      this.#receipt(operation, input.idempotencyKey, requestHash, input.membershipId, now);
      return this.#required(input.membershipId);
    });
  }

  #required(membershipId: string): TenantMembershipRecord {
    const record = this.get(membershipId);
    if (!record) throw new TenantMembershipStoreError("NOT_FOUND", "Membership was not found");
    return record;
  }

  #replay(operation: string, idempotencyKey: string, requestHash: string): string | null {
    const row = this.#database
      .prepare(
        `SELECT request_hash, membership_id FROM membership_idempotency
          WHERE operation = ? AND idempotency_key = ?`
      )
      .get(operation, idempotencyKey) as { request_hash: string; membership_id: string } | undefined;
    if (!row) return null;
    if (row.request_hash !== requestHash) {
      throw new TenantMembershipStoreError("IDEMPOTENCY_CONFLICT", "Idempotency key was used with another request");
    }
    return row.membership_id;
  }

  #receipt(operation: string, key: string, requestHash: string, membershipId: string, now: string): void {
    this.#database
      .prepare(
        `INSERT INTO membership_idempotency (
           operation, idempotency_key, request_hash, membership_id, created_at
         ) VALUES (?, ?, ?, ?, ?)`
      )
      .run(operation, key, requestHash, membershipId, now);
  }

  #audit(membershipId: string, eventType: string, actor: string, now: string): void {
    this.#database
      .prepare(
        `INSERT INTO membership_audit_events (
           event_id, membership_id, event_type, actor, occurred_at
         ) VALUES (?, ?, ?, ?, ?)`
      )
      .run(randomUUID(), membershipId, eventType, actor, now);
  }

  #transaction<T>(operation: () => T): T {
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      try {
        this.#database.exec("ROLLBACK");
      } catch {
        // Preserve the original error.
      }
      throw error;
    }
  }

  #now(): string {
    const date = this.#clock();
    if (Number.isNaN(date.getTime())) throw invalid("Clock is invalid");
    return date.toISOString();
  }
}

interface MembershipRow {
  readonly membership_id: string;
  readonly issuer: string;
  readonly subject: string;
  readonly client_id: string;
  readonly tenant_id: string;
  readonly principal_id: string;
  readonly not_before: string | null;
  readonly expires_at: string | null;
  readonly status: MembershipStatus;
  readonly proposed_by: string;
  readonly proposed_at: string;
  readonly approved_by: string | null;
  readonly approved_at: string | null;
  readonly revoked_by: string | null;
  readonly revoked_at: string | null;
}

function membershipRow(row: MembershipRow): TenantMembershipRecord {
  return Object.freeze({
    membershipId: row.membership_id,
    issuer: row.issuer,
    subject: row.subject,
    clientId: row.client_id,
    tenantId: row.tenant_id,
    principalId: row.principal_id,
    notBefore: row.not_before,
    expiresAt: row.expires_at,
    status: row.status,
    proposedBy: row.proposed_by,
    proposedAt: row.proposed_at,
    approvedBy: row.approved_by,
    approvedAt: row.approved_at,
    revokedBy: row.revoked_by,
    revokedAt: row.revoked_at
  });
}

function validateProposal(input: ProposeTenantMembershipInput): void {
  identifier(input.membershipId, "membership id");
  httpsUrl(input.issuer, "issuer");
  text(input.subject, "subject", 512);
  text(input.clientId, "client id", 512);
  identifier(input.tenantId, "tenant id");
  identifier(input.principalId, "principal id");
  const notBefore = input.notBefore === undefined ? undefined : timestamp(input.notBefore, "notBefore");
  const expiresAt = input.expiresAt === undefined ? undefined : timestamp(input.expiresAt, "expiresAt");
  if (notBefore && expiresAt && expiresAt <= notBefore) throw invalid("Membership expiry must follow its start");
  identifier(input.proposedBy, "proposer");
  identifier(input.idempotencyKey, "idempotency key");
}

function httpsUrl(value: string, label: string): string {
  const normalized = text(value, label, 2_048);
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw invalid(`${label} must be an HTTPS URL`);
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash) {
    throw invalid(`${label} must be an HTTPS URL without credentials or fragment`);
  }
  return parsed.href;
}

function text(value: string, label: string, maximum: number): string {
  if (!value || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) throw invalid(`${label} is invalid`);
  return value;
}

function identifier(value: string, label: string): string {
  const normalized = text(value, label, 256);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(normalized)) throw invalid(`${label} is invalid`);
  return normalized;
}

function timestamp(value: string, label: string): string {
  const milliseconds = Date.parse(value);
  if (Number.isNaN(milliseconds)) throw invalid(`${label} must be an ISO timestamp`);
  return new Date(milliseconds).toISOString();
}

function boundedInteger(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw invalid(`${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function hashJson(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function invalid(message: string): TenantMembershipStoreError {
  return new TenantMembershipStoreError("INVALID_INPUT", message);
}

const MEMBERSHIP_SCHEMA = `
CREATE TABLE IF NOT EXISTS oauth_tenant_memberships (
  membership_id TEXT PRIMARY KEY,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  client_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  not_before TEXT,
  expires_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('proposed', 'active', 'revoked')),
  proposed_by TEXT NOT NULL,
  proposed_at TEXT NOT NULL,
  approved_by TEXT,
  approved_at TEXT,
  revoked_by TEXT,
  revoked_at TEXT
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS oauth_memberships_one_live_tuple
  ON oauth_tenant_memberships (issuer, subject, client_id)
  WHERE status != 'revoked';

CREATE INDEX IF NOT EXISTS oauth_memberships_resolution
  ON oauth_tenant_memberships (issuer, subject, client_id, status, not_before, expires_at);

CREATE TABLE IF NOT EXISTS membership_idempotency (
  operation TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  membership_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (operation, idempotency_key),
  FOREIGN KEY (membership_id) REFERENCES oauth_tenant_memberships (membership_id)
) STRICT;

CREATE TABLE IF NOT EXISTS membership_audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  membership_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  FOREIGN KEY (membership_id) REFERENCES oauth_tenant_memberships (membership_id)
) STRICT;

CREATE TRIGGER IF NOT EXISTS oauth_membership_immutable_identity
BEFORE UPDATE ON oauth_tenant_memberships
WHEN OLD.membership_id != NEW.membership_id OR OLD.issuer != NEW.issuer
  OR OLD.subject != NEW.subject OR OLD.client_id != NEW.client_id
  OR OLD.tenant_id != NEW.tenant_id OR OLD.principal_id != NEW.principal_id
  OR COALESCE(OLD.not_before, '') != COALESCE(NEW.not_before, '')
  OR COALESCE(OLD.expires_at, '') != COALESCE(NEW.expires_at, '')
  OR OLD.proposed_by != NEW.proposed_by OR OLD.proposed_at != NEW.proposed_at
BEGIN SELECT RAISE(ABORT, 'membership identity is immutable'); END;

CREATE TRIGGER IF NOT EXISTS oauth_membership_no_delete
BEFORE DELETE ON oauth_tenant_memberships BEGIN SELECT RAISE(ABORT, 'memberships are retained'); END;
CREATE TRIGGER IF NOT EXISTS membership_idempotency_no_update
BEFORE UPDATE ON membership_idempotency BEGIN SELECT RAISE(ABORT, 'idempotency receipts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS membership_idempotency_no_delete
BEFORE DELETE ON membership_idempotency BEGIN SELECT RAISE(ABORT, 'idempotency receipts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS membership_audit_no_update
BEFORE UPDATE ON membership_audit_events BEGIN SELECT RAISE(ABORT, 'membership audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS membership_audit_no_delete
BEFORE DELETE ON membership_audit_events BEGIN SELECT RAISE(ABORT, 'membership audit is append-only'); END;
`;
