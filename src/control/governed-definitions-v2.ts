import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  GovernedDefinitionKindV2Schema,
  IdentifierSchema,
  IsoDateSchema,
  SemanticVersionV2Schema,
  canonicalHash,
  canonicalJson,
  compareSemanticVersionsV2,
  computeDefinitionImpactPreviewV1,
  computeSemanticDiffV1,
  createGovernedDefinitionVersionV2,
  parseGovernedDefinitionVersionV2,
  validateGovernedDefinitionDocumentV2,
  type CanonicalJsonValue,
  type GovernedDefinitionKindV2,
  type GovernedDefinitionVersionV2,
  type SemanticDiffV1,
  type Sha256Hash
} from "../contracts/index.js";
import { migrateSqliteComponent } from "../infrastructure/sqlite-component-schema.js";

export const GOVERNED_DEFINITION_V2_STORE_COMPONENT = "abl.governed-definition-v2-store" as const;
export const GOVERNED_DEFINITION_V2_STORE_SCHEMA_VERSION = 1 as const;

export type GovernedDefinitionStatusV2 =
  | "proposed"
  | "validated"
  | "approved"
  | "active"
  | "superseded"
  | "retired";

export type GovernedDefinitionTransitionV2 = "validated" | "approved" | "active" | "retired";

export interface ProposeGovernedDefinitionV2Input {
  readonly tenantId: string;
  readonly definitionVersionId: string;
  readonly definitionKey: string;
  readonly kind: GovernedDefinitionKindV2;
  readonly semanticVersion: string;
  readonly effectiveFrom: string;
  readonly effectiveTo?: string;
  readonly predecessorDefinitionVersionId?: string;
  readonly rollbackTargetDefinitionVersionId?: string;
  readonly document: CanonicalJsonValue;
  readonly proposedBy: string;
  readonly idempotencyKey: string;
}

export interface TransitionGovernedDefinitionV2Input {
  readonly tenantId: string;
  readonly definitionVersionId: string;
  readonly toStatus: GovernedDefinitionTransitionV2;
  readonly expectedRevision: number;
  readonly actor: string;
  readonly evidence?: CanonicalJsonValue;
  readonly idempotencyKey: string;
}

export interface GovernedDefinitionViewV2 {
  readonly version: GovernedDefinitionVersionV2;
  readonly status: GovernedDefinitionStatusV2;
  readonly lifecycleRevision: number;
  readonly lastTransitionBy: string;
  readonly lastTransitionAt: string;
  /** Authority comes only from the immutable approved lifecycle event. */
  readonly approvalEvidence: DurableDefinitionApprovalV2 | null;
}

export interface DurableDefinitionApprovalV2 {
  readonly status: "approved";
  readonly proposedBy: string;
  readonly approvedBy: string;
  readonly approvedAt: string;
  readonly approvalEventHash: Sha256Hash;
}

export interface GovernedDefinitionAuditEventV2 {
  readonly sequence: number;
  readonly tenantId: string;
  readonly eventId: string;
  readonly definitionVersionId: string;
  readonly lifecycleRevision: number;
  readonly fromStatus: GovernedDefinitionStatusV2 | null;
  readonly toStatus: GovernedDefinitionStatusV2;
  readonly actor: string;
  readonly evidence: CanonicalJsonValue;
  readonly occurredAt: string;
  readonly previousEventHash: Sha256Hash | null;
  readonly eventHash: Sha256Hash;
}

export interface GovernedDefinitionV2StoreOptions {
  readonly clock?: () => Date;
  readonly busyTimeoutMs?: number;
}

export type GovernedDefinitionV2StoreErrorCode =
  | "INVALID_INPUT"
  | "NOT_FOUND"
  | "CONFLICT"
  | "IDEMPOTENCY_CONFLICT"
  | "CONCURRENCY_CONFLICT"
  | "ILLEGAL_TRANSITION"
  | "MAKER_CHECKER_VIOLATION"
  | "STORE_CLOSED";

export class GovernedDefinitionV2StoreError extends Error {
  constructor(readonly code: GovernedDefinitionV2StoreErrorCode, message: string) {
    super(message);
    this.name = "GovernedDefinitionV2StoreError";
  }
}

/**
 * Additive definition governance. Version rows, lifecycle events, audit hashes,
 * and idempotency receipts are immutable; v1 definition tables are untouched.
 */
export class GovernedDefinitionV2Store {
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;
  #closed = false;

  constructor(databasePath: string, options: GovernedDefinitionV2StoreOptions = {}) {
    if (!databasePath.trim()) invalid("Governed-definition v2 database path is required");
    const absolute = resolve(databasePath);
    if (databasePath !== ":memory:") mkdirSync(dirname(absolute), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(databasePath === ":memory:" ? databasePath : absolute);
    this.#clock = options.clock ?? (() => new Date());
    const busyTimeoutMs = integer(options.busyTimeoutMs ?? 5_000, "busyTimeoutMs", 0, 60_000);
    try {
      this.#database.exec(
        `PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${busyTimeoutMs};`
      );
      migrateSqliteComponent(this.#database, {
        componentName: GOVERNED_DEFINITION_V2_STORE_COMPONENT,
        supportedVersion: GOVERNED_DEFINITION_V2_STORE_SCHEMA_VERSION,
        migrations: [{ version: 1, sql: GOVERNED_DEFINITION_V2_SCHEMA }],
        unsupportedVersionError: (current, supported) =>
          new GovernedDefinitionV2StoreError(
            "CONFLICT",
            `Governed-definition v2 schema ${current} is newer than supported version ${supported}`
          )
      });
    } catch (error) {
      this.#database.close();
      throw error;
    }
  }

  propose(inputValue: ProposeGovernedDefinitionV2Input): GovernedDefinitionViewV2 {
    this.#assertOpen();
    const input = validateProposal(inputValue);
    const requestHash = canonicalHash(input);
    return this.#transaction(() => {
      const replay = this.#readReceipt(
        input.tenantId,
        "definition_v2.propose",
        input.proposedBy,
        input.idempotencyKey,
        requestHash
      );
      if (replay) {
        return this.#atRevision(
          input.tenantId,
          replay.definitionVersionId,
          replay.responseRevision
        );
      }
      if (this.get(input.tenantId, input.definitionVersionId)) {
        conflict("Governed definition version id already exists in this tenant");
      }
      const latest = this.#latestVersion(input.tenantId, input.kind, input.definitionKey);
      if (!latest) {
        if (input.predecessorDefinitionVersionId !== undefined) {
          conflict("The first governed definition version cannot name a predecessor");
        }
      } else {
        if (input.predecessorDefinitionVersionId !== latest.version.definitionVersionId) {
          conflict("Predecessor must be the latest immutable definition version");
        }
        if (compareSemanticVersionsV2(input.semanticVersion, latest.version.semanticVersion) <= 0) {
          conflict("Semantic version must increase from the predecessor");
        }
        if (input.effectiveFrom <= latest.version.effectiveFrom) {
          conflict("A successor definition must start after its immutable predecessor");
        }
      }

      const active = this.#activeForKey(input.tenantId, input.kind, input.definitionKey);
      if (!active && input.rollbackTargetDefinitionVersionId !== undefined) {
        conflict("A rollback target is invalid when no active definition exists");
      }
      if (active && input.rollbackTargetDefinitionVersionId !== active.version.definitionVersionId) {
        conflict("A replacement proposal must lock the current active version as its rollback target");
      }

      const document = validateGovernedDefinitionDocumentV2(
        input.kind,
        input.document,
        input.tenantId,
        input.definitionKey,
        input.semanticVersion,
        input.effectiveFrom,
        input.effectiveTo ?? null
      );
      const semanticDiff = computeSemanticDiffV1(latest?.version.document ?? null, document);
      const impactPreview = computeDefinitionImpactPreviewV1(
        input.kind,
        latest?.version.semanticVersion ?? null,
        input.semanticVersion,
        semanticDiff,
        active !== undefined
      );
      const proposedAt = this.#now();
      const version = createGovernedDefinitionVersionV2({
        contractVersion: 2,
        tenantId: input.tenantId,
        definitionVersionId: input.definitionVersionId,
        definitionKey: input.definitionKey,
        kind: input.kind,
        semanticVersion: input.semanticVersion,
        effectiveFrom: input.effectiveFrom,
        effectiveTo: input.effectiveTo ?? null,
        predecessorDefinitionVersionId: input.predecessorDefinitionVersionId ?? null,
        rollbackTargetDefinitionVersionId: input.rollbackTargetDefinitionVersionId ?? null,
        document,
        semanticDiff,
        impactPreview,
        proposedBy: input.proposedBy,
        proposedAt
      });
      this.#insertVersion(version);
      this.#appendEvent({
        tenantId: input.tenantId,
        definitionVersionId: input.definitionVersionId,
        lifecycleRevision: 1,
        fromStatus: null,
        toStatus: "proposed",
        actor: input.proposedBy,
        evidence: {
          documentHash: version.documentHash,
          semanticDiffHash: version.semanticDiffHash,
          versionHash: version.versionHash
        },
        occurredAt: proposedAt
      });
      const response = this.#required(input.tenantId, input.definitionVersionId);
      this.#recordReceipt(
        input.tenantId,
        "definition_v2.propose",
        input.proposedBy,
        input.idempotencyKey,
        requestHash,
        input.definitionVersionId,
        response.lifecycleRevision,
        proposedAt
      );
      return response;
    });
  }

  transition(inputValue: TransitionGovernedDefinitionV2Input): GovernedDefinitionViewV2 {
    this.#assertOpen();
    const input = validateTransition(inputValue);
    const requestHash = canonicalHash(input);
    return this.#transaction(() => {
      const replay = this.#readReceipt(
        input.tenantId,
        "definition_v2.transition",
        input.actor,
        input.idempotencyKey,
        requestHash
      );
      if (replay) {
        return this.#atRevision(
          input.tenantId,
          replay.definitionVersionId,
          replay.responseRevision
        );
      }
      const current = this.#required(input.tenantId, input.definitionVersionId);
      if (current.lifecycleRevision !== input.expectedRevision) {
        concurrency("Governed definition lifecycle revision changed");
      }
      if (current.version.proposedBy === input.actor) {
        throw new GovernedDefinitionV2StoreError(
          "MAKER_CHECKER_VIOLATION",
          "A governed definition proposer cannot validate, approve, activate, or retire that version"
        );
      }
      const expected: Record<GovernedDefinitionTransitionV2, readonly GovernedDefinitionStatusV2[]> = {
        validated: ["proposed"],
        approved: ["validated"],
        active: ["approved"],
        retired: ["active", "superseded"]
      };
      if (!expected[input.toStatus].includes(current.status)) {
        transition(`Cannot transition ${current.status} definition to ${input.toStatus}`);
      }
      if (
        input.toStatus === "retired" &&
        this.#hasPendingRollbackDependent(input.tenantId, input.definitionVersionId)
      ) {
        conflict("A definition with a pending rollback-dependent successor cannot be retired");
      }
      const occurredAt = this.#now();
      if (input.toStatus === "active") {
        const priorActive = this.#activeForKey(
          input.tenantId,
          current.version.kind,
          current.version.definitionKey
        );
        if (priorActive) {
          if (
            current.version.rollbackTargetDefinitionVersionId !==
            priorActive.version.definitionVersionId
          ) {
            conflict("Activation rollback target no longer matches the current active version");
          }
          if (current.version.effectiveFrom <= priorActive.version.effectiveFrom) {
            conflict("A replacement definition must start after the active version");
          }
          this.#appendEvent({
            tenantId: input.tenantId,
            definitionVersionId: priorActive.version.definitionVersionId,
            lifecycleRevision: priorActive.lifecycleRevision + 1,
            fromStatus: "active",
            toStatus: "superseded",
            actor: input.actor,
            evidence: { replacementDefinitionVersionId: current.version.definitionVersionId },
            occurredAt
          });
        } else if (current.version.rollbackTargetDefinitionVersionId !== null) {
          conflict("Activation cannot resolve the locked rollback target");
        }
      }
      this.#appendEvent({
        tenantId: input.tenantId,
        definitionVersionId: input.definitionVersionId,
        lifecycleRevision: current.lifecycleRevision + 1,
        fromStatus: current.status,
        toStatus: input.toStatus,
        actor: input.actor,
        evidence: input.evidence ?? {},
        occurredAt
      });
      const response = this.#required(input.tenantId, input.definitionVersionId);
      this.#recordReceipt(
        input.tenantId,
        "definition_v2.transition",
        input.actor,
        input.idempotencyKey,
        requestHash,
        input.definitionVersionId,
        response.lifecycleRevision,
        occurredAt
      );
      return response;
    });
  }

  get(tenantId: string, definitionVersionId: string): GovernedDefinitionViewV2 | undefined {
    this.#assertOpen();
    id(tenantId, "tenantId");
    id(definitionVersionId, "definitionVersionId");
    const row = this.#database
      .prepare(CURRENT_VIEW_SQL + " WHERE version.tenant_id = ? AND version.definition_version_id = ?")
      .get(tenantId, definitionVersionId) as GovernedDefinitionCurrentRow | undefined;
    return row ? currentRow(row) : undefined;
  }

  list(
    tenantId: string,
    options: Readonly<{
      kind?: GovernedDefinitionKindV2;
      definitionKey?: string;
      limit?: number;
    }> = {}
  ): readonly GovernedDefinitionViewV2[] {
    this.#assertOpen();
    id(tenantId, "tenantId");
    if (options.kind !== undefined) kind(options.kind);
    if (options.definitionKey !== undefined) id(options.definitionKey, "definitionKey");
    const limit = integer(options.limit ?? 100, "limit", 1, 1_000);
    const conditions = ["version.tenant_id = ?"];
    const parameters: Array<string | number> = [tenantId];
    if (options.kind !== undefined) {
      conditions.push("version.kind = ?");
      parameters.push(options.kind);
    }
    if (options.definitionKey !== undefined) {
      conditions.push("version.definition_key = ?");
      parameters.push(options.definitionKey);
    }
    parameters.push(limit);
    const rows = this.#database
      .prepare(
        `${CURRENT_VIEW_SQL} WHERE ${conditions.join(" AND ")}
         ORDER BY version.kind, version.definition_key, version.proposed_at, version.definition_version_id
         LIMIT ?`
      )
      .all(...parameters) as unknown as GovernedDefinitionCurrentRow[];
    return rows.map(currentRow);
  }

  selectEffective(
    tenantId: string,
    kindValue: GovernedDefinitionKindV2,
    definitionKey: string,
    asOfDate: string
  ): GovernedDefinitionViewV2 {
    this.#assertOpen();
    id(tenantId, "tenantId");
    kind(kindValue);
    id(definitionKey, "definitionKey");
    date(asOfDate, "asOfDate");
    const rows = this.#database
      .prepare(
        `${CURRENT_VIEW_SQL}
         WHERE version.tenant_id = ? AND version.kind = ? AND version.definition_key = ?
           AND transition.to_status IN ('active','superseded','retired')
           AND version.effective_from <= ?
         ORDER BY version.effective_from DESC, transition.occurred_at DESC
         LIMIT 2`
      )
      .all(tenantId, kindValue, definitionKey, asOfDate) as unknown as GovernedDefinitionCurrentRow[];
    if (rows.length === 0) notFound("No effective governed definition v2 version was found");
    const selected = rows[0]!;
    if (rows[1]?.effective_from === selected.effective_from) {
      conflict("Multiple governed definition v2 versions start on the same effective date");
    }
    if (selected.current_status === "retired") {
      notFound("The latest applicable governed definition v2 version is retired");
    }
    if (selected.effective_to !== null && selected.effective_to <= asOfDate) {
      notFound("The latest applicable governed definition v2 version has expired");
    }
    return currentRow(selected);
  }

  listAuditEvents(
    tenantId: string,
    afterSequence = 0,
    limit = 100
  ): readonly GovernedDefinitionAuditEventV2[] {
    this.#assertOpen();
    id(tenantId, "tenantId");
    integer(afterSequence, "afterSequence", 0, Number.MAX_SAFE_INTEGER);
    integer(limit, "limit", 1, 1_000);
    const rows = this.#database
      .prepare(
        `SELECT * FROM governed_definition_v2_events
          WHERE tenant_id = ? AND sequence > ?
          ORDER BY sequence LIMIT ?`
      )
      .all(tenantId, afterSequence, limit) as unknown as GovernedDefinitionEventRow[];
    return rows.map(eventRow);
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#database.close();
  }

  #latestVersion(
    tenantId: string,
    kindValue: GovernedDefinitionKindV2,
    definitionKey: string
  ): GovernedDefinitionViewV2 | undefined {
    const row = this.#database
      .prepare(
        `${CURRENT_VIEW_SQL}
         WHERE version.tenant_id = ? AND version.kind = ? AND version.definition_key = ?
         ORDER BY version.rowid DESC LIMIT 1`
      )
      .get(tenantId, kindValue, definitionKey) as GovernedDefinitionCurrentRow | undefined;
    return row ? currentRow(row) : undefined;
  }

  #activeForKey(
    tenantId: string,
    kindValue: GovernedDefinitionKindV2,
    definitionKey: string
  ): GovernedDefinitionViewV2 | undefined {
    const rows = this.#database
      .prepare(
        `${CURRENT_VIEW_SQL}
         WHERE version.tenant_id = ? AND version.kind = ? AND version.definition_key = ?
           AND transition.to_status = 'active'
         ORDER BY version.effective_from DESC LIMIT 2`
      )
      .all(tenantId, kindValue, definitionKey) as unknown as GovernedDefinitionCurrentRow[];
    if (rows.length > 1) conflict("More than one active governed definition version exists");
    return rows[0] ? currentRow(rows[0]) : undefined;
  }

  #hasPendingRollbackDependent(tenantId: string, definitionVersionId: string): boolean {
    return this.#database
      .prepare(
        `SELECT 1
           FROM governed_definition_v2_versions AS successor
           JOIN governed_definition_v2_events AS transition
             ON transition.tenant_id = successor.tenant_id
            AND transition.definition_version_id = successor.definition_version_id
            AND transition.lifecycle_revision = (
              SELECT MAX(latest.lifecycle_revision)
                FROM governed_definition_v2_events AS latest
               WHERE latest.tenant_id = successor.tenant_id
                 AND latest.definition_version_id = successor.definition_version_id
            )
          WHERE successor.tenant_id = ?1
            AND successor.rollback_target_definition_version_id = ?2
            AND transition.to_status IN ('proposed','validated','approved')
          LIMIT 1`
      )
      .get(tenantId, definitionVersionId) !== undefined;
  }

  #insertVersion(version: GovernedDefinitionVersionV2): void {
    this.#database
      .prepare(
        `INSERT INTO governed_definition_v2_versions (
           tenant_id, definition_version_id, definition_key, kind, semantic_version,
           effective_from, effective_to, predecessor_definition_version_id,
           rollback_target_definition_version_id, document_json, document_hash,
           semantic_diff_json, semantic_diff_hash, impact_preview_json, impact_preview_hash,
           proposed_by, proposed_at, version_hash
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        version.tenantId,
        version.definitionVersionId,
        version.definitionKey,
        version.kind,
        version.semanticVersion,
        version.effectiveFrom,
        version.effectiveTo,
        version.predecessorDefinitionVersionId,
        version.rollbackTargetDefinitionVersionId,
        canonicalJson(version.document),
        version.documentHash,
        canonicalJson(version.semanticDiff),
        version.semanticDiffHash,
        canonicalJson(version.impactPreview),
        version.impactPreviewHash,
        version.proposedBy,
        version.proposedAt,
        version.versionHash
      );
  }

  #appendEvent(input: Readonly<{
    tenantId: string;
    definitionVersionId: string;
    lifecycleRevision: number;
    fromStatus: GovernedDefinitionStatusV2 | null;
    toStatus: GovernedDefinitionStatusV2;
    actor: string;
    evidence: CanonicalJsonValue;
    occurredAt: string;
  }>): void {
    const previous = this.#database
      .prepare(
        `SELECT event_hash FROM governed_definition_v2_events
          WHERE tenant_id = ? ORDER BY sequence DESC LIMIT 1`
      )
      .get(input.tenantId) as { readonly event_hash: Sha256Hash } | undefined;
    const eventId = randomUUID();
    const body = {
      tenantId: input.tenantId,
      eventId,
      definitionVersionId: input.definitionVersionId,
      lifecycleRevision: input.lifecycleRevision,
      fromStatus: input.fromStatus,
      toStatus: input.toStatus,
      actor: input.actor,
      evidence: input.evidence,
      occurredAt: input.occurredAt,
      previousEventHash: previous?.event_hash ?? null
    };
    this.#database
      .prepare(
        `INSERT INTO governed_definition_v2_events (
           tenant_id, event_id, definition_version_id, lifecycle_revision,
           from_status, to_status, actor, evidence_json, occurred_at,
           previous_event_hash, event_hash
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        input.tenantId,
        eventId,
        input.definitionVersionId,
        input.lifecycleRevision,
        input.fromStatus,
        input.toStatus,
        input.actor,
        canonicalJson(input.evidence),
        input.occurredAt,
        body.previousEventHash,
        canonicalHash(body)
      );
  }

  #required(tenantId: string, definitionVersionId: string): GovernedDefinitionViewV2 {
    const value = this.get(tenantId, definitionVersionId);
    if (!value) notFound("Governed definition v2 version was not found");
    return value;
  }

  #atRevision(
    tenantId: string,
    definitionVersionId: string,
    lifecycleRevision: number
  ): GovernedDefinitionViewV2 {
    const row = this.#database
      .prepare(VIEW_AT_REVISION_SQL)
      .get(tenantId, definitionVersionId, lifecycleRevision) as
      | GovernedDefinitionCurrentRow
      | undefined;
    if (!row) conflict("Governed-definition v2 idempotency response is unavailable");
    return currentRow(row);
  }

  #readReceipt(
    tenantId: string,
    operation: string,
    actor: string,
    idempotencyKey: string,
    requestHash: Sha256Hash
  ): { readonly definitionVersionId: string; readonly responseRevision: number } | null {
    const row = this.#database
      .prepare(
        `SELECT request_hash, definition_version_id, response_revision
           FROM governed_definition_v2_idempotency
          WHERE tenant_id = ? AND operation = ? AND actor = ? AND idempotency_key = ?`
      )
      .get(tenantId, operation, actor, idempotencyKey) as
      | {
          readonly request_hash: Sha256Hash;
          readonly definition_version_id: string;
          readonly response_revision: number;
        }
      | undefined;
    if (!row) return null;
    if (row.request_hash !== requestHash) {
      throw new GovernedDefinitionV2StoreError(
        "IDEMPOTENCY_CONFLICT",
        "Idempotency key was used with another governed-definition v2 request"
      );
    }
    return {
      definitionVersionId: row.definition_version_id,
      responseRevision: row.response_revision
    };
  }

  #recordReceipt(
    tenantId: string,
    operation: string,
    actor: string,
    idempotencyKey: string,
    requestHash: Sha256Hash,
    definitionVersionId: string,
    responseRevision: number,
    createdAt: string
  ): void {
    this.#database
      .prepare(
        `INSERT INTO governed_definition_v2_idempotency (
           tenant_id, operation, actor, idempotency_key, request_hash,
           definition_version_id, response_revision, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        tenantId,
        operation,
        actor,
        idempotencyKey,
        requestHash,
        definitionVersionId,
        responseRevision,
        createdAt
      );
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
        // Preserve the original failure.
      }
      throw error;
    }
  }

  #now(): string {
    const value = this.#clock();
    if (Number.isNaN(value.getTime())) invalid("Governed-definition v2 clock is invalid");
    const timestamp = value.toISOString();
    const latest = this.#database
      .prepare("SELECT occurred_at FROM governed_definition_v2_events ORDER BY sequence DESC LIMIT 1")
      .get() as { readonly occurred_at: string } | undefined;
    if (latest && timestamp < latest.occurred_at) {
      invalid("Governed-definition v2 clock must not move backward");
    }
    return timestamp;
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw new GovernedDefinitionV2StoreError("STORE_CLOSED", "Governed-definition v2 store is closed");
    }
  }
}

const CURRENT_VIEW_SQL = `
SELECT version.*,
       transition.to_status AS current_status,
       transition.lifecycle_revision AS current_revision,
       transition.actor AS current_actor,
       transition.occurred_at AS current_at,
       approval.actor AS approved_by,
       approval.occurred_at AS approved_at,
       approval.event_hash AS approval_event_hash
  FROM governed_definition_v2_versions AS version
  JOIN governed_definition_v2_events AS transition
    ON transition.tenant_id = version.tenant_id
   AND transition.definition_version_id = version.definition_version_id
   AND transition.lifecycle_revision = (
     SELECT MAX(latest.lifecycle_revision)
       FROM governed_definition_v2_events AS latest
      WHERE latest.tenant_id = version.tenant_id
        AND latest.definition_version_id = version.definition_version_id
   )
  LEFT JOIN governed_definition_v2_events AS approval
    ON approval.tenant_id = version.tenant_id
   AND approval.definition_version_id = version.definition_version_id
   AND approval.to_status = 'approved'`;

const VIEW_AT_REVISION_SQL = `
SELECT version.*,
       transition.to_status AS current_status,
       transition.lifecycle_revision AS current_revision,
       transition.actor AS current_actor,
       transition.occurred_at AS current_at,
       approval.actor AS approved_by,
       approval.occurred_at AS approved_at,
       approval.event_hash AS approval_event_hash
  FROM governed_definition_v2_versions AS version
  JOIN governed_definition_v2_events AS transition
    ON transition.tenant_id = version.tenant_id
   AND transition.definition_version_id = version.definition_version_id
   AND transition.lifecycle_revision = ?3
  LEFT JOIN governed_definition_v2_events AS approval
    ON approval.tenant_id = version.tenant_id
   AND approval.definition_version_id = version.definition_version_id
   AND approval.to_status = 'approved'
   AND approval.lifecycle_revision <= ?3
 WHERE version.tenant_id = ?1 AND version.definition_version_id = ?2`;

const GOVERNED_DEFINITION_V2_SCHEMA = `
CREATE TABLE governed_definition_v2_versions (
  tenant_id TEXT NOT NULL,
  definition_version_id TEXT NOT NULL,
  definition_key TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN (
    'source_contract','mapping_spec','methodology_bundle','borrowing_base_policy_v2',
    'metric_definition','metric_projection','cohort_definition','bin_definition',
    'reconciliation_definition','entity_resolution_definition','report_definition',
    'scenario_definition','covenant_definition'
  )),
  semantic_version TEXT NOT NULL,
  effective_from TEXT NOT NULL,
  effective_to TEXT,
  predecessor_definition_version_id TEXT,
  rollback_target_definition_version_id TEXT,
  document_json TEXT NOT NULL,
  document_hash TEXT NOT NULL CHECK (document_hash GLOB 'sha256:[0-9a-f]*' AND length(document_hash) = 71),
  semantic_diff_json TEXT NOT NULL,
  semantic_diff_hash TEXT NOT NULL CHECK (semantic_diff_hash GLOB 'sha256:[0-9a-f]*' AND length(semantic_diff_hash) = 71),
  impact_preview_json TEXT NOT NULL,
  impact_preview_hash TEXT NOT NULL CHECK (impact_preview_hash GLOB 'sha256:[0-9a-f]*' AND length(impact_preview_hash) = 71),
  proposed_by TEXT NOT NULL,
  proposed_at TEXT NOT NULL,
  version_hash TEXT NOT NULL CHECK (version_hash GLOB 'sha256:[0-9a-f]*' AND length(version_hash) = 71),
  PRIMARY KEY (tenant_id, definition_version_id),
  UNIQUE (tenant_id, kind, definition_key, semantic_version),
  FOREIGN KEY (tenant_id, predecessor_definition_version_id)
    REFERENCES governed_definition_v2_versions (tenant_id, definition_version_id),
  FOREIGN KEY (tenant_id, rollback_target_definition_version_id)
    REFERENCES governed_definition_v2_versions (tenant_id, definition_version_id)
) STRICT;
CREATE INDEX governed_definition_v2_key
  ON governed_definition_v2_versions (tenant_id, kind, definition_key, effective_from);
CREATE TRIGGER governed_definition_v2_versions_no_update
BEFORE UPDATE ON governed_definition_v2_versions
BEGIN SELECT RAISE(ABORT, 'governed definition v2 versions are immutable'); END;
CREATE TRIGGER governed_definition_v2_versions_no_delete
BEFORE DELETE ON governed_definition_v2_versions
BEGIN SELECT RAISE(ABORT, 'governed definition v2 versions are immutable'); END;

CREATE TABLE governed_definition_v2_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL UNIQUE,
  definition_version_id TEXT NOT NULL,
  lifecycle_revision INTEGER NOT NULL CHECK (lifecycle_revision > 0),
  from_status TEXT CHECK (from_status IS NULL OR from_status IN (
    'proposed','validated','approved','active','superseded','retired'
  )),
  to_status TEXT NOT NULL CHECK (to_status IN (
    'proposed','validated','approved','active','superseded','retired'
  )),
  actor TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  previous_event_hash TEXT CHECK (
    previous_event_hash IS NULL OR
    (previous_event_hash GLOB 'sha256:[0-9a-f]*' AND length(previous_event_hash) = 71)
  ),
  event_hash TEXT NOT NULL CHECK (event_hash GLOB 'sha256:[0-9a-f]*' AND length(event_hash) = 71),
  UNIQUE (tenant_id, definition_version_id, lifecycle_revision),
  FOREIGN KEY (tenant_id, definition_version_id)
    REFERENCES governed_definition_v2_versions (tenant_id, definition_version_id)
) STRICT;
CREATE INDEX governed_definition_v2_events_tenant_sequence
  ON governed_definition_v2_events (tenant_id, sequence);
CREATE TRIGGER governed_definition_v2_events_no_update
BEFORE UPDATE ON governed_definition_v2_events
BEGIN SELECT RAISE(ABORT, 'governed definition v2 events are append-only'); END;
CREATE TRIGGER governed_definition_v2_events_no_delete
BEFORE DELETE ON governed_definition_v2_events
BEGIN SELECT RAISE(ABORT, 'governed definition v2 events are append-only'); END;

CREATE TABLE governed_definition_v2_idempotency (
  tenant_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  actor TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL CHECK (request_hash GLOB 'sha256:[0-9a-f]*' AND length(request_hash) = 71),
  definition_version_id TEXT NOT NULL,
  response_revision INTEGER NOT NULL CHECK (response_revision > 0),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, operation, actor, idempotency_key),
  FOREIGN KEY (tenant_id, definition_version_id)
    REFERENCES governed_definition_v2_versions (tenant_id, definition_version_id)
) STRICT;
CREATE TRIGGER governed_definition_v2_idempotency_no_update
BEFORE UPDATE ON governed_definition_v2_idempotency
BEGIN SELECT RAISE(ABORT, 'governed definition v2 idempotency is immutable'); END;
CREATE TRIGGER governed_definition_v2_idempotency_no_delete
BEFORE DELETE ON governed_definition_v2_idempotency
BEGIN SELECT RAISE(ABORT, 'governed definition v2 idempotency is immutable'); END;
`;

interface GovernedDefinitionVersionRow {
  readonly tenant_id: string;
  readonly definition_version_id: string;
  readonly definition_key: string;
  readonly kind: GovernedDefinitionKindV2;
  readonly semantic_version: string;
  readonly effective_from: string;
  readonly effective_to: string | null;
  readonly predecessor_definition_version_id: string | null;
  readonly rollback_target_definition_version_id: string | null;
  readonly document_json: string;
  readonly document_hash: Sha256Hash;
  readonly semantic_diff_json: string;
  readonly semantic_diff_hash: Sha256Hash;
  readonly impact_preview_json: string;
  readonly impact_preview_hash: Sha256Hash;
  readonly proposed_by: string;
  readonly proposed_at: string;
  readonly version_hash: Sha256Hash;
}

interface GovernedDefinitionCurrentRow extends GovernedDefinitionVersionRow {
  readonly current_status: GovernedDefinitionStatusV2;
  readonly current_revision: number;
  readonly current_actor: string;
  readonly current_at: string;
  readonly approved_by: string | null;
  readonly approved_at: string | null;
  readonly approval_event_hash: Sha256Hash | null;
  readonly rowid?: number;
}

interface GovernedDefinitionEventRow {
  readonly sequence: number;
  readonly tenant_id: string;
  readonly event_id: string;
  readonly definition_version_id: string;
  readonly lifecycle_revision: number;
  readonly from_status: GovernedDefinitionStatusV2 | null;
  readonly to_status: GovernedDefinitionStatusV2;
  readonly actor: string;
  readonly evidence_json: string;
  readonly occurred_at: string;
  readonly previous_event_hash: Sha256Hash | null;
  readonly event_hash: Sha256Hash;
}

function currentRow(row: GovernedDefinitionCurrentRow): GovernedDefinitionViewV2 {
  return Object.freeze({
    version: versionRow(row),
    status: row.current_status,
    lifecycleRevision: row.current_revision,
    lastTransitionBy: row.current_actor,
    lastTransitionAt: row.current_at,
    approvalEvidence:
      row.approved_by === null || row.approved_at === null || row.approval_event_hash === null
        ? null
        : Object.freeze({
            status: "approved" as const,
            proposedBy: row.proposed_by,
            approvedBy: row.approved_by,
            approvedAt: row.approved_at,
            approvalEventHash: row.approval_event_hash
          })
  });
}

function versionRow(row: GovernedDefinitionVersionRow): GovernedDefinitionVersionV2 {
  return parseGovernedDefinitionVersionV2({
    contractVersion: 2,
    tenantId: row.tenant_id,
    definitionVersionId: row.definition_version_id,
    definitionKey: row.definition_key,
    kind: row.kind,
    semanticVersion: row.semantic_version,
    effectiveFrom: row.effective_from,
    effectiveTo: row.effective_to,
    predecessorDefinitionVersionId: row.predecessor_definition_version_id,
    rollbackTargetDefinitionVersionId: row.rollback_target_definition_version_id,
    document: parseJson(row.document_json, "definition document"),
    documentHash: row.document_hash,
    semanticDiff: parseJson(row.semantic_diff_json, "semantic diff") as unknown as SemanticDiffV1,
    semanticDiffHash: row.semantic_diff_hash,
    impactPreview: parseJson(row.impact_preview_json, "impact preview"),
    impactPreviewHash: row.impact_preview_hash,
    proposedBy: row.proposed_by,
    proposedAt: row.proposed_at,
    versionHash: row.version_hash
  });
}

function eventRow(row: GovernedDefinitionEventRow): GovernedDefinitionAuditEventV2 {
  const event: GovernedDefinitionAuditEventV2 = {
    sequence: row.sequence,
    tenantId: row.tenant_id,
    eventId: row.event_id,
    definitionVersionId: row.definition_version_id,
    lifecycleRevision: row.lifecycle_revision,
    fromStatus: row.from_status,
    toStatus: row.to_status,
    actor: row.actor,
    evidence: parseJson(row.evidence_json, "definition event evidence"),
    occurredAt: row.occurred_at,
    previousEventHash: row.previous_event_hash,
    eventHash: row.event_hash
  };
  const { sequence: _sequence, eventHash: _eventHash, ...body } = event;
  if (canonicalHash(body) !== event.eventHash) {
    conflict("Governed definition v2 audit event hash failed verification");
  }
  return Object.freeze(event);
}

function validateProposal(input: ProposeGovernedDefinitionV2Input): ProposeGovernedDefinitionV2Input {
  exactInputKeys(
    input,
    [
      "definitionKey",
      "definitionVersionId",
      "document",
      "effectiveFrom",
      "idempotencyKey",
      "kind",
      "proposedBy",
      "semanticVersion",
      "tenantId"
    ],
    ["effectiveTo", "predecessorDefinitionVersionId", "rollbackTargetDefinitionVersionId"]
  );
  id(input.tenantId, "tenantId");
  id(input.definitionVersionId, "definitionVersionId");
  id(input.definitionKey, "definitionKey");
  kind(input.kind);
  semanticVersion(input.semanticVersion);
  date(input.effectiveFrom, "effectiveFrom");
  if (input.effectiveTo !== undefined) {
    date(input.effectiveTo, "effectiveTo");
    if (input.effectiveTo <= input.effectiveFrom) invalid("effectiveTo must follow effectiveFrom");
  }
  if (input.predecessorDefinitionVersionId !== undefined) {
    id(input.predecessorDefinitionVersionId, "predecessorDefinitionVersionId");
  }
  if (input.rollbackTargetDefinitionVersionId !== undefined) {
    id(input.rollbackTargetDefinitionVersionId, "rollbackTargetDefinitionVersionId");
  }
  if (input.predecessorDefinitionVersionId === input.definitionVersionId) {
    invalid("A definition version cannot be its own predecessor");
  }
  if (input.rollbackTargetDefinitionVersionId === input.definitionVersionId) {
    invalid("A definition version cannot be its own rollback target");
  }
  id(input.proposedBy, "proposedBy");
  id(input.idempotencyKey, "idempotencyKey");
  const document = validateGovernedDefinitionDocumentV2(
    input.kind,
    input.document,
    input.tenantId,
    input.definitionKey,
    input.semanticVersion,
    input.effectiveFrom,
    input.effectiveTo ?? null
  );
  return Object.freeze({ ...input, document });
}

function validateTransition(
  input: TransitionGovernedDefinitionV2Input
): TransitionGovernedDefinitionV2Input {
  exactInputKeys(
    input,
    ["actor", "definitionVersionId", "expectedRevision", "idempotencyKey", "tenantId", "toStatus"],
    ["evidence"]
  );
  id(input.tenantId, "tenantId");
  id(input.definitionVersionId, "definitionVersionId");
  if (!["validated", "approved", "active", "retired"].includes(input.toStatus)) {
    invalid("Governed definition transition is invalid");
  }
  integer(input.expectedRevision, "expectedRevision", 1, Number.MAX_SAFE_INTEGER);
  id(input.actor, "actor");
  id(input.idempotencyKey, "idempotencyKey");
  const evidence = input.evidence === undefined
    ? undefined
    : (JSON.parse(canonicalJson(input.evidence)) as CanonicalJsonValue);
  return Object.freeze({ ...input, ...(evidence === undefined ? {} : { evidence }) });
}

function parseJson(value: string, label: string): CanonicalJsonValue {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    conflict(`${label} is not valid JSON`);
  }
  canonicalJson(parsed);
  return parsed as CanonicalJsonValue;
}

function id(value: string, label: string): void {
  if (!IdentifierSchema.safeParse(value).success) invalid(`${label} must be a portable identifier`);
}

function kind(value: GovernedDefinitionKindV2): void {
  if (!GovernedDefinitionKindV2Schema.safeParse(value).success) invalid("Definition kind is invalid");
}

function semanticVersion(value: string): void {
  if (!SemanticVersionV2Schema.safeParse(value).success) invalid("semanticVersion is invalid");
}

function date(value: string, label: string): void {
  if (!IsoDateSchema.safeParse(value).success) invalid(`${label} is invalid`);
}

function integer(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalid(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

function exactInputKeys(
  value: object,
  required: readonly string[],
  optional: readonly string[]
): void {
  const keys = Object.keys(value).sort();
  const allowed = new Set([...required, ...optional]);
  if (
    required.some((key) => !Object.hasOwn(value, key)) ||
    keys.some((key) => !allowed.has(key)) ||
    optional.some(
      (key) =>
        Object.hasOwn(value, key) &&
        (value as Readonly<Record<string, unknown>>)[key] === undefined
    )
  ) {
    invalid("Governed-definition v2 request contains missing or unknown fields");
  }
}

function invalid(message: string): never {
  throw new GovernedDefinitionV2StoreError("INVALID_INPUT", message);
}

function notFound(message: string): never {
  throw new GovernedDefinitionV2StoreError("NOT_FOUND", message);
}

function conflict(message: string): never {
  throw new GovernedDefinitionV2StoreError("CONFLICT", message);
}

function concurrency(message: string): never {
  throw new GovernedDefinitionV2StoreError("CONCURRENCY_CONFLICT", message);
}

function transition(message: string): never {
  throw new GovernedDefinitionV2StoreError("ILLEGAL_TRANSITION", message);
}
