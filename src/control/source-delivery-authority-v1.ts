import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { z } from "zod";

import {
  createGovernedSourceDeliveryRecordV1,
  GovernedSourceDeliveryLocatorV1Schema,
  parseGovernedSourceDeliveryRecordV1,
  type DisableGovernedSourceDeliveryV1,
  type GovernedSourceDeliveryLocatorV1,
  type GovernedSourceDeliveryMutationResultV1,
  type GovernedSourceDeliveryRecordV1,
  type GovernedSourceDeliveryResolutionV1,
  type GovernedSourceDeliveryStatusV1,
  type RegisterGovernedSourceDeliveryV1,
  type SourceDeliveryAuditEventV1,
  type TrustedSourceDeliveryActorV1
} from "../contracts/source-delivery-authority-v1.js";
import {
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  canonicalHash,
  canonicalJson,
  deepFreeze,
  parseWithSchema,
  type Sha256Hash
} from "../contracts/canonical.js";
import {
  parseGovernedDatasetScopeBindingV1,
  type GovernedDatasetScopeBindingV1
} from "../contracts/dataset-scope-binding-v1.js";
import { parseSourceContractV1, type SourceContractV1 } from "../contracts/source-contract-v1.js";
import {
  migrateSqliteComponent,
  type SqliteComponentMigration
} from "../infrastructure/sqlite-component-schema.js";
import type {
  ActivatedSourceContractAuthorityV1,
  GovernedDatasetScopeBindingAuthorityV1
} from "../services/modern-snapshot-capture.js";

export const SQLITE_SOURCE_DELIVERY_AUTHORITY_COMPONENT = "abl.source-delivery-authority" as const;
export const SQLITE_SOURCE_DELIVERY_AUTHORITY_SCHEMA_VERSION = 1 as const;

const SQLITE_SOURCE_DELIVERY_AUTHORITY_SCHEMA = `
CREATE TABLE source_delivery_authority_source_contracts_v1 (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  source_contract_id TEXT NOT NULL CHECK (length(source_contract_id) BETWEEN 1 AND 128),
  source_contract_revision INTEGER NOT NULL CHECK (source_contract_revision > 0),
  source_contract_hash TEXT NOT NULL CHECK (length(source_contract_hash) = 71 AND source_contract_hash GLOB 'sha256:*'),
  document_json TEXT NOT NULL CHECK (json_valid(document_json)),
  PRIMARY KEY (tenant_id, source_contract_id, source_contract_revision),
  UNIQUE (tenant_id, source_contract_id, source_contract_revision, source_contract_hash),
  UNIQUE (tenant_id, source_contract_hash)
) STRICT;

CREATE TRIGGER source_delivery_authority_source_contracts_v1_no_update
BEFORE UPDATE ON source_delivery_authority_source_contracts_v1
BEGIN SELECT RAISE(ABORT, 'source-delivery source contracts are immutable'); END;
CREATE TRIGGER source_delivery_authority_source_contracts_v1_no_delete
BEFORE DELETE ON source_delivery_authority_source_contracts_v1
BEGIN SELECT RAISE(ABORT, 'source-delivery source contracts are immutable'); END;

CREATE TABLE source_delivery_authority_scope_bindings_v1 (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  binding_id TEXT NOT NULL CHECK (length(binding_id) BETWEEN 1 AND 128),
  binding_revision INTEGER NOT NULL CHECK (binding_revision > 0),
  binding_hash TEXT NOT NULL CHECK (length(binding_hash) = 71 AND binding_hash GLOB 'sha256:*'),
  source_contract_id TEXT NOT NULL,
  source_contract_revision INTEGER NOT NULL,
  source_contract_hash TEXT NOT NULL,
  dataset_id TEXT NOT NULL CHECK (length(dataset_id) BETWEEN 1 AND 128),
  facility_id TEXT NOT NULL CHECK (length(facility_id) BETWEEN 1 AND 128),
  document_json TEXT NOT NULL CHECK (json_valid(document_json)),
  PRIMARY KEY (tenant_id, binding_id, binding_revision),
  UNIQUE (tenant_id, binding_id, binding_revision, binding_hash),
  UNIQUE (tenant_id, binding_hash),
  FOREIGN KEY (tenant_id, source_contract_id, source_contract_revision, source_contract_hash)
    REFERENCES source_delivery_authority_source_contracts_v1 (
      tenant_id, source_contract_id, source_contract_revision, source_contract_hash
    )
    ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER source_delivery_authority_scope_bindings_v1_no_update
BEFORE UPDATE ON source_delivery_authority_scope_bindings_v1
BEGIN SELECT RAISE(ABORT, 'source-delivery scope bindings are immutable'); END;
CREATE TRIGGER source_delivery_authority_scope_bindings_v1_no_delete
BEFORE DELETE ON source_delivery_authority_scope_bindings_v1
BEGIN SELECT RAISE(ABORT, 'source-delivery scope bindings are immutable'); END;

CREATE TABLE source_delivery_authority_records_v1 (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  delivery_id TEXT NOT NULL CHECK (length(delivery_id) BETWEEN 1 AND 128),
  delivery_revision INTEGER NOT NULL CHECK (delivery_revision IN (1, 2)),
  status TEXT NOT NULL CHECK (status IN ('usable', 'disabled')),
  delivery_hash TEXT NOT NULL CHECK (length(delivery_hash) = 71 AND delivery_hash GLOB 'sha256:*'),
  previous_delivery_hash TEXT CHECK (previous_delivery_hash IS NULL OR (length(previous_delivery_hash) = 71 AND previous_delivery_hash GLOB 'sha256:*')),
  source_contract_id TEXT NOT NULL,
  source_contract_revision INTEGER NOT NULL,
  source_contract_hash TEXT NOT NULL,
  binding_id TEXT NOT NULL,
  binding_revision INTEGER NOT NULL,
  binding_hash TEXT NOT NULL,
  dataset_id TEXT NOT NULL CHECK (length(dataset_id) BETWEEN 1 AND 128),
  facility_id TEXT NOT NULL CHECK (length(facility_id) BETWEEN 1 AND 128),
  locator_identity_hash TEXT NOT NULL CHECK (length(locator_identity_hash) = 71 AND locator_identity_hash GLOB 'sha256:*'),
  source_observed_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  record_json TEXT NOT NULL CHECK (json_valid(record_json)),
  PRIMARY KEY (tenant_id, delivery_id, delivery_revision),
  UNIQUE (tenant_id, delivery_hash),
  FOREIGN KEY (tenant_id, source_contract_id, source_contract_revision, source_contract_hash)
    REFERENCES source_delivery_authority_source_contracts_v1 (
      tenant_id, source_contract_id, source_contract_revision, source_contract_hash
    )
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, binding_id, binding_revision, binding_hash)
    REFERENCES source_delivery_authority_scope_bindings_v1 (
      tenant_id, binding_id, binding_revision, binding_hash
    )
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CHECK (
    (delivery_revision = 1 AND status = 'usable' AND previous_delivery_hash IS NULL)
    OR
    (delivery_revision = 2 AND status = 'disabled' AND previous_delivery_hash IS NOT NULL)
  )
) STRICT;

CREATE UNIQUE INDEX source_delivery_authority_unique_locator_v1
  ON source_delivery_authority_records_v1 (tenant_id, locator_identity_hash)
  WHERE delivery_revision = 1;
CREATE INDEX source_delivery_authority_records_tenant_v1
  ON source_delivery_authority_records_v1 (tenant_id, delivery_id, delivery_revision);

CREATE TRIGGER source_delivery_authority_records_v1_no_update
BEFORE UPDATE ON source_delivery_authority_records_v1
BEGIN SELECT RAISE(ABORT, 'source delivery records are immutable'); END;
CREATE TRIGGER source_delivery_authority_records_v1_no_delete
BEFORE DELETE ON source_delivery_authority_records_v1
BEGIN SELECT RAISE(ABORT, 'source delivery records are immutable'); END;

CREATE TABLE source_delivery_authority_audit_v1 (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  tenant_sequence INTEGER NOT NULL CHECK (tenant_sequence > 0),
  event_id TEXT NOT NULL CHECK (length(event_id) BETWEEN 1 AND 128),
  event_type TEXT NOT NULL CHECK (event_type IN ('source_delivery_registered', 'source_delivery_disabled')),
  delivery_id TEXT NOT NULL,
  delivery_revision INTEGER NOT NULL,
  delivery_hash TEXT NOT NULL,
  actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
  occurred_at TEXT NOT NULL,
  previous_event_hash TEXT CHECK (previous_event_hash IS NULL OR (length(previous_event_hash) = 71 AND previous_event_hash GLOB 'sha256:*')),
  event_hash TEXT NOT NULL CHECK (length(event_hash) = 71 AND event_hash GLOB 'sha256:*'),
  event_json TEXT NOT NULL CHECK (json_valid(event_json)),
  PRIMARY KEY (tenant_id, tenant_sequence),
  UNIQUE (tenant_id, event_id),
  UNIQUE (tenant_id, event_hash),
  UNIQUE (tenant_id, delivery_id, delivery_revision),
  FOREIGN KEY (tenant_id, delivery_id, delivery_revision)
    REFERENCES source_delivery_authority_records_v1 (tenant_id, delivery_id, delivery_revision)
    ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER source_delivery_authority_audit_v1_no_update
BEFORE UPDATE ON source_delivery_authority_audit_v1
BEGIN SELECT RAISE(ABORT, 'source-delivery audit events are immutable'); END;
CREATE TRIGGER source_delivery_authority_audit_v1_no_delete
BEFORE DELETE ON source_delivery_authority_audit_v1
BEGIN SELECT RAISE(ABORT, 'source-delivery audit events are immutable'); END;

CREATE TABLE source_delivery_authority_idempotency_v1 (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  operation TEXT NOT NULL CHECK (operation IN ('register', 'disable')),
  actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
  idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  request_hash TEXT NOT NULL CHECK (length(request_hash) = 71 AND request_hash GLOB 'sha256:*'),
  request_json TEXT NOT NULL CHECK (json_valid(request_json)),
  delivery_id TEXT NOT NULL,
  delivery_revision INTEGER NOT NULL,
  delivery_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  receipt_hash TEXT NOT NULL CHECK (length(receipt_hash) = 71 AND receipt_hash GLOB 'sha256:*'),
  PRIMARY KEY (tenant_id, operation, actor_id, idempotency_key),
  UNIQUE (tenant_id, delivery_id, delivery_revision),
  FOREIGN KEY (tenant_id, delivery_id, delivery_revision)
    REFERENCES source_delivery_authority_records_v1 (tenant_id, delivery_id, delivery_revision)
    ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER source_delivery_authority_idempotency_v1_no_update
BEFORE UPDATE ON source_delivery_authority_idempotency_v1
BEGIN SELECT RAISE(ABORT, 'source-delivery idempotency receipts are immutable'); END;
CREATE TRIGGER source_delivery_authority_idempotency_v1_no_delete
BEFORE DELETE ON source_delivery_authority_idempotency_v1
BEGIN SELECT RAISE(ABORT, 'source-delivery idempotency receipts are immutable'); END;
`;

export const SQLITE_SOURCE_DELIVERY_AUTHORITY_MIGRATIONS = Object.freeze([
  { version: 1, sql: SQLITE_SOURCE_DELIVERY_AUTHORITY_SCHEMA }
] as const satisfies readonly SqliteComponentMigration[]);

export type SourceDeliveryAuthorityErrorCode =
  | "INVALID_ARGUMENT"
  | "OPERATOR_REQUIRED"
  | "NOT_FOUND"
  | "ALREADY_EXISTS"
  | "IDEMPOTENCY_CONFLICT"
  | "DELIVERY_DISABLED"
  | "CLOCK_ROLLBACK"
  | "INTEGRITY_FAILURE"
  | "STORE_CLOSED";

export class SourceDeliveryAuthorityError extends Error {
  constructor(readonly code: SourceDeliveryAuthorityErrorCode, message: string) {
    super(message);
    this.name = "SourceDeliveryAuthorityError";
  }
}

export interface SqliteSourceDeliveryAuthorityOptionsV1 {
  readonly clock?: () => Date;
  readonly eventId?: () => string;
  readonly busyTimeoutMs?: number;
}

interface SourceContractRow {
  readonly tenant_id: string;
  readonly source_contract_id: string;
  readonly source_contract_revision: number;
  readonly source_contract_hash: string;
  readonly document_json: string;
}

interface BindingRow {
  readonly tenant_id: string;
  readonly binding_id: string;
  readonly binding_revision: number;
  readonly binding_hash: string;
  readonly source_contract_id: string;
  readonly source_contract_revision: number;
  readonly source_contract_hash: string;
  readonly dataset_id: string;
  readonly facility_id: string;
  readonly document_json: string;
}

interface DeliveryRow {
  readonly tenant_id: string;
  readonly delivery_id: string;
  readonly delivery_revision: number;
  readonly status: string;
  readonly delivery_hash: string;
  readonly previous_delivery_hash: string | null;
  readonly source_contract_id: string;
  readonly source_contract_revision: number;
  readonly source_contract_hash: string;
  readonly binding_id: string;
  readonly binding_revision: number;
  readonly binding_hash: string;
  readonly dataset_id: string;
  readonly facility_id: string;
  readonly locator_identity_hash: string;
  readonly source_observed_at: string;
  readonly received_at: string;
  readonly recorded_at: string;
  readonly record_json: string;
}

interface AuditRow {
  readonly tenant_id: string;
  readonly tenant_sequence: number;
  readonly event_id: string;
  readonly event_type: string;
  readonly delivery_id: string;
  readonly delivery_revision: number;
  readonly delivery_hash: string;
  readonly actor_id: string;
  readonly occurred_at: string;
  readonly previous_event_hash: string | null;
  readonly event_hash: string;
  readonly event_json: string;
}

interface IdempotencyRow {
  readonly request_hash: string;
  readonly request_json: string;
  readonly delivery_id: string;
  readonly delivery_revision: number;
  readonly delivery_hash: string;
  readonly created_at: string;
  readonly receipt_hash: string;
}

const TrustedActorSchema = z
  .object({
    tenantId: IdentifierSchema,
    actorId: IdentifierSchema,
    authority: z.literal("platform_operator"),
    identitySource: z.literal("server_derived")
  })
  .strict();

const AuditBodySchema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    tenantSequence: z.number().int().positive(),
    eventId: IdentifierSchema,
    eventType: z.enum(["source_delivery_registered", "source_delivery_disabled"]),
    deliveryId: IdentifierSchema,
    deliveryRevision: z.number().int().min(1).max(2),
    deliveryHash: Sha256HashSchema,
    actorId: IdentifierSchema,
    identitySource: z.literal("server_derived"),
    occurredAt: IsoTimestampSchema,
    previousEventHash: Sha256HashSchema.nullable()
  })
  .strict();

/**
 * Append-only delivery authority. Public resolution is IDs-only; paths,
 * source hashes, source versions, and actor identity are selected by the
 * server-held record rather than accepted from capture callers.
 */
export interface TrustedSourceDeliveryExtractionResolutionAuthorityV1 {
  resolveGovernedDeliveryForCapture(input: {
    readonly tenantId: string;
    readonly sourceContractId: string;
    readonly deliveryId: string;
  }): Promise<GovernedSourceDeliveryResolutionV1 | undefined>;

  resolveTrustedDeliveryForExtraction(input: {
    readonly tenantId: string;
    readonly deliveryId: string;
    readonly sourceContract: SourceContractV1;
    readonly scopeBinding: GovernedDatasetScopeBindingV1;
  }): Promise<GovernedSourceDeliveryResolutionV1 | undefined>;
}

export class SqliteSourceDeliveryAuthorityV1
  implements
    ActivatedSourceContractAuthorityV1,
    GovernedDatasetScopeBindingAuthorityV1,
    TrustedSourceDeliveryExtractionResolutionAuthorityV1
{
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;
  readonly #eventId: () => string;
  #closed = false;

  constructor(databasePath: string, options: SqliteSourceDeliveryAuthorityOptionsV1 = {}) {
    const path = requiredPath(databasePath);
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(path, { enableForeignKeyConstraints: true });
    this.#clock = options.clock ?? (() => new Date());
    this.#eventId = options.eventId ?? (() => `evt:${randomUUID().replaceAll("-", "")}`);
    const timeout = safeInteger(options.busyTimeoutMs ?? 5_000, "busyTimeoutMs", 0, 60_000);
    try {
      this.#database.exec(
        `PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${timeout};`
      );
      migrateSqliteComponent(this.#database, {
        componentName: SQLITE_SOURCE_DELIVERY_AUTHORITY_COMPONENT,
        supportedVersion: SQLITE_SOURCE_DELIVERY_AUTHORITY_SCHEMA_VERSION,
        migrations: SQLITE_SOURCE_DELIVERY_AUTHORITY_MIGRATIONS,
        unsupportedVersionError: (current, supported) =>
          integrity(`Source-delivery authority schema ${current} is newer than supported ${supported}`)
      });
      this.#verifyIntegrity();
    } catch (error) {
      this.#database.close();
      if (error instanceof SourceDeliveryAuthorityError) throw error;
      throw integrity("Source-delivery authority initialization failed", error);
    }
  }

  register(
    actorValue: TrustedSourceDeliveryActorV1,
    inputValue: RegisterGovernedSourceDeliveryV1
  ): GovernedSourceDeliveryMutationResultV1 {
    this.#assertOpen();
    const actor = trustedActor(actorValue);
    const input = registrationInput(inputValue);
    if (input.sourceContract.tenantId !== actor.tenantId || input.scopeBinding.tenantId !== actor.tenantId) {
      invalid("Registration evidence must belong to the server-derived actor tenant");
    }
    validateBinding(input.sourceContract, input.scopeBinding);
    validateLocator(input.sourceContract, input.locator);
    const recordedAt = this.#nextEventTime(actor.tenantId);
    if (input.sourceObservedAt > input.receivedAt || input.receivedAt > recordedAt) {
      invalid("Delivery timestamps must satisfy sourceObservedAt <= receivedAt <= recordedAt");
    }
    validateEffectivity(input.sourceContract, input.scopeBinding, input.sourceObservedAt);

    const request = deepFreeze({
      operation: "register" as const,
      tenantId: actor.tenantId,
      actorId: actor.actorId,
      deliveryId: input.deliveryId,
      sourceContract: {
        sourceContractId: input.sourceContract.sourceContractId,
        revision: input.sourceContract.revision,
        sourceContractHash: input.sourceContract.sourceContractHash
      },
      scopeBinding: {
        bindingId: input.scopeBinding.bindingId,
        revision: input.scopeBinding.revision,
        bindingHash: input.scopeBinding.bindingHash
      },
      locator: input.locator,
      sourceObservedAt: input.sourceObservedAt,
      receivedAt: input.receivedAt
    });
    const requestHash = canonicalHash(request);

    return this.#transaction(() => {
      const replay = this.#readReceipt(
        actor.tenantId,
        "register",
        actor.actorId,
        input.idempotencyKey,
        requestHash
      );
      if (replay) {
        return {
          resolution: this.#requiredResolutionAtRevision(
            actor.tenantId,
            replay.delivery_id,
            replay.delivery_revision,
            replay.delivery_hash
          ),
          replayed: true
        };
      }

      if (this.#currentDeliveryRow(actor.tenantId, input.deliveryId)) {
        throw new SourceDeliveryAuthorityError("ALREADY_EXISTS", "Delivery id is already registered");
      }
      if (this.#deliveryLocatorExists(actor.tenantId, input.locator)) {
        throw new SourceDeliveryAuthorityError(
          "ALREADY_EXISTS",
          "Immutable source locator/version is already registered in this tenant"
        );
      }
      this.#insertOrVerifySourceContract(input.sourceContract);
      this.#insertOrVerifyBinding(input.scopeBinding);

      const record = createGovernedSourceDeliveryRecordV1({
        contractVersion: 1,
        tenantId: actor.tenantId,
        deliveryId: input.deliveryId,
        deliveryRevision: 1,
        datasetId: input.scopeBinding.datasetId,
        facilityId: input.scopeBinding.scope.scopeId,
        sourceContract: request.sourceContract,
        scopeBinding: request.scopeBinding,
        locator: input.locator,
        sourceObservedAt: input.sourceObservedAt,
        receivedAt: input.receivedAt,
        status: "usable",
        recordedBy: actor.actorId,
        identitySource: "server_derived",
        recordedAt,
        previousDeliveryHash: null
      });
      this.#insertDelivery(record);
      this.#appendAudit(actor, record, "source_delivery_registered");
      this.#recordReceipt(
        actor,
        "register",
        input.idempotencyKey,
        requestHash,
        request,
        record
      );
      return { resolution: this.#requiredResolution(actor.tenantId, record.deliveryId), replayed: false };
    });
  }

  disable(
    actorValue: TrustedSourceDeliveryActorV1,
    inputValue: DisableGovernedSourceDeliveryV1
  ): GovernedSourceDeliveryMutationResultV1 {
    this.#assertOpen();
    const actor = trustedActor(actorValue);
    const input = disableInput(inputValue);
    const request = deepFreeze({
      operation: "disable" as const,
      tenantId: actor.tenantId,
      actorId: actor.actorId,
      deliveryId: input.deliveryId,
      reasonCode: input.reasonCode
    });
    const requestHash = canonicalHash(request);

    return this.#transaction(() => {
      const replay = this.#readReceipt(
        actor.tenantId,
        "disable",
        actor.actorId,
        input.idempotencyKey,
        requestHash
      );
      if (replay) {
        return {
          resolution: this.#requiredResolutionAtRevision(
            actor.tenantId,
            replay.delivery_id,
            replay.delivery_revision,
            replay.delivery_hash
          ),
          replayed: true
        };
      }

      const current = this.#requiredResolution(actor.tenantId, input.deliveryId);
      if (current.delivery.status === "disabled") {
        throw new SourceDeliveryAuthorityError("DELIVERY_DISABLED", "Delivery is already disabled");
      }
      const recordedAt = this.#nextEventTime(actor.tenantId);
      if (recordedAt < current.delivery.recordedAt) {
        throw new SourceDeliveryAuthorityError("CLOCK_ROLLBACK", "Disable clock moved behind delivery registration");
      }
      const record = createGovernedSourceDeliveryRecordV1({
        contractVersion: 1,
        tenantId: current.delivery.tenantId,
        deliveryId: current.delivery.deliveryId,
        deliveryRevision: 2,
        datasetId: current.delivery.datasetId,
        facilityId: current.delivery.facilityId,
        sourceContract: current.delivery.sourceContract,
        scopeBinding: current.delivery.scopeBinding,
        locator: current.delivery.locator,
        sourceObservedAt: current.delivery.sourceObservedAt,
        receivedAt: current.delivery.receivedAt,
        status: "disabled",
        statusReason: input.reasonCode,
        recordedBy: actor.actorId,
        identitySource: "server_derived",
        recordedAt,
        previousDeliveryHash: current.delivery.deliveryHash
      });
      this.#insertDelivery(record);
      this.#appendAudit(actor, record, "source_delivery_disabled");
      this.#recordReceipt(actor, "disable", input.idempotencyKey, requestHash, request, record);
      return { resolution: this.#requiredResolution(actor.tenantId, record.deliveryId), replayed: false };
    });
  }

  /** IDs-only safe inspection. Raw relation/object location remains on the trusted extraction port. */
  resolveDeliveryStatus(inputValue: {
    readonly tenantId: string;
    readonly deliveryId: string;
  }): Promise<GovernedSourceDeliveryStatusV1 | undefined> {
    this.#assertOpen();
    exactKeys(inputValue, ["deliveryId", "tenantId"], "delivery lookup");
    const tenantId = identifier(inputValue.tenantId, "tenantId");
    const deliveryId = identifier(inputValue.deliveryId, "deliveryId");
    const resolution = this.#resolution(tenantId, deliveryId);
    return Promise.resolve(resolution ? deliveryStatus(resolution.delivery) : undefined);
  }

  /** Trusted adapter preflight for an extraction implementation; never expose this result to operators. */
  resolveGovernedDeliveryForCapture(inputValue: {
    readonly tenantId: string;
    readonly sourceContractId: string;
    readonly deliveryId: string;
  }): Promise<GovernedSourceDeliveryResolutionV1 | undefined> {
    this.#assertOpen();
    exactKeys(
      inputValue,
      ["deliveryId", "sourceContractId", "tenantId"],
      "governed capture lookup"
    );
    const tenantId = identifier(inputValue.tenantId, "tenantId");
    const sourceContractId = identifier(inputValue.sourceContractId, "sourceContractId");
    const deliveryId = identifier(inputValue.deliveryId, "deliveryId");
    const resolution = this.#resolution(tenantId, deliveryId);
    if (
      !resolution ||
      resolution.delivery.status !== "usable" ||
      resolution.sourceContract.status !== "active" ||
      resolution.sourceContract.sourceContractId !== sourceContractId
    ) {
      return Promise.resolve(undefined);
    }
    const active = this.#activeSourceContract(tenantId, sourceContractId);
    if (!active || canonicalJson(active) !== canonicalJson(resolution.sourceContract)) {
      return Promise.resolve(undefined);
    }
    return Promise.resolve(resolution);
  }

  /** Trusted adapter preflight for an extraction implementation; never expose this result to operators. */
  resolveTrustedDeliveryForExtraction(inputValue: {
    readonly tenantId: string;
    readonly deliveryId: string;
    readonly sourceContract: SourceContractV1;
    readonly scopeBinding: GovernedDatasetScopeBindingV1;
  }): Promise<GovernedSourceDeliveryResolutionV1 | undefined> {
    this.#assertOpen();
    exactKeys(
      inputValue,
      ["deliveryId", "scopeBinding", "sourceContract", "tenantId"],
      "trusted extraction lookup"
    );
    const tenantId = identifier(inputValue.tenantId, "tenantId");
    const deliveryId = identifier(inputValue.deliveryId, "deliveryId");
    const source = sourceContract(inputValue.sourceContract);
    const binding = scopeBinding(inputValue.scopeBinding);
    const resolution = this.#resolution(tenantId, deliveryId);
    if (!resolution || resolution.delivery.status !== "usable") return Promise.resolve(undefined);
    const active = this.#activeSourceContract(tenantId, source.sourceContractId);
    if (
      !active ||
      canonicalJson(active) !== canonicalJson(source) ||
      canonicalJson(resolution.sourceContract) !== canonicalJson(source) ||
      canonicalJson(resolution.scopeBinding) !== canonicalJson(binding)
    ) {
      return Promise.resolve(undefined);
    }
    return Promise.resolve(resolution);
  }

  resolveActivatedSourceContract(inputValue: {
    readonly tenantId: string;
    readonly sourceContractId: string;
  }): Promise<SourceContractV1 | undefined> {
    this.#assertOpen();
    exactKeys(inputValue, ["sourceContractId", "tenantId"], "source-contract lookup");
    const tenantId = identifier(inputValue.tenantId, "tenantId");
    const sourceContractId = identifier(inputValue.sourceContractId, "sourceContractId");
    return Promise.resolve(this.#activeSourceContract(tenantId, sourceContractId));
  }

  resolveGovernedDatasetScopeBinding(inputValue: {
    readonly tenantId: string;
    readonly sourceContract: SourceContractV1;
    readonly deliveryId: string;
  }): Promise<GovernedDatasetScopeBindingV1 | undefined> {
    this.#assertOpen();
    exactKeys(inputValue, ["deliveryId", "sourceContract", "tenantId"], "scope-binding lookup");
    const tenantId = identifier(inputValue.tenantId, "tenantId");
    const deliveryId = identifier(inputValue.deliveryId, "deliveryId");
    const source = sourceContract(inputValue.sourceContract);
    if (source.tenantId !== tenantId) return Promise.resolve(undefined);
    const active = this.#activeSourceContract(tenantId, source.sourceContractId);
    if (!active || canonicalJson(active) !== canonicalJson(source)) return Promise.resolve(undefined);
    const resolution = this.#resolution(tenantId, deliveryId);
    if (!resolution || resolution.delivery.status !== "usable") return Promise.resolve(undefined);
    if (
      resolution.sourceContract.sourceContractId !== source.sourceContractId ||
      resolution.sourceContract.revision !== source.revision ||
      resolution.sourceContract.sourceContractHash !== source.sourceContractHash
    ) {
      return Promise.resolve(undefined);
    }
    return Promise.resolve(resolution.scopeBinding);
  }

  listAudit(
    tenantValue: string,
    afterTenantSequenceValue = 0,
    limitValue = 100
  ): readonly SourceDeliveryAuditEventV1[] {
    this.#assertOpen();
    const tenantId = identifier(tenantValue, "tenantId");
    const afterTenantSequence = safeInteger(
      afterTenantSequenceValue,
      "afterTenantSequence",
      0,
      Number.MAX_SAFE_INTEGER
    );
    const limit = safeInteger(limitValue, "limit", 1, 1_000);
    const rows = this.#database
      .prepare(
        `SELECT * FROM source_delivery_authority_audit_v1
          WHERE tenant_id = ? AND tenant_sequence > ?
          ORDER BY tenant_sequence LIMIT ?`
      )
      .all(tenantId, afterTenantSequence, limit) as unknown as AuditRow[];
    return Object.freeze(rows.map((row) => auditFromRow(row)));
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#database.close();
  }

  #resolution(tenantId: string, deliveryId: string): GovernedSourceDeliveryResolutionV1 | undefined {
    const row = this.#currentDeliveryRow(tenantId, deliveryId);
    if (!row) return undefined;
    const delivery = deliveryFromRow(row);
    const sourceRow = this.#database
      .prepare(
        `SELECT * FROM source_delivery_authority_source_contracts_v1
          WHERE tenant_id = ? AND source_contract_id = ?
            AND source_contract_revision = ? AND source_contract_hash = ?`
      )
      .get(
        tenantId,
        delivery.sourceContract.sourceContractId,
        delivery.sourceContract.revision,
        delivery.sourceContract.sourceContractHash
      ) as SourceContractRow | undefined;
    const bindingRow = this.#database
      .prepare(
        `SELECT * FROM source_delivery_authority_scope_bindings_v1
          WHERE tenant_id = ? AND binding_id = ? AND binding_revision = ? AND binding_hash = ?`
      )
      .get(
        tenantId,
        delivery.scopeBinding.bindingId,
        delivery.scopeBinding.revision,
        delivery.scopeBinding.bindingHash
      ) as BindingRow | undefined;
    if (!sourceRow || !bindingRow) throw integrity("Delivery evidence references missing authority documents");
    const source = sourceFromRow(sourceRow);
    const binding = bindingFromRow(bindingRow);
    verifyResolution(delivery, source, binding);
    return deepFreeze({ delivery, sourceContract: source, scopeBinding: binding });
  }

  #requiredResolution(tenantId: string, deliveryId: string): GovernedSourceDeliveryResolutionV1 {
    const result = this.#resolution(tenantId, deliveryId);
    if (!result) throw new SourceDeliveryAuthorityError("NOT_FOUND", "Delivery was not found in this tenant");
    return result;
  }

  #requiredResolutionAtRevision(
    tenantId: string,
    deliveryId: string,
    deliveryRevision: number,
    expectedHash: string
  ): GovernedSourceDeliveryResolutionV1 {
    const row = this.#database
      .prepare(
        `SELECT * FROM source_delivery_authority_records_v1
          WHERE tenant_id = ? AND delivery_id = ? AND delivery_revision = ?`
      )
      .get(tenantId, deliveryId, deliveryRevision) as DeliveryRow | undefined;
    if (!row) throw integrity("Idempotency receipt references a missing delivery revision");
    const delivery = deliveryFromRow(row);
    if (delivery.deliveryHash !== expectedHash) {
      throw integrity("Idempotency receipt references a substituted delivery hash");
    }
    const sourceRow = this.#database
      .prepare(
        `SELECT * FROM source_delivery_authority_source_contracts_v1
          WHERE tenant_id = ? AND source_contract_id = ?
            AND source_contract_revision = ? AND source_contract_hash = ?`
      )
      .get(
        tenantId,
        delivery.sourceContract.sourceContractId,
        delivery.sourceContract.revision,
        delivery.sourceContract.sourceContractHash
      ) as SourceContractRow | undefined;
    const bindingRow = this.#database
      .prepare(
        `SELECT * FROM source_delivery_authority_scope_bindings_v1
          WHERE tenant_id = ? AND binding_id = ? AND binding_revision = ? AND binding_hash = ?`
      )
      .get(
        tenantId,
        delivery.scopeBinding.bindingId,
        delivery.scopeBinding.revision,
        delivery.scopeBinding.bindingHash
      ) as BindingRow | undefined;
    if (!sourceRow || !bindingRow) throw integrity("Delivery revision references missing authority documents");
    const source = sourceFromRow(sourceRow);
    const binding = bindingFromRow(bindingRow);
    verifyResolution(delivery, source, binding);
    return deepFreeze({ delivery, sourceContract: source, scopeBinding: binding });
  }

  #currentDeliveryRow(tenantId: string, deliveryId: string): DeliveryRow | undefined {
    return this.#database
      .prepare(
        `SELECT * FROM source_delivery_authority_records_v1
          WHERE tenant_id = ? AND delivery_id = ?
          ORDER BY delivery_revision DESC LIMIT 1`
      )
      .get(tenantId, deliveryId) as DeliveryRow | undefined;
  }

  #activeSourceContract(tenantId: string, sourceContractId: string): SourceContractV1 | undefined {
    const rows = this.#database
      .prepare(
        `SELECT * FROM source_delivery_authority_source_contracts_v1
          WHERE tenant_id = ? AND source_contract_id = ?
          ORDER BY source_contract_revision DESC`
      )
      .all(tenantId, sourceContractId) as unknown as SourceContractRow[];
    return rows.map((row) => sourceFromRow(row)).find((source) => source.status === "active");
  }

  #deliveryLocatorExists(tenantId: string, locator: GovernedSourceDeliveryLocatorV1): boolean {
    return this.#database
      .prepare(
        `SELECT 1 FROM source_delivery_authority_records_v1
          WHERE tenant_id = ? AND delivery_revision = 1 AND locator_identity_hash = ?`
      )
      .get(tenantId, locatorIdentityHash(locator)) !== undefined;
  }

  #insertOrVerifySourceContract(source: SourceContractV1): void {
    const existing = this.#database
      .prepare(
        `SELECT * FROM source_delivery_authority_source_contracts_v1
          WHERE tenant_id = ? AND source_contract_id = ? AND source_contract_revision = ?`
      )
      .get(source.tenantId, source.sourceContractId, source.revision) as SourceContractRow | undefined;
    if (existing) {
      const actual = sourceFromRow(existing);
      if (canonicalJson(actual) !== canonicalJson(source)) {
        throw new SourceDeliveryAuthorityError(
          "ALREADY_EXISTS",
          "Source-contract id is already bound to another exact revision or hash"
        );
      }
      return;
    }
    this.#database
      .prepare(
        `INSERT INTO source_delivery_authority_source_contracts_v1 (
          tenant_id, source_contract_id, source_contract_revision,
          source_contract_hash, document_json
        ) VALUES (?, ?, ?, ?, ?)`
      )
      .run(
        source.tenantId,
        source.sourceContractId,
        source.revision,
        source.sourceContractHash,
        canonicalJson(source)
      );
  }

  #insertOrVerifyBinding(binding: GovernedDatasetScopeBindingV1): void {
    const existing = this.#database
      .prepare(
        `SELECT * FROM source_delivery_authority_scope_bindings_v1
          WHERE tenant_id = ? AND binding_id = ? AND binding_revision = ?`
      )
      .get(binding.tenantId, binding.bindingId, binding.revision) as BindingRow | undefined;
    if (existing) {
      const actual = bindingFromRow(existing);
      if (canonicalJson(actual) !== canonicalJson(binding)) {
        throw new SourceDeliveryAuthorityError(
          "ALREADY_EXISTS",
          "Scope-binding id is already bound to another exact revision or hash"
        );
      }
      return;
    }
    this.#database
      .prepare(
        `INSERT INTO source_delivery_authority_scope_bindings_v1 (
          tenant_id, binding_id, binding_revision, binding_hash,
          source_contract_id, source_contract_revision, source_contract_hash,
          dataset_id, facility_id, document_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        binding.tenantId,
        binding.bindingId,
        binding.revision,
        binding.bindingHash,
        binding.sourceContract.sourceContractId,
        binding.sourceContract.revision,
        binding.sourceContract.sourceContractHash,
        binding.datasetId,
        binding.scope.scopeId,
        canonicalJson(binding)
      );
  }

  #insertDelivery(record: GovernedSourceDeliveryRecordV1): void {
    try {
      this.#database
        .prepare(
          `INSERT INTO source_delivery_authority_records_v1 (
            tenant_id, delivery_id, delivery_revision, status, delivery_hash,
            previous_delivery_hash, source_contract_id, source_contract_revision,
            source_contract_hash, binding_id, binding_revision, binding_hash,
            dataset_id, facility_id, locator_identity_hash, source_observed_at,
            received_at, recorded_at, record_json
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          record.tenantId,
          record.deliveryId,
          record.deliveryRevision,
          record.status,
          record.deliveryHash,
          record.previousDeliveryHash,
          record.sourceContract.sourceContractId,
          record.sourceContract.revision,
          record.sourceContract.sourceContractHash,
          record.scopeBinding.bindingId,
          record.scopeBinding.revision,
          record.scopeBinding.bindingHash,
          record.datasetId,
          record.facilityId,
          locatorIdentityHash(record.locator),
          record.sourceObservedAt,
          record.receivedAt,
          record.recordedAt,
          canonicalJson(record)
        );
    } catch (error) {
      if (
        String(error).includes("source_delivery_authority_unique_locator_v1") ||
        String(error).includes("source_delivery_authority_records_v1.tenant_id") &&
          String(error).includes("source_delivery_authority_records_v1.locator_identity_hash")
      ) {
        throw new SourceDeliveryAuthorityError(
          "ALREADY_EXISTS",
          "Immutable source locator/version is already registered in this tenant"
        );
      }
      throw error;
    }
  }

  #appendAudit(
    actor: TrustedSourceDeliveryActorV1,
    record: GovernedSourceDeliveryRecordV1,
    eventType: "source_delivery_registered" | "source_delivery_disabled"
  ): void {
    const previous = this.#database
      .prepare(
        `SELECT tenant_sequence, occurred_at, event_hash
           FROM source_delivery_authority_audit_v1
          WHERE tenant_id = ? ORDER BY tenant_sequence DESC LIMIT 1`
      )
      .get(actor.tenantId) as
      | { readonly tenant_sequence: number; readonly occurred_at: string; readonly event_hash: string }
      | undefined;
    if (previous && record.recordedAt < previous.occurred_at) {
      throw new SourceDeliveryAuthorityError("CLOCK_ROLLBACK", "Audit clock moved behind its tenant chain");
    }
    const body = parseWithSchema(
      AuditBodySchema,
      {
        contractVersion: 1,
        tenantId: actor.tenantId,
        tenantSequence: (previous?.tenant_sequence ?? 0) + 1,
        eventId: identifier(this.#eventId(), "eventId"),
        eventType,
        deliveryId: record.deliveryId,
        deliveryRevision: record.deliveryRevision,
        deliveryHash: record.deliveryHash,
        actorId: actor.actorId,
        identitySource: "server_derived",
        occurredAt: record.recordedAt,
        previousEventHash: (previous?.event_hash as Sha256Hash | undefined) ?? null
      },
      "SourceDeliveryAuditEventV1"
    );
    const eventHash = canonicalHash(body);
    this.#database
      .prepare(
        `INSERT INTO source_delivery_authority_audit_v1 (
          tenant_id, tenant_sequence, event_id, event_type, delivery_id,
          delivery_revision, delivery_hash, actor_id, occurred_at,
          previous_event_hash, event_hash, event_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        body.tenantId,
        body.tenantSequence,
        body.eventId,
        body.eventType,
        body.deliveryId,
        body.deliveryRevision,
        body.deliveryHash,
        body.actorId,
        body.occurredAt,
        body.previousEventHash,
        eventHash,
        canonicalJson(body)
      );
  }

  #readReceipt(
    tenantId: string,
    operation: "register" | "disable",
    actorId: string,
    idempotencyKey: string,
    requestHash: Sha256Hash
  ): IdempotencyRow | undefined {
    const row = this.#database
      .prepare(
        `SELECT request_hash, request_json, delivery_id, delivery_revision, delivery_hash, created_at, receipt_hash
           FROM source_delivery_authority_idempotency_v1
          WHERE tenant_id = ? AND operation = ? AND actor_id = ? AND idempotency_key = ?`
      )
      .get(tenantId, operation, actorId, idempotencyKey) as IdempotencyRow | undefined;
    if (row && row.request_hash !== requestHash) {
      throw new SourceDeliveryAuthorityError(
        "IDEMPOTENCY_CONFLICT",
        "Actor-scoped idempotency key is bound to another request"
      );
    }
    return row;
  }

  #recordReceipt(
    actor: TrustedSourceDeliveryActorV1,
    operation: "register" | "disable",
    idempotencyKey: string,
    requestHash: Sha256Hash,
    request: object,
    record: GovernedSourceDeliveryRecordV1
  ): void {
    this.#database
      .prepare(
        `INSERT INTO source_delivery_authority_idempotency_v1 (
          tenant_id, operation, actor_id, idempotency_key, request_hash,
          request_json, delivery_id, delivery_revision, delivery_hash, created_at, receipt_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        actor.tenantId,
        operation,
        actor.actorId,
        idempotencyKey,
        requestHash,
        canonicalJson(request),
        record.deliveryId,
        record.deliveryRevision,
        record.deliveryHash,
        record.recordedAt,
        receiptHash({
          tenantId: actor.tenantId,
          operation,
          actorId: actor.actorId,
          idempotencyKey,
          requestHash,
          deliveryId: record.deliveryId,
          deliveryRevision: record.deliveryRevision,
          deliveryHash: record.deliveryHash,
          createdAt: record.recordedAt
        })
      );
  }

  #nextEventTime(tenantId: string): string {
    const value = this.#clock();
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) invalid("Authority clock is invalid");
    const now = parseWithSchema(IsoTimestampSchema, value.toISOString(), "authority clock");
    const last = this.#database
      .prepare(
        `SELECT occurred_at FROM source_delivery_authority_audit_v1
          WHERE tenant_id = ? ORDER BY tenant_sequence DESC LIMIT 1`
      )
      .get(tenantId) as { readonly occurred_at: string } | undefined;
    if (last && now < last.occurred_at) {
      throw new SourceDeliveryAuthorityError("CLOCK_ROLLBACK", "Authority clock moved behind its audit chain");
    }
    return now;
  }

  #verifyIntegrity(): void {
    const sourceRows = this.#database
      .prepare("SELECT * FROM source_delivery_authority_source_contracts_v1 ORDER BY tenant_id, source_contract_id")
      .all() as unknown as SourceContractRow[];
    for (const row of sourceRows) sourceFromRow(row);

    const bindingRows = this.#database
      .prepare("SELECT * FROM source_delivery_authority_scope_bindings_v1 ORDER BY tenant_id, binding_id")
      .all() as unknown as BindingRow[];
    for (const row of bindingRows) bindingFromRow(row);

    const deliveryRows = this.#database
      .prepare(
        "SELECT * FROM source_delivery_authority_records_v1 ORDER BY tenant_id, delivery_id, delivery_revision"
      )
      .all() as unknown as DeliveryRow[];
    const deliveries = new Map<string, GovernedSourceDeliveryRecordV1[]>();
    for (const row of deliveryRows) {
      const record = deliveryFromRow(row);
      const key = `${record.tenantId}\u0000${record.deliveryId}`;
      const history = deliveries.get(key) ?? [];
      history.push(record);
      deliveries.set(key, history);
      this.#requiredResolution(record.tenantId, record.deliveryId);
    }
    for (const history of deliveries.values()) {
      if (history.length < 1 || history.length > 2 || history[0]?.deliveryRevision !== 1) {
        throw integrity("Delivery revision history is incomplete or non-contiguous");
      }
      if (
        history[1] &&
        (history[1].deliveryRevision !== 2 ||
          history[1].previousDeliveryHash !== history[0]?.deliveryHash ||
          !sameImmutableDeliveryEvidence(history[0], history[1]))
      ) {
        throw integrity("Delivery disable record broke immutable evidence lineage");
      }
    }

    const auditRows = this.#database
      .prepare("SELECT * FROM source_delivery_authority_audit_v1 ORDER BY tenant_id, tenant_sequence")
      .all() as unknown as AuditRow[];
    const sequenceByTenant = new Map<string, number>();
    const hashByTenant = new Map<string, Sha256Hash | null>();
    const timeByTenant = new Map<string, string>();
    for (const row of auditRows) {
      const event = auditFromRow(row);
      const expectedSequence = (sequenceByTenant.get(event.tenantId) ?? 0) + 1;
      const expectedPrevious = hashByTenant.get(event.tenantId) ?? null;
      const previousTime = timeByTenant.get(event.tenantId);
      if (
        event.tenantSequence !== expectedSequence ||
        event.previousEventHash !== expectedPrevious ||
        (previousTime !== undefined && event.occurredAt < previousTime)
      ) {
        throw integrity("Source-delivery tenant audit chain is invalid");
      }
      const delivery = this.#database
        .prepare(
          `SELECT delivery_hash, recorded_at, record_json FROM source_delivery_authority_records_v1
            WHERE tenant_id = ? AND delivery_id = ? AND delivery_revision = ?`
        )
        .get(event.tenantId, event.deliveryId, event.deliveryRevision) as
        | { readonly delivery_hash: string; readonly recorded_at: string; readonly record_json: string }
        | undefined;
      const deliveryRecord = delivery
        ? parseGovernedSourceDeliveryRecordV1(
            parseCanonicalJson(delivery.record_json, "audit-linked delivery")
          )
        : undefined;
      const expectedEventType = deliveryRecord?.status === "usable"
        ? "source_delivery_registered"
        : "source_delivery_disabled";
      if (
        !delivery ||
        !deliveryRecord ||
        delivery.delivery_hash !== event.deliveryHash ||
        delivery.recorded_at !== event.occurredAt ||
        deliveryRecord.recordedBy !== event.actorId ||
        event.eventType !== expectedEventType
      ) {
        throw integrity("Source-delivery audit event references substituted evidence");
      }
      sequenceByTenant.set(event.tenantId, event.tenantSequence);
      hashByTenant.set(event.tenantId, event.eventHash);
      timeByTenant.set(event.tenantId, event.occurredAt);
    }
    if (auditRows.length !== deliveryRows.length) {
      throw integrity("Every source-delivery revision must have exactly one audit event");
    }

    const receipts = this.#database
      .prepare("SELECT * FROM source_delivery_authority_idempotency_v1")
      .all() as unknown as (IdempotencyRow & {
      readonly tenant_id: string;
      readonly operation: string;
      readonly actor_id: string;
      readonly idempotency_key: string;
    })[];
    for (const receipt of receipts) {
      const request = parseCanonicalJson(receipt.request_json, "idempotency request");
      if (canonicalHash(request) !== receipt.request_hash) {
        throw integrity("Source-delivery idempotency request hash is invalid");
      }
      identifier(receipt.tenant_id, "idempotency tenantId");
      identifier(receipt.actor_id, "idempotency actorId");
      identifier(receipt.idempotency_key, "idempotency key");
      if (receipt.operation !== "register" && receipt.operation !== "disable") {
        throw integrity("Source-delivery idempotency operation is invalid");
      }
      if (
        (receipt.operation === "register" && receipt.delivery_revision !== 1) ||
        (receipt.operation === "disable" && receipt.delivery_revision !== 2)
      ) {
        throw integrity("Source-delivery idempotency operation does not match delivery revision");
      }
      if (
        request === null ||
        typeof request !== "object" ||
        Array.isArray(request) ||
        (request as Record<string, unknown>).operation !== receipt.operation ||
        (request as Record<string, unknown>).tenantId !== receipt.tenant_id ||
        (request as Record<string, unknown>).actorId !== receipt.actor_id ||
        (request as Record<string, unknown>).deliveryId !== receipt.delivery_id
      ) {
        throw integrity("Source-delivery idempotency request does not match receipt scope");
      }
      const row = this.#database
        .prepare(
          `SELECT delivery_hash, recorded_at, record_json FROM source_delivery_authority_records_v1
            WHERE tenant_id = ? AND delivery_id = ? AND delivery_revision = ?`
        )
        .get(receipt.tenant_id, receipt.delivery_id, receipt.delivery_revision) as
        | { readonly delivery_hash: string; readonly recorded_at: string; readonly record_json: string }
        | undefined;
      const receiptDelivery = row
        ? parseGovernedSourceDeliveryRecordV1(
            parseCanonicalJson(row.record_json, "idempotency-linked delivery")
          )
        : undefined;
      const expectedReceiptHash = receiptHash({
        tenantId: receipt.tenant_id,
        operation: receipt.operation,
        actorId: receipt.actor_id,
        idempotencyKey: receipt.idempotency_key,
        requestHash: receipt.request_hash as Sha256Hash,
        deliveryId: receipt.delivery_id,
        deliveryRevision: receipt.delivery_revision,
        deliveryHash: receipt.delivery_hash as Sha256Hash,
        createdAt: receipt.created_at
      });
      if (
        !row ||
        !receiptDelivery ||
        row.delivery_hash !== receipt.delivery_hash ||
        row.recorded_at !== receipt.created_at ||
        receiptDelivery.recordedBy !== receipt.actor_id ||
        receipt.receipt_hash !== expectedReceiptHash
      ) {
        throw integrity("Source-delivery idempotency receipt references substituted evidence");
      }
    }
    if (receipts.length !== deliveryRows.length) {
      throw integrity("Every source-delivery revision must have exactly one idempotency receipt");
    }
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
      if (error instanceof SourceDeliveryAuthorityError) throw error;
      throw integrity("Source-delivery authority transaction failed", error);
    }
  }

  #assertOpen(): void {
    if (this.#closed) throw new SourceDeliveryAuthorityError("STORE_CLOSED", "Authority is closed");
  }
}

function registrationInput(inputValue: RegisterGovernedSourceDeliveryV1): RegisterGovernedSourceDeliveryV1 {
  try {
    exactKeys(
      inputValue,
      [
        "deliveryId",
        "idempotencyKey",
        "locator",
        "receivedAt",
        "scopeBinding",
        "sourceContract",
        "sourceObservedAt"
      ],
      "registration input"
    );
    const source = parseSourceContractV1(inputValue.sourceContract);
    const binding = parseGovernedDatasetScopeBindingV1(inputValue.scopeBinding);
    const locator = parseWithSchema(
      GovernedSourceDeliveryLocatorV1Schema,
      inputValue.locator,
      "GovernedSourceDeliveryLocatorV1"
    );
    return deepFreeze({
      deliveryId: identifier(inputValue.deliveryId, "deliveryId"),
      sourceContract: source,
      scopeBinding: binding,
      locator,
      sourceObservedAt: timestamp(inputValue.sourceObservedAt, "sourceObservedAt"),
      receivedAt: timestamp(inputValue.receivedAt, "receivedAt"),
      idempotencyKey: identifier(inputValue.idempotencyKey, "idempotencyKey")
    });
  } catch (error) {
    if (error instanceof SourceDeliveryAuthorityError) throw error;
    invalid("Registration input failed contract validation");
  }
}

function disableInput(inputValue: DisableGovernedSourceDeliveryV1): DisableGovernedSourceDeliveryV1 {
  exactKeys(inputValue, ["deliveryId", "idempotencyKey", "reasonCode"], "disable input");
  return deepFreeze({
    deliveryId: identifier(inputValue.deliveryId, "deliveryId"),
    reasonCode: identifier(inputValue.reasonCode, "reasonCode"),
    idempotencyKey: identifier(inputValue.idempotencyKey, "idempotencyKey")
  });
}

function trustedActor(value: TrustedSourceDeliveryActorV1): TrustedSourceDeliveryActorV1 {
  try {
    return parseWithSchema(TrustedActorSchema, value, "TrustedSourceDeliveryActorV1");
  } catch (error) {
    throw new SourceDeliveryAuthorityError("OPERATOR_REQUIRED", "Server-derived platform operator is required");
  }
}

function validateBinding(source: SourceContractV1, binding: GovernedDatasetScopeBindingV1): void {
  // A lifecycle resolver projects an executable source contract with its
  // immutable approval evidence as `approved`; the legacy trusted-import
  // path may still carry an already materialized `active` source contract.
  // Neither state is authority on its own — lifecycle-backed registration
  // verifies the governed version before it reaches this catalog.
  if (source.status !== "active" && source.status !== "approved") {
    invalid("Source contract must be active or lifecycle-approved");
  }
  if (
    binding.sourceContract.sourceContractId !== source.sourceContractId ||
    binding.sourceContract.revision !== source.revision ||
    binding.sourceContract.sourceContractHash !== source.sourceContractHash
  ) {
    invalid("Scope binding must reference the exact active source-contract revision and hash");
  }
  if (binding.scope.scopeType !== "facility") {
    invalid("Delivery authority requires a facility-scoped dataset binding");
  }
}

function validateLocator(source: SourceContractV1, locator: GovernedSourceDeliveryLocatorV1): void {
  if (source.delivery.mode !== locator.mode) invalid("Delivery locator mode must match source contract");
  if (source.delivery.mode === "postgresql_pull" && locator.mode === "postgresql_pull") {
    if (
      source.delivery.connectorId !== locator.connectorId ||
      source.delivery.catalog !== locator.catalog ||
      source.delivery.schema !== locator.schema ||
      source.delivery.relation !== locator.relation
    ) {
      invalid("PostgreSQL relation identity must match its source contract exactly");
    }
    const relationIdentity = canonicalHash({
      connectorId: locator.connectorId,
      catalog: locator.catalog ?? null,
      schema: locator.schema,
      relation: locator.relation
    });
    if (relationIdentity !== locator.relationIdentityHash) {
      invalid("PostgreSQL relation identity hash does not match its canonical relation");
    }
    if (
      (source.extractionPolicy.mode === "watermark" && locator.watermark === undefined) ||
      (source.extractionPolicy.mode === "full" && locator.watermark !== undefined)
    ) {
      invalid("PostgreSQL watermark evidence must match the extraction policy");
    }
    return;
  }
  if (source.delivery.mode === "object_storage" && locator.mode === "object_storage") {
    if (
      source.delivery.connectorId !== locator.connectorId ||
      source.delivery.bucket !== locator.bucket ||
      source.delivery.format !== locator.format ||
      !safeGlobMatch(source.delivery.keyPattern, locator.objectKey)
    ) {
      invalid("Object locator must match its governed connector, bucket, format, and key pattern");
    }
    if (
      canonicalHash({
        connectorId: locator.connectorId,
        bucket: locator.bucket,
        objectKey: locator.objectKey,
        immutableVersionId: locator.immutableVersionId
      }) !== locator.immutableVersionHash
    ) {
      invalid("Object immutable version hash is invalid");
    }
    return;
  }
  invalid("Unsupported source-delivery locator");
}

function validateEffectivity(
  source: SourceContractV1,
  binding: GovernedDatasetScopeBindingV1,
  sourceObservedAt: string
): void {
  const date = sourceObservedAt.slice(0, 10);
  if (
    date < source.effectiveFrom ||
    (source.effectiveTo !== undefined && date >= source.effectiveTo) ||
    date < binding.effectiveFrom ||
    (binding.effectiveTo !== undefined && date >= binding.effectiveTo)
  ) {
    invalid("Delivery observation falls outside source-contract or scope-binding effectivity");
  }
}

function verifyResolution(
  delivery: GovernedSourceDeliveryRecordV1,
  source: SourceContractV1,
  binding: GovernedDatasetScopeBindingV1
): void {
  if (
    delivery.tenantId !== source.tenantId ||
    delivery.tenantId !== binding.tenantId ||
    delivery.sourceContract.sourceContractId !== source.sourceContractId ||
    delivery.sourceContract.revision !== source.revision ||
    delivery.sourceContract.sourceContractHash !== source.sourceContractHash ||
    delivery.scopeBinding.bindingId !== binding.bindingId ||
    delivery.scopeBinding.revision !== binding.revision ||
    delivery.scopeBinding.bindingHash !== binding.bindingHash ||
    delivery.datasetId !== binding.datasetId ||
    delivery.facilityId !== binding.scope.scopeId
  ) {
    throw integrity("Delivery resolution does not match its exact governed documents");
  }
  validateBinding(source, binding);
  validateLocator(source, delivery.locator);
  validateEffectivity(source, binding, delivery.sourceObservedAt);
}

function sourceFromRow(row: SourceContractRow): SourceContractV1 {
  const source = sourceContract(parseCanonicalJson(row.document_json, "source contract"));
  if (
    source.tenantId !== row.tenant_id ||
    source.sourceContractId !== row.source_contract_id ||
    source.revision !== row.source_contract_revision ||
    source.sourceContractHash !== row.source_contract_hash
  ) {
    throw integrity("Stored source-contract columns do not match canonical evidence");
  }
  return source;
}

function bindingFromRow(row: BindingRow): GovernedDatasetScopeBindingV1 {
  const binding = scopeBinding(parseCanonicalJson(row.document_json, "scope binding"));
  if (
    binding.tenantId !== row.tenant_id ||
    binding.bindingId !== row.binding_id ||
    binding.revision !== row.binding_revision ||
    binding.bindingHash !== row.binding_hash ||
    binding.sourceContract.sourceContractId !== row.source_contract_id ||
    binding.sourceContract.revision !== row.source_contract_revision ||
    binding.sourceContract.sourceContractHash !== row.source_contract_hash ||
    binding.datasetId !== row.dataset_id ||
    binding.scope.scopeId !== row.facility_id
  ) {
    throw integrity("Stored scope-binding columns do not match canonical evidence");
  }
  return binding;
}

function deliveryFromRow(row: DeliveryRow): GovernedSourceDeliveryRecordV1 {
  const record = parseGovernedSourceDeliveryRecordV1(
    parseCanonicalJson(row.record_json, "source delivery record")
  );
  if (
    record.tenantId !== row.tenant_id ||
    record.deliveryId !== row.delivery_id ||
    record.deliveryRevision !== row.delivery_revision ||
    record.status !== row.status ||
    record.deliveryHash !== row.delivery_hash ||
    record.previousDeliveryHash !== row.previous_delivery_hash ||
    record.sourceContract.sourceContractId !== row.source_contract_id ||
    record.sourceContract.revision !== row.source_contract_revision ||
    record.sourceContract.sourceContractHash !== row.source_contract_hash ||
    record.scopeBinding.bindingId !== row.binding_id ||
    record.scopeBinding.revision !== row.binding_revision ||
    record.scopeBinding.bindingHash !== row.binding_hash ||
    record.datasetId !== row.dataset_id ||
    record.facilityId !== row.facility_id ||
    locatorIdentityHash(record.locator) !== row.locator_identity_hash ||
    record.sourceObservedAt !== row.source_observed_at ||
    record.receivedAt !== row.received_at ||
    record.recordedAt !== row.recorded_at
  ) {
    throw integrity("Stored delivery columns do not match canonical evidence");
  }
  return record;
}

function auditFromRow(row: AuditRow): SourceDeliveryAuditEventV1 {
  const body = parseWithSchema(
    AuditBodySchema,
    parseCanonicalJson(row.event_json, "source-delivery audit event"),
    "SourceDeliveryAuditEventV1"
  );
  if (
    body.tenantId !== row.tenant_id ||
    body.tenantSequence !== row.tenant_sequence ||
    body.eventId !== row.event_id ||
    body.eventType !== row.event_type ||
    body.deliveryId !== row.delivery_id ||
    body.deliveryRevision !== row.delivery_revision ||
    body.deliveryHash !== row.delivery_hash ||
    body.actorId !== row.actor_id ||
    body.occurredAt !== row.occurred_at ||
    body.previousEventHash !== row.previous_event_hash ||
    canonicalHash(body) !== row.event_hash
  ) {
    throw integrity("Stored audit columns or event hash do not match canonical evidence");
  }
  return deepFreeze({ ...body, eventHash: row.event_hash as Sha256Hash });
}

function sourceContract(value: unknown): SourceContractV1 {
  try {
    return parseSourceContractV1(value);
  } catch (error) {
    throw integrity("Source-contract evidence is invalid", error);
  }
}

function scopeBinding(value: unknown): GovernedDatasetScopeBindingV1 {
  try {
    return parseGovernedDatasetScopeBindingV1(value);
  } catch (error) {
    throw integrity("Scope-binding evidence is invalid", error);
  }
}

function sameImmutableDeliveryEvidence(
  usable: GovernedSourceDeliveryRecordV1,
  disabled: GovernedSourceDeliveryRecordV1
): boolean {
  return canonicalJson({
    tenantId: usable.tenantId,
    deliveryId: usable.deliveryId,
    datasetId: usable.datasetId,
    facilityId: usable.facilityId,
    sourceContract: usable.sourceContract,
    scopeBinding: usable.scopeBinding,
    locator: usable.locator,
    sourceObservedAt: usable.sourceObservedAt,
    receivedAt: usable.receivedAt
  }) === canonicalJson({
    tenantId: disabled.tenantId,
    deliveryId: disabled.deliveryId,
    datasetId: disabled.datasetId,
    facilityId: disabled.facilityId,
    sourceContract: disabled.sourceContract,
    scopeBinding: disabled.scopeBinding,
    locator: disabled.locator,
    sourceObservedAt: disabled.sourceObservedAt,
    receivedAt: disabled.receivedAt
  });
}

function deliveryStatus(record: GovernedSourceDeliveryRecordV1): GovernedSourceDeliveryStatusV1 {
  const common = {
    contractVersion: 1 as const,
    tenantId: record.tenantId,
    deliveryId: record.deliveryId,
    deliveryRevision: record.deliveryRevision,
    deliveryHash: record.deliveryHash,
    datasetId: record.datasetId,
    facilityId: record.facilityId,
    sourceContract: record.sourceContract,
    scopeBinding: record.scopeBinding,
    sourceObservedAt: record.sourceObservedAt,
    receivedAt: record.receivedAt,
    status: record.status,
    recordedAt: record.recordedAt
  };
  const mode = record.locator.mode;
  const format = mode === "postgresql_pull" ? "sql_rows" as const : record.locator.format;
  return deepFreeze(
    record.statusReason === undefined
      ? { ...common, mode, format }
      : { ...common, mode, format, statusReason: record.statusReason }
  );
}

function locatorIdentityHash(locator: GovernedSourceDeliveryLocatorV1): Sha256Hash {
  return locator.mode === "postgresql_pull"
    ? canonicalHash({
        mode: locator.mode,
        connectorId: locator.connectorId,
        catalog: locator.catalog ?? null,
        schema: locator.schema,
        relation: locator.relation,
        sourceVersionHash: locator.sourceVersionHash,
        watermark: locator.watermark ?? null
      })
    : canonicalHash({
        mode: locator.mode,
        connectorId: locator.connectorId,
        bucket: locator.bucket,
        objectKey: locator.objectKey,
        immutableVersionId: locator.immutableVersionId
      });
}

function receiptHash(input: {
  readonly tenantId: string;
  readonly operation: string;
  readonly actorId: string;
  readonly idempotencyKey: string;
  readonly requestHash: Sha256Hash;
  readonly deliveryId: string;
  readonly deliveryRevision: number;
  readonly deliveryHash: Sha256Hash;
  readonly createdAt: string;
}): Sha256Hash {
  return canonicalHash({ contractVersion: 1, ...input });
}

function safeGlobMatch(pattern: string, value: string): boolean {
  let patternIndex = 0;
  let valueIndex = 0;
  let starIndex = -1;
  let starValueIndex = -1;
  while (valueIndex < value.length) {
    const token = pattern[patternIndex];
    if (token === "?" || token === value[valueIndex]) {
      patternIndex += 1;
      valueIndex += 1;
      continue;
    }
    if (token === "*") {
      starIndex = patternIndex;
      starValueIndex = valueIndex;
      patternIndex += 1;
      continue;
    }
    if (starIndex >= 0) {
      patternIndex = starIndex + 1;
      starValueIndex += 1;
      valueIndex = starValueIndex;
      continue;
    }
    return false;
  }
  while (pattern[patternIndex] === "*") patternIndex += 1;
  return patternIndex === pattern.length;
}

function parseCanonicalJson(value: string, label: string): unknown {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch (error) {
    throw integrity(`${label} is not valid JSON`, error);
  }
  if (canonicalJson(parsed) !== value) throw integrity(`${label} is not canonical JSON`);
  return parsed;
}

function exactKeys(value: unknown, expected: readonly string[], label: string): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object`);
  const actual = Object.keys(value as Record<string, unknown>).sort();
  const wanted = [...expected].sort();
  if (canonicalJson(actual) !== canonicalJson(wanted)) invalid(`${label} contains missing or unknown fields`);
}

function identifier(value: unknown, label: string): string {
  try {
    return parseWithSchema(IdentifierSchema, value, label);
  } catch (error) {
    invalid(`${label} must be a portable identifier`);
  }
}

function timestamp(value: unknown, label: string): string {
  try {
    return parseWithSchema(IsoTimestampSchema, value, label);
  } catch (error) {
    invalid(`${label} must be a canonical UTC timestamp`);
  }
}

function requiredPath(value: string): string {
  if (typeof value !== "string" || value.trim().length === 0 || value.includes("\u0000")) {
    invalid("databasePath must be a non-empty path");
  }
  return value === ":memory:" ? value : resolve(value);
}

function safeInteger(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalid(`${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function invalid(message: string): never {
  throw new SourceDeliveryAuthorityError("INVALID_ARGUMENT", message);
}

function integrity(message: string, cause?: unknown): SourceDeliveryAuthorityError {
  const suffix = cause instanceof Error && cause.message.length > 0 ? `: ${cause.message}` : "";
  return new SourceDeliveryAuthorityError("INTEGRITY_FAILURE", `${message}${suffix}`);
}
