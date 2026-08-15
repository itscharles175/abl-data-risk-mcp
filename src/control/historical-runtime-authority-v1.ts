import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { z } from "zod";

import {
  DictionaryBundleReferenceV1Schema,
  ImmutableBundleReferenceV1Schema,
  assertResolvedBundle,
  canonicalHash,
  canonicalJson,
  createHistoricalRuntimeBundleV1,
  deepFreeze,
  IdentifierSchema,
  IsoTimestampSchema,
  parseHistoricalRuntimeBundleV1,
  parseWithSchema,
  Sha256HashSchema,
  type CanonicalJsonValue,
  type DictionaryBundleReferenceV1,
  type HistoricalRuntimeBundleV1,
  type HistoricalRuntimeResolver,
  type ImmutableBundleReferenceV1,
  type ResolvedDictionaryBundleV1,
  type ResolvedImmutableBundleV1,
  type Sha256Hash
} from "../contracts/index.js";
import { ArtifactStore, type StoredArtifact } from "./artifacts.js";
import {
  migrateSqliteComponent,
  type SqliteComponentMigration
} from "../infrastructure/sqlite-component-schema.js";

export const HISTORICAL_RUNTIME_AUTHORITY_COMPONENT = "abl.historical-runtime-authority" as const;
export const HISTORICAL_RUNTIME_AUTHORITY_SCHEMA_VERSION = 1 as const;

const SCHEMA = `
CREATE TABLE historical_runtime_bundles_v1 (
  tenant_id TEXT NOT NULL,
  bundle_kind TEXT NOT NULL CHECK (bundle_kind IN ('dictionary','field_policy','mapping_compiler','methodology')),
  bundle_id TEXT NOT NULL,
  bundle_version TEXT NOT NULL,
  content_hash TEXT NOT NULL CHECK (length(content_hash) = 71 AND content_hash GLOB 'sha256:*'),
  artifact_id TEXT NOT NULL,
  artifact_content_hash TEXT NOT NULL CHECK (length(artifact_content_hash) = 64),
  reference_json TEXT NOT NULL CHECK (json_valid(reference_json)),
  registered_by TEXT NOT NULL,
  registered_at TEXT NOT NULL,
  record_hash TEXT NOT NULL CHECK (length(record_hash) = 71 AND record_hash GLOB 'sha256:*'),
  PRIMARY KEY (tenant_id, bundle_kind, bundle_id, bundle_version),
  UNIQUE (tenant_id, content_hash, artifact_id)
) STRICT;
CREATE TRIGGER historical_runtime_bundles_v1_no_update
BEFORE UPDATE ON historical_runtime_bundles_v1
BEGIN SELECT RAISE(ABORT, 'historical runtime bundles are immutable'); END;
CREATE TRIGGER historical_runtime_bundles_v1_no_delete
BEFORE DELETE ON historical_runtime_bundles_v1
BEGIN SELECT RAISE(ABORT, 'historical runtime bundles are immutable'); END;

CREATE TABLE historical_runtime_assemblies_v1 (
  tenant_id TEXT NOT NULL,
  runtime_bundle_id TEXT NOT NULL,
  runtime_bundle_hash TEXT NOT NULL CHECK (length(runtime_bundle_hash) = 71 AND runtime_bundle_hash GLOB 'sha256:*'),
  runtime_version TEXT NOT NULL,
  assembled_at TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  artifact_content_hash TEXT NOT NULL CHECK (length(artifact_content_hash) = 64),
  registered_by TEXT NOT NULL,
  registered_at TEXT NOT NULL,
  record_hash TEXT NOT NULL CHECK (length(record_hash) = 71 AND record_hash GLOB 'sha256:*'),
  PRIMARY KEY (tenant_id, runtime_bundle_id, runtime_bundle_hash),
  UNIQUE (tenant_id, runtime_bundle_id, runtime_version)
) STRICT;
CREATE TRIGGER historical_runtime_assemblies_v1_no_update
BEFORE UPDATE ON historical_runtime_assemblies_v1
BEGIN SELECT RAISE(ABORT, 'historical runtime assemblies are immutable'); END;
CREATE TRIGGER historical_runtime_assemblies_v1_no_delete
BEFORE DELETE ON historical_runtime_assemblies_v1
BEGIN SELECT RAISE(ABORT, 'historical runtime assemblies are immutable'); END;

CREATE TABLE historical_runtime_activations_v1 (
  tenant_id TEXT NOT NULL,
  runtime_bundle_id TEXT NOT NULL,
  runtime_bundle_hash TEXT NOT NULL,
  activated_by TEXT NOT NULL,
  activated_at TEXT NOT NULL,
  activation_hash TEXT NOT NULL CHECK (length(activation_hash) = 71 AND activation_hash GLOB 'sha256:*'),
  PRIMARY KEY (tenant_id, runtime_bundle_id, runtime_bundle_hash),
  FOREIGN KEY (tenant_id, runtime_bundle_id, runtime_bundle_hash)
    REFERENCES historical_runtime_assemblies_v1 (tenant_id, runtime_bundle_id, runtime_bundle_hash)
    ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;
CREATE TRIGGER historical_runtime_activations_v1_no_update
BEFORE UPDATE ON historical_runtime_activations_v1
BEGIN SELECT RAISE(ABORT, 'historical runtime activations are immutable'); END;
CREATE TRIGGER historical_runtime_activations_v1_no_delete
BEFORE DELETE ON historical_runtime_activations_v1
BEGIN SELECT RAISE(ABORT, 'historical runtime activations are immutable'); END;

CREATE TABLE historical_runtime_audit_v1 (
  tenant_id TEXT NOT NULL,
  tenant_sequence INTEGER NOT NULL CHECK (tenant_sequence > 0),
  event_id TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('bundle_registered','runtime_registered','runtime_activated')),
  subject_id TEXT NOT NULL,
  subject_hash TEXT NOT NULL CHECK (length(subject_hash) = 71 AND subject_hash GLOB 'sha256:*'),
  actor_id TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  previous_event_hash TEXT CHECK (previous_event_hash IS NULL OR (length(previous_event_hash) = 71 AND previous_event_hash GLOB 'sha256:*')),
  event_hash TEXT NOT NULL CHECK (length(event_hash) = 71 AND event_hash GLOB 'sha256:*'),
  PRIMARY KEY (tenant_id, tenant_sequence),
  UNIQUE (tenant_id, event_id),
  UNIQUE (tenant_id, event_hash)
) STRICT;
CREATE TRIGGER historical_runtime_audit_v1_no_update
BEFORE UPDATE ON historical_runtime_audit_v1
BEGIN SELECT RAISE(ABORT, 'historical runtime audit is append-only'); END;
CREATE TRIGGER historical_runtime_audit_v1_no_delete
BEFORE DELETE ON historical_runtime_audit_v1
BEGIN SELECT RAISE(ABORT, 'historical runtime audit is append-only'); END;

CREATE TABLE historical_runtime_idempotency_v1 (
  tenant_id TEXT NOT NULL,
  operation TEXT NOT NULL CHECK (operation IN ('register_bundle','register_runtime','activate_runtime')),
  actor_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL CHECK (length(request_hash) = 71 AND request_hash GLOB 'sha256:*'),
  response_json TEXT NOT NULL CHECK (json_valid(response_json)),
  response_hash TEXT NOT NULL CHECK (length(response_hash) = 71 AND response_hash GLOB 'sha256:*'),
  created_at TEXT NOT NULL,
  receipt_hash TEXT NOT NULL CHECK (length(receipt_hash) = 71 AND receipt_hash GLOB 'sha256:*'),
  PRIMARY KEY (tenant_id, operation, actor_id, idempotency_key)
) STRICT;
CREATE TRIGGER historical_runtime_idempotency_v1_no_update
BEFORE UPDATE ON historical_runtime_idempotency_v1
BEGIN SELECT RAISE(ABORT, 'historical runtime idempotency is immutable'); END;
CREATE TRIGGER historical_runtime_idempotency_v1_no_delete
BEFORE DELETE ON historical_runtime_idempotency_v1
BEGIN SELECT RAISE(ABORT, 'historical runtime idempotency is immutable'); END;
`;

export const HISTORICAL_RUNTIME_AUTHORITY_MIGRATIONS = Object.freeze([
  { version: 1, sql: SCHEMA }
] as const satisfies readonly SqliteComponentMigration[]);

const ActorSchema = z
  .object({
    tenantId: IdentifierSchema,
    actorId: IdentifierSchema,
    authority: z.literal("platform_operator"),
    identitySource: z.literal("server_derived")
  })
  .strict();

export interface TrustedRuntimeAuthorityActorV1 {
  readonly tenantId: string;
  readonly actorId: string;
  readonly authority: "platform_operator";
  readonly identitySource: "server_derived";
}

export interface RegisterImmutableBundleV1 {
  readonly bundleKind: "field_policy" | "mapping_compiler" | "methodology";
  readonly bundleId: string;
  readonly version: string;
  readonly mediaType: string;
  readonly createdAt: string;
  readonly content: CanonicalJsonValue;
  readonly idempotencyKey: string;
}

export interface RegisterDictionaryBundleV1 {
  readonly bundleKind: "dictionary";
  readonly bundleId: string;
  readonly version: string;
  readonly mediaType: string;
  readonly createdAt: string;
  readonly dictionaryVersion: string;
  readonly dictionaryHash: Sha256Hash;
  readonly fieldPolicyVersion: string;
  readonly fieldPolicyHash: Sha256Hash;
  readonly content: CanonicalJsonValue;
  readonly idempotencyKey: string;
}

export interface RegisterRuntimeAssemblyV1 {
  readonly runtimeBundleId: string;
  readonly runtimeVersion: string;
  readonly dictionary: DictionaryBundleReferenceV1;
  readonly mappingCompiler: ImmutableBundleReferenceV1 & { readonly bundleKind: "mapping_compiler" };
  readonly methodologies: readonly (ImmutableBundleReferenceV1 & { readonly bundleKind: "methodology" })[];
  readonly assembledAt: string;
  readonly idempotencyKey: string;
}

export interface RuntimeActivationProofV1 {
  readonly tenantId: string;
  readonly runtimeBundleId: string;
  readonly runtimeBundleHash: Sha256Hash;
  readonly registeredBy: string;
  readonly registeredAt: string;
  readonly activatedBy: string;
  readonly activatedAt: string;
  readonly activationHash: Sha256Hash;
}

export interface AuthorityMutationResultV1<T> {
  readonly value: T;
  readonly replayed: boolean;
}

export type HistoricalRuntimeAuthorityErrorCode =
  | "INVALID_INPUT"
  | "NOT_FOUND"
  | "ALREADY_EXISTS"
  | "IDEMPOTENCY_CONFLICT"
  | "MAKER_CHECKER_VIOLATION"
  | "INACTIVE"
  | "CLOCK_ROLLBACK"
  | "INTEGRITY_FAILURE"
  | "STORE_CLOSED";

export class HistoricalRuntimeAuthorityError extends Error {
  constructor(readonly code: HistoricalRuntimeAuthorityErrorCode, message: string) {
    super(message);
    this.name = "HistoricalRuntimeAuthorityError";
  }
}

export interface HistoricalRuntimeAuthorityOptionsV1 {
  readonly clock?: () => Date;
  readonly eventId?: () => string;
  readonly busyTimeoutMs?: number;
}

export interface HistoricalRuntimeAuditEventV1 {
  readonly tenantId: string;
  readonly tenantSequence: number;
  readonly eventId: string;
  readonly eventType: "bundle_registered" | "runtime_registered" | "runtime_activated";
  readonly subjectId: string;
  readonly subjectHash: Sha256Hash;
  readonly actorId: string;
  readonly occurredAt: string;
  readonly previousEventHash: Sha256Hash | null;
  readonly eventHash: Sha256Hash;
}

interface BundleRow {
  readonly tenant_id: string;
  readonly bundle_kind: string;
  readonly bundle_id: string;
  readonly bundle_version: string;
  readonly content_hash: string;
  readonly artifact_id: string;
  readonly artifact_content_hash: string;
  readonly reference_json: string;
  readonly registered_by: string;
  readonly registered_at: string;
  readonly record_hash: string;
}

interface RuntimeRow {
  readonly tenant_id: string;
  readonly runtime_bundle_id: string;
  readonly runtime_bundle_hash: string;
  readonly runtime_version: string;
  readonly assembled_at: string;
  readonly artifact_id: string;
  readonly artifact_content_hash: string;
  readonly registered_by: string;
  readonly registered_at: string;
  readonly record_hash: string;
}

interface ActivationRow {
  readonly tenant_id: string;
  readonly runtime_bundle_id: string;
  readonly runtime_bundle_hash: string;
  readonly activated_by: string;
  readonly activated_at: string;
  readonly activation_hash: string;
}

/** Durable tenant authority for immutable executable runtime evidence. */
export class SqliteHistoricalRuntimeAuthorityV1 {
  readonly #database: DatabaseSync;
  readonly #artifacts: ArtifactStore;
  readonly #clock: () => Date;
  readonly #eventId: () => string;
  #closed = false;

  constructor(
    databasePath: string,
    artifacts: ArtifactStore,
    options: HistoricalRuntimeAuthorityOptionsV1 = {}
  ) {
    const path = requiredPath(databasePath);
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.#database = new DatabaseSync(path, { enableForeignKeyConstraints: true });
    this.#artifacts = artifacts;
    this.#clock = options.clock ?? (() => new Date());
    this.#eventId = options.eventId ?? (() => `evt:${randomUUID().replaceAll("-", "")}`);
    const timeout = integer(options.busyTimeoutMs ?? 5_000, "busyTimeoutMs", 0, 60_000);
    try {
      this.#database.exec(
        `PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = ${timeout};`
      );
      migrateSqliteComponent(this.#database, {
        componentName: HISTORICAL_RUNTIME_AUTHORITY_COMPONENT,
        supportedVersion: HISTORICAL_RUNTIME_AUTHORITY_SCHEMA_VERSION,
        migrations: HISTORICAL_RUNTIME_AUTHORITY_MIGRATIONS,
        unsupportedVersionError: (current, supported) =>
          integrity(`Historical-runtime authority schema ${current} is newer than supported ${supported}`)
      });
      this.#verifyIntegrity();
    } catch (error) {
      this.#database.close();
      if (error instanceof HistoricalRuntimeAuthorityError) throw error;
      throw integrity("Historical-runtime authority initialization failed", error);
    }
  }

  registerBundle(
    actorValue: TrustedRuntimeAuthorityActorV1,
    inputValue: RegisterImmutableBundleV1 | RegisterDictionaryBundleV1
  ): AuthorityMutationResultV1<ImmutableBundleReferenceV1 | DictionaryBundleReferenceV1> {
    this.#assertOpen();
    const actor = trustedActor(actorValue);
    const input = bundleInput(inputValue);
    const now = this.#now(actor.tenantId);
    if (input.createdAt > now) invalid("Bundle creation cannot follow registration");
    const request = deepFreeze({ ...input, contentHash: canonicalHash(input.content) });
    const requestHash = canonicalHash(request);
    const replay = this.#readReceipt(actor, "register_bundle", input.idempotencyKey, requestHash);
    if (replay) return { value: parseBundleReference(replay), replayed: true };

    const stored = this.#artifacts.putJson({
      tenantId: actor.tenantId,
      kind: "historical_bundle",
      mediaType: input.mediaType,
      value: input.content
    });
    const contentHash = canonicalHash(input.content);
    assertArtifactHash(stored, contentHash);
    const base = {
      contractVersion: 1 as const,
      bundleKind: input.bundleKind,
      bundleId: input.bundleId,
      version: input.version,
      contentHash,
      artifactId: stored.artifactId,
      mediaType: input.mediaType,
      createdAt: input.createdAt
    };
    const reference = input.bundleKind === "dictionary"
      ? parseWithSchema(DictionaryBundleReferenceV1Schema, {
          ...base,
          bundleKind: "dictionary",
          dictionaryVersion: input.dictionaryVersion,
          dictionaryHash: input.dictionaryHash,
          fieldPolicyVersion: input.fieldPolicyVersion,
          fieldPolicyHash: input.fieldPolicyHash
        }, "DictionaryBundleReferenceV1")
      : parseWithSchema(ImmutableBundleReferenceV1Schema, base, "ImmutableBundleReferenceV1");

    return this.#transaction(() => {
      const secondReplay = this.#readReceipt(actor, "register_bundle", input.idempotencyKey, requestHash);
      if (secondReplay) return { value: parseBundleReference(secondReplay), replayed: true };
      if (this.#bundleByIdentity(actor.tenantId, reference.bundleKind, reference.bundleId, reference.version)) {
        throw new HistoricalRuntimeAuthorityError("ALREADY_EXISTS", "Bundle identity is already registered");
      }
      const recordBody = {
        tenantId: actor.tenantId,
        reference,
        artifactContentHash: stored.contentHash,
        registeredBy: actor.actorId,
        registeredAt: now
      };
      this.#database.prepare(
        `INSERT INTO historical_runtime_bundles_v1 (
          tenant_id, bundle_kind, bundle_id, bundle_version, content_hash,
          artifact_id, artifact_content_hash, reference_json, registered_by,
          registered_at, record_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        actor.tenantId, reference.bundleKind, reference.bundleId, reference.version,
        reference.contentHash, reference.artifactId, stored.contentHash,
        canonicalJson(reference), actor.actorId, now, canonicalHash(recordBody)
      );
      this.#appendAudit(actor, "bundle_registered", `${reference.bundleKind}:${reference.bundleId}:${reference.version}`, reference.contentHash, now);
      this.#writeReceipt(actor, "register_bundle", input.idempotencyKey, requestHash, reference, now);
      return { value: reference, replayed: false };
    });
  }

  registerRuntime(
    actorValue: TrustedRuntimeAuthorityActorV1,
    inputValue: RegisterRuntimeAssemblyV1
  ): AuthorityMutationResultV1<HistoricalRuntimeBundleV1> {
    this.#assertOpen();
    const actor = trustedActor(actorValue);
    const input = runtimeInput(inputValue);
    const now = this.#now(actor.tenantId);
    if (input.assembledAt > now) invalid("Runtime assembly cannot follow registration");
    for (const reference of [input.dictionary, input.mappingCompiler, ...input.methodologies]) {
      if (reference.createdAt > input.assembledAt) invalid("Runtime assembly precedes a referenced bundle");
      this.#resolveBundle(actor.tenantId, reference);
    }
    const runtime = createHistoricalRuntimeBundleV1({
      contractVersion: 1,
      runtimeBundleId: input.runtimeBundleId,
      runtimeVersion: input.runtimeVersion,
      dictionary: input.dictionary,
      mappingCompiler: input.mappingCompiler,
      methodologies: [...input.methodologies],
      assembledAt: input.assembledAt
    });
    const requestHash = canonicalHash(input);
    const replay = this.#readReceipt(actor, "register_runtime", input.idempotencyKey, requestHash);
    if (replay) return { value: parseHistoricalRuntimeBundleV1(replay), replayed: true };
    const stored = this.#artifacts.putJson({
      tenantId: actor.tenantId,
      kind: "historical_runtime",
      mediaType: "application/json",
      value: runtime
    });
    assertArtifactHash(stored, canonicalHash(runtime));

    return this.#transaction(() => {
      const secondReplay = this.#readReceipt(actor, "register_runtime", input.idempotencyKey, requestHash);
      if (secondReplay) return { value: parseHistoricalRuntimeBundleV1(secondReplay), replayed: true };
      if (this.#runtimeRow(actor.tenantId, runtime.runtimeBundleId, runtime.runtimeBundleHash)) {
        throw new HistoricalRuntimeAuthorityError("ALREADY_EXISTS", "Runtime assembly is already registered");
      }
      const recordBody = {
        tenantId: actor.tenantId,
        runtime,
        artifactId: stored.artifactId,
        artifactContentHash: stored.contentHash,
        registeredBy: actor.actorId,
        registeredAt: now
      };
      this.#database.prepare(
        `INSERT INTO historical_runtime_assemblies_v1 (
          tenant_id, runtime_bundle_id, runtime_bundle_hash, runtime_version,
          assembled_at, artifact_id, artifact_content_hash, registered_by,
          registered_at, record_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        actor.tenantId, runtime.runtimeBundleId, runtime.runtimeBundleHash,
        runtime.runtimeVersion, runtime.assembledAt, stored.artifactId,
        stored.contentHash, actor.actorId, now, canonicalHash(recordBody)
      );
      this.#appendAudit(actor, "runtime_registered", runtime.runtimeBundleId, runtime.runtimeBundleHash, now);
      this.#writeReceipt(actor, "register_runtime", input.idempotencyKey, requestHash, runtime, now);
      return { value: runtime, replayed: false };
    });
  }

  activateRuntime(
    actorValue: TrustedRuntimeAuthorityActorV1,
    input: {
      readonly runtimeBundleId: string;
      readonly runtimeBundleHash: Sha256Hash;
      readonly idempotencyKey: string;
    }
  ): AuthorityMutationResultV1<RuntimeActivationProofV1> {
    this.#assertOpen();
    const actor = trustedActor(actorValue);
    const runtimeBundleId = identifier(input.runtimeBundleId, "runtimeBundleId");
    const runtimeBundleHash = hash(input.runtimeBundleHash, "runtimeBundleHash");
    const idempotencyKey = identifier(input.idempotencyKey, "idempotencyKey");
    const request = deepFreeze({ runtimeBundleId, runtimeBundleHash });
    const requestHash = canonicalHash(request);
    const replay = this.#readReceipt(actor, "activate_runtime", idempotencyKey, requestHash);
    if (replay) return { value: activationProof(replay), replayed: true };
    const runtimeRow = this.#runtimeRow(actor.tenantId, runtimeBundleId, runtimeBundleHash);
    if (!runtimeRow) notFound("Runtime assembly was not found in the actor tenant");
    const runtime = this.#runtimeFromRow(runtimeRow);
    if (runtimeRow.registered_by === actor.actorId) {
      throw new HistoricalRuntimeAuthorityError(
        "MAKER_CHECKER_VIOLATION",
        "Runtime assembler cannot activate the same runtime"
      );
    }
    const now = this.#now(actor.tenantId);
    if (now < runtime.assembledAt || now < runtimeRow.registered_at) {
      throw new HistoricalRuntimeAuthorityError("CLOCK_ROLLBACK", "Activation precedes runtime evidence");
    }

    return this.#transaction(() => {
      const secondReplay = this.#readReceipt(actor, "activate_runtime", idempotencyKey, requestHash);
      if (secondReplay) return { value: activationProof(secondReplay), replayed: true };
      const existing = this.#activationRow(actor.tenantId, runtimeBundleId, runtimeBundleHash);
      if (existing) throw new HistoricalRuntimeAuthorityError("ALREADY_EXISTS", "Runtime is already activated");
      const proofBody = {
        tenantId: actor.tenantId,
        runtimeBundleId,
        runtimeBundleHash,
        registeredBy: runtimeRow.registered_by,
        registeredAt: runtimeRow.registered_at,
        activatedBy: actor.actorId,
        activatedAt: now
      };
      const proof = deepFreeze({ ...proofBody, activationHash: canonicalHash(proofBody) });
      this.#database.prepare(
        `INSERT INTO historical_runtime_activations_v1 (
          tenant_id, runtime_bundle_id, runtime_bundle_hash, activated_by,
          activated_at, activation_hash
        ) VALUES (?, ?, ?, ?, ?, ?)`
      ).run(actor.tenantId, runtimeBundleId, runtimeBundleHash, actor.actorId, now, proof.activationHash);
      this.#appendAudit(actor, "runtime_activated", runtimeBundleId, runtimeBundleHash, now);
      this.#writeReceipt(actor, "activate_runtime", idempotencyKey, requestHash, proof, now);
      return { value: proof, replayed: false };
    });
  }

  listAudit(
    tenantIdValue: string,
    afterTenantSequenceValue = 0,
    limitValue = 100
  ): readonly HistoricalRuntimeAuditEventV1[] {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenantId");
    const afterTenantSequence = integer(
      afterTenantSequenceValue,
      "afterTenantSequence",
      0,
      Number.MAX_SAFE_INTEGER
    );
    const limit = integer(limitValue, "limit", 1, 1_000);
    const rows = this.#database.prepare(
      `SELECT * FROM historical_runtime_audit_v1
       WHERE tenant_id = ? ORDER BY tenant_sequence`
    ).all(tenantId) as unknown as readonly Record<string, unknown>[];
    let previousEventHash: Sha256Hash | null = null;
    let previousOccurredAt: string | null = null;
    const events = rows.map((row, index) => {
      const body = {
        tenantId: String(row.tenant_id),
        tenantSequence: Number(row.tenant_sequence),
        eventId: String(row.event_id),
        eventType: String(row.event_type) as HistoricalRuntimeAuditEventV1["eventType"],
        subjectId: String(row.subject_id),
        subjectHash: String(row.subject_hash) as Sha256Hash,
        actorId: String(row.actor_id),
        occurredAt: String(row.occurred_at),
        previousEventHash:
          row.previous_event_hash === null ? null : String(row.previous_event_hash) as Sha256Hash
      };
      const eventHash = String(row.event_hash) as Sha256Hash;
      if (
        body.tenantId !== tenantId ||
        body.tenantSequence !== index + 1 ||
        body.previousEventHash !== previousEventHash ||
        (previousOccurredAt !== null && body.occurredAt < previousOccurredAt) ||
        canonicalHash(body) !== eventHash
      ) {
        throw integrity("Historical runtime audit hash chain failed verification");
      }
      previousEventHash = eventHash;
      previousOccurredAt = body.occurredAt;
      return deepFreeze({ ...body, eventHash });
    });
    return Object.freeze(
      events
        .filter((event) => event.tenantSequence > afterTenantSequence)
        .slice(0, limit)
    );
  }

  resolveBundleReference(
    tenantIdValue: string,
    bundleKindValue: "dictionary",
    bundleIdValue: string,
    versionValue: string
  ): DictionaryBundleReferenceV1;
  resolveBundleReference(
    tenantIdValue: string,
    bundleKindValue: "mapping_compiler",
    bundleIdValue: string,
    versionValue: string
  ): ImmutableBundleReferenceV1 & { readonly bundleKind: "mapping_compiler" };
  resolveBundleReference(
    tenantIdValue: string,
    bundleKindValue: "methodology",
    bundleIdValue: string,
    versionValue: string
  ): ImmutableBundleReferenceV1 & { readonly bundleKind: "methodology" };
  resolveBundleReference(
    tenantIdValue: string,
    bundleKindValue: "field_policy",
    bundleIdValue: string,
    versionValue: string
  ): ImmutableBundleReferenceV1 & { readonly bundleKind: "field_policy" };
  resolveBundleReference(
    tenantIdValue: string,
    bundleKindValue: "dictionary" | "field_policy" | "mapping_compiler" | "methodology",
    bundleIdValue: string,
    versionValue: string
  ): ImmutableBundleReferenceV1 | DictionaryBundleReferenceV1 {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenantId");
    const bundleKind = bundleKindValue;
    if (!(["dictionary", "field_policy", "mapping_compiler", "methodology"] as const).includes(bundleKind)) {
      invalid("bundleKind is invalid");
    }
    const bundleId = identifier(bundleIdValue, "bundleId");
    const version = identifier(versionValue, "version");
    const row = this.#bundleByIdentity(tenantId, bundleKind, bundleId, version);
    if (!row) notFound("Immutable historical bundle was not found");
    const reference = this.#bundleReferenceFromRow(row);
    this.#resolveBundle(tenantId, reference);
    return reference;
  }

  forTenant(
    tenantIdValue: string,
    options: { readonly usedAt?: () => string } = {}
  ): HistoricalRuntimeResolver {
    const tenantId = identifier(tenantIdValue, "tenantId");
    return new ArtifactBackedHistoricalRuntimeResolverV1(
      this,
      tenantId,
      options.usedAt ?? (() => this.#clock().toISOString())
    );
  }

  resolveActivatedRuntime(
    tenantIdValue: string,
    reference: { readonly runtimeBundleId: string; readonly runtimeBundleHash: Sha256Hash },
    usedAtValue: string
  ): { readonly runtime: HistoricalRuntimeBundleV1; readonly activation: RuntimeActivationProofV1 } {
    this.#assertOpen();
    const tenantId = identifier(tenantIdValue, "tenantId");
    const runtimeBundleId = identifier(reference.runtimeBundleId, "runtimeBundleId");
    const runtimeBundleHash = hash(reference.runtimeBundleHash, "runtimeBundleHash");
    const usedAt = timestamp(usedAtValue, "usedAt");
    const row = this.#runtimeRow(tenantId, runtimeBundleId, runtimeBundleHash);
    if (!row) notFound("Historical runtime assembly was not found");
    const runtime = this.#runtimeFromRow(row);
    const activationRow = this.#activationRow(tenantId, runtimeBundleId, runtimeBundleHash);
    if (!activationRow) throw new HistoricalRuntimeAuthorityError("INACTIVE", "Runtime lacks activation evidence");
    const activation = this.#activationFromRows(row, activationRow);
    if (activation.activatedAt > usedAt) {
      throw new HistoricalRuntimeAuthorityError("INACTIVE", "Runtime was activated after the requested use time");
    }
    return Object.freeze({ runtime, activation });
  }

  resolveBundleForTenant(
    tenantIdValue: string,
    reference: ImmutableBundleReferenceV1
  ): ResolvedImmutableBundleV1 {
    this.#assertOpen();
    return this.#resolveBundle(identifier(tenantIdValue, "tenantId"), reference);
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#database.close();
  }

  #resolveBundle(tenantId: string, referenceValue: ImmutableBundleReferenceV1): ResolvedImmutableBundleV1 {
    const reference = parseBundleReference(referenceValue);
    const row = this.#bundleByIdentity(tenantId, reference.bundleKind, reference.bundleId, reference.version);
    if (!row) notFound("Immutable historical bundle was not found");
    const storedReference = this.#bundleReferenceFromRow(row);
    if (canonicalJson(storedReference) !== canonicalJson(reference)) {
      throw integrity("Historical bundle reference does not match immutable authority metadata");
    }
    const loaded = this.#artifacts.getJson(tenantId, row.artifact_id);
    if (loaded.metadata.contentHash !== row.artifact_content_hash) {
      throw integrity("Historical bundle artifact metadata failed verification");
    }
    const content = canonicalValue(loaded.value, "historical bundle content");
    const resolved = deepFreeze({ reference: storedReference, content });
    assertResolvedBundle(reference, resolved);
    return resolved;
  }

  #runtimeFromRow(row: RuntimeRow): HistoricalRuntimeBundleV1 {
    const loaded = this.#artifacts.getJson(row.tenant_id, row.artifact_id);
    const runtime = parseHistoricalRuntimeBundleV1(loaded.value);
    const body = {
      tenantId: row.tenant_id,
      runtime,
      artifactId: row.artifact_id,
      artifactContentHash: row.artifact_content_hash,
      registeredBy: row.registered_by,
      registeredAt: row.registered_at
    };
    if (
      runtime.runtimeBundleId !== row.runtime_bundle_id ||
      runtime.runtimeBundleHash !== row.runtime_bundle_hash ||
      runtime.runtimeVersion !== row.runtime_version ||
      runtime.assembledAt !== row.assembled_at ||
      loaded.metadata.artifactId !== row.artifact_id ||
      loaded.metadata.contentHash !== row.artifact_content_hash ||
      canonicalHash(body) !== row.record_hash
    ) {
      throw integrity("Historical runtime authority record failed exact replay verification");
    }
    for (const reference of [runtime.dictionary, runtime.mappingCompiler, ...runtime.methodologies]) {
      if (reference.createdAt > runtime.assembledAt) {
        throw integrity("Historical runtime assembly predates a referenced bundle");
      }
      this.#resolveBundle(row.tenant_id, reference);
    }
    return runtime;
  }

  #activationFromRows(row: RuntimeRow, activation: ActivationRow): RuntimeActivationProofV1 {
    const body = {
      tenantId: row.tenant_id,
      runtimeBundleId: row.runtime_bundle_id,
      runtimeBundleHash: row.runtime_bundle_hash as Sha256Hash,
      registeredBy: row.registered_by,
      registeredAt: row.registered_at,
      activatedBy: activation.activated_by,
      activatedAt: activation.activated_at
    };
    if (
      activation.tenant_id !== row.tenant_id ||
      activation.runtime_bundle_id !== row.runtime_bundle_id ||
      activation.runtime_bundle_hash !== row.runtime_bundle_hash ||
      activation.activated_by === row.registered_by ||
      activation.activated_at < row.registered_at ||
      activation.activated_at < row.assembled_at ||
      canonicalHash(body) !== activation.activation_hash
    ) {
      throw integrity("Historical runtime activation proof failed verification");
    }
    return deepFreeze({ ...body, activationHash: activation.activation_hash as Sha256Hash });
  }

  #bundleReferenceFromRow(row: BundleRow): ImmutableBundleReferenceV1 | DictionaryBundleReferenceV1 {
    const reference = parseBundleReference(parseJson(row.reference_json, "bundle reference"));
    const body = {
      tenantId: row.tenant_id,
      reference,
      artifactContentHash: row.artifact_content_hash,
      registeredBy: row.registered_by,
      registeredAt: row.registered_at
    };
    if (
      reference.bundleKind !== row.bundle_kind ||
      reference.bundleId !== row.bundle_id ||
      reference.version !== row.bundle_version ||
      reference.contentHash !== row.content_hash ||
      reference.artifactId !== row.artifact_id ||
      canonicalHash(body) !== row.record_hash
    ) {
      throw integrity("Historical bundle authority record failed verification");
    }
    return reference;
  }

  #verifyIntegrity(): void {
    const bundleRows = this.#database.prepare(
      "SELECT * FROM historical_runtime_bundles_v1 ORDER BY tenant_id, bundle_kind, bundle_id, bundle_version"
    ).all() as unknown as BundleRow[];
    for (const row of bundleRows) this.#resolveBundle(row.tenant_id, this.#bundleReferenceFromRow(row));

    const runtimeRows = this.#database.prepare(
      "SELECT * FROM historical_runtime_assemblies_v1 ORDER BY tenant_id, runtime_bundle_id, runtime_bundle_hash"
    ).all() as unknown as RuntimeRow[];
    for (const row of runtimeRows) this.#runtimeFromRow(row);

    const activationRows = this.#database.prepare(
      "SELECT * FROM historical_runtime_activations_v1 ORDER BY tenant_id, runtime_bundle_id"
    ).all() as unknown as ActivationRow[];
    for (const activation of activationRows) {
      const runtime = this.#runtimeRow(activation.tenant_id, activation.runtime_bundle_id, activation.runtime_bundle_hash);
      if (!runtime) throw integrity("Runtime activation references missing assembly evidence");
      this.#activationFromRows(runtime, activation);
    }

    const events = this.#database.prepare(
      "SELECT * FROM historical_runtime_audit_v1 ORDER BY tenant_id, tenant_sequence"
    ).all() as unknown as readonly Record<string, unknown>[];
    const sequence = new Map<string, number>();
    const previousHash = new Map<string, Sha256Hash | null>();
    const previousTime = new Map<string, string>();
    const eventSubjects = new Set<string>();
    for (const row of events) {
      const tenantId = String(row.tenant_id);
      const body = {
        tenantId,
        tenantSequence: Number(row.tenant_sequence),
        eventId: String(row.event_id),
        eventType: String(row.event_type),
        subjectId: String(row.subject_id),
        subjectHash: String(row.subject_hash),
        actorId: String(row.actor_id),
        occurredAt: String(row.occurred_at),
        previousEventHash: row.previous_event_hash === null ? null : String(row.previous_event_hash)
      };
      const expectedSequence = (sequence.get(tenantId) ?? 0) + 1;
      if (
        body.tenantSequence !== expectedSequence ||
        body.previousEventHash !== (previousHash.get(tenantId) ?? null) ||
        (previousTime.get(tenantId) !== undefined && body.occurredAt < previousTime.get(tenantId)!) ||
        canonicalHash(body) !== row.event_hash
      ) {
        throw integrity("Historical runtime audit hash chain failed verification");
      }
      sequence.set(tenantId, body.tenantSequence);
      previousHash.set(tenantId, row.event_hash as Sha256Hash);
      previousTime.set(tenantId, body.occurredAt);
      const subjectKey = `${tenantId}\u0000${body.eventType}\u0000${body.subjectId}\u0000${body.subjectHash}\u0000${body.actorId}\u0000${body.occurredAt}`;
      if (eventSubjects.has(subjectKey)) throw integrity("Historical runtime audit subject is duplicated");
      eventSubjects.add(subjectKey);
    }

    for (const row of bundleRows) {
      const subjectId = `${row.bundle_kind}:${row.bundle_id}:${row.bundle_version}`;
      if (!eventSubjects.has(`${row.tenant_id}\u0000bundle_registered\u0000${subjectId}\u0000${row.content_hash}\u0000${row.registered_by}\u0000${row.registered_at}`)) {
        throw integrity("Historical bundle lacks exact audit evidence");
      }
    }
    for (const row of runtimeRows) {
      if (!eventSubjects.has(`${row.tenant_id}\u0000runtime_registered\u0000${row.runtime_bundle_id}\u0000${row.runtime_bundle_hash}\u0000${row.registered_by}\u0000${row.registered_at}`)) {
        throw integrity("Historical runtime lacks exact registration audit evidence");
      }
    }
    for (const row of activationRows) {
      if (!eventSubjects.has(`${row.tenant_id}\u0000runtime_activated\u0000${row.runtime_bundle_id}\u0000${row.runtime_bundle_hash}\u0000${row.activated_by}\u0000${row.activated_at}`)) {
        throw integrity("Historical runtime activation lacks exact audit evidence");
      }
    }
    if (events.length !== bundleRows.length + runtimeRows.length + activationRows.length) {
      throw integrity("Historical runtime records and audit evidence cardinality differ");
    }

    const receipts = this.#database.prepare(
      "SELECT * FROM historical_runtime_idempotency_v1"
    ).all() as unknown as readonly Record<string, unknown>[];
    const receiptSubjects = new Set<string>();
    for (const row of receipts) {
      const response = parseJson(String(row.response_json), "historical runtime receipt");
      const tenantId = identifier(String(row.tenant_id), "receipt tenantId");
      const actorId = identifier(String(row.actor_id), "receipt actorId");
      const idempotencyKey = identifier(String(row.idempotency_key), "receipt idempotencyKey");
      const operation = String(row.operation);
      const requestHash = hash(String(row.request_hash), "receipt requestHash");
      const createdAt = timestamp(String(row.created_at), "receipt createdAt");
      const expectedReceiptHash = canonicalHash({
        tenantId,
        operation,
        actorId,
        idempotencyKey,
        requestHash,
        responseHash: row.response_hash,
        createdAt
      });
      if (
        canonicalHash(response) !== row.response_hash ||
        !["register_bundle", "register_runtime", "activate_runtime"].includes(operation) ||
        tenantId.length === 0 || actorId.length === 0 || idempotencyKey.length === 0 ||
        requestHash.length === 0 || createdAt.length === 0 ||
        row.receipt_hash !== expectedReceiptHash
      ) {
        throw integrity("Historical runtime idempotency receipt failed verification");
      }
      const responseObject = record(response, "historical runtime receipt response");
      let subjectKey: string;
      if (operation === "register_bundle") {
        const reference = parseBundleReference(response);
        subjectKey = `${tenantId}\u0000bundle_registered\u0000${reference.bundleKind}:${reference.bundleId}:${reference.version}\u0000${reference.contentHash}\u0000${actorId}\u0000${createdAt}`;
      } else if (operation === "register_runtime") {
        const runtime = parseHistoricalRuntimeBundleV1(response);
        subjectKey = `${tenantId}\u0000runtime_registered\u0000${runtime.runtimeBundleId}\u0000${runtime.runtimeBundleHash}\u0000${actorId}\u0000${createdAt}`;
      } else {
        const activation = activationProof(responseObject);
        subjectKey = `${tenantId}\u0000runtime_activated\u0000${activation.runtimeBundleId}\u0000${activation.runtimeBundleHash}\u0000${actorId}\u0000${createdAt}`;
      }
      if (!eventSubjects.has(subjectKey) || receiptSubjects.has(subjectKey)) {
        throw integrity("Historical runtime receipt does not bind one exact audited record");
      }
      receiptSubjects.add(subjectKey);
    }
    if (receipts.length !== bundleRows.length + runtimeRows.length + activationRows.length) {
      throw integrity("Historical runtime records and idempotency receipt cardinality differ");
    }
  }

  #appendAudit(
    actor: TrustedRuntimeAuthorityActorV1,
    eventType: "bundle_registered" | "runtime_registered" | "runtime_activated",
    subjectId: string,
    subjectHash: Sha256Hash,
    occurredAt: string
  ): void {
    const previous = this.#database.prepare(
      `SELECT tenant_sequence, occurred_at, event_hash FROM historical_runtime_audit_v1
       WHERE tenant_id = ? ORDER BY tenant_sequence DESC LIMIT 1`
    ).get(actor.tenantId) as { tenant_sequence: number; occurred_at: string; event_hash: Sha256Hash } | undefined;
    if (previous && occurredAt < previous.occurred_at) {
      throw new HistoricalRuntimeAuthorityError("CLOCK_ROLLBACK", "Audit clock moved backward");
    }
    const body = deepFreeze({
      tenantId: actor.tenantId,
      tenantSequence: (previous?.tenant_sequence ?? 0) + 1,
      eventId: identifier(this.#eventId(), "eventId"),
      eventType,
      subjectId,
      subjectHash,
      actorId: actor.actorId,
      occurredAt,
      previousEventHash: previous?.event_hash ?? null
    });
    const eventHash = canonicalHash(body);
    this.#database.prepare(
      `INSERT INTO historical_runtime_audit_v1 (
        tenant_id, tenant_sequence, event_id, event_type, subject_id,
        subject_hash, actor_id, occurred_at, previous_event_hash, event_hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      body.tenantId, body.tenantSequence, body.eventId, body.eventType,
      body.subjectId, body.subjectHash, body.actorId, body.occurredAt,
      body.previousEventHash, eventHash
    );
  }

  #readReceipt(
    actor: TrustedRuntimeAuthorityActorV1,
    operation: "register_bundle" | "register_runtime" | "activate_runtime",
    idempotencyKey: string,
    requestHash: Sha256Hash
  ): unknown | undefined {
    const row = this.#database.prepare(
      `SELECT request_hash, response_json, response_hash FROM historical_runtime_idempotency_v1
       WHERE tenant_id = ? AND operation = ? AND actor_id = ? AND idempotency_key = ?`
    ).get(actor.tenantId, operation, actor.actorId, idempotencyKey) as
      | { request_hash: string; response_json: string; response_hash: string }
      | undefined;
    if (!row) return undefined;
    if (row.request_hash !== requestHash) {
      throw new HistoricalRuntimeAuthorityError("IDEMPOTENCY_CONFLICT", "Idempotency key is bound to another request");
    }
    const response = parseJson(row.response_json, "historical runtime receipt");
    if (canonicalHash(response) !== row.response_hash) throw integrity("Idempotency response hash failed verification");
    return response;
  }

  #writeReceipt(
    actor: TrustedRuntimeAuthorityActorV1,
    operation: "register_bundle" | "register_runtime" | "activate_runtime",
    idempotencyKey: string,
    requestHash: Sha256Hash,
    response: unknown,
    createdAt: string
  ): void {
    const responseJson = canonicalJson(response);
    this.#database.prepare(
      `INSERT INTO historical_runtime_idempotency_v1 (
        tenant_id, operation, actor_id, idempotency_key, request_hash,
        response_json, response_hash, created_at, receipt_hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      actor.tenantId, operation, actor.actorId, idempotencyKey, requestHash,
      responseJson, canonicalHash(response), createdAt,
      canonicalHash({
        tenantId: actor.tenantId,
        operation,
        actorId: actor.actorId,
        idempotencyKey,
        requestHash,
        responseHash: canonicalHash(response),
        createdAt
      })
    );
  }

  #bundleByIdentity(tenantId: string, kind: string, bundleId: string, version: string): BundleRow | undefined {
    return this.#database.prepare(
      `SELECT * FROM historical_runtime_bundles_v1
       WHERE tenant_id = ? AND bundle_kind = ? AND bundle_id = ? AND bundle_version = ?`
    ).get(tenantId, kind, bundleId, version) as BundleRow | undefined;
  }

  #runtimeRow(tenantId: string, runtimeBundleId: string, runtimeBundleHash: string): RuntimeRow | undefined {
    return this.#database.prepare(
      `SELECT * FROM historical_runtime_assemblies_v1
       WHERE tenant_id = ? AND runtime_bundle_id = ? AND runtime_bundle_hash = ?`
    ).get(tenantId, runtimeBundleId, runtimeBundleHash) as RuntimeRow | undefined;
  }

  #activationRow(tenantId: string, runtimeBundleId: string, runtimeBundleHash: string): ActivationRow | undefined {
    return this.#database.prepare(
      `SELECT * FROM historical_runtime_activations_v1
       WHERE tenant_id = ? AND runtime_bundle_id = ? AND runtime_bundle_hash = ?`
    ).get(tenantId, runtimeBundleId, runtimeBundleHash) as ActivationRow | undefined;
  }

  #now(tenantId: string): string {
    const value = this.#clock();
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) invalid("Historical-runtime clock is invalid");
    const now = timestamp(value.toISOString(), "clock");
    const prior = this.#database.prepare(
      "SELECT occurred_at FROM historical_runtime_audit_v1 WHERE tenant_id = ? ORDER BY tenant_sequence DESC LIMIT 1"
    ).get(tenantId) as { occurred_at: string } | undefined;
    if (prior && now < prior.occurred_at) {
      throw new HistoricalRuntimeAuthorityError("CLOCK_ROLLBACK", "Historical-runtime clock moved backward");
    }
    return now;
  }

  #transaction<T>(operation: () => T): T {
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      try { this.#database.exec("ROLLBACK"); } catch { /* preserve original */ }
      if (error instanceof HistoricalRuntimeAuthorityError) throw error;
      throw integrity("Historical-runtime authority transaction failed", error);
    }
  }

  #assertOpen(): void {
    if (this.#closed) throw new HistoricalRuntimeAuthorityError("STORE_CLOSED", "Authority is closed");
  }
}

export class ArtifactBackedHistoricalRuntimeResolverV1 implements HistoricalRuntimeResolver {
  constructor(
    readonly authority: SqliteHistoricalRuntimeAuthorityV1,
    readonly tenantId: string,
    readonly usedAt: () => string
  ) {}

  async resolveRuntimeBundle(reference: {
    readonly runtimeBundleId: string;
    readonly runtimeBundleHash: Sha256Hash;
  }): Promise<HistoricalRuntimeBundleV1> {
    return this.authority.resolveActivatedRuntime(this.tenantId, reference, this.usedAt()).runtime;
  }

  async resolveDictionary(reference: DictionaryBundleReferenceV1): Promise<ResolvedDictionaryBundleV1> {
    const parsed = parseWithSchema(DictionaryBundleReferenceV1Schema, reference, "DictionaryBundleReferenceV1");
    const resolved = this.authority.resolveBundleForTenant(this.tenantId, parsed);
    return deepFreeze({ reference: parsed, content: resolved.content });
  }

  async resolveBundle(reference: ImmutableBundleReferenceV1): Promise<ResolvedImmutableBundleV1> {
    return this.authority.resolveBundleForTenant(this.tenantId, reference);
  }
}

function bundleInput(
  value: RegisterImmutableBundleV1 | RegisterDictionaryBundleV1
): RegisterImmutableBundleV1 | RegisterDictionaryBundleV1 {
  const common = {
    bundleKind: value.bundleKind,
    bundleId: identifier(value.bundleId, "bundleId"),
    version: boundedText(value.version, "version", 64),
    mediaType: mediaType(value.mediaType),
    createdAt: timestamp(value.createdAt, "createdAt"),
    content: canonicalValue(value.content, "bundle content"),
    idempotencyKey: identifier(value.idempotencyKey, "idempotencyKey")
  };
  if (value.bundleKind !== "dictionary") return deepFreeze(common as RegisterImmutableBundleV1);
  const dictionaryContent = record(value.content, "dictionary content");
  if (!("dictionary" in dictionaryContent) || !("fieldPolicy" in dictionaryContent)) {
    invalid("Dictionary content must contain exact dictionary and fieldPolicy subdocuments");
  }
  const expectedDictionaryHash = canonicalHash(dictionaryContent.dictionary);
  const expectedFieldPolicyHash = canonicalHash(dictionaryContent.fieldPolicy);
  if (
    value.dictionaryHash !== expectedDictionaryHash ||
    value.fieldPolicyHash !== expectedFieldPolicyHash
  ) {
    invalid("Dictionary semantic hashes do not match dictionary artifact subdocuments");
  }
  return deepFreeze({
    ...common,
    bundleKind: "dictionary" as const,
    dictionaryVersion: boundedText(value.dictionaryVersion, "dictionaryVersion", 64),
    dictionaryHash: hash(expectedDictionaryHash, "dictionaryHash"),
    fieldPolicyVersion: boundedText(value.fieldPolicyVersion, "fieldPolicyVersion", 64),
    fieldPolicyHash: hash(expectedFieldPolicyHash, "fieldPolicyHash")
  });
}

function runtimeInput(value: RegisterRuntimeAssemblyV1): RegisterRuntimeAssemblyV1 {
  const dictionary = parseWithSchema(DictionaryBundleReferenceV1Schema, value.dictionary, "dictionary reference");
  const mappingCompiler = parseWithSchema(ImmutableBundleReferenceV1Schema, value.mappingCompiler, "mapping compiler reference");
  if (mappingCompiler.bundleKind !== "mapping_compiler") invalid("Runtime mapping compiler reference has the wrong kind");
  const methodologies = value.methodologies.map((item) => {
    const parsed = parseWithSchema(ImmutableBundleReferenceV1Schema, item, "methodology reference");
    if (parsed.bundleKind !== "methodology") invalid("Runtime methodology reference has the wrong kind");
    return parsed as ImmutableBundleReferenceV1 & { bundleKind: "methodology" };
  });
  return deepFreeze({
    runtimeBundleId: identifier(value.runtimeBundleId, "runtimeBundleId"),
    runtimeVersion: boundedText(value.runtimeVersion, "runtimeVersion", 64),
    dictionary,
    mappingCompiler: mappingCompiler as ImmutableBundleReferenceV1 & { bundleKind: "mapping_compiler" },
    methodologies,
    assembledAt: timestamp(value.assembledAt, "assembledAt"),
    idempotencyKey: identifier(value.idempotencyKey, "idempotencyKey")
  });
}

function activationProof(value: unknown): RuntimeActivationProofV1 {
  const object = record(value, "runtime activation proof");
  const body = {
    tenantId: identifier(String(object.tenantId), "tenantId"),
    runtimeBundleId: identifier(String(object.runtimeBundleId), "runtimeBundleId"),
    runtimeBundleHash: hash(String(object.runtimeBundleHash), "runtimeBundleHash"),
    registeredBy: identifier(String(object.registeredBy), "registeredBy"),
    registeredAt: timestamp(String(object.registeredAt), "registeredAt"),
    activatedBy: identifier(String(object.activatedBy), "activatedBy"),
    activatedAt: timestamp(String(object.activatedAt), "activatedAt")
  };
  const activationHash = hash(String(object.activationHash), "activationHash");
  if (canonicalHash(body) !== activationHash) throw integrity("Runtime activation proof hash failed verification");
  return deepFreeze({ ...body, activationHash });
}

function parseBundleReference(value: unknown): ImmutableBundleReferenceV1 | DictionaryBundleReferenceV1 {
  const object = record(value, "bundle reference");
  return object.bundleKind === "dictionary"
    ? parseWithSchema(DictionaryBundleReferenceV1Schema, value, "DictionaryBundleReferenceV1")
    : parseWithSchema(ImmutableBundleReferenceV1Schema, value, "ImmutableBundleReferenceV1");
}

function trustedActor(value: TrustedRuntimeAuthorityActorV1): TrustedRuntimeAuthorityActorV1 {
  try {
    return parseWithSchema(ActorSchema, value, "TrustedRuntimeAuthorityActorV1");
  } catch {
    invalid("Server-derived platform operator identity is required");
  }
}

function assertArtifactHash(stored: StoredArtifact, contentHash: Sha256Hash): void {
  if (`sha256:${stored.contentHash}` !== contentHash) {
    throw integrity("Artifact content hash does not match canonical contract content");
  }
}

function canonicalValue(value: unknown, label: string): CanonicalJsonValue {
  try {
    return JSON.parse(canonicalJson(value)) as CanonicalJsonValue;
  } catch {
    invalid(`${label} is not canonical JSON evidence`);
  }
}

function parseJson(value: string, label: string): unknown {
  try { return JSON.parse(value) as unknown; }
  catch { throw integrity(`${label} is unreadable`); }
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function requiredPath(value: string): string {
  if (typeof value !== "string" || !value.trim()) invalid("Historical-runtime database path is required");
  return value === ":memory:" ? value : resolve(value);
}

function identifier(value: string, label: string): string {
  if (!IdentifierSchema.safeParse(value).success) invalid(`${label} is invalid`);
  return value;
}

function timestamp(value: string, label: string): string {
  if (!IsoTimestampSchema.safeParse(value).success) invalid(`${label} is invalid`);
  return value;
}

function hash(value: string, label: string): Sha256Hash {
  const parsed = Sha256HashSchema.safeParse(value);
  if (!parsed.success) invalid(`${label} is invalid`);
  return parsed.data;
}

function boundedText(value: string, label: string, maximum: number): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum) invalid(`${label} is invalid`);
  return value;
}

function mediaType(value: string): string {
  if (!/^[^\s/]+\/[^\s/]+$/u.test(value) || value.length > 128) invalid("mediaType is invalid");
  return value;
}

function integer(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalid(`${label} is outside its bound`);
  return value;
}

function invalid(message: string): never {
  throw new HistoricalRuntimeAuthorityError("INVALID_INPUT", message);
}

function notFound(message: string): never {
  throw new HistoricalRuntimeAuthorityError("NOT_FOUND", message);
}

function integrity(message: string, cause?: unknown): HistoricalRuntimeAuthorityError {
  return new HistoricalRuntimeAuthorityError(
    "INTEGRITY_FAILURE",
    cause === undefined ? message : `${message}: ${cause instanceof Error ? cause.message : "unknown failure"}`
  );
}
