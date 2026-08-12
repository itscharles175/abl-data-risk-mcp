import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  IdentifierSchema,
  IsoDateSchema,
  Sha256HashSchema,
  canonicalHash,
  canonicalJson,
  parseWithSchema,
  type Sha256Hash
} from "../contracts/canonical.js";
import { migrateSqliteComponent } from "../infrastructure/sqlite-component-schema.js";

export const INPUT_CERTIFICATION_STORE_COMPONENT = "abl.input-certification-store" as const;
export const INPUT_CERTIFICATION_STORE_SCHEMA_VERSION = 1 as const;

export type InputCertificationKindV1 = "borrowing_base" | "monitoring";
export type CertifiedInputArtifactKindV1 =
  | "certified_borrowing_base_input"
  | "certified_monitoring_input";

export interface InputDefinitionReferenceV1 {
  readonly definitionId: string;
  readonly version: string;
  readonly definitionHash: Sha256Hash;
}

export interface InputDeclaredControlsV1 {
  readonly rowCount: number;
  readonly balance?: string;
  readonly currency?: string;
}

export interface ProposeInputCertificationInput {
  readonly tenantId: string;
  readonly inputId: string;
  readonly inputKind: InputCertificationKindV1;
  readonly candidateArtifactId: string;
  readonly candidateArtifactHash: Sha256Hash;
  readonly candidateArtifactKind: string;
  readonly snapshotId: string;
  readonly asOfDate: string;
  readonly purpose: string;
  readonly primaryCertificationManifestId: string;
  readonly definitionReferences: readonly InputDefinitionReferenceV1[];
  readonly declaredControls: InputDeclaredControlsV1;
  readonly payloadHash: Sha256Hash;
  readonly fieldSetHash: Sha256Hash;
  readonly rowCount: number;
  readonly proposedBy: string;
  readonly idempotencyKey: string;
}

export interface InputCertificationProposalV1
  extends Omit<ProposeInputCertificationInput, "idempotencyKey"> {
  readonly contractVersion: 1;
  readonly status: "proposed";
  readonly proposalHash: Sha256Hash;
  readonly proposedAt: string;
}

export interface CertifyInputCertificationInput {
  readonly tenantId: string;
  readonly inputId: string;
  readonly certifiedArtifactId: string;
  readonly certifiedArtifactHash: Sha256Hash;
  readonly certifiedArtifactKind: CertifiedInputArtifactKindV1;
  readonly lineageHash: Sha256Hash;
  readonly envelopeHash: Sha256Hash;
  readonly derivationHash: Sha256Hash;
  readonly primaryCertificationHash: Sha256Hash;
  readonly primaryPopulationHash: Sha256Hash;
  readonly sidecarCertificationHash: Sha256Hash;
  readonly sidecarPopulationHash: Sha256Hash;
  readonly dataQualityRunId: string;
  readonly dataQualityResultHash: Sha256Hash;
  readonly reconciliationId: string;
  readonly reconciliationResultHash: Sha256Hash;
  readonly certifiedBy: string;
  readonly idempotencyKey: string;
}

export interface InputCertificationRecordV1
  extends Omit<InputCertificationProposalV1, "status">,
    Omit<CertifyInputCertificationInput, "tenantId" | "inputId" | "idempotencyKey"> {
  readonly status: "certified";
  readonly certifiedAt: string;
}

export type InputCertificationViewV1 = InputCertificationProposalV1 | InputCertificationRecordV1;

export interface InputCertificationAuditEventV1 {
  readonly sequence: number;
  readonly tenantId: string;
  readonly eventId: string;
  readonly eventType: "input_certification.proposed" | "input_certification.certified";
  readonly inputId: string;
  readonly actor: string;
  readonly details: Readonly<Record<string, unknown>>;
  readonly occurredAt: string;
}

export interface InputCertificationStoreOptions {
  readonly clock?: () => Date;
  readonly busyTimeoutMs?: number;
}

export type InputCertificationStoreErrorCode =
  | "INVALID_INPUT"
  | "NOT_FOUND"
  | "CONFLICT"
  | "IDEMPOTENCY_CONFLICT"
  | "MAKER_CHECKER_VIOLATION"
  | "ILLEGAL_TRANSITION"
  | "STORE_CLOSED";

export class InputCertificationStoreError extends Error {
  constructor(readonly code: InputCertificationStoreErrorCode, message: string) {
    super(message);
    this.name = "InputCertificationStoreError";
  }
}

export class InputCertificationStore {
  readonly #database: DatabaseSync;
  readonly #clock: () => Date;
  #closed = false;

  constructor(databasePath: string, options: InputCertificationStoreOptions = {}) {
    if (!databasePath.trim()) invalid("Input-certification database path is required");
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
        componentName: INPUT_CERTIFICATION_STORE_COMPONENT,
        supportedVersion: INPUT_CERTIFICATION_STORE_SCHEMA_VERSION,
        migrations: [{ version: 1, sql: INPUT_CERTIFICATION_SCHEMA }],
        unsupportedVersionError: (current, supported) =>
          new InputCertificationStoreError(
            "CONFLICT",
            `Input-certification schema ${current} is newer than supported version ${supported}`
          )
      });
    } catch (error) {
      this.#database.close();
      throw error;
    }
  }

  propose(inputValue: ProposeInputCertificationInput): InputCertificationProposalV1 {
    this.#assertOpen();
    const input = validateProposal(inputValue);
    const requestHash = canonicalHash(input);
    return this.#transaction(() => {
      const replay = this.#readReceipt(
        input.tenantId,
        "input_certification.propose",
        input.proposedBy,
        input.idempotencyKey,
        requestHash
      );
      if (replay) return this.#required(input.tenantId, replay.inputId) as InputCertificationProposalV1;
      if (this.get(input.tenantId, input.inputId)) conflict("Input certification id already exists");
      const proposedAt = this.#now();
      const proposalBody = proposalHashBody(input, proposedAt);
      const proposalHash = canonicalHash(proposalBody);
      this.#database
        .prepare(
          `INSERT INTO input_certification_proposals (
             tenant_id, input_id, input_kind, candidate_artifact_id, candidate_artifact_hash,
             candidate_artifact_kind, snapshot_id, as_of_date, purpose,
             primary_certification_manifest_id, definition_references_json,
             declared_controls_json, payload_hash, field_set_hash, row_count,
             proposed_by, proposed_at, proposal_hash
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          input.tenantId,
          input.inputId,
          input.inputKind,
          input.candidateArtifactId,
          input.candidateArtifactHash,
          input.candidateArtifactKind,
          input.snapshotId,
          input.asOfDate,
          input.purpose,
          input.primaryCertificationManifestId,
          canonicalJson(input.definitionReferences),
          canonicalJson(input.declaredControls),
          input.payloadHash,
          input.fieldSetHash,
          input.rowCount,
          input.proposedBy,
          proposedAt,
          proposalHash
        );
      this.#audit(input.tenantId, input.inputId, "input_certification.proposed", input.proposedBy, {
        candidateArtifactHash: input.candidateArtifactHash,
        inputKind: input.inputKind,
        payloadHash: input.payloadHash,
        proposalHash,
        snapshotId: input.snapshotId
      }, proposedAt);
      this.#recordReceipt(
        input.tenantId,
        "input_certification.propose",
        input.proposedBy,
        input.idempotencyKey,
        requestHash,
        input.inputId,
        proposedAt
      );
      return this.#required(input.tenantId, input.inputId) as InputCertificationProposalV1;
    });
  }

  get(tenantId: string, inputId: string): InputCertificationViewV1 | undefined {
    this.#assertOpen();
    id(tenantId, "tenantId");
    id(inputId, "inputId");
    const row = this.#database
      .prepare(
        `SELECT proposal.*, certification.certified_artifact_id,
                certification.certified_artifact_hash, certification.certified_artifact_kind,
                certification.lineage_hash, certification.envelope_hash,
                certification.derivation_hash, certification.primary_certification_hash,
                certification.primary_population_hash, certification.sidecar_certification_hash,
                certification.sidecar_population_hash, certification.data_quality_run_id,
                certification.data_quality_result_hash, certification.reconciliation_id,
                certification.reconciliation_result_hash, certification.certified_by,
                certification.certified_at
           FROM input_certification_proposals AS proposal
           LEFT JOIN input_certifications AS certification
             ON certification.tenant_id = proposal.tenant_id
            AND certification.input_id = proposal.input_id
          WHERE proposal.tenant_id = ? AND proposal.input_id = ?`
      )
      .get(tenantId, inputId) as InputCertificationRow | undefined;
    return row ? recordFromRow(row) : undefined;
  }

  list(tenantId: string, limit = 100): readonly InputCertificationViewV1[] {
    this.#assertOpen();
    id(tenantId, "tenantId");
    integer(limit, "limit", 1, 1_000);
    const rows = this.#database
      .prepare(
        `SELECT proposal.*, certification.certified_artifact_id,
                certification.certified_artifact_hash, certification.certified_artifact_kind,
                certification.lineage_hash, certification.envelope_hash,
                certification.derivation_hash, certification.primary_certification_hash,
                certification.primary_population_hash, certification.sidecar_certification_hash,
                certification.sidecar_population_hash, certification.data_quality_run_id,
                certification.data_quality_result_hash, certification.reconciliation_id,
                certification.reconciliation_result_hash, certification.certified_by,
                certification.certified_at
           FROM input_certification_proposals AS proposal
           LEFT JOIN input_certifications AS certification
             ON certification.tenant_id = proposal.tenant_id
            AND certification.input_id = proposal.input_id
          WHERE proposal.tenant_id = ?
          ORDER BY proposal.proposed_at, proposal.input_id
          LIMIT ?`
      )
      .all(tenantId, limit) as unknown as InputCertificationRow[];
    return rows.map(recordFromRow);
  }

  certify(inputValue: CertifyInputCertificationInput): InputCertificationRecordV1 {
    this.#assertOpen();
    const input = validateCertification(inputValue);
    const requestHash = canonicalHash(input);
    return this.#transaction(() => {
      const replay = this.#readReceipt(
        input.tenantId,
        "input_certification.certify",
        input.certifiedBy,
        input.idempotencyKey,
        requestHash
      );
      if (replay) return this.#required(input.tenantId, replay.inputId) as InputCertificationRecordV1;
      const proposal = this.#required(input.tenantId, input.inputId);
      if (proposal.status !== "proposed") transition("Input certification is already terminal");
      if (proposal.proposedBy === input.certifiedBy) {
        throw new InputCertificationStoreError(
          "MAKER_CHECKER_VIOLATION",
          "Input certification proposer cannot certify the same input"
        );
      }
      const expectedKind = certifiedArtifactKind(proposal.inputKind);
      if (input.certifiedArtifactKind !== expectedKind) {
        invalid(`Certified artifact kind must be ${expectedKind}`);
      }
      if (input.sidecarPopulationHash !== proposal.payloadHash) {
        invalid("Sidecar population hash must match the locked proposal payload hash");
      }
      const certifiedAt = this.#now();
      this.#database
        .prepare(
          `INSERT INTO input_certifications (
             tenant_id, input_id, certified_artifact_id, certified_artifact_hash,
             certified_artifact_kind, lineage_hash, envelope_hash, derivation_hash,
             primary_certification_hash, primary_population_hash,
             sidecar_certification_hash, sidecar_population_hash,
             data_quality_run_id, data_quality_result_hash,
             reconciliation_id, reconciliation_result_hash, certified_by, certified_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          input.tenantId,
          input.inputId,
          input.certifiedArtifactId,
          input.certifiedArtifactHash,
          input.certifiedArtifactKind,
          input.lineageHash,
          input.envelopeHash,
          input.derivationHash,
          input.primaryCertificationHash,
          input.primaryPopulationHash,
          input.sidecarCertificationHash,
          input.sidecarPopulationHash,
          input.dataQualityRunId,
          input.dataQualityResultHash,
          input.reconciliationId,
          input.reconciliationResultHash,
          input.certifiedBy,
          certifiedAt
        );
      this.#audit(input.tenantId, input.inputId, "input_certification.certified", input.certifiedBy, {
        certifiedArtifactHash: input.certifiedArtifactHash,
        envelopeHash: input.envelopeHash,
        lineageHash: input.lineageHash,
        proposalHash: proposal.proposalHash,
        sidecarCertificationHash: input.sidecarCertificationHash
      }, certifiedAt);
      this.#recordReceipt(
        input.tenantId,
        "input_certification.certify",
        input.certifiedBy,
        input.idempotencyKey,
        requestHash,
        input.inputId,
        certifiedAt
      );
      return this.#required(input.tenantId, input.inputId) as InputCertificationRecordV1;
    });
  }

  listAuditEvents(
    tenantId: string,
    afterSequence = 0,
    limit = 100
  ): readonly InputCertificationAuditEventV1[] {
    this.#assertOpen();
    id(tenantId, "tenantId");
    integer(afterSequence, "afterSequence", 0, Number.MAX_SAFE_INTEGER);
    integer(limit, "limit", 1, 1_000);
    const rows = this.#database
      .prepare(
        `SELECT * FROM input_certification_audit_events
          WHERE tenant_id = ? AND sequence > ?
          ORDER BY sequence LIMIT ?`
      )
      .all(tenantId, afterSequence, limit) as unknown as InputCertificationAuditRow[];
    return rows.map((row) => ({
      sequence: row.sequence,
      tenantId: row.tenant_id,
      eventId: row.event_id,
      eventType: row.event_type,
      inputId: row.input_id,
      actor: row.actor,
      details: parseObject(row.details_json, "audit details"),
      occurredAt: row.occurred_at
    }));
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#database.close();
  }

  #required(tenantId: string, inputId: string): InputCertificationViewV1 {
    const record = this.get(tenantId, inputId);
    if (!record) throw new InputCertificationStoreError("NOT_FOUND", "Input certification was not found");
    return record;
  }

  #readReceipt(
    tenantId: string,
    operation: string,
    actor: string,
    idempotencyKey: string,
    requestHash: Sha256Hash
  ): { readonly inputId: string } | null {
    const row = this.#database
      .prepare(
        `SELECT request_hash, input_id FROM input_certification_idempotency
          WHERE tenant_id = ? AND operation = ? AND actor = ? AND idempotency_key = ?`
      )
      .get(tenantId, operation, actor, idempotencyKey) as
      | { readonly request_hash: string; readonly input_id: string }
      | undefined;
    if (!row) return null;
    if (row.request_hash !== requestHash) {
      throw new InputCertificationStoreError(
        "IDEMPOTENCY_CONFLICT",
        "Idempotency key was used with another input-certification request"
      );
    }
    return { inputId: row.input_id };
  }

  #recordReceipt(
    tenantId: string,
    operation: string,
    actor: string,
    idempotencyKey: string,
    requestHash: Sha256Hash,
    inputId: string,
    now: string
  ): void {
    this.#database
      .prepare(
        `INSERT INTO input_certification_idempotency (
           tenant_id, operation, actor, idempotency_key, request_hash, input_id, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(tenantId, operation, actor, idempotencyKey, requestHash, inputId, now);
  }

  #audit(
    tenantId: string,
    inputId: string,
    eventType: InputCertificationAuditEventV1["eventType"],
    actor: string,
    details: Readonly<Record<string, unknown>>,
    now: string
  ): void {
    this.#database
      .prepare(
        `INSERT INTO input_certification_audit_events (
           tenant_id, event_id, input_id, event_type, actor, details_json, occurred_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(tenantId, randomUUID(), inputId, eventType, actor, canonicalJson(details), now);
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
    if (Number.isNaN(value.getTime())) invalid("Input-certification clock is invalid");
    return value.toISOString();
  }

  #assertOpen(): void {
    if (this.#closed) throw new InputCertificationStoreError("STORE_CLOSED", "Input-certification store is closed");
  }
}

const INPUT_CERTIFICATION_SCHEMA = `
CREATE TABLE input_certification_proposals (
  tenant_id TEXT NOT NULL,
  input_id TEXT NOT NULL,
  input_kind TEXT NOT NULL CHECK (input_kind IN ('borrowing_base','monitoring')),
  candidate_artifact_id TEXT NOT NULL,
  candidate_artifact_hash TEXT NOT NULL CHECK (candidate_artifact_hash GLOB 'sha256:[0-9a-f]*' AND length(candidate_artifact_hash) = 71),
  candidate_artifact_kind TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  as_of_date TEXT NOT NULL,
  purpose TEXT NOT NULL,
  primary_certification_manifest_id TEXT NOT NULL,
  definition_references_json TEXT NOT NULL,
  declared_controls_json TEXT NOT NULL,
  payload_hash TEXT NOT NULL CHECK (payload_hash GLOB 'sha256:[0-9a-f]*' AND length(payload_hash) = 71),
  field_set_hash TEXT NOT NULL CHECK (field_set_hash GLOB 'sha256:[0-9a-f]*' AND length(field_set_hash) = 71),
  row_count INTEGER NOT NULL CHECK (row_count >= 0),
  proposed_by TEXT NOT NULL,
  proposed_at TEXT NOT NULL,
  proposal_hash TEXT NOT NULL CHECK (proposal_hash GLOB 'sha256:[0-9a-f]*' AND length(proposal_hash) = 71),
  PRIMARY KEY (tenant_id, input_id)
) STRICT;
CREATE TRIGGER input_certification_proposals_no_update BEFORE UPDATE ON input_certification_proposals
BEGIN SELECT RAISE(ABORT, 'input certification proposals are immutable'); END;
CREATE TRIGGER input_certification_proposals_no_delete BEFORE DELETE ON input_certification_proposals
BEGIN SELECT RAISE(ABORT, 'input certification proposals are immutable'); END;

CREATE TABLE input_certifications (
  tenant_id TEXT NOT NULL,
  input_id TEXT NOT NULL,
  certified_artifact_id TEXT NOT NULL,
  certified_artifact_hash TEXT NOT NULL CHECK (certified_artifact_hash GLOB 'sha256:[0-9a-f]*' AND length(certified_artifact_hash) = 71),
  certified_artifact_kind TEXT NOT NULL CHECK (certified_artifact_kind IN ('certified_borrowing_base_input','certified_monitoring_input')),
  lineage_hash TEXT NOT NULL CHECK (lineage_hash GLOB 'sha256:[0-9a-f]*' AND length(lineage_hash) = 71),
  envelope_hash TEXT NOT NULL CHECK (envelope_hash GLOB 'sha256:[0-9a-f]*' AND length(envelope_hash) = 71),
  derivation_hash TEXT NOT NULL CHECK (derivation_hash GLOB 'sha256:[0-9a-f]*' AND length(derivation_hash) = 71),
  primary_certification_hash TEXT NOT NULL CHECK (primary_certification_hash GLOB 'sha256:[0-9a-f]*' AND length(primary_certification_hash) = 71),
  primary_population_hash TEXT NOT NULL CHECK (primary_population_hash GLOB 'sha256:[0-9a-f]*' AND length(primary_population_hash) = 71),
  sidecar_certification_hash TEXT NOT NULL CHECK (sidecar_certification_hash GLOB 'sha256:[0-9a-f]*' AND length(sidecar_certification_hash) = 71),
  sidecar_population_hash TEXT NOT NULL CHECK (sidecar_population_hash GLOB 'sha256:[0-9a-f]*' AND length(sidecar_population_hash) = 71),
  data_quality_run_id TEXT NOT NULL,
  data_quality_result_hash TEXT NOT NULL CHECK (data_quality_result_hash GLOB 'sha256:[0-9a-f]*' AND length(data_quality_result_hash) = 71),
  reconciliation_id TEXT NOT NULL,
  reconciliation_result_hash TEXT NOT NULL CHECK (reconciliation_result_hash GLOB 'sha256:[0-9a-f]*' AND length(reconciliation_result_hash) = 71),
  certified_by TEXT NOT NULL,
  certified_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, input_id),
  FOREIGN KEY (tenant_id, input_id) REFERENCES input_certification_proposals (tenant_id, input_id)
) STRICT;
CREATE TRIGGER input_certifications_no_update BEFORE UPDATE ON input_certifications
BEGIN SELECT RAISE(ABORT, 'input certifications are immutable'); END;
CREATE TRIGGER input_certifications_no_delete BEFORE DELETE ON input_certifications
BEGIN SELECT RAISE(ABORT, 'input certifications are immutable'); END;

CREATE TABLE input_certification_idempotency (
  tenant_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  actor TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL CHECK (request_hash GLOB 'sha256:[0-9a-f]*' AND length(request_hash) = 71),
  input_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, operation, actor, idempotency_key)
) STRICT;
CREATE TRIGGER input_certification_idempotency_no_update BEFORE UPDATE ON input_certification_idempotency
BEGIN SELECT RAISE(ABORT, 'input certification idempotency is immutable'); END;
CREATE TRIGGER input_certification_idempotency_no_delete BEFORE DELETE ON input_certification_idempotency
BEGIN SELECT RAISE(ABORT, 'input certification idempotency is immutable'); END;

CREATE TABLE input_certification_audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL UNIQUE,
  input_id TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('input_certification.proposed','input_certification.certified')),
  actor TEXT NOT NULL,
  details_json TEXT NOT NULL,
  occurred_at TEXT NOT NULL
) STRICT;
CREATE INDEX input_certification_audit_tenant_sequence
  ON input_certification_audit_events (tenant_id, sequence);
CREATE TRIGGER input_certification_audit_no_update BEFORE UPDATE ON input_certification_audit_events
BEGIN SELECT RAISE(ABORT, 'input certification audit is append-only'); END;
CREATE TRIGGER input_certification_audit_no_delete BEFORE DELETE ON input_certification_audit_events
BEGIN SELECT RAISE(ABORT, 'input certification audit is append-only'); END;
`;

interface InputCertificationRow {
  readonly tenant_id: string;
  readonly input_id: string;
  readonly input_kind: InputCertificationKindV1;
  readonly candidate_artifact_id: string;
  readonly candidate_artifact_hash: string;
  readonly candidate_artifact_kind: string;
  readonly snapshot_id: string;
  readonly as_of_date: string;
  readonly purpose: string;
  readonly primary_certification_manifest_id: string;
  readonly definition_references_json: string;
  readonly declared_controls_json: string;
  readonly payload_hash: string;
  readonly field_set_hash: string;
  readonly row_count: number;
  readonly proposed_by: string;
  readonly proposed_at: string;
  readonly proposal_hash: string;
  readonly certified_artifact_id: string | null;
  readonly certified_artifact_hash: string | null;
  readonly certified_artifact_kind: CertifiedInputArtifactKindV1 | null;
  readonly lineage_hash: string | null;
  readonly envelope_hash: string | null;
  readonly derivation_hash: string | null;
  readonly primary_certification_hash: string | null;
  readonly primary_population_hash: string | null;
  readonly sidecar_certification_hash: string | null;
  readonly sidecar_population_hash: string | null;
  readonly data_quality_run_id: string | null;
  readonly data_quality_result_hash: string | null;
  readonly reconciliation_id: string | null;
  readonly reconciliation_result_hash: string | null;
  readonly certified_by: string | null;
  readonly certified_at: string | null;
}

interface InputCertificationAuditRow {
  readonly sequence: number;
  readonly tenant_id: string;
  readonly event_id: string;
  readonly event_type: InputCertificationAuditEventV1["eventType"];
  readonly input_id: string;
  readonly actor: string;
  readonly details_json: string;
  readonly occurred_at: string;
}

function validateProposal(input: ProposeInputCertificationInput): ProposeInputCertificationInput {
  id(input.tenantId, "tenantId");
  id(input.inputId, "inputId");
  if (input.inputKind !== "borrowing_base" && input.inputKind !== "monitoring") invalid("inputKind is invalid");
  id(input.candidateArtifactId, "candidateArtifactId");
  hash(input.candidateArtifactHash, "candidateArtifactHash");
  id(input.candidateArtifactKind, "candidateArtifactKind");
  id(input.snapshotId, "snapshotId");
  parseWithSchema(IsoDateSchema, input.asOfDate, "input certification asOfDate");
  text(input.purpose, "purpose", 512);
  id(input.primaryCertificationManifestId, "primaryCertificationManifestId");
  id(input.proposedBy, "proposedBy");
  id(input.idempotencyKey, "idempotencyKey");
  hash(input.payloadHash, "payloadHash");
  hash(input.fieldSetHash, "fieldSetHash");
  integer(input.rowCount, "rowCount", 0, 1_000_000_000);
  const references = normalizeDefinitionReferences(input.definitionReferences);
  const declaredControls = normalizeDeclaredControls(input.declaredControls);
  if (declaredControls.rowCount !== input.rowCount) {
    invalid("Declared control row count must match the locked input row count");
  }
  return Object.freeze({ ...input, definitionReferences: references, declaredControls });
}

function validateCertification(input: CertifyInputCertificationInput): CertifyInputCertificationInput {
  id(input.tenantId, "tenantId");
  id(input.inputId, "inputId");
  id(input.certifiedArtifactId, "certifiedArtifactId");
  for (const [label, value] of [
    ["certifiedArtifactHash", input.certifiedArtifactHash],
    ["lineageHash", input.lineageHash],
    ["envelopeHash", input.envelopeHash],
    ["derivationHash", input.derivationHash],
    ["primaryCertificationHash", input.primaryCertificationHash],
    ["primaryPopulationHash", input.primaryPopulationHash],
    ["sidecarCertificationHash", input.sidecarCertificationHash],
    ["sidecarPopulationHash", input.sidecarPopulationHash],
    ["dataQualityResultHash", input.dataQualityResultHash],
    ["reconciliationResultHash", input.reconciliationResultHash]
  ] as const) hash(value, label);
  if (
    input.certifiedArtifactKind !== "certified_borrowing_base_input" &&
    input.certifiedArtifactKind !== "certified_monitoring_input"
  ) {
    invalid("certifiedArtifactKind is invalid");
  }
  id(input.dataQualityRunId, "dataQualityRunId");
  id(input.reconciliationId, "reconciliationId");
  id(input.certifiedBy, "certifiedBy");
  id(input.idempotencyKey, "idempotencyKey");
  return Object.freeze({ ...input });
}

function normalizeDefinitionReferences(
  values: readonly InputDefinitionReferenceV1[]
): readonly InputDefinitionReferenceV1[] {
  if (values.length < 1 || values.length > 128) invalid("definitionReferences must contain 1 through 128 items");
  const normalized = values.map((reference) => {
    id(reference.definitionId, "definitionId");
    text(reference.version, "definition version", 64);
    hash(reference.definitionHash, "definitionHash");
    return Object.freeze({ ...reference });
  });
  const keys = normalized.map(
    (reference) => `${reference.definitionId}\u0000${reference.version}\u0000${reference.definitionHash}`
  );
  if (new Set(keys).size !== keys.length) invalid("definitionReferences must be unique");
  return Object.freeze(
    [...normalized].sort(
      (left, right) =>
        compare(left.definitionId, right.definitionId) ||
        compare(left.version, right.version) ||
        compare(left.definitionHash, right.definitionHash)
    )
  );
}

function normalizeDeclaredControls(value: InputDeclaredControlsV1): InputDeclaredControlsV1 {
  const keys = Object.keys(value).sort();
  if (keys.some((key) => key !== "balance" && key !== "currency" && key !== "rowCount")) {
    invalid("declaredControls contains an unknown field");
  }
  integer(value.rowCount, "declaredControls.rowCount", 0, 1_000_000_000);
  if (value.balance !== undefined && !/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value.balance)) {
    invalid("declaredControls.balance must be an exact decimal string");
  }
  if (value.currency !== undefined && !/^[A-Z]{3}$/.test(value.currency)) {
    invalid("declaredControls.currency must be an uppercase currency code");
  }
  if (value.balance !== undefined && value.currency === undefined) {
    invalid("declaredControls.balance requires currency");
  }
  return Object.freeze({
    rowCount: value.rowCount,
    ...(value.balance === undefined ? {} : { balance: value.balance }),
    ...(value.currency === undefined ? {} : { currency: value.currency })
  });
}

function proposalHashBody(input: ProposeInputCertificationInput, proposedAt: string): Record<string, unknown> {
  const { idempotencyKey: _idempotencyKey, ...locked } = input;
  return { contractVersion: 1, status: "proposed", ...locked, proposedAt };
}

function recordFromRow(row: InputCertificationRow): InputCertificationViewV1 {
  const proposal: InputCertificationProposalV1 = {
    contractVersion: 1,
    tenantId: row.tenant_id,
    inputId: row.input_id,
    inputKind: row.input_kind,
    candidateArtifactId: row.candidate_artifact_id,
    candidateArtifactHash: persistedHash(row.candidate_artifact_hash, "candidateArtifactHash"),
    candidateArtifactKind: row.candidate_artifact_kind,
    snapshotId: row.snapshot_id,
    asOfDate: row.as_of_date,
    purpose: row.purpose,
    primaryCertificationManifestId: row.primary_certification_manifest_id,
    definitionReferences: parseDefinitions(row.definition_references_json),
    declaredControls: parseDeclaredControls(row.declared_controls_json),
    payloadHash: persistedHash(row.payload_hash, "payloadHash"),
    fieldSetHash: persistedHash(row.field_set_hash, "fieldSetHash"),
    rowCount: row.row_count,
    proposedBy: row.proposed_by,
    status: "proposed",
    proposalHash: persistedHash(row.proposal_hash, "proposalHash"),
    proposedAt: row.proposed_at
  };
  const proposalBody = {
    contractVersion: proposal.contractVersion,
    status: proposal.status,
    tenantId: proposal.tenantId,
    inputId: proposal.inputId,
    inputKind: proposal.inputKind,
    candidateArtifactId: proposal.candidateArtifactId,
    candidateArtifactHash: proposal.candidateArtifactHash,
    candidateArtifactKind: proposal.candidateArtifactKind,
    snapshotId: proposal.snapshotId,
    asOfDate: proposal.asOfDate,
    purpose: proposal.purpose,
    primaryCertificationManifestId: proposal.primaryCertificationManifestId,
    definitionReferences: proposal.definitionReferences,
    declaredControls: proposal.declaredControls,
    payloadHash: proposal.payloadHash,
    fieldSetHash: proposal.fieldSetHash,
    rowCount: proposal.rowCount,
    proposedBy: proposal.proposedBy,
    proposedAt: proposal.proposedAt
  };
  if (canonicalHash(proposalBody) !== proposal.proposalHash) integrity("Proposal hash did not verify");
  if (row.certified_at === null) return Object.freeze(proposal);
  if (
    row.certified_artifact_id === null ||
    row.certified_artifact_hash === null ||
    row.certified_artifact_kind === null ||
    row.lineage_hash === null ||
    row.envelope_hash === null ||
    row.derivation_hash === null ||
    row.primary_certification_hash === null ||
    row.primary_population_hash === null ||
    row.sidecar_certification_hash === null ||
    row.sidecar_population_hash === null ||
    row.data_quality_run_id === null ||
    row.data_quality_result_hash === null ||
    row.reconciliation_id === null ||
    row.reconciliation_result_hash === null ||
    row.certified_by === null
  ) {
    integrity("Certified input record is incomplete");
  }
  return Object.freeze({
    ...proposal,
    status: "certified",
    certifiedArtifactId: row.certified_artifact_id,
    certifiedArtifactHash: persistedHash(row.certified_artifact_hash, "certifiedArtifactHash"),
    certifiedArtifactKind: row.certified_artifact_kind,
    lineageHash: persistedHash(row.lineage_hash, "lineageHash"),
    envelopeHash: persistedHash(row.envelope_hash, "envelopeHash"),
    derivationHash: persistedHash(row.derivation_hash, "derivationHash"),
    primaryCertificationHash: persistedHash(row.primary_certification_hash, "primaryCertificationHash"),
    primaryPopulationHash: persistedHash(row.primary_population_hash, "primaryPopulationHash"),
    sidecarCertificationHash: persistedHash(row.sidecar_certification_hash, "sidecarCertificationHash"),
    sidecarPopulationHash: persistedHash(row.sidecar_population_hash, "sidecarPopulationHash"),
    dataQualityRunId: row.data_quality_run_id,
    dataQualityResultHash: persistedHash(row.data_quality_result_hash, "dataQualityResultHash"),
    reconciliationId: row.reconciliation_id,
    reconciliationResultHash: persistedHash(row.reconciliation_result_hash, "reconciliationResultHash"),
    certifiedBy: row.certified_by,
    certifiedAt: row.certified_at
  });
}

function parseDefinitions(value: string): readonly InputDefinitionReferenceV1[] {
  const parsed = parseJson(value, "definitionReferences");
  if (!Array.isArray(parsed)) integrity("Definition references are not an array");
  return normalizeDefinitionReferences(parsed as unknown as readonly InputDefinitionReferenceV1[]);
}

function parseDeclaredControls(value: string): InputDeclaredControlsV1 {
  return normalizeDeclaredControls(parseObject(value, "declaredControls") as unknown as InputDeclaredControlsV1);
}

function parseObject(value: string, label: string): Readonly<Record<string, unknown>> {
  const parsed = parseJson(value, label);
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") integrity(`${label} must be an object`);
  return parsed as Readonly<Record<string, unknown>>;
}

function parseJson(value: string, label: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    integrity(`${label} is not valid JSON`);
  }
}

function persistedHash(value: string, label: string): Sha256Hash {
  try {
    return parseWithSchema(Sha256HashSchema, value, label);
  } catch {
    integrity(`${label} is invalid`);
  }
}

function certifiedArtifactKind(inputKind: InputCertificationKindV1): CertifiedInputArtifactKindV1 {
  return inputKind === "borrowing_base"
    ? "certified_borrowing_base_input"
    : "certified_monitoring_input";
}

function id(value: string, label: string): void {
  try {
    parseWithSchema(IdentifierSchema, value, label);
  } catch {
    invalid(`${label} is invalid`);
  }
}

function hash(value: string, label: string): asserts value is Sha256Hash {
  try {
    parseWithSchema(Sha256HashSchema, value, label);
  } catch {
    invalid(`${label} is invalid`);
  }
}

function text(value: string, label: string, maximum: number): void {
  if (!value || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) invalid(`${label} is invalid`);
}

function integer(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalid(`${label} is invalid`);
  return value;
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function invalid(message: string): never {
  throw new InputCertificationStoreError("INVALID_INPUT", message);
}

function conflict(message: string): never {
  throw new InputCertificationStoreError("CONFLICT", message);
}

function transition(message: string): never {
  throw new InputCertificationStoreError("ILLEGAL_TRANSITION", message);
}

function integrity(message: string): never {
  throw new InputCertificationStoreError("CONFLICT", message);
}
