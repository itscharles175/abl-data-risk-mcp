import { createHash } from "node:crypto";

import {
  artifactJsonContentHash,
  type ArtifactStore,
  type StoredArtifact
} from "../control/artifacts.js";
import type {
  AnalysisManifest,
  ControlStore,
  DataQualityRun,
  DatasetSnapshot,
  JsonValue,
  MappingVersion,
  Reconciliation
} from "../control/store.js";
import {
  reconcileControlTotals,
  runDataQuality,
  type ControlTotals,
  type DataQualityProfile,
  type DataQualityResult,
  type ReconciliationTolerance
} from "../domain/data-quality.js";
import { getCanonicalField, type LogicalType } from "../domain/dictionary.js";

export interface RegisterDeliveredSnapshotInput {
  readonly tenantId: string;
  readonly snapshotId: string;
  readonly sourceId: string;
  readonly asOfDate: string;
  readonly records: readonly Readonly<Record<string, unknown>>[];
  readonly deliveredBy: string;
  readonly idempotencyKey: string;
  readonly expectedCanonicalContentHash?: string;
}

export interface RegisteredSnapshot {
  readonly snapshot: DatasetSnapshot;
  readonly sourceArtifact: StoredArtifact;
}

export interface CertifyMappedSnapshotInput {
  readonly tenantId: string;
  readonly snapshotId: string;
  readonly mappingVersionId: string;
  readonly dataQualityRunId: string;
  readonly reconciliationId: string;
  readonly certificationManifestId: string;
  readonly dataQualityProfile: DataQualityProfile;
  readonly declaredControlTotals: ControlTotals;
  readonly reconciliationTolerance?: ReconciliationTolerance;
  readonly evaluatedAt: string;
  readonly codeVersion: string;
  readonly executedBy: string;
  readonly idempotencyKey: string;
}

export interface SnapshotCertification {
  readonly snapshot: DatasetSnapshot;
  readonly mappingVersion: MappingVersion;
  readonly normalizedArtifact: StoredArtifact;
  readonly dataQuality: DataQualityResult;
  readonly durableDataQualityRun: DataQualityRun;
  readonly reconciliation: Reconciliation;
  readonly manifest: AnalysisManifest;
  readonly certified: boolean;
  readonly blockerCodes: readonly string[];
}

export interface SnapshotIngestionOptions {
  readonly maximumRecords?: number;
  readonly maximumColumns?: number;
}

/**
 * Trusted control-plane ingestion. This service is intentionally not an MCP
 * raw-row tool; callers must be an operator connector or batch process.
 */
export class SnapshotIngestionService {
  readonly #control: ControlStore;
  readonly #artifacts: ArtifactStore;
  readonly #maximumRecords: number;
  readonly #maximumColumns: number;

  constructor(control: ControlStore, artifacts: ArtifactStore, options: SnapshotIngestionOptions = {}) {
    this.#control = control;
    this.#artifacts = artifacts;
    this.#maximumRecords = boundedInteger(options.maximumRecords ?? 100_000, "maximumRecords", 1, 1_000_000);
    this.#maximumColumns = boundedInteger(options.maximumColumns ?? 500, "maximumColumns", 1, 2_000);
  }

  registerDeliveredSnapshot(input: RegisterDeliveredSnapshotInput): RegisteredSnapshot {
    validateRecords(input.records, this.#maximumRecords, this.#maximumColumns);
    const schema = inferSchema(input.records);
    const artifactValue = { asOfDate: input.asOfDate, records: input.records, schema };
    const canonicalContentHash = artifactJsonContentHash(artifactValue);
    if (
      input.expectedCanonicalContentHash !== undefined &&
      canonicalContentHash !== normalizeHash(input.expectedCanonicalContentHash)
    ) {
      throw new Error("Delivered snapshot content hash did not match the operator-declared hash");
    }
    const sourceArtifact = this.#artifacts.putJson({
      tenantId: input.tenantId,
      kind: "delivered_snapshot",
      mediaType: "application/json",
      value: artifactValue
    });
    if (sourceArtifact.contentHash !== canonicalContentHash) {
      throw new Error("Delivered snapshot artifact hash did not match its canonical preflight hash");
    }
    const snapshot = this.#control.createDatasetSnapshot({
      tenantId: input.tenantId,
      snapshotId: input.snapshotId,
      sourceId: input.sourceId,
      sourceLocator: sourceArtifact.uri,
      asOfDate: input.asOfDate,
      contentHash: sourceArtifact.contentHash,
      rowCount: input.records.length,
      schema,
      createdBy: input.deliveredBy,
      idempotencyKey: input.idempotencyKey
    });
    return { snapshot, sourceArtifact };
  }

  certifyMappedSnapshot(input: CertifyMappedSnapshotInput): SnapshotCertification {
    const snapshot = required(
      this.#control.getDatasetSnapshot(input.tenantId, input.snapshotId),
      "Dataset snapshot was not found"
    );
    const mappingVersion = required(
      this.#control.getMappingVersion(input.tenantId, input.mappingVersionId),
      "Mapping version was not found"
    );
    if (mappingVersion.status !== "active") throw new Error("Snapshot certification requires an active mapping version");
    if (mappingVersion.snapshotId !== snapshot.snapshotId) {
      throw new Error("Mapping version does not belong to the requested snapshot");
    }
    const sourceArtifactId = parseArtifactUri(snapshot.sourceLocator);
    const sourceArtifact = this.#artifacts.getJson(input.tenantId, sourceArtifactId);
    if (sourceArtifact.metadata.contentHash !== snapshot.contentHash) {
      throw new Error("Snapshot source artifact no longer matches its immutable manifest");
    }
    const payload = sourceArtifact.value as { readonly asOfDate?: unknown; readonly records?: unknown };
    if (!payload || payload.asOfDate !== snapshot.asOfDate || !Array.isArray(payload.records)) {
      throw new Error("Snapshot source artifact has an invalid structure");
    }
    validateRecords(
      payload.records as readonly Readonly<Record<string, unknown>>[],
      this.#maximumRecords,
      this.#maximumColumns
    );
    if (payload.records.length !== snapshot.rowCount) {
      throw new Error("Snapshot source row count no longer matches its immutable manifest");
    }

    const normalizedRecords = applyApprovedMapping(
      payload.records as readonly Readonly<Record<string, unknown>>[],
      mappingVersion
    );
    const dataQuality = runDataQuality(normalizedRecords, input.dataQualityProfile, input.evaluatedAt);
    const normalizedArtifact = this.#artifacts.putJson({
      tenantId: input.tenantId,
      kind: "normalized_snapshot",
      mediaType: "application/json",
      value: {
        snapshotId: snapshot.snapshotId,
        mappingVersionId: mappingVersion.mappingVersionId,
        records: normalizedRecords,
        dataQualityFingerprint: dataQuality.fingerprint
      }
    });

    const durableDataQualityRun = this.#control.recordDataQualityRun({
      tenantId: input.tenantId,
      runId: input.dataQualityRunId,
      snapshotId: input.snapshotId,
      rulesetId: input.dataQualityProfile.id,
      rulesetHash: hashJson(input.dataQualityProfile),
      findings: dataQuality.findings.map((finding, index) => ({
        findingId: `${input.dataQualityRunId}-${String(index + 1).padStart(4, "0")}`,
        ruleId: finding.code,
        severity: finding.severity === "critical" ? "error" : finding.severity,
        passed: finding.severity === "warning",
        affectedRows: finding.affectedRows,
        message: finding.message,
        evidence: {
          affectedBalance: finding.affectedBalance,
          ...(finding.field ? { field: finding.field } : {})
        }
      })),
      executedBy: input.executedBy,
      idempotencyKey: certificationIdempotencyKey(input.idempotencyKey, "dq")
    });

    const actualTotals: ControlTotals = {
      rowCount: dataQuality.recordCount,
      balance: dataQuality.totalBalance,
      ...(dataQuality.currency ? { currency: dataQuality.currency } : {})
    };
    const reconciliationResult = reconcileControlTotals(
      input.declaredControlTotals,
      actualTotals,
      input.reconciliationTolerance
    );
    const reconciliation = this.#control.recordReconciliation({
      tenantId: input.tenantId,
      reconciliationId: input.reconciliationId,
      snapshotId: input.snapshotId,
      kind: "delivery_to_normalized_snapshot",
      checks: [
        {
          checkId: "row_count",
          expected: String(reconciliationResult.declared.rowCount),
          actual: String(reconciliationResult.actual.rowCount),
          difference: String(reconciliationResult.difference.rowCount),
          tolerance: String(reconciliationResult.tolerance.rowCount),
          passed: !reconciliationResult.reasonCodes.includes("row_count_out_of_tolerance")
        },
        {
          checkId: "balance",
          expected: reconciliationResult.declared.balance,
          actual: reconciliationResult.actual.balance,
          difference: reconciliationResult.difference.balance,
          tolerance: reconciliationResult.tolerance.balance,
          passed: !reconciliationResult.reasonCodes.includes("balance_out_of_tolerance")
        },
        {
          checkId: "currency",
          expected: reconciliationResult.declared.currency ?? "",
          actual: reconciliationResult.actual.currency ?? "",
          difference: reconciliationResult.reasonCodes.includes("currency_mismatch") ? "mismatch" : "0",
          passed: !reconciliationResult.reasonCodes.includes("currency_mismatch")
        }
      ],
      details: {
        fingerprint: reconciliationResult.fingerprint,
        normalizedArtifactId: normalizedArtifact.artifactId,
        reasonCodes: reconciliationResult.reasonCodes
      },
      performedBy: input.executedBy,
      idempotencyKey: certificationIdempotencyKey(input.idempotencyKey, "reconciliation")
    });

    const blockerCodes = [
      ...dataQuality.findings
        .filter((finding) => finding.severity === "critical" || finding.severity === "error")
        .map((finding) => finding.code),
      ...reconciliationResult.reasonCodes
    ].filter((code, index, codes) => codes.indexOf(code) === index).sort();
    const certified = blockerCodes.length === 0;
    const manifest = this.#control.recordAnalysisManifest({
      tenantId: input.tenantId,
      manifestId: input.certificationManifestId,
      snapshotId: input.snapshotId,
      mappingVersionId: input.mappingVersionId,
      analysisType: certified ? "snapshot_certification" : "snapshot_certification_failed",
      parameters: asJsonValue({
        dataQualityProfileId: input.dataQualityProfile.id,
        dataQualityProfileVersion: input.dataQualityProfile.version,
        dataQualityRunId: input.dataQualityRunId,
        reconciliationId: input.reconciliationId,
        evaluatedAt: dataQuality.evaluatedAt,
        certified,
        blockerCodes
      }),
      queryHash: hashJson({
        snapshotHash: snapshot.contentHash,
        mappingHash: mappingVersion.mappingHash,
        dataQualityFingerprint: dataQuality.fingerprint,
        reconciliationFingerprint: reconciliationResult.fingerprint
      }),
      codeVersion: input.codeVersion,
      artifacts: [
        {
          artifactId: normalizedArtifact.artifactId,
          kind: "normalized_snapshot",
          mediaType: normalizedArtifact.mediaType,
          contentHash: normalizedArtifact.contentHash,
          uri: normalizedArtifact.uri,
          metadata: asJsonValue({
            byteLength: normalizedArtifact.byteLength,
            keyId: normalizedArtifact.keyId,
            certified
          })
        }
      ],
      createdBy: input.executedBy,
      idempotencyKey: certificationIdempotencyKey(input.idempotencyKey, "manifest")
    });

    return {
      snapshot,
      mappingVersion,
      normalizedArtifact,
      dataQuality,
      durableDataQualityRun,
      reconciliation,
      manifest,
      certified,
      blockerCodes
    };
  }
}

function applyApprovedMapping(
  records: readonly Readonly<Record<string, unknown>>[],
  mappingVersion: MappingVersion
): readonly Readonly<Record<string, unknown>>[] {
  const sourceFields = new Set<string>();
  const canonicalFields = new Set<string>();
  for (const mapping of mappingVersion.mappings) {
    if (sourceFields.has(mapping.sourceColumn)) throw new Error(`Duplicate source mapping: ${mapping.sourceColumn}`);
    if (canonicalFields.has(mapping.canonicalField)) throw new Error(`Duplicate canonical mapping: ${mapping.canonicalField}`);
    sourceFields.add(mapping.sourceColumn);
    canonicalFields.add(mapping.canonicalField);
  }
  return records.map((record, recordIndex) =>
    Object.freeze(
      Object.fromEntries(
        mappingVersion.mappings
          .map((mapping) => {
            const definition = getCanonicalField(mapping.canonicalField);
            if (!definition) throw new Error(`Unknown canonical mapping field: ${mapping.canonicalField}`);
            return [
              mapping.canonicalField,
              canonicalizeMappedValue(
                record[mapping.sourceColumn],
                definition.logicalType,
                mapping.canonicalField,
                recordIndex
              )
            ] as const;
          })
          .sort(([left], [right]) => left.localeCompare(right))
      )
    )
  );
}

const CANONICAL_INTEGER = /^-?(?:0|[1-9]\d*)$/;
const CANONICAL_DECIMAL = /^-?(?:0|[1-9]\d*)(?:\.\d+)?$/;
const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const EXPLICIT_OFFSET_DATETIME = /(?:Z|[+-]\d{2}:\d{2})$/;

function canonicalizeMappedValue(
  value: unknown,
  logicalType: LogicalType,
  canonicalField: string,
  recordIndex: number
): unknown {
  if (value === null || value === undefined) return null;
  switch (logicalType) {
    case "identifier":
      if (typeof value === "string") return value;
      if (typeof value === "bigint") return value.toString();
      if (typeof value === "number" && Number.isSafeInteger(value)) return String(value);
      break;
    case "string":
      if (typeof value === "string") return value;
      break;
    case "integer": {
      const exact = exactIntegerString(value);
      if (exact !== undefined) return exact;
      break;
    }
    case "decimal":
    case "currency":
    case "percentage": {
      const exact = exactDecimalString(value);
      if (exact !== undefined) return exact;
      break;
    }
    case "boolean":
      if (typeof value === "boolean") return value;
      if (value === "true") return true;
      if (value === "false") return false;
      break;
    case "date":
      if (typeof value === "string" && isRealIsoDate(value)) return value;
      break;
    case "datetime":
      if (
        typeof value === "string" &&
        EXPLICIT_OFFSET_DATETIME.test(value) &&
        Number.isFinite(Date.parse(value))
      ) {
        return new Date(value).toISOString();
      }
      break;
  }
  throw new Error(
    `Record ${recordIndex} mapped field ${canonicalField} is not an exact canonical ${logicalType}`
  );
}

function exactIntegerString(value: unknown): string | undefined {
  if (typeof value === "number") return Number.isSafeInteger(value) ? String(value) : undefined;
  if (typeof value === "bigint") return Number.isSafeInteger(Number(value)) ? value.toString() : undefined;
  if (typeof value !== "string" || !CANONICAL_INTEGER.test(value)) return undefined;
  return Number.isSafeInteger(Number(value)) ? value : undefined;
}

function exactDecimalString(value: unknown): string | undefined {
  if (typeof value === "number") return Number.isSafeInteger(value) ? String(value) : undefined;
  if (typeof value === "bigint") return value.toString();
  return typeof value === "string" && CANONICAL_DECIMAL.test(value) ? value : undefined;
}

function isRealIsoDate(value: string): boolean {
  if (!ISO_DATE.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function inferSchema(records: readonly Readonly<Record<string, unknown>>[]) {
  const fields = new Map<string, { types: Set<string>; nullable: boolean }>();
  for (const record of records) {
    for (const field of Object.keys(record)) {
      if (!fields.has(field)) fields.set(field, { types: new Set(), nullable: false });
    }
    for (const [field, summary] of fields) {
      if (!(field in record) || record[field] === null || record[field] === undefined) summary.nullable = true;
      else summary.types.add(valueType(record[field]));
    }
  }
  return {
    fields: [...fields.entries()]
      .map(([name, summary]) => ({ name, nullable: summary.nullable, types: [...summary.types].sort() }))
      .sort((left, right) => left.name.localeCompare(right.name))
  };
}

function validateRecords(
  records: readonly Readonly<Record<string, unknown>>[],
  maximumRecords: number,
  maximumColumns: number
): void {
  if (!Array.isArray(records) || records.length > maximumRecords) {
    throw new Error(`Snapshot must contain at most ${maximumRecords} records`);
  }
  const columns = new Set<string>();
  for (const record of records) {
    if (!record || typeof record !== "object" || Array.isArray(record)) throw new Error("Every snapshot record must be an object");
    for (const field of Object.keys(record)) {
      if (!field || field.length > 128 || /[\u0000-\u001f\u007f]/.test(field)) {
        throw new Error("Snapshot field names must be non-empty, bounded printable strings");
      }
      columns.add(field);
      if (columns.size > maximumColumns) throw new Error(`Snapshot must contain at most ${maximumColumns} columns`);
    }
  }
}

function valueType(value: unknown): string {
  if (Array.isArray(value)) return "array";
  if (value === null) return "null";
  if (value instanceof Date) return "date";
  return typeof value;
}

function parseArtifactUri(uri: string): string {
  const match = /^abl-artifact:\/\/([a-f0-9]{64})$/.exec(uri);
  if (!match?.[1]) throw new Error("Snapshot source locator is not a governed artifact URI");
  return match[1];
}

function normalizeHash(value: string): string {
  const normalized = value.startsWith("sha256:") ? value.slice(7) : value;
  if (!/^[a-f0-9]{64}$/.test(normalized)) throw new Error("Expected content hash must be lowercase SHA-256");
  return normalized;
}

function hashJson(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(canonicalize(value))).digest("hex");
}

function certificationIdempotencyKey(idempotencyKey: string, phase: string): string {
  return `certification:${hashJson({ idempotencyKey, phase })}`;
}

function asJsonValue(value: unknown): JsonValue {
  return JSON.parse(JSON.stringify(canonicalize(value))) as JsonValue;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, nested]) => nested !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalize(nested)])
    );
  }
  return value;
}

function boundedInteger(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function required<T>(value: T | undefined, message: string): T {
  if (value === undefined) throw new Error(message);
  return value;
}
