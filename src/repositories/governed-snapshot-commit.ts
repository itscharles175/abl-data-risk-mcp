import { z } from "zod";

import {
  IdentifierSchema,
  IsoDateSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  parseWithSchema,
  type DatasetSnapshotV2
} from "../contracts/index.js";
import type {
  ImmutableRepositoryPort,
  RepositoryPutResult,
  RepositoryWriteContext
} from "./ports.js";

const SourceContractReferenceSchema = z
  .object({
    sourceContractId: IdentifierSchema,
    revision: z.number().int().positive().max(1_000_000),
    sourceContractHash: Sha256HashSchema
  })
  .strict();

const ScopeBindingReferenceSchema = z
  .object({
    bindingId: IdentifierSchema,
    revision: z.number().int().positive().max(1_000_000),
    bindingHash: Sha256HashSchema
  })
  .strict();

const SourceDeliveryReferenceSchema = z
  .object({
    deliveryId: IdentifierSchema,
    deliveryRevision: z.number().int().positive().max(2),
    deliveryHash: Sha256HashSchema,
    locatorHash: Sha256HashSchema,
    sourceVersionHash: Sha256HashSchema
  })
  .strict();

const ExtractionReceiptReferenceSchema = z
  .object({
    receiptId: IdentifierSchema,
    receiptHash: Sha256HashSchema
  })
  .strict();

const GovernedSnapshotCommitLineageBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    snapshotId: IdentifierSchema,
    snapshotHash: Sha256HashSchema,
    datasetId: IdentifierSchema,
    facilityId: IdentifierSchema,
    sourceContract: SourceContractReferenceSchema,
    scopeBinding: ScopeBindingReferenceSchema,
    sourceDelivery: SourceDeliveryReferenceSchema,
    extractionReceipt: ExtractionReceiptReferenceSchema,
    asOfDate: IsoDateSchema
  })
  .strict();

export const GovernedSnapshotCommitLineageV1Schema =
  GovernedSnapshotCommitLineageBodyV1Schema.extend({
    lineageHash: Sha256HashSchema
  }).strict();

export type GovernedSnapshotCommitLineageV1 = Readonly<
  z.infer<typeof GovernedSnapshotCommitLineageV1Schema>
>;
export type GovernedSnapshotCommitLineageV1Input = Readonly<
  z.input<typeof GovernedSnapshotCommitLineageBodyV1Schema>
>;

export function createGovernedSnapshotCommitLineageV1(
  input: GovernedSnapshotCommitLineageV1Input
): GovernedSnapshotCommitLineageV1 {
  const body = parseWithSchema(
    GovernedSnapshotCommitLineageBodyV1Schema,
    input,
    "GovernedSnapshotCommitLineageV1"
  );
  return parseGovernedSnapshotCommitLineageV1({
    ...body,
    lineageHash: canonicalHash(body)
  });
}

export function parseGovernedSnapshotCommitLineageV1(
  value: unknown
): GovernedSnapshotCommitLineageV1 {
  const parsed = parseWithSchema(
    GovernedSnapshotCommitLineageV1Schema,
    value,
    "GovernedSnapshotCommitLineageV1"
  );
  const { lineageHash, ...body } = parsed;
  assertCanonicalHash(body, lineageHash, "GovernedSnapshotCommitLineageV1");
  return parsed;
}

/**
 * A capture repository must commit the snapshot and its facility/dataset,
 * delivery, scope-binding, and receipt lineage in one durable CAS boundary.
 */
export interface GovernedDatasetSnapshotCommitRepositoryV1
  extends ImmutableRepositoryPort<DatasetSnapshotV2> {
  commitGovernedCapture(
    snapshot: DatasetSnapshotV2,
    lineage: GovernedSnapshotCommitLineageV1,
    context: RepositoryWriteContext
  ): Promise<RepositoryPutResult<DatasetSnapshotV2>>;
}

/**
 * Read-only authority for the immutable capture-commit lineage of a governed
 * dataset snapshot.  A missing snapshot and a legacy (non-governed) snapshot
 * are intentionally indistinguishable to callers: neither has governed
 * capture lineage that can safely be published.
 */
export interface GovernedSnapshotCaptureLineageReadPortV1 {
  getGovernedCaptureLineage(
    tenantId: string,
    snapshotId: string
  ): Promise<GovernedSnapshotCommitLineageV1 | undefined>;
}

/**
 * Direct, tenant-scoped successor lookup for correction terminality checks.
 *
 * Implementations must query the immutable correction index rather than scan
 * keyset-paginated snapshot history. This prevents a correction inserted
 * between pages with an identity at or before the current cursor from being
 * omitted by a later terminality check.
 */
export interface DatasetSnapshotCorrectionReadPortV1 {
  getDirectCorrection(
    tenantId: string,
    correctsSnapshotId: string,
    correctsSnapshotHash: string
  ): Promise<DatasetSnapshotV2 | undefined>;
}
