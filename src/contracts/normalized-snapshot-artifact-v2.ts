import { z } from "zod";

import {
  ContractValidationError,
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  canonicalJson,
  parseWithSchema,
  type CanonicalJsonValue,
  type Sha256Hash
} from "./canonical.js";

const CanonicalFieldNameSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z_][A-Za-z0-9_]*$/u, "must be an ASCII canonical field identifier");

const CanonicalScalarSchema = z.union([
  z.string().max(32_768),
  z.boolean(),
  z.null(),
  z.number().int().safe()
]);

const CanonicalRecordSchema = z.record(CanonicalFieldNameSchema, CanonicalScalarSchema);

const SnapshotReferenceV2Schema = z
  .object({
    snapshotId: IdentifierSchema,
    snapshotHash: Sha256HashSchema
  })
  .strict();

const MappingApplicationReferenceV1Schema = z
  .object({
    mappingApplicationId: IdentifierSchema,
    mappingApplicationHash: Sha256HashSchema
  })
  .strict();

const NormalizedSnapshotArtifactCreateInputSchema = z
  .object({
    contractVersion: z.literal(2),
    kind: z.literal("normalized_snapshot"),
    tenantId: IdentifierSchema,
    normalizedPopulationId: IdentifierSchema,
    snapshot: SnapshotReferenceV2Schema,
    mappingApplication: MappingApplicationReferenceV1Schema,
    records: z.array(CanonicalRecordSchema).max(1_000_000),
    createdAt: IsoTimestampSchema
  })
  .strict();

const NormalizedSnapshotArtifactBodyV2Schema = NormalizedSnapshotArtifactCreateInputSchema.extend({
  rowCount: z.number().int().min(0).max(1_000_000),
  populationHash: Sha256HashSchema,
  fieldSetHash: Sha256HashSchema
}).strict();

export const NormalizedSnapshotArtifactV2Schema = NormalizedSnapshotArtifactBodyV2Schema.extend({
  artifactHash: Sha256HashSchema
}).strict();

export type NormalizedSnapshotArtifactV2 = Readonly<
  z.infer<typeof NormalizedSnapshotArtifactV2Schema>
>;
export type NormalizedSnapshotArtifactV2Input = Readonly<
  z.input<typeof NormalizedSnapshotArtifactCreateInputSchema>
>;

/**
 * Builds the only canonical normalized-snapshot artifact shape. Population,
 * row-count, and field-set controls are derived from the records and cannot be
 * asserted independently by a caller.
 */
export function createNormalizedSnapshotArtifactV2(
  inputValue: NormalizedSnapshotArtifactV2Input
): NormalizedSnapshotArtifactV2 {
  assertCanonicalJsonValue(inputValue, "NormalizedSnapshotArtifactV2 input");
  const input = parseWithSchema(
    NormalizedSnapshotArtifactCreateInputSchema,
    inputValue,
    "NormalizedSnapshotArtifactV2 input"
  );
  const body = parseWithSchema(
    NormalizedSnapshotArtifactBodyV2Schema,
    {
      ...input,
      rowCount: input.records.length,
      populationHash: canonicalHash(input.records),
      fieldSetHash: normalizedFieldSetHash(input.records)
    },
    "NormalizedSnapshotArtifactV2"
  );
  return parseNormalizedSnapshotArtifactV2({ ...body, artifactHash: canonicalHash(body) });
}

export function parseNormalizedSnapshotArtifactV2(value: unknown): NormalizedSnapshotArtifactV2 {
  assertCanonicalJsonValue(value, "NormalizedSnapshotArtifactV2");
  const parsed = parseWithSchema(
    NormalizedSnapshotArtifactV2Schema,
    value,
    "NormalizedSnapshotArtifactV2"
  );
  if (parsed.rowCount !== parsed.records.length) {
    invariant("Normalized snapshot row count does not match its records");
  }
  if (parsed.populationHash !== canonicalHash(parsed.records)) {
    invariant("Normalized snapshot population hash does not match its records");
  }
  if (parsed.fieldSetHash !== normalizedFieldSetHash(parsed.records)) {
    invariant("Normalized snapshot field-set hash does not match its records");
  }
  const { artifactHash, ...body } = parsed;
  assertCanonicalHash(body, artifactHash, "NormalizedSnapshotArtifactV2");
  return parsed;
}

export function normalizedFieldSetHash(
  records: readonly Readonly<Record<string, unknown>>[]
): Sha256Hash {
  const fields = new Set<string>();
  for (const record of records) {
    assertCanonicalJsonValue(record, "normalized snapshot record");
    for (const field of Object.keys(record)) fields.add(field);
  }
  return canonicalHash([...fields].sort());
}

/** Hash of the exact canonical bytes stored for the complete artifact. */
export function normalizedSnapshotArtifactContentHash(
  artifactValue: NormalizedSnapshotArtifactV2
): Sha256Hash {
  return canonicalHash(parseNormalizedSnapshotArtifactV2(artifactValue));
}

/** UTF-8 byte length of the exact canonical bytes stored for the artifact. */
export function normalizedSnapshotArtifactByteLength(
  artifactValue: NormalizedSnapshotArtifactV2
): number {
  return Buffer.byteLength(
    canonicalJson(parseNormalizedSnapshotArtifactV2(artifactValue)),
    "utf8"
  );
}

function assertCanonicalJsonValue(value: unknown, label: string): asserts value is CanonicalJsonValue {
  try {
    canonicalJson(value);
  } catch (error) {
    if (error instanceof ContractValidationError) throw error;
    throw new ContractValidationError("NON_CANONICAL_VALUE", `${label} is not canonical JSON`);
  }
}

function invariant(message: string): never {
  throw new ContractValidationError("INVARIANT_VIOLATION", message);
}
