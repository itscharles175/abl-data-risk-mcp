import { z } from "zod";

import {
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  canonicalJson,
  parseWithSchema
} from "./canonical.js";

const SourceScalarSchema = z.union([
  z.string().max(32_768),
  z.boolean(),
  z.null(),
  z.number().int().safe()
]);
const SourceRecordSchema = z.record(
  z.string().min(1).max(256).regex(/^[A-Za-z_][A-Za-z0-9_]*$/u),
  SourceScalarSchema
);
const SourceContractReferenceSchema = z.object({
  sourceContractId: IdentifierSchema,
  revision: z.number().int().positive().max(1_000_000),
  sourceContractHash: Sha256HashSchema
}).strict();

const CapturedSourceSectionArtifactBodyV1Schema = z.object({
  contractVersion: z.literal(1),
  kind: z.literal("captured_source_section"),
  tenantId: IdentifierSchema,
  snapshotId: IdentifierSchema,
  snapshotHash: Sha256HashSchema,
  extractionReceiptHash: Sha256HashSchema,
  sourceContract: SourceContractReferenceSchema,
  sectionId: IdentifierSchema,
  sectionContentHash: Sha256HashSchema,
  sectionSchemaHash: Sha256HashSchema,
  controlPopulationHash: Sha256HashSchema,
  rowCount: z.number().int().min(0).max(1_000_000),
  records: z.array(SourceRecordSchema).max(1_000_000),
  capturedAt: IsoTimestampSchema
}).strict().superRefine((value, context) => {
  if (value.records.length !== value.rowCount) {
    context.addIssue({ code: "custom", path: ["rowCount"], message: "must equal records length" });
  }
  if (canonicalHash(value.records) !== value.controlPopulationHash) {
    context.addIssue({
      code: "custom",
      path: ["controlPopulationHash"],
      message: "must authenticate the exact captured records"
    });
  }
});

export const CapturedSourceSectionArtifactV1Schema = CapturedSourceSectionArtifactBodyV1Schema.extend({
  artifactHash: Sha256HashSchema
}).strict();

export type CapturedSourceSectionArtifactV1 = Readonly<z.infer<typeof CapturedSourceSectionArtifactV1Schema>>;
export type CapturedSourceSectionArtifactV1Input = Readonly<z.input<typeof CapturedSourceSectionArtifactBodyV1Schema>>;

const CapturedSourceSectionArtifactMetadataBodyV1Schema = z.object({
  contractVersion: z.literal(1),
  tenantId: IdentifierSchema,
  snapshotId: IdentifierSchema,
  snapshotHash: Sha256HashSchema,
  sectionId: IdentifierSchema,
  artifactHash: Sha256HashSchema,
  artifactId: z.string().regex(/^[a-f0-9]{64}$/u),
  contentHash: z.string().regex(/^[a-f0-9]{64}$/u),
  byteLength: z.number().int().positive().max(1_000_000_000),
  keyId: IdentifierSchema,
  uri: z.string().regex(/^abl-artifact:\/\/[a-f0-9]{64}$/u),
  storedAt: IsoTimestampSchema
}).strict();

export const CapturedSourceSectionArtifactMetadataV1Schema = CapturedSourceSectionArtifactMetadataBodyV1Schema.extend({
  metadataHash: Sha256HashSchema
}).strict();

export type CapturedSourceSectionArtifactMetadataV1 = Readonly<
  z.infer<typeof CapturedSourceSectionArtifactMetadataV1Schema>
>;
export type CapturedSourceSectionArtifactMetadataV1Input = Readonly<
  z.input<typeof CapturedSourceSectionArtifactMetadataBodyV1Schema>
>;

export function createCapturedSourceSectionArtifactV1(
  value: CapturedSourceSectionArtifactV1Input
): CapturedSourceSectionArtifactV1 {
  canonicalJson(value);
  const body = parseWithSchema(
    CapturedSourceSectionArtifactBodyV1Schema,
    value,
    "CapturedSourceSectionArtifactV1"
  );
  return parseCapturedSourceSectionArtifactV1({ ...body, artifactHash: canonicalHash(body) });
}

export function parseCapturedSourceSectionArtifactV1(value: unknown): CapturedSourceSectionArtifactV1 {
  canonicalJson(value);
  const parsed = parseWithSchema(
    CapturedSourceSectionArtifactV1Schema,
    value,
    "CapturedSourceSectionArtifactV1"
  );
  const { artifactHash, ...body } = parsed;
  assertCanonicalHash(body, artifactHash, "CapturedSourceSectionArtifactV1");
  return parsed;
}

export function createCapturedSourceSectionArtifactMetadataV1(
  value: CapturedSourceSectionArtifactMetadataV1Input
): CapturedSourceSectionArtifactMetadataV1 {
  canonicalJson(value);
  const body = parseWithSchema(
    CapturedSourceSectionArtifactMetadataBodyV1Schema,
    value,
    "CapturedSourceSectionArtifactMetadataV1"
  );
  return parseCapturedSourceSectionArtifactMetadataV1({ ...body, metadataHash: canonicalHash(body) });
}

export function parseCapturedSourceSectionArtifactMetadataV1(
  value: unknown
): CapturedSourceSectionArtifactMetadataV1 {
  canonicalJson(value);
  const parsed = parseWithSchema(
    CapturedSourceSectionArtifactMetadataV1Schema,
    value,
    "CapturedSourceSectionArtifactMetadataV1"
  );
  const { metadataHash, ...body } = parsed;
  assertCanonicalHash(body, metadataHash, "CapturedSourceSectionArtifactMetadataV1");
  return parsed;
}
