import { z } from "zod";

import {
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  parseWithSchema,
  type Sha256Hash
} from "./canonical.js";

const SnapshotCertificationAttemptBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    certificationManifestId: IdentifierSchema,
    snapshotId: IdentifierSchema,
    snapshotHash: Sha256HashSchema,
    actorId: IdentifierSchema,
    requestHash: Sha256HashSchema,
    certifiedAt: IsoTimestampSchema,
    createdAt: IsoTimestampSchema
  })
  .strict()
  .superRefine((value, context) => {
    if (value.certifiedAt > value.createdAt) {
      context.addIssue({
        code: "custom",
        path: ["certifiedAt"],
        message: "must not be after createdAt"
      });
    }
  });

export const SnapshotCertificationAttemptV1Schema =
  SnapshotCertificationAttemptBodyV1Schema.extend({ attemptHash: Sha256HashSchema }).strict();

export type SnapshotCertificationAttemptV1 = Readonly<z.infer<typeof SnapshotCertificationAttemptV1Schema>>;
export type SnapshotCertificationAttemptV1Input = Readonly<z.input<typeof SnapshotCertificationAttemptBodyV1Schema>>;

export function createSnapshotCertificationAttemptV1(
  value: SnapshotCertificationAttemptV1Input
): SnapshotCertificationAttemptV1 {
  const body = parseWithSchema(
    SnapshotCertificationAttemptBodyV1Schema,
    value,
    "SnapshotCertificationAttemptV1"
  );
  return parseSnapshotCertificationAttemptV1({ ...body, attemptHash: canonicalHash(body) });
}

export function parseSnapshotCertificationAttemptV1(value: unknown): SnapshotCertificationAttemptV1 {
  const parsed = parseWithSchema(
    SnapshotCertificationAttemptV1Schema,
    value,
    "SnapshotCertificationAttemptV1"
  );
  const { attemptHash, ...body } = parsed;
  assertCanonicalHash(body, attemptHash, "SnapshotCertificationAttemptV1");
  return parsed;
}

export type SnapshotCertificationAttemptHashV1 = Sha256Hash;
