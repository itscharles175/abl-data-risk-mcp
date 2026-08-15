import { z } from "zod";

import {
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  canonicalJson,
  parseWithSchema,
  type Sha256Hash
} from "./canonical.js";
import { CertifiedSnapshotArtifactMetadataV1Schema } from "./certified-snapshot-evidence-v1.js";

const CertificationArtifactStageBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    certificationManifestId: IdentifierSchema,
    /** Immutable certification-attempt identity, fixed before artifact materialization. */
    attemptHash: Sha256HashSchema,
    normalizedArtifact: CertifiedSnapshotArtifactMetadataV1Schema,
    artifactBindingHash: Sha256HashSchema,
    preparedAt: IsoTimestampSchema
  })
  .strict()
  .superRefine((value, context) => {
    if (value.normalizedArtifact.tenantId !== value.tenantId) {
      context.addIssue({
        code: "custom",
        path: ["normalizedArtifact", "tenantId"],
        message: "must match the stage tenant"
      });
    }
    const expectedBinding = canonicalHash({
      contractVersion: 1,
      tenantId: value.tenantId,
      certificationManifestId: value.certificationManifestId,
      attemptHash: value.attemptHash,
      normalizedArtifact: value.normalizedArtifact
    });
    if (value.artifactBindingHash !== expectedBinding) {
      context.addIssue({
        code: "custom",
        path: ["artifactBindingHash"],
        message: "does not bind the exact staged artifact to this certification attempt"
      });
    }
  });

export const CertificationArtifactStageV1Schema = CertificationArtifactStageBodyV1Schema.extend({
  stageHash: Sha256HashSchema
}).strict();

export type CertificationArtifactStageV1 = Readonly<z.infer<typeof CertificationArtifactStageV1Schema>>;
export type CertificationArtifactStageV1Input = Readonly<
  z.input<typeof CertificationArtifactStageBodyV1Schema>
>;

export function createCertificationArtifactStageV1(
  value: CertificationArtifactStageV1Input
): CertificationArtifactStageV1 {
  canonicalJson(value);
  const body = parseWithSchema(
    CertificationArtifactStageBodyV1Schema,
    value,
    "CertificationArtifactStageV1"
  );
  return parseCertificationArtifactStageV1({ ...body, stageHash: canonicalHash(body) });
}

export function parseCertificationArtifactStageV1(value: unknown): CertificationArtifactStageV1 {
  canonicalJson(value);
  const parsed = parseWithSchema(
    CertificationArtifactStageV1Schema,
    value,
    "CertificationArtifactStageV1"
  );
  const { stageHash, ...body } = parsed;
  assertCanonicalHash(body, stageHash, "CertificationArtifactStageV1");
  return parsed;
}

const PreparedEventBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    certificationManifestId: IdentifierSchema,
    stageHash: Sha256HashSchema,
    sequence: z.literal(1),
    eventType: z.literal("artifact_prepared"),
    occurredAt: IsoTimestampSchema
  })
  .strict();

const EvidenceCommittedEventBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    certificationManifestId: IdentifierSchema,
    stageHash: Sha256HashSchema,
    sequence: z.number().int().min(2).max(1_000_000_000),
    eventType: z.literal("certification_evidence_committed"),
    certificationEvidenceHash: Sha256HashSchema,
    occurredAt: IsoTimestampSchema
  })
  .strict();

const EvidenceFailedEventBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    tenantId: IdentifierSchema,
    certificationManifestId: IdentifierSchema,
    stageHash: Sha256HashSchema,
    sequence: z.number().int().min(2).max(1_000_000_000),
    eventType: z.literal("certification_evidence_failed"),
    failureHash: Sha256HashSchema,
    occurredAt: IsoTimestampSchema
  })
  .strict();

const CertificationArtifactOutboxEventBodyV1Schema = z.discriminatedUnion("eventType", [
  PreparedEventBodyV1Schema,
  EvidenceCommittedEventBodyV1Schema,
  EvidenceFailedEventBodyV1Schema
]);

export const CertificationArtifactOutboxEventV1Schema = CertificationArtifactOutboxEventBodyV1Schema
  .and(z.object({ eventHash: Sha256HashSchema }).strict())
  .superRefine((value, context) => {
    const { eventHash, ...body } = value;
    if (eventHash !== canonicalHash(body)) {
      context.addIssue({ code: "custom", path: ["eventHash"], message: "does not match canonical event content" });
    }
  });

export type CertificationArtifactOutboxEventV1 = Readonly<
  z.infer<typeof CertificationArtifactOutboxEventV1Schema>
>;
export type CertificationArtifactOutboxEventV1Input = Readonly<
  z.input<typeof CertificationArtifactOutboxEventBodyV1Schema>
>;

export function createCertificationArtifactOutboxEventV1(
  value: CertificationArtifactOutboxEventV1Input
): CertificationArtifactOutboxEventV1 {
  canonicalJson(value);
  const body = parseWithSchema(
    CertificationArtifactOutboxEventBodyV1Schema,
    value,
    "CertificationArtifactOutboxEventV1"
  );
  return parseCertificationArtifactOutboxEventV1({ ...body, eventHash: canonicalHash(body) });
}

export function parseCertificationArtifactOutboxEventV1(
  value: unknown
): CertificationArtifactOutboxEventV1 {
  canonicalJson(value);
  const parsed = parseWithSchema(
    CertificationArtifactOutboxEventV1Schema,
    value,
    "CertificationArtifactOutboxEventV1"
  );
  const { eventHash, ...body } = parsed;
  assertCanonicalHash(body, eventHash, "CertificationArtifactOutboxEventV1");
  return parsed;
}

export type CertificationArtifactOutboxStateV1 =
  | "prepared"
  | "evidence_commit_failed"
  | "evidence_committed";

export interface CertificationArtifactOutboxRecordV1 {
  readonly stage: CertificationArtifactStageV1;
  readonly state: CertificationArtifactOutboxStateV1;
  readonly events: readonly CertificationArtifactOutboxEventV1[];
  readonly certificationEvidenceHash?: Sha256Hash;
  readonly latestFailureHash?: Sha256Hash;
}

export function deriveCertificationArtifactOutboxRecordV1(input: {
  readonly stage: CertificationArtifactStageV1;
  readonly events: readonly CertificationArtifactOutboxEventV1[];
}): CertificationArtifactOutboxRecordV1 {
  const stage = parseCertificationArtifactStageV1(input.stage);
  if (input.events.length === 0) invariant("Outbox must contain its prepared event");
  let state: CertificationArtifactOutboxStateV1 = "prepared";
  let certificationEvidenceHash: Sha256Hash | undefined;
  let latestFailureHash: Sha256Hash | undefined;
  for (const [index, eventValue] of input.events.entries()) {
    const event = parseCertificationArtifactOutboxEventV1(eventValue);
    if (
      event.tenantId !== stage.tenantId ||
      event.certificationManifestId !== stage.certificationManifestId ||
      event.stageHash !== stage.stageHash ||
      event.sequence !== index + 1
    ) {
      invariant("Outbox event does not bind to the staged artifact identity");
    }
    if (index === 0) {
      if (event.eventType !== "artifact_prepared" || event.occurredAt !== stage.preparedAt) {
        invariant("Outbox must begin with the staged artifact preparation event");
      }
      continue;
    }
    if (event.eventType === "artifact_prepared") invariant("Prepared event can occur only once");
    if (event.eventType === "certification_evidence_committed") {
      if (certificationEvidenceHash !== undefined) invariant("Certification evidence can commit only once");
      certificationEvidenceHash = event.certificationEvidenceHash;
      state = "evidence_committed";
      continue;
    }
    if (state === "evidence_committed") invariant("Cannot record failure after evidence commit");
    latestFailureHash = event.failureHash;
    state = "evidence_commit_failed";
  }
  return Object.freeze({
    stage,
    state,
    events: Object.freeze([...input.events]),
    ...(certificationEvidenceHash === undefined ? {} : { certificationEvidenceHash }),
    ...(latestFailureHash === undefined ? {} : { latestFailureHash })
  });
}

function invariant(message: string): never {
  throw new Error(`Certification artifact staging invariant violation: ${message}`);
}
