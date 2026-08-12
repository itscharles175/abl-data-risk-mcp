import { z } from "zod";

import {
  AnalysisInputLineageV1Schema,
  assertCertifiedAnalysisInputs,
  parseAnalysisInputLineageV1,
  type AnalysisInputLineageV1,
  type CertifiedAnalysisInputLineageV1
} from "./certified-lineage-v1.js";
import {
  ContractValidationError,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  parseWithSchema,
  type CanonicalJsonValue
} from "./canonical.js";

const MAX_PAYLOAD_BYTES = 8_000_000;

const CanonicalPayloadSchema = z.custom<CanonicalJsonValue>(
  (value) => {
    try {
      const serialized = JSON.stringify(value);
      if (serialized === undefined || Buffer.byteLength(serialized, "utf8") > MAX_PAYLOAD_BYTES) {
        return false;
      }
      canonicalHash(value);
      return true;
    } catch {
      return false;
    }
  },
  "must be bounded canonical JSON"
);

const CertifiedOperationInputBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    inputKind: z.enum(["borrowing_base", "monitoring"]),
    payload: CanonicalPayloadSchema,
    payloadHash: Sha256HashSchema,
    lineage: AnalysisInputLineageV1Schema
  })
  .strict();

export const CertifiedOperationInputV1Schema = CertifiedOperationInputBodyV1Schema.extend({
  envelopeHash: Sha256HashSchema
}).strict();

export type CertifiedOperationInputKindV1 = "borrowing_base" | "monitoring";
export type CertifiedOperationInputV1 = Readonly<
  Omit<z.infer<typeof CertifiedOperationInputV1Schema>, "lineage"> & {
    readonly lineage: CertifiedAnalysisInputLineageV1;
  }
>;
export interface CertifiedOperationInputV1Input {
  readonly contractVersion: 1;
  readonly inputKind: CertifiedOperationInputKindV1;
  readonly payload: CanonicalJsonValue;
  readonly payloadHash: string;
  readonly lineage: AnalysisInputLineageV1;
}

export function createCertifiedOperationInputV1(
  input: CertifiedOperationInputV1Input
): CertifiedOperationInputV1 {
  const body = parseWithSchema(
    CertifiedOperationInputBodyV1Schema,
    input,
    "CertifiedOperationInputV1"
  );
  return parseCertifiedOperationInputV1({ ...body, envelopeHash: canonicalHash(body) });
}

export function parseCertifiedOperationInputV1(value: unknown): CertifiedOperationInputV1 {
  const parsed = parseWithSchema(
    CertifiedOperationInputV1Schema,
    value,
    "CertifiedOperationInputV1"
  );
  const lineage = parseAnalysisInputLineageV1(parsed.lineage);
  assertCertifiedAnalysisInputs(lineage);
  assertOperationLineage(parsed.inputKind, parsed.payload, parsed.payloadHash, lineage);
  const { envelopeHash, ...body } = parsed;
  assertCanonicalHash(body, envelopeHash, "CertifiedOperationInputV1");
  return parsed as CertifiedOperationInputV1;
}

function assertOperationLineage(
  inputKind: CertifiedOperationInputKindV1,
  payload: CanonicalJsonValue,
  payloadHash: string,
  lineage: CertifiedAnalysisInputLineageV1
): void {
  const expectedAnalysisKind = inputKind === "borrowing_base" ? "borrowing_base" : "monitoring";
  if (lineage.analysisKind !== expectedAnalysisKind) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      `Certified ${inputKind} input requires ${expectedAnalysisKind} lineage`
    );
  }
  if (lineage.sidecars.length !== 1) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "Certified operation input requires exactly one certified sidecar"
    );
  }
  const canonicalPayloadHash = canonicalHash(payload);
  if (payloadHash !== canonicalPayloadHash) {
    throw new ContractValidationError(
      "HASH_MISMATCH",
      "Certified operation input payload hash did not match its canonical payload"
    );
  }
  if (lineage.sidecars[0]!.populationHash !== payloadHash) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "Certified operation input payload hash must match its sidecar population hash"
    );
  }
}
