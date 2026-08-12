import { z } from "zod";

import {
  IdentifierSchema,
  IsoDateSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalJson,
  parseWithSchema
} from "./canonical.js";
import { SemanticVersionV2Schema } from "./governed-definition-v2.js";

export const LongitudinalMethodologyReferenceV1Schema = z
  .object({
    methodologyId: IdentifierSchema,
    definitionVersionId: IdentifierSchema,
    version: SemanticVersionV2Schema,
    versionHash: Sha256HashSchema,
    documentHash: Sha256HashSchema,
    methodologyHash: Sha256HashSchema,
    approvalEventHash: Sha256HashSchema,
    approvedAt: IsoTimestampSchema
  })
  .strict();

export type LongitudinalMethodologyReferenceV1 = Readonly<
  z.infer<typeof LongitudinalMethodologyReferenceV1Schema>
>;

const CertificationManifestReferenceV1Schema = z
  .object({
    certificationManifestId: IdentifierSchema,
    certificationManifestHash: Sha256HashSchema,
    certifiedAt: IsoTimestampSchema
  })
  .strict();

const CertifiedSnapshotReferenceV1Schema = z
  .object({
    snapshotId: IdentifierSchema,
    asOfDate: IsoDateSchema,
    snapshotHash: Sha256HashSchema
  })
  .strict();

export const GovernedDatasetScopeV1Schema = z
  .object({
    scopeType: z.enum(["portfolio", "facility"]),
    scopeId: IdentifierSchema
  })
  .strict();

export type GovernedDatasetScopeV1 = Readonly<z.infer<typeof GovernedDatasetScopeV1Schema>>;

export const LongitudinalSourceIdentityV1Schema = z
  .object({
    sourceContractId: IdentifierSchema,
    sourceKey: IdentifierSchema,
    revision: z.number().int().positive(),
    sourceContractHash: Sha256HashSchema
  })
  .strict();

export type LongitudinalSourceIdentityV1 = Readonly<
  z.infer<typeof LongitudinalSourceIdentityV1Schema>
>;

const SnapshotDeliveryEvidenceV1Schema = z
  .object({
    deliveryId: IdentifierSchema,
    deliveryMode: z.enum(["postgresql_pull", "managed_upload", "object_storage"]),
    deliveredContentHash: Sha256HashSchema,
    immutableSourceVersion: z.string().min(1).max(1_024).optional()
  })
  .strict()
  .superRefine((value, context) => {
    if (value.deliveryMode === "object_storage" && value.immutableSourceVersion === undefined) {
      context.addIssue({
        code: "custom",
        path: ["immutableSourceVersion"],
        message: "object-storage delivery requires an immutable source version"
      });
    }
    if (value.deliveryMode !== "object_storage" && value.immutableSourceVersion !== undefined) {
      context.addIssue({
        code: "custom",
        path: ["immutableSourceVersion"],
        message: "is only valid for object-storage delivery"
      });
    }
  });

const SnapshotCorrectionLineageV1Schema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("original") }).strict(),
  z
    .object({
      kind: z.literal("correction"),
      correctsSnapshotId: IdentifierSchema,
      correctsSnapshotHash: Sha256HashSchema,
      correctionSequence: z.number().int().min(1).max(119),
      reasonCode: IdentifierSchema,
      reason: z.string().min(1).max(2_000),
      detectedAt: IsoTimestampSchema
    })
    .strict()
]);

const CertifiedDictionaryReferenceV1Schema = z
  .object({
    dictionaryBundleId: IdentifierSchema,
    version: z.string().min(1).max(64),
    dictionaryHash: Sha256HashSchema
  })
  .strict();

const CertifiedMappingReferenceV1Schema = z
  .object({
    mappingApplicationId: IdentifierSchema,
    mappingApplicationHash: Sha256HashSchema,
    mappingSpecId: IdentifierSchema,
    mappingSpecHash: Sha256HashSchema,
    runtime: z
      .object({
        runtimeBundleId: IdentifierSchema,
        runtimeVersion: z.string().min(1).max(64),
        runtimeBundleHash: Sha256HashSchema,
        compilerHash: Sha256HashSchema
      })
      .strict()
  })
  .strict();

const CertifiedNormalizedArtifactReferenceV1Schema = z
  .object({
    artifactId: IdentifierSchema,
    contentHash: Sha256HashSchema
  })
  .strict();

export const LongitudinalCertifiedPeriodV1Schema = z
  .object({
    revisionSequence: z.number().int().min(1).max(120),
    tenantId: IdentifierSchema,
    datasetId: IdentifierSchema,
    source: LongitudinalSourceIdentityV1Schema,
    scope: GovernedDatasetScopeV1Schema,
    certification: CertificationManifestReferenceV1Schema,
    snapshot: CertifiedSnapshotReferenceV1Schema,
    delivery: SnapshotDeliveryEvidenceV1Schema,
    correction: SnapshotCorrectionLineageV1Schema,
    dictionary: CertifiedDictionaryReferenceV1Schema,
    mapping: CertifiedMappingReferenceV1Schema,
    normalizedArtifact: CertifiedNormalizedArtifactReferenceV1Schema,
    rowCount: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
    populationHash: Sha256HashSchema
  })
  .strict()
  .superRefine((value, context) => {
    if (value.snapshot.asOfDate > value.certification.certifiedAt.slice(0, 10)) {
      context.addIssue({
        code: "custom",
        path: ["snapshot", "asOfDate"],
        message: "cannot be after certification"
      });
    }
    if (
      value.correction.kind === "correction" &&
      value.correction.detectedAt > value.certification.certifiedAt
    ) {
      context.addIssue({
        code: "custom",
        path: ["correction", "detectedAt"],
        message: "cannot be after certification"
      });
    }
  });

export type LongitudinalCertifiedRevisionV1 = Readonly<
  z.infer<typeof LongitudinalCertifiedPeriodV1Schema>
>;

/** Backward-compatible name retained from the initial additive foundation. */
export type LongitudinalCertifiedPeriodV1 = LongitudinalCertifiedRevisionV1;

const AnalyticsSelectionV1Schema = z
  .object({
    revisionSequence: z.number().int().min(1).max(120),
    certificationManifestId: IdentifierSchema,
    certificationManifestHash: Sha256HashSchema,
    snapshotId: IdentifierSchema,
    snapshotHash: Sha256HashSchema,
    normalizedArtifactContentHash: Sha256HashSchema,
    populationHash: Sha256HashSchema
  })
  .strict();

export const LongitudinalAsOfPeriodV1Schema = z
  .object({
    sequence: z.number().int().min(1).max(120),
    asOfDate: IsoDateSchema,
    revisions: z.array(LongitudinalCertifiedPeriodV1Schema).min(1).max(120),
    analyticsSelection: AnalyticsSelectionV1Schema
  })
  .strict()
  .superRefine(validateCorrectionChain);

export type LongitudinalAsOfPeriodV1 = Readonly<z.infer<typeof LongitudinalAsOfPeriodV1Schema>>;

const LongitudinalCertificationBundleBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    bundleId: IdentifierSchema,
    tenantId: IdentifierSchema,
    datasetId: IdentifierSchema,
    source: LongitudinalSourceIdentityV1Schema,
    scope: GovernedDatasetScopeV1Schema,
    purpose: z.string().trim().min(1).max(512),
    methodology: LongitudinalMethodologyReferenceV1Schema,
    periodCount: z.number().int().min(1).max(120),
    certificationCount: z.number().int().min(1).max(120),
    firstAsOfDate: IsoDateSchema,
    lastAsOfDate: IsoDateSchema,
    periods: z.array(LongitudinalAsOfPeriodV1Schema).min(1).max(120),
    createdBy: IdentifierSchema,
    createdAt: IsoTimestampSchema
  })
  .strict()
  .superRefine((value, context) => {
    if (value.periodCount !== value.periods.length) {
      context.addIssue({
        code: "custom",
        path: ["periodCount"],
        message: "must equal the number of certified periods"
      });
    }

    const certificationCount = value.periods.reduce(
      (count, period) => count + period.revisions.length,
      0
    );
    if (value.certificationCount !== certificationCount) {
      context.addIssue({
        code: "custom",
        path: ["certificationCount"],
        message: "must equal the number of bound certification manifests"
      });
    }
    if (certificationCount > 120) {
      context.addIssue({
        code: "custom",
        path: ["periods"],
        message: "a bundle may bind at most 120 certification manifests"
      });
    }

    if (value.methodology.approvedAt > value.createdAt) {
      context.addIssue({
        code: "custom",
        path: ["methodology", "approvedAt"],
        message: "cannot be after bundle creation"
      });
    }

    const manifestIds = new Set<string>();
    const snapshotIds = new Set<string>();
    const deliveryIds = new Set<string>();
    const asOfDates = new Set<string>();
    for (const [index, period] of value.periods.entries()) {
      if (period.sequence !== index + 1) {
        context.addIssue({
          code: "custom",
          path: ["periods", index, "sequence"],
          message: "must be contiguous and one-based"
        });
      }
      if (index > 0 && value.periods[index - 1]!.asOfDate >= period.asOfDate) {
        context.addIssue({
          code: "custom",
          path: ["periods", index, "asOfDate"],
          message: "periods must be strictly chronological"
        });
      }
      recordUnique(
        asOfDates,
        period.asOfDate,
        ["periods", index, "asOfDate"],
        "as-of dates",
        context
      );

      for (const [revisionIndex, revision] of period.revisions.entries()) {
        const revisionPath = ["periods", index, "revisions", revisionIndex] as const;
        if (revision.tenantId !== value.tenantId) {
          context.addIssue({
            code: "custom",
            path: [...revisionPath, "tenantId"],
            message: "must match the bundle tenant"
          });
        }
        if (revision.datasetId !== value.datasetId) {
          context.addIssue({
            code: "custom",
            path: [...revisionPath, "datasetId"],
            message: "must match the bundle dataset"
          });
        }
        if (canonicalJson(revision.source) !== canonicalJson(value.source)) {
          context.addIssue({
            code: "custom",
            path: [...revisionPath, "source"],
            message: "must match the bundle source"
          });
        }
        if (canonicalJson(revision.scope) !== canonicalJson(value.scope)) {
          context.addIssue({
            code: "custom",
            path: [...revisionPath, "scope"],
            message: "must match the governed bundle scope"
          });
        }
        recordUnique(
          manifestIds,
          revision.certification.certificationManifestId,
          [...revisionPath, "certification", "certificationManifestId"],
          "certification manifest ids",
          context
        );
        recordUnique(
          snapshotIds,
          revision.snapshot.snapshotId,
          [...revisionPath, "snapshot", "snapshotId"],
          "snapshot ids",
          context
        );
        recordUnique(
          deliveryIds,
          revision.delivery.deliveryId,
          [...revisionPath, "delivery", "deliveryId"],
          "delivery ids",
          context
        );
        if (revision.certification.certifiedAt > value.createdAt) {
          context.addIssue({
            code: "custom",
            path: [...revisionPath, "certification", "certifiedAt"],
            message: "cannot be after bundle creation"
          });
        }
      }
    }

    const firstPeriod = value.periods[0];
    const lastPeriod = value.periods.at(-1);
    if (firstPeriod && value.firstAsOfDate !== firstPeriod.asOfDate) {
      context.addIssue({
        code: "custom",
        path: ["firstAsOfDate"],
        message: "must match the first certified period"
      });
    }
    if (lastPeriod && value.lastAsOfDate !== lastPeriod.asOfDate) {
      context.addIssue({
        code: "custom",
        path: ["lastAsOfDate"],
        message: "must match the last certified period"
      });
    }
  });

export const LongitudinalCertificationBundleV1Schema =
  LongitudinalCertificationBundleBodyV1Schema.extend({
    bundleHash: Sha256HashSchema
  }).strict();

export type LongitudinalCertificationBundleV1 = Readonly<
  z.infer<typeof LongitudinalCertificationBundleV1Schema>
>;

export function parseLongitudinalCertificationBundleV1(
  value: unknown
): LongitudinalCertificationBundleV1 {
  const parsed = parseWithSchema(
    LongitudinalCertificationBundleV1Schema,
    value,
    "LongitudinalCertificationBundleV1"
  );
  const { bundleHash, ...body } = parsed;
  assertCanonicalHash(body, bundleHash, "LongitudinalCertificationBundleV1");
  return parsed;
}

function validateCorrectionChain(
  period: z.infer<typeof LongitudinalAsOfPeriodV1Schema>,
  context: z.core.$RefinementCtx
): void {
  for (const [index, revision] of period.revisions.entries()) {
    if (revision.revisionSequence !== index + 1) {
      context.addIssue({
        code: "custom",
        path: ["revisions", index, "revisionSequence"],
        message: "must be contiguous and one-based"
      });
    }
    if (revision.snapshot.asOfDate !== period.asOfDate) {
      context.addIssue({
        code: "custom",
        path: ["revisions", index, "snapshot", "asOfDate"],
        message: "must match the period as-of date"
      });
    }
    if (index === 0) {
      if (revision.correction.kind !== "original") {
        context.addIssue({
          code: "custom",
          path: ["revisions", index, "correction"],
          message: "the first revision must be an original delivery"
        });
      }
      continue;
    }
    const previous = period.revisions[index - 1]!;
    if (
      revision.correction.kind === "correction" &&
      revision.correction.detectedAt < previous.certification.certifiedAt
    ) {
      context.addIssue({
        code: "custom",
        path: ["revisions", index, "correction", "detectedAt"],
        message: "cannot precede the prior revision certification"
      });
    }
    if (revision.certification.certifiedAt < previous.certification.certifiedAt) {
      context.addIssue({
        code: "custom",
        path: ["revisions", index, "certification", "certifiedAt"],
        message: "cannot precede the prior revision certification"
      });
    }
    if (revision.correction.kind !== "correction") {
      context.addIssue({
        code: "custom",
        path: ["revisions", index, "correction"],
        message: "replacement revisions must declare correction lineage"
      });
      continue;
    }
    if (revision.correction.correctionSequence !== index) {
      context.addIssue({
        code: "custom",
        path: ["revisions", index, "correction", "correctionSequence"],
        message: "must be monotonic without gaps"
      });
    }
    if (
      revision.correction.correctsSnapshotId !== previous.snapshot.snapshotId ||
      revision.correction.correctsSnapshotHash !== previous.snapshot.snapshotHash
    ) {
      context.addIssue({
        code: "custom",
        path: ["revisions", index, "correction"],
        message: "must exactly replace the preceding certified snapshot"
      });
    }
  }

  const terminal = period.revisions.at(-1);
  if (!terminal) return;
  const expectedSelection = {
    revisionSequence: terminal.revisionSequence,
    certificationManifestId: terminal.certification.certificationManifestId,
    certificationManifestHash: terminal.certification.certificationManifestHash,
    snapshotId: terminal.snapshot.snapshotId,
    snapshotHash: terminal.snapshot.snapshotHash,
    normalizedArtifactContentHash: terminal.normalizedArtifact.contentHash,
    populationHash: terminal.populationHash
  };
  if (canonicalJson(expectedSelection) !== canonicalJson(period.analyticsSelection)) {
    context.addIssue({
      code: "custom",
      path: ["analyticsSelection"],
      message: "must select the terminal replacement revision"
    });
  }
}

function recordUnique(
  values: Set<string>,
  value: string,
  path: (string | number)[],
  label: string,
  context: z.core.$RefinementCtx
): void {
  if (values.has(value)) {
    context.addIssue({ code: "custom", path, message: `${label} must be unique` });
  }
  values.add(value);
}
