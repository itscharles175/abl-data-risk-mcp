import { z } from "zod";

import {
  parseLongitudinalCertificationBundleV1,
  type LongitudinalCertificationBundleV1,
  type LongitudinalCertifiedPeriodV1,
  type LongitudinalMethodologyReferenceV1
} from "../contracts/longitudinal-certification-bundle-v1.js";
import {
  IdentifierSchema,
  IsoDateSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  canonicalHash,
  canonicalJson,
  parseWithSchema
} from "../contracts/canonical.js";
import { SemanticVersionV2Schema } from "../contracts/governed-definition-v2.js";

const FrozenSnapshotCertificationSchema = z
  .object({
    tenantId: IdentifierSchema,
    certificationManifestId: IdentifierSchema,
    certificationManifestHash: Sha256HashSchema,
    certificationStatus: z.enum(["certified", "rejected"]),
    recordedAt: IsoTimestampSchema,
    datasetId: IdentifierSchema,
    source: z
      .object({
        sourceContractId: IdentifierSchema,
        sourceKey: IdentifierSchema,
        revision: z.number().int().positive(),
        sourceContractHash: Sha256HashSchema
      })
      .strict(),
    scope: z
      .object({
        scopeType: z.enum(["portfolio", "facility"]),
        scopeId: IdentifierSchema
      })
      .strict(),
    snapshot: z
      .object({
        snapshotId: IdentifierSchema,
        asOfDate: IsoDateSchema,
        snapshotHash: Sha256HashSchema
      })
      .strict(),
    delivery: z
      .object({
        deliveryId: IdentifierSchema,
        deliveryMode: z.enum(["postgresql_pull", "managed_upload", "object_storage"]),
        deliveredContentHash: Sha256HashSchema,
        immutableSourceVersion: z.string().min(1).max(1_024).optional()
      })
      .strict(),
    correction: z.discriminatedUnion("kind", [
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
    ]),
    dictionary: z
      .object({
        dictionaryBundleId: IdentifierSchema,
        version: z.string().min(1).max(64),
        dictionaryHash: Sha256HashSchema
      })
      .strict(),
    mapping: z
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
      .strict(),
    normalizedArtifact: z
      .object({
        artifactId: IdentifierSchema,
        contentHash: Sha256HashSchema
      })
      .strict(),
    rowCount: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
    populationHash: Sha256HashSchema
  })
  .strict()
  .superRefine((value, context) => {
    if (value.snapshot.asOfDate > value.recordedAt.slice(0, 10)) {
      context.addIssue({
        code: "custom",
        path: ["snapshot", "asOfDate"],
        message: "cannot be after certification recordedAt"
      });
    }
    if (
      value.correction.kind === "correction" &&
      value.correction.detectedAt > value.recordedAt
    ) {
      context.addIssue({
        code: "custom",
        path: ["correction", "detectedAt"],
        message: "cannot be after certification recordedAt"
      });
    }
  });

const FrozenMethodologySchema = z
  .object({
    tenantId: IdentifierSchema,
    methodologyId: IdentifierSchema,
    definitionVersionId: IdentifierSchema,
    version: SemanticVersionV2Schema,
    versionHash: Sha256HashSchema,
    documentHash: Sha256HashSchema,
    methodologyHash: Sha256HashSchema,
    definitionStatus: z.enum([
      "proposed",
      "validated",
      "approved",
      "active",
      "superseded",
      "retired"
    ]),
    approvalEventHash: Sha256HashSchema.nullable(),
    approvedAt: IsoTimestampSchema.nullable()
  })
  .strict();

const BuildLongitudinalCertificationBundleRequestSchema = z
  .object({
    bundleId: IdentifierSchema,
    tenantId: IdentifierSchema,
    certificationManifestIds: z.array(IdentifierSchema).min(1).max(120),
    methodologyId: IdentifierSchema,
    methodologyVersion: SemanticVersionV2Schema,
    purpose: z.string().trim().min(1).max(512),
    createdBy: IdentifierSchema
  })
  .strict()
  .superRefine((value, context) => {
    if (new Set(value.certificationManifestIds).size !== value.certificationManifestIds.length) {
      context.addIssue({
        code: "custom",
        path: ["certificationManifestIds"],
        message: "certification manifest ids must be unique"
      });
    }
  });

export type FrozenSnapshotCertificationV1 = Readonly<
  z.infer<typeof FrozenSnapshotCertificationSchema>
>;

export type FrozenLongitudinalMethodologyV1 = Readonly<z.infer<typeof FrozenMethodologySchema>>;

export type BuildLongitudinalCertificationBundleRequest = Readonly<
  z.input<typeof BuildLongitudinalCertificationBundleRequestSchema>
>;

export interface LongitudinalCertificationAuthority {
  /**
   * Resolves the complete certified correction chain containing the requested
   * manifest as it was knowable at the supplied cutoff. Implementations must
   * validate every stored manifest hash, include the original plus every
   * certified replacement recorded no later than the cutoff, and must not
   * substitute current mappings, dictionaries, artifacts, or later corrections.
   */
  resolveCertifiedCorrectionChainAsOf(input: {
    readonly tenantId: string;
    readonly certificationManifestId: string;
    readonly knowledgeCutoff: string;
  }): Promise<readonly FrozenSnapshotCertificationV1[] | undefined>;

  /** Resolves the frozen methodology revision; active-definition lookup is forbidden. */
  resolveFrozenMethodology(input: {
    readonly tenantId: string;
    readonly methodologyId: string;
    readonly version: string;
  }): Promise<FrozenLongitudinalMethodologyV1 | undefined>;
}

export type LongitudinalCertificationErrorCode =
  | "INVALID_REQUEST"
  | "MANIFEST_NOT_FOUND"
  | "MANIFEST_NOT_CERTIFIED"
  | "METHODOLOGY_NOT_FOUND"
  | "METHODOLOGY_NOT_APPROVED"
  | "AUTHORITY_MISMATCH"
  | "FROZEN_EVIDENCE_DRIFT"
  | "CORRECTION_CHAIN_INVALID";

export class LongitudinalCertificationError extends Error {
  constructor(
    readonly code: LongitudinalCertificationErrorCode,
    message: string
  ) {
    super(message);
    this.name = "LongitudinalCertificationError";
  }
}

export interface LongitudinalCertificationServiceOptions {
  readonly clock?: () => Date;
}

/**
 * Assembles and replays immutable longitudinal certification evidence. This
 * service is deliberately metadata-only and has no source-system write port.
 */
export class LongitudinalCertificationService {
  readonly #authority: LongitudinalCertificationAuthority;
  readonly #clock: () => Date;

  constructor(
    authority: LongitudinalCertificationAuthority,
    options: LongitudinalCertificationServiceOptions = {}
  ) {
    this.#authority = authority;
    this.#clock = options.clock ?? (() => new Date());
  }

  async build(
    request: BuildLongitudinalCertificationBundleRequest
  ): Promise<LongitudinalCertificationBundleV1> {
    const parsedRequest = parseWithSchema(
      BuildLongitudinalCertificationBundleRequestSchema,
      request,
      "BuildLongitudinalCertificationBundleRequest"
    );
    const createdAt = this.#now();
    const methodology = await this.#loadMethodology(
      parsedRequest.tenantId,
      parsedRequest.methodologyId,
      parsedRequest.methodologyVersion,
      createdAt
    );
    const requestedChains = await Promise.all(
      parsedRequest.certificationManifestIds.map((certificationManifestId) =>
        this.#loadCorrectionChain(
          parsedRequest.tenantId,
          certificationManifestId,
          createdAt
        )
      )
    );
    const resolvedById = new Map<string, FrozenSnapshotCertificationV1>();
    for (const chain of requestedChains) {
      for (const manifest of chain) {
        const existing = resolvedById.get(manifest.certificationManifestId);
        if (existing && canonicalJson(existing) !== canonicalJson(manifest)) {
          throw new LongitudinalCertificationError(
            "AUTHORITY_MISMATCH",
            "Correction-chain authority returned conflicting evidence for one manifest"
          );
        }
        resolvedById.set(manifest.certificationManifestId, manifest);
      }
    }
    const resolved = [...resolvedById.values()];
    if (resolved.length > 120) {
      throw new LongitudinalCertificationError(
        "INVALID_REQUEST",
        "Expanded correction chains exceed the 120-manifest bundle bound"
      );
    }
    const grouped = groupByAsOfDate(resolved);
    const periods = [...grouped.entries()]
      .sort(([left], [right]) => compareText(left, right))
      .map(([asOfDate, manifests], index) => {
        const chain = assembleCorrectionChain(asOfDate, manifests);
        const revisions = chain.map((manifest, revisionIndex) =>
          toCertifiedRevision(manifest, revisionIndex + 1)
        );
        const terminal = revisions.at(-1)!;
        return {
          sequence: index + 1,
          asOfDate,
          revisions,
          analyticsSelection: analyticsSelection(terminal)
        };
      });
    const firstPeriod = periods[0]!;
    const lastPeriod = periods.at(-1)!;
    const firstManifest = resolved[0]!;
    const body = {
      contractVersion: 1 as const,
      bundleId: parsedRequest.bundleId,
      tenantId: parsedRequest.tenantId,
      datasetId: firstManifest.datasetId,
      source: firstManifest.source,
      scope: firstManifest.scope,
      purpose: parsedRequest.purpose,
      methodology: methodologyReference(methodology),
      periodCount: periods.length,
      certificationCount: resolved.length,
      firstAsOfDate: firstPeriod.asOfDate,
      lastAsOfDate: lastPeriod.asOfDate,
      periods,
      createdBy: parsedRequest.createdBy,
      createdAt
    };
    return parseLongitudinalCertificationBundleV1({
      ...body,
      bundleHash: canonicalHash(body)
    });
  }

  async verify(
    value: LongitudinalCertificationBundleV1
  ): Promise<LongitudinalCertificationBundleV1> {
    const bundle = parseLongitudinalCertificationBundleV1(value);
    const methodology = await this.#loadMethodology(
      bundle.tenantId,
      bundle.methodology.methodologyId,
      bundle.methodology.version,
      bundle.createdAt
    );
    if (canonicalJson(methodologyReference(methodology)) !== canonicalJson(bundle.methodology)) {
      throw new LongitudinalCertificationError(
        "FROZEN_EVIDENCE_DRIFT",
        "Frozen methodology evidence no longer matches the longitudinal bundle"
      );
    }

    for (const period of bundle.periods) {
      let chain: readonly FrozenSnapshotCertificationV1[];
      try {
        chain = await this.#loadCorrectionChain(
          bundle.tenantId,
          period.revisions[0]!.certification.certificationManifestId,
          bundle.createdAt
        );
      } catch {
        throw new LongitudinalCertificationError(
          "FROZEN_EVIDENCE_DRIFT",
          `Frozen correction-chain evidence no longer resolves for period ${period.sequence}`
        );
      }
      const current = chain.map((manifest, index) =>
        toCertifiedRevision(manifest, index + 1)
      );
      if (canonicalJson(current) !== canonicalJson(period.revisions)) {
        throw new LongitudinalCertificationError(
          "FROZEN_EVIDENCE_DRIFT",
          `Frozen correction-chain evidence no longer matches period ${period.sequence}`
        );
      }
    }
    return bundle;
  }

  async #loadCorrectionChain(
    tenantId: string,
    certificationManifestId: string,
    knowledgeCutoff: string
  ): Promise<readonly FrozenSnapshotCertificationV1[]> {
    const value = await this.#authority.resolveCertifiedCorrectionChainAsOf({
      tenantId,
      certificationManifestId,
      knowledgeCutoff
    });
    if (!value) {
      throw new LongitudinalCertificationError(
        "MANIFEST_NOT_FOUND",
        `Certification manifest '${certificationManifestId}' was not found`
      );
    }
    if (!Array.isArray(value) || value.length === 0 || value.length > 120) {
      throw new LongitudinalCertificationError(
        "AUTHORITY_MISMATCH",
        "Correction-chain authority returned an invalid chain size"
      );
    }
    const resolved = value.map((manifest) => {
      let parsed: FrozenSnapshotCertificationV1;
      try {
        parsed = parseWithSchema(
          FrozenSnapshotCertificationSchema,
          manifest,
          "FrozenSnapshotCertificationV1"
        );
      } catch {
        throw new LongitudinalCertificationError(
          "AUTHORITY_MISMATCH",
          "Correction-chain authority returned malformed evidence"
        );
      }
      if (parsed.tenantId !== tenantId) {
        throw new LongitudinalCertificationError(
          "AUTHORITY_MISMATCH",
          `Certification manifest '${parsed.certificationManifestId}' belongs to a different tenant`
        );
      }
      if (parsed.certificationStatus !== "certified") {
        throw new LongitudinalCertificationError(
          "MANIFEST_NOT_CERTIFIED",
          `Certification manifest '${parsed.certificationManifestId}' is rejected`
        );
      }
      if (parsed.recordedAt > knowledgeCutoff) {
        throw new LongitudinalCertificationError(
          "AUTHORITY_MISMATCH",
          "Correction-chain authority returned evidence recorded after the knowledge cutoff"
        );
      }
      return parsed;
    });
    const requested = resolved.find(
      (manifest) => manifest.certificationManifestId === certificationManifestId
    );
    if (!requested) {
      throw new LongitudinalCertificationError(
        "AUTHORITY_MISMATCH",
        "Correction-chain authority omitted the requested manifest identity"
      );
    }
    if (resolved.some((manifest) => manifest.snapshot.asOfDate !== requested.snapshot.asOfDate)) {
      throw new LongitudinalCertificationError(
        "AUTHORITY_MISMATCH",
        "Correction-chain authority crossed an as-of period boundary"
      );
    }
    if (
      new Set(resolved.map((manifest) => manifest.certificationManifestId)).size !==
        resolved.length ||
      new Set(resolved.map((manifest) => manifest.snapshot.snapshotId)).size !==
        resolved.length
    ) {
      throw new LongitudinalCertificationError(
        "AUTHORITY_MISMATCH",
        "Correction-chain authority returned duplicate manifest or snapshot identities"
      );
    }
    return assembleCorrectionChain(requested.snapshot.asOfDate, resolved);
  }

  async #loadMethodology(
    tenantId: string,
    methodologyId: string,
    version: string,
    knowledgeCutoff: string
  ): Promise<FrozenLongitudinalMethodologyV1> {
    const value = await this.#authority.resolveFrozenMethodology({
      tenantId,
      methodologyId,
      version
    });
    if (!value) {
      throw new LongitudinalCertificationError(
        "METHODOLOGY_NOT_FOUND",
        `Frozen methodology '${methodologyId}:${version}' was not found`
      );
    }
    if (
      !value ||
      typeof value !== "object" ||
      !("approvalEventHash" in value) ||
      !("approvedAt" in value) ||
      value.approvalEventHash === null ||
      value.approvedAt === null ||
      value.definitionStatus === "proposed" ||
      value.definitionStatus === "validated" ||
      value.definitionStatus === "approved"
    ) {
      throw new LongitudinalCertificationError(
        "METHODOLOGY_NOT_APPROVED",
        "Frozen methodology lacks durable approval evidence"
      );
    }
    let resolved: FrozenLongitudinalMethodologyV1;
    try {
      resolved = parseWithSchema(
        FrozenMethodologySchema,
        value,
        "FrozenLongitudinalMethodologyV1"
      );
    } catch {
      throw new LongitudinalCertificationError(
        "AUTHORITY_MISMATCH",
        "Methodology authority returned malformed frozen evidence"
      );
    }
    if (
      resolved.tenantId !== tenantId ||
      resolved.methodologyId !== methodologyId ||
      resolved.version !== version
    ) {
      throw new LongitudinalCertificationError(
        "AUTHORITY_MISMATCH",
        "Methodology authority returned a different frozen identity"
      );
    }
    if (
      !["active", "superseded", "retired"].includes(
        resolved.definitionStatus
      ) ||
      resolved.approvalEventHash === null ||
      resolved.approvedAt === null ||
      resolved.approvedAt > knowledgeCutoff
    ) {
      throw new LongitudinalCertificationError(
        "METHODOLOGY_NOT_APPROVED",
        "Frozen methodology lacks durable approval evidence at the knowledge cutoff"
      );
    }
    return resolved;
  }

  #now(): string {
    const value = this.#clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw new LongitudinalCertificationError(
        "INVALID_REQUEST",
        "Longitudinal bundle clock is invalid"
      );
    }
    return value.toISOString();
  }
}

function methodologyReference(
  methodology: FrozenLongitudinalMethodologyV1
): LongitudinalMethodologyReferenceV1 {
  if (!(["active", "superseded", "retired"] as const).includes(
    methodology.definitionStatus as "active" | "superseded" | "retired"
  )) {
    throw new LongitudinalCertificationError(
      "METHODOLOGY_NOT_APPROVED",
      "Frozen methodology was never activated"
    );
  }
  const approvalEventHash = methodology.approvalEventHash;
  const approvedAt = methodology.approvedAt;
  if (approvalEventHash === null || approvedAt === null) {
    throw new LongitudinalCertificationError("METHODOLOGY_NOT_APPROVED", "Frozen methodology lacks durable approval evidence");
  }
  return {
    methodologyId: methodology.methodologyId,
    definitionVersionId: methodology.definitionVersionId,
    version: methodology.version,
    versionHash: methodology.versionHash,
    documentHash: methodology.documentHash,
    methodologyHash: methodology.methodologyHash,
    approvalEventHash,
    approvedAt
  };
}

function toCertifiedRevision(
  resolved: FrozenSnapshotCertificationV1,
  revisionSequence: number
): LongitudinalCertifiedPeriodV1 {
  return {
    revisionSequence,
    tenantId: resolved.tenantId,
    datasetId: resolved.datasetId,
    source: resolved.source,
    scope: resolved.scope,
    certification: {
      certificationManifestId: resolved.certificationManifestId,
      certificationManifestHash: resolved.certificationManifestHash,
      certifiedAt: resolved.recordedAt
    },
    snapshot: resolved.snapshot,
    delivery: resolved.delivery,
    correction: resolved.correction,
    dictionary: resolved.dictionary,
    mapping: resolved.mapping,
    normalizedArtifact: resolved.normalizedArtifact,
    rowCount: resolved.rowCount,
    populationHash: resolved.populationHash
  };
}

function analyticsSelection(revision: LongitudinalCertifiedPeriodV1) {
  return {
    revisionSequence: revision.revisionSequence,
    certificationManifestId: revision.certification.certificationManifestId,
    certificationManifestHash: revision.certification.certificationManifestHash,
    snapshotId: revision.snapshot.snapshotId,
    snapshotHash: revision.snapshot.snapshotHash,
    normalizedArtifactContentHash: revision.normalizedArtifact.contentHash,
    populationHash: revision.populationHash
  };
}

function groupByAsOfDate(
  manifests: readonly FrozenSnapshotCertificationV1[]
): Map<string, FrozenSnapshotCertificationV1[]> {
  const grouped = new Map<string, FrozenSnapshotCertificationV1[]>();
  for (const manifest of manifests) {
    const group = grouped.get(manifest.snapshot.asOfDate) ?? [];
    group.push(manifest);
    grouped.set(manifest.snapshot.asOfDate, group);
  }
  return grouped;
}

function assembleCorrectionChain(
  asOfDate: string,
  manifests: readonly FrozenSnapshotCertificationV1[]
): readonly FrozenSnapshotCertificationV1[] {
  const originals = manifests.filter((manifest) => manifest.correction.kind === "original");
  if (originals.length !== 1) {
    invalidCorrectionChain(
      asOfDate,
      originals.length === 0 ? "has no original snapshot" : "contains unrelated original snapshots"
    );
  }

  const original = originals[0]!;
  const remaining = new Set(
    manifests
      .filter((manifest) => manifest !== original)
      .map((manifest) => manifest.certificationManifestId)
  );
  const chain = [original];
  let current = original;
  let expectedSequence = 1;
  while (remaining.size > 0) {
    const children = manifests.filter(
      (manifest) =>
        remaining.has(manifest.certificationManifestId) &&
        manifest.correction.kind === "correction" &&
        manifest.correction.correctsSnapshotId === current.snapshot.snapshotId &&
        manifest.correction.correctsSnapshotHash === current.snapshot.snapshotHash
    );
    if (children.length > 1) {
      invalidCorrectionChain(asOfDate, `forks after snapshot '${current.snapshot.snapshotId}'`);
    }
    const child = children[0];
    if (!child) {
      invalidCorrectionChain(asOfDate, "contains a gap or an unrelated correction");
    }
    if (
      child.correction.kind !== "correction" ||
      child.correction.correctionSequence !== expectedSequence
    ) {
      invalidCorrectionChain(asOfDate, "has a non-monotonic correction sequence");
    }
    if (child.recordedAt < current.recordedAt) {
      invalidCorrectionChain(
        asOfDate,
        "has a correction certified before its predecessor"
      );
    }
    if (
      child.correction.kind === "correction" &&
      child.correction.detectedAt < current.recordedAt
    ) {
      invalidCorrectionChain(
        asOfDate,
        "has a correction detected before its predecessor certification"
      );
    }
    chain.push(child);
    remaining.delete(child.certificationManifestId);
    current = child;
    expectedSequence += 1;
  }
  return chain;
}

function invalidCorrectionChain(asOfDate: string, reason: string): never {
  throw new LongitudinalCertificationError(
    "CORRECTION_CHAIN_INVALID",
    `Correction chain for ${asOfDate} ${reason}`
  );
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
