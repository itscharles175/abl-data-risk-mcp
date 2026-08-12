import assert from "node:assert/strict";
import test from "node:test";

import {
  ContractValidationError,
  canonicalHash,
  type Sha256Hash
} from "../src/contracts/canonical.js";
import {
  parseLongitudinalCertificationBundleV1,
  type LongitudinalCertificationBundleV1
} from "../src/contracts/longitudinal-certification-bundle-v1.js";
import {
  LongitudinalCertificationError,
  LongitudinalCertificationService,
  type FrozenLongitudinalMethodologyV1,
  type FrozenSnapshotCertificationV1,
  type LongitudinalCertificationAuthority
} from "../src/services/longitudinal-certification.js";

const CREATED_AT = "2026-09-01T12:00:00.000Z";

test("build resolves ids only and canonicalizes longitudinal periods chronologically", async () => {
  const authority = authorityFixture([
    certification("cert-jun", "snapshot-jun", "2026-06-30"),
    certification("cert-jul", "snapshot-jul", "2026-07-31"),
    certification("cert-aug", "snapshot-aug", "2026-08-31")
  ]);
  const service = serviceFixture(authority);

  const reversed = await service.build(
    request(["cert-aug", "cert-jun", "cert-jul"])
  );
  const ordered = await service.build(
    request(["cert-jun", "cert-jul", "cert-aug"])
  );

  assert.equal(reversed.bundleHash, ordered.bundleHash);
  assert.deepEqual(
    reversed.periods.map((period) => [period.sequence, period.asOfDate]),
    [
      [1, "2026-06-30"],
      [2, "2026-07-31"],
      [3, "2026-08-31"]
    ]
  );
  assert.equal(reversed.firstAsOfDate, "2026-06-30");
  assert.equal(reversed.lastAsOfDate, "2026-08-31");
  assert.equal(reversed.datasetId, "loan-tape");
  assert.deepEqual(reversed.scope, { scopeType: "portfolio", scopeId: "portfolio-a" });
  assert.equal(reversed.certificationCount, 3);
  assert.ok(Object.isFrozen(reversed));
  assert.ok(Object.isFrozen(reversed.periods));
  assert.doesNotMatch(JSON.stringify(reversed), /records|credential|sourceLocator/);
});

test("bundle construction rejects duplicate manifest, snapshot, and as-of identities", async () => {
  const base = certification("cert-a", "snapshot-a", "2026-06-30");
  const authority = authorityFixture([
    base,
    certification("cert-b", "snapshot-b", "2026-06-30"),
    certification("cert-c", "snapshot-a", "2026-07-31")
  ]);
  const service = serviceFixture(authority);

  await assert.rejects(
    () => service.build(request(["cert-a", "cert-a"])),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
  await assert.rejects(
    () => service.build(request(["cert-a", "cert-b"])),
    (error: unknown) => serviceError(error, "CORRECTION_CHAIN_INVALID")
  );
  await assert.rejects(
    () =>
      serviceFixture(authorityFixture([base, authority.manifests.get("cert-c")!])).build(
        request(["cert-a", "cert-c"])
      ),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
});

test("authority cannot cross tenant boundaries", async () => {
  const wrongTenant = {
    ...certification("cert-a", "snapshot-a", "2026-06-30"),
    tenantId: "tenant-b"
  } satisfies FrozenSnapshotCertificationV1;
  const service = serviceFixture(authorityFixture([wrongTenant]));

  await assert.rejects(
    () => service.build(request(["cert-a"])),
    (error: unknown) => serviceError(error, "AUTHORITY_MISMATCH")
  );
});

test("missing and rejected certifications never enter a longitudinal bundle", async () => {
  const rejected = {
    ...certification("cert-rejected", "snapshot-rejected", "2026-06-30"),
    certificationStatus: "rejected" as const
  };
  const service = serviceFixture(authorityFixture([rejected]));

  await assert.rejects(
    () => service.build(request(["cert-missing"])),
    (error: unknown) => serviceError(error, "MANIFEST_NOT_FOUND")
  );
  await assert.rejects(
    () => service.build(request(["cert-rejected"])),
    (error: unknown) => serviceError(error, "MANIFEST_NOT_CERTIFIED")
  );
});

test("verification detects drift in frozen manifest and methodology evidence", async () => {
  const authority = authorityFixture([
    certification("cert-a", "snapshot-a", "2026-06-30")
  ]);
  const service = serviceFixture(authority);
  const bundle = await service.build(request(["cert-a"]));
  assert.deepEqual(await service.verify(bundle), bundle);

  const original = authority.manifests.get("cert-a")!;
  authority.manifests.set("cert-a", {
    ...original,
    normalizedArtifact: {
      ...original.normalizedArtifact,
      contentHash: hash("rewritten-normalized-artifact")
    }
  });
  await assert.rejects(
    () => service.verify(bundle),
    (error: unknown) => serviceError(error, "FROZEN_EVIDENCE_DRIFT")
  );

  authority.manifests.set("cert-a", original);
  authority.frozenMethodology = {
    ...authority.frozenMethodology,
    methodologyHash: hash("rewritten-methodology")
  };
  await assert.rejects(
    () => service.verify(bundle),
    (error: unknown) => serviceError(error, "FROZEN_EVIDENCE_DRIFT")
  );
});

test("valid corrections bind the full chain and select only the terminal replacement", async () => {
  const original = certification("cert-original", "snapshot-original", "2026-06-30");
  const correctionOne = correctedCertification(
    "cert-correction-1",
    "snapshot-correction-1",
    original,
    1
  );
  const correctionTwo = correctedCertification(
    "cert-correction-2",
    "snapshot-correction-2",
    correctionOne,
    2
  );
  const authority = authorityFixture([original, correctionOne, correctionTwo]);
  const bundle = await serviceFixture(authority).build(
    request(["cert-correction-2", "cert-original", "cert-correction-1"])
  );

  assert.equal(bundle.periodCount, 1);
  assert.equal(bundle.certificationCount, 3);
  assert.deepEqual(
    bundle.periods[0]?.revisions.map((revision) => revision.snapshot.snapshotId),
    ["snapshot-original", "snapshot-correction-1", "snapshot-correction-2"]
  );
  assert.equal(bundle.periods[0]?.analyticsSelection.snapshotId, "snapshot-correction-2");
  assert.equal(bundle.periods[0]?.analyticsSelection.revisionSequence, 3);
  assert.deepEqual(await serviceFixture(authority).verify(bundle), bundle);
});

test("requesting only the original expands to every certified correction known at bundle creation", async () => {
  const original = certification("cert-original", "snapshot-original", "2026-06-30");
  const correctionOne = correctedCertification(
    "cert-correction-1",
    "snapshot-correction-1",
    original,
    1
  );
  const correctionTwo = correctedCertification(
    "cert-correction-2",
    "snapshot-correction-2",
    correctionOne,
    2
  );
  const authority = authorityFixture([original, correctionOne, correctionTwo]);
  const bundle = await serviceFixture(authority).build(request(["cert-original"]));

  assert.equal(bundle.certificationCount, 3);
  assert.deepEqual(
    bundle.periods[0]?.revisions.map(
      (revision) => revision.certification.certificationManifestId
    ),
    ["cert-original", "cert-correction-1", "cert-correction-2"]
  );
  assert.equal(bundle.periods[0]?.analyticsSelection.snapshotId, "snapshot-correction-2");
});

test("requesting more than one revision deduplicates their authority-expanded period", async () => {
  const original = certification("cert-original", "snapshot-original", "2026-06-30");
  const correction = correctedCertification(
    "cert-correction",
    "snapshot-correction",
    original,
    1
  );
  const bundle = await serviceFixture(authorityFixture([original, correction])).build(
    request(["cert-original", "cert-correction"])
  );

  assert.equal(bundle.periodCount, 1);
  assert.equal(bundle.certificationCount, 2);
});

test("authority chains must include the requested manifest and stay within its period", async () => {
  const original = certification("cert-original", "snapshot-original", "2026-06-30");
  const anotherPeriod = certification("cert-july", "snapshot-july", "2026-07-31");
  const authority = authorityFixture([original, anotherPeriod]);
  authority.chainOverrides.set("cert-original", [anotherPeriod]);

  await assert.rejects(
    () => serviceFixture(authority).build(request(["cert-original"])),
    (error: unknown) => serviceError(error, "AUTHORITY_MISMATCH")
  );

  authority.chainOverrides.set("cert-original", [original, anotherPeriod]);
  await assert.rejects(
    () => serviceFixture(authority).build(request(["cert-original"])),
    (error: unknown) => serviceError(error, "AUTHORITY_MISMATCH")
  );
});

test("later corrections do not invalidate a bundle frozen at its creation cutoff", async () => {
  const original = certification("cert-original", "snapshot-original", "2026-06-30");
  const authority = authorityFixture([original]);
  const service = serviceFixture(authority);
  const bundle = await service.build(request(["cert-original"]));
  const lateCorrection = {
    ...correctedCertification(
      "cert-late-correction",
      "snapshot-late-correction",
      original,
      1
    ),
    recordedAt: "2026-09-02T12:00:00.000Z",
    correction: {
      kind: "correction" as const,
      correctsSnapshotId: original.snapshot.snapshotId,
      correctsSnapshotHash: original.snapshot.snapshotHash,
      correctionSequence: 1,
      reasonCode: "source-restatement",
      reason: "Source system restatement",
      detectedAt: "2026-09-02T11:00:00.000Z"
    }
  };
  authority.manifests.set(lateCorrection.certificationManifestId, lateCorrection);

  assert.deepEqual(await service.verify(bundle), bundle);
});

test("verification detects correction-chain drift that was knowable at the frozen cutoff", async () => {
  const original = certification("cert-original", "snapshot-original", "2026-06-30");
  const correction = correctedCertification(
    "cert-correction",
    "snapshot-correction",
    original,
    1
  );
  const authority = authorityFixture([original, correction]);
  const service = serviceFixture(authority);
  const bundle = await service.build(request(["cert-original"]));
  authority.manifests.set("cert-correction", {
    ...correction,
    correction: {
      ...correction.correction,
      reason: "Rewritten correction explanation"
    }
  });

  await assert.rejects(
    () => service.verify(bundle),
    (error: unknown) => serviceError(error, "FROZEN_EVIDENCE_DRIFT")
  );
});

test("correction forks, sequence gaps, and unrelated same-date snapshots are rejected", async () => {
  const original = certification("cert-original", "snapshot-original", "2026-06-30");
  const first = correctedCertification("cert-first", "snapshot-first", original, 1);
  const fork = correctedCertification("cert-fork", "snapshot-fork", original, 1);
  const gap = correctedCertification("cert-gap", "snapshot-gap", first, 3);
  const unrelated = certification("cert-unrelated", "snapshot-unrelated", "2026-06-30");

  for (const manifests of [
    [original, first, fork],
    [original, first, gap],
    [original, unrelated]
  ]) {
    const service = serviceFixture(authorityFixture(manifests));
    await assert.rejects(
      () => service.build(request(manifests.map((manifest) => manifest.certificationManifestId))),
      (error: unknown) => serviceError(error, "CORRECTION_CHAIN_INVALID")
    );
  }
});

test("mixed dataset, source, and governed scope cannot share a bundle", async () => {
  const base = certification("cert-base", "snapshot-base", "2026-06-30");
  const variants: readonly FrozenSnapshotCertificationV1[] = [
    {
      ...certification("cert-dataset", "snapshot-dataset", "2026-07-31"),
      datasetId: "another-dataset"
    },
    {
      ...certification("cert-source", "snapshot-source", "2026-07-31"),
      source: {
        sourceContractId: "another-contract",
        sourceKey: "another-source",
        revision: 1,
        sourceContractHash: hash("another-source-contract")
      }
    },
    {
      ...certification("cert-source-revision", "snapshot-source-revision", "2026-07-31"),
      source: { ...base.source, revision: base.source.revision + 1 }
    },
    {
      ...certification("cert-source-hash", "snapshot-source-hash", "2026-07-31"),
      source: { ...base.source, sourceContractHash: hash("rewritten-source-contract") }
    },
    {
      ...certification("cert-scope", "snapshot-scope", "2026-07-31"),
      scope: { scopeType: "facility", scopeId: "facility-a" }
    }
  ];

  for (const variant of variants) {
    const service = serviceFixture(authorityFixture([base, variant]));
    await assert.rejects(
      () => service.build(request([base.certificationManifestId, variant.certificationManifestId])),
      (error: unknown) => contractError(error, "INVALID_CONTRACT")
    );
  }
});

test("verification detects frozen source-contract revision or hash drift", async () => {
  const authority = authorityFixture([
    certification("cert-a", "snapshot-a", "2026-06-30")
  ]);
  const service = serviceFixture(authority);
  const bundle = await service.build(request(["cert-a"]));
  const original = authority.manifests.get("cert-a")!;

  authority.manifests.set("cert-a", {
    ...original,
    source: { ...original.source, revision: original.source.revision + 1 }
  });
  await assert.rejects(
    () => service.verify(bundle),
    (error: unknown) => serviceError(error, "FROZEN_EVIDENCE_DRIFT")
  );

  authority.manifests.set("cert-a", {
    ...original,
    source: { ...original.source, sourceContractHash: hash("drifted-source-contract") }
  });
  await assert.rejects(
    () => service.verify(bundle),
    (error: unknown) => serviceError(error, "FROZEN_EVIDENCE_DRIFT")
  );
});

test("verification detects frozen runtime compiler drift in any correction revision", async () => {
  const original = certification("cert-original", "snapshot-original", "2026-06-30");
  const correction = correctedCertification(
    "cert-correction",
    "snapshot-correction",
    original,
    1
  );
  const authority = authorityFixture([original, correction]);
  const service = serviceFixture(authority);
  const bundle = await service.build(request(["cert-original", "cert-correction"]));

  authority.manifests.set("cert-correction", {
    ...correction,
    mapping: {
      ...correction.mapping,
      runtime: {
        ...correction.mapping.runtime,
        compilerHash: hash("drifted-compiler")
      }
    }
  });
  await assert.rejects(
    () => service.verify(bundle),
    (error: unknown) => serviceError(error, "FROZEN_EVIDENCE_DRIFT")
  );
});

test("correction detection cannot occur after its certification is recorded", async () => {
  const original = certification("cert-original", "snapshot-original", "2026-06-30");
  const invalid = {
    ...correctedCertification("cert-invalid", "snapshot-invalid", original, 1),
    recordedAt: "2026-08-05T11:00:00.000Z",
    correction: {
      kind: "correction" as const,
      correctsSnapshotId: original.snapshot.snapshotId,
      correctsSnapshotHash: original.snapshot.snapshotHash,
      correctionSequence: 1,
      reasonCode: "source-restatement",
      reason: "Source system restatement",
      detectedAt: "2026-08-05T12:00:00.000Z"
    }
  };

  await assert.rejects(
    () => serviceFixture(authorityFixture([original, invalid])).build(request(["cert-original"])),
    (error: unknown) => serviceError(error, "AUTHORITY_MISMATCH")
  );
});

test("a correction cannot be detected before its predecessor is certified", async () => {
  const original = certification("cert-original", "snapshot-original", "2026-06-30");
  const invalid = {
    ...correctedCertification("cert-invalid", "snapshot-invalid", original, 1),
    recordedAt: "2026-07-01T12:00:00.000Z",
    correction: {
      kind: "correction" as const,
      correctsSnapshotId: original.snapshot.snapshotId,
      correctsSnapshotHash: original.snapshot.snapshotHash,
      correctionSequence: 1,
      reasonCode: "source-restatement",
      reason: "Source system restatement",
      detectedAt: "2026-06-29T12:00:00.000Z"
    }
  };
  await assert.rejects(
    () => serviceFixture(authorityFixture([original, invalid])).build(request(["cert-original"])),
    (error: unknown) => serviceError(error, "CORRECTION_CHAIN_INVALID")
  );
});

test("a snapshot cannot be certified before its as-of date", async () => {
  const future = {
    ...certification("cert-future", "snapshot-future", "2026-08-31"),
    recordedAt: "2026-08-01T12:00:00.000Z"
  };
  await assert.rejects(
    () => serviceFixture(authorityFixture([future])).build(request(["cert-future"])),
    (error: unknown) => serviceError(error, "AUTHORITY_MISMATCH")
  );
});

test("replacement certification timestamps cannot regress across a correction chain", async () => {
  const original = {
    ...certification("cert-original", "snapshot-original", "2026-06-30"),
    recordedAt: "2026-08-07T12:00:00.000Z"
  };
  const correction = {
    ...correctedCertification("cert-correction", "snapshot-correction", original, 1),
    recordedAt: "2026-08-06T12:00:00.000Z",
    correction: {
      kind: "correction" as const,
      correctsSnapshotId: original.snapshot.snapshotId,
      correctsSnapshotHash: original.snapshot.snapshotHash,
      correctionSequence: 1,
      reasonCode: "source-restatement",
      reason: "Source system restatement",
      detectedAt: "2026-08-06T11:00:00.000Z"
    }
  };

  await assert.rejects(
    () => serviceFixture(authorityFixture([original, correction])).build(request(["cert-original"])),
    (error: unknown) => serviceError(error, "CORRECTION_CHAIN_INVALID")
  );
});

test("invalid clocks fail with a stable longitudinal service error", async () => {
  const service = new LongitudinalCertificationService(
    authorityFixture([certification("cert-a", "snapshot-a", "2026-06-30")]),
    { clock: () => new Date(Number.NaN) }
  );

  await assert.rejects(
    () => service.build(request(["cert-a"])),
    (error: unknown) => serviceError(error, "INVALID_REQUEST")
  );
});

test("methodology approval proof is lifecycle-stable while unapproved evidence is rejected", async () => {
  const authority = authorityFixture([
    certification("cert-a", "snapshot-a", "2026-06-30")
  ]);
  authority.frozenMethodology = {
    ...authority.frozenMethodology,
    definitionStatus: "approved"
  };
  const service = serviceFixture(authority);
  await assert.rejects(
    () => service.build(request(["cert-a"])),
    (error: unknown) => serviceError(error, "METHODOLOGY_NOT_APPROVED")
  );
  authority.frozenMethodology = {
    ...authority.frozenMethodology,
    definitionStatus: "active"
  };
  const bundle = await service.build(request(["cert-a"]));
  assert.equal(bundle.methodology.definitionVersionId, "portfolio-surveillance-v1");
  assert.match(bundle.methodology.approvalEventHash, /^sha256:/u);

  assert.deepEqual(await service.verify(bundle), bundle);
  authority.frozenMethodology = {
    ...authority.frozenMethodology,
    definitionStatus: "superseded"
  };
  assert.deepEqual(await service.verify(bundle), bundle);

  authority.frozenMethodology = {
    ...authority.frozenMethodology,
    definitionStatus: "validated",
    approvalEventHash: null,
    approvedAt: null
  };
  await assert.rejects(
    () => service.build(request(["cert-a"])),
    (error: unknown) => serviceError(error, "METHODOLOGY_NOT_APPROVED")
  );
});

test("historical replay ignores newer active definitions and resolves frozen evidence", async () => {
  const authority = authorityFixture([
    certification("cert-a", "snapshot-a", "2026-06-30"),
    certification("cert-b", "snapshot-b", "2026-07-31")
  ]);
  const service = serviceFixture(authority);
  const bundle = await service.build(request(["cert-a", "cert-b"]));

  authority.activateMethodology(hash("new-active-methodology"));
  authority.activateDictionary(hash("new-active-dictionary"));

  assert.deepEqual(await service.verify(bundle), bundle);
  assert.equal(authority.activeResolutionCount, 0);
  assert.equal(authority.frozenMethodologyResolutionCount, 2);
  assert.equal(authority.frozenManifestResolutionCount, 4);
});

test("strict parsing rejects tampering even when a caller recomputes the outer hash", async () => {
  const authority = authorityFixture([
    certification("cert-a", "snapshot-a", "2026-06-30"),
    certification("cert-b", "snapshot-b", "2026-07-31")
  ]);
  const bundle = await serviceFixture(authority).build(request(["cert-a", "cert-b"]));
  const tampered = JSON.parse(JSON.stringify(bundle)) as LongitudinalCertificationBundleV1;
  const reversed = [...tampered.periods].reverse();
  const { bundleHash: _oldHash, ...oldBody } = tampered;
  const body = { ...oldBody, periods: reversed };

  assert.throws(
    () =>
      parseLongitudinalCertificationBundleV1({
        ...body,
        bundleHash: canonicalHash(body)
      }),
    (error: unknown) => contractError(error, "INVALID_CONTRACT")
  );
});

class FakeLongitudinalAuthority implements LongitudinalCertificationAuthority {
  readonly manifests = new Map<string, FrozenSnapshotCertificationV1>();
  readonly chainOverrides = new Map<
    string,
    readonly FrozenSnapshotCertificationV1[] | undefined
  >();
  frozenMethodology: FrozenLongitudinalMethodologyV1 = {
    tenantId: "tenant-a",
    methodologyId: "portfolio-surveillance",
    definitionVersionId: "portfolio-surveillance-v1",
    version: "1.0.0",
    versionHash: hash("methodology-version:1.0.0"),
    documentHash: hash("methodology-document:1.0.0"),
    methodologyHash: hash("frozen-methodology-1.0.0"),
    definitionStatus: "active",
    approvalEventHash: hash("methodology-approval:1.0.0"),
    approvedAt: "2026-08-01T10:00:00.000Z"
  };
  frozenManifestResolutionCount = 0;
  frozenMethodologyResolutionCount = 0;
  activeResolutionCount = 0;
  #activeMethodologyHash = this.frozenMethodology.methodologyHash;
  #activeDictionaryHash = hash("active-dictionary");

  constructor(manifests: readonly FrozenSnapshotCertificationV1[]) {
    for (const manifest of manifests) this.manifests.set(manifest.certificationManifestId, manifest);
  }

  async resolveCertifiedCorrectionChainAsOf(input: {
    readonly tenantId: string;
    readonly certificationManifestId: string;
    readonly knowledgeCutoff: string;
  }): Promise<readonly FrozenSnapshotCertificationV1[] | undefined> {
    this.frozenManifestResolutionCount += 1;
    if (this.chainOverrides.has(input.certificationManifestId)) {
      return this.chainOverrides.get(input.certificationManifestId);
    }
    const requested = this.manifests.get(input.certificationManifestId);
    if (!requested) return undefined;
    return [...this.manifests.values()].filter(
      (manifest) =>
        manifest.snapshot.asOfDate === requested.snapshot.asOfDate &&
        manifest.recordedAt <= input.knowledgeCutoff
    );
  }

  async resolveFrozenMethodology(input: {
    readonly tenantId: string;
    readonly methodologyId: string;
    readonly version: string;
  }): Promise<FrozenLongitudinalMethodologyV1 | undefined> {
    this.frozenMethodologyResolutionCount += 1;
    return this.frozenMethodology;
  }

  activateMethodology(methodologyHash: Sha256Hash): void {
    this.#activeMethodologyHash = methodologyHash;
  }

  activateDictionary(dictionaryHash: Sha256Hash): void {
    this.#activeDictionaryHash = dictionaryHash;
  }
}

function authorityFixture(
  manifests: readonly FrozenSnapshotCertificationV1[]
): FakeLongitudinalAuthority {
  return new FakeLongitudinalAuthority(manifests);
}

function serviceFixture(authority: LongitudinalCertificationAuthority): LongitudinalCertificationService {
  return new LongitudinalCertificationService(authority, {
    clock: () => new Date(CREATED_AT)
  });
}

function certification(
  certificationManifestId: string,
  snapshotId: string,
  asOfDate: string
): FrozenSnapshotCertificationV1 {
  return {
    tenantId: "tenant-a",
    certificationManifestId,
    certificationManifestHash: hash(`manifest:${certificationManifestId}`),
    certificationStatus: "certified",
    recordedAt: `${asOfDate}T12:00:00.000Z`,
    datasetId: "loan-tape",
    source: {
      sourceContractId: "loan-tape-source-v1",
      sourceKey: "loan-tape-source",
      revision: 1,
      sourceContractHash: hash("source-contract:loan-tape-source-v1")
    },
    scope: {
      scopeType: "portfolio",
      scopeId: "portfolio-a"
    },
    snapshot: {
      snapshotId,
      asOfDate,
      snapshotHash: hash(`snapshot:${snapshotId}`)
    },
    delivery: {
      deliveryId: `delivery-${snapshotId}`,
      deliveryMode: "postgresql_pull",
      deliveredContentHash: hash(`delivered:${snapshotId}`)
    },
    correction: { kind: "original" },
    dictionary: {
      dictionaryBundleId: "canonical-dictionary",
      version: "2.0.0",
      dictionaryHash: hash("dictionary:2.0.0")
    },
    mapping: {
      mappingApplicationId: `application-${snapshotId}`,
      mappingApplicationHash: hash(`application:${snapshotId}`),
      mappingSpecId: "portfolio-mapping",
      mappingSpecHash: hash("mapping-spec:portfolio"),
      runtime: {
        runtimeBundleId: "mapping-runtime",
        runtimeVersion: "1.0.0",
        runtimeBundleHash: hash("mapping-runtime:1.0.0"),
        compilerHash: hash("mapping-compiler:1.0.0")
      }
    },
    normalizedArtifact: {
      artifactId: `normalized-${snapshotId}`,
      contentHash: hash(`normalized:${snapshotId}`)
    },
    rowCount: 100,
    populationHash: hash(`population:${snapshotId}`)
  };
}

function correctedCertification(
  certificationManifestId: string,
  snapshotId: string,
  corrected: FrozenSnapshotCertificationV1,
  correctionSequence: number
): FrozenSnapshotCertificationV1 {
  const day = 4 + correctionSequence * 2;
  const detectedAt = `2026-08-${String(day + 1).padStart(2, "0")}T12:00:00.000Z`;
  const recordedAt = `2026-08-${String(day + 2).padStart(2, "0")}T12:00:00.000Z`;
  return {
    ...certification(certificationManifestId, snapshotId, corrected.snapshot.asOfDate),
    recordedAt,
    correction: {
      kind: "correction",
      correctsSnapshotId: corrected.snapshot.snapshotId,
      correctsSnapshotHash: corrected.snapshot.snapshotHash,
      correctionSequence,
      reasonCode: "source-restatement",
      reason: "Source system restatement",
      detectedAt
    }
  };
}

function request(certificationManifestIds: readonly string[]) {
  return {
    bundleId: "golden-portfolio-history",
    tenantId: "tenant-a",
    certificationManifestIds,
    methodologyId: "portfolio-surveillance",
    methodologyVersion: "1.0.0",
    purpose: "Reproduce governed longitudinal surveillance",
    createdBy: "risk-reviewer"
  } as const;
}

function hash(value: string): Sha256Hash {
  return canonicalHash(value);
}

function contractError(error: unknown, code: ContractValidationError["code"]): boolean {
  return error instanceof ContractValidationError && error.code === code;
}

function serviceError(
  error: unknown,
  code: LongitudinalCertificationError["code"]
): boolean {
  return error instanceof LongitudinalCertificationError && error.code === code;
}
