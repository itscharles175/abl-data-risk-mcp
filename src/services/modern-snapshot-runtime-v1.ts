import { IdentifierSchema, parseWithSchema } from "../contracts/canonical.js";
import { ArtifactStore } from "../control/artifacts.js";
import { CertificationRuntimeAuthorityFactoryV1 } from "../control/certification-runtime-authority-v1.js";
import {
  LifecycleSnapshotCertificationDefinitionAuthorityV1
} from "../control/lifecycle-snapshot-certification-definition-authority-v1.js";
import type { DatasetSnapshotV2 } from "../contracts/dataset-snapshot-v2.js";
import type { ImmutableRepositoryPort } from "../repositories/ports.js";
import type { GovernedDatasetSnapshotCommitRepositoryV1 } from "../repositories/governed-snapshot-commit.js";
import { SqliteCapturedSourceMaterialStoreV1 } from "../repositories/captured-source-material-v1.js";
import { SqliteCertificationArtifactStagingStoreV1 } from "../repositories/certification-artifact-staging-v1.js";
import { SqliteCertifiedSnapshotEvidenceV2Repository } from "../repositories/certified-snapshot-evidence-v2.js";
import { SqliteSnapshotCertificationAttemptStoreV1 } from "../repositories/snapshot-certification-attempts-v1.js";
import {
  ArtifactBackedModernSnapshotSourceEvidenceAuthorityV1,
  CapturedSourceMaterialPublisherV1
} from "./artifact-backed-modern-source-evidence-v1.js";
import {
  ModernSnapshotCaptureServiceV1,
  type GovernedSourceDeliveryCaptureAuthorityV1,
  type ModernSnapshotExtractionReceiptV1,
  type TrustedModernSnapshotExtractionAuthorityV1
} from "./modern-snapshot-capture.js";
import {
  ModernSnapshotCertificationService,
  type ModernMappingDimensionAuthorityV1
} from "./modern-snapshot-certification.js";

/**
 * Explicit dependency set for the production-shaped modern capture and
 * certification vertical.  This factory intentionally has no defaults:
 * callers must bring every authority and durable store required to prove
 * Bronze capture and Gold certification lineage.
 *
 * The shared receipt repository remains an injected port because its durable
 * PostgreSQL implementation is environment-owned.  All local pilot state in
 * this composition is nevertheless required to be append-only SQLite rather
 * than an in-memory fixture.
 */
export interface ModernSnapshotRuntimeV1Dependencies {
  /** The one tenant this runtime instance is permitted to serve. */
  readonly tenantId: string;
  readonly sourceDeliveries: GovernedSourceDeliveryCaptureAuthorityV1;
  readonly extraction: TrustedModernSnapshotExtractionAuthorityV1;
  readonly receipts: ImmutableRepositoryPort<ModernSnapshotExtractionReceiptV1>;
  readonly snapshots: GovernedDatasetSnapshotCommitRepositoryV1;
  readonly certifiedEvidenceV2: SqliteCertifiedSnapshotEvidenceV2Repository;
  readonly attempts: SqliteSnapshotCertificationAttemptStoreV1;
  readonly artifactStaging: SqliteCertificationArtifactStagingStoreV1;
  readonly sourceMaterial: SqliteCapturedSourceMaterialStoreV1;
  readonly lifecycleDefinitions: LifecycleSnapshotCertificationDefinitionAuthorityV1;
  readonly certificationRuntime: CertificationRuntimeAuthorityFactoryV1;
  readonly dimensions: ModernMappingDimensionAuthorityV1;
  readonly artifacts: ArtifactStore;
  /** Server-owned clock used only to mint the immutable certification attempt. */
  readonly now: () => string;
}

export interface ModernSnapshotRuntimeV1 {
  readonly tenantId: string;
  readonly capture: ModernSnapshotCaptureServiceV1;
  readonly certification: ModernSnapshotCertificationService;
}

export type ModernSnapshotRuntimeV1ErrorCode = "INVALID_CONFIGURATION" | "TENANT_MISMATCH";

export class ModernSnapshotRuntimeV1Error extends Error {
  constructor(readonly code: ModernSnapshotRuntimeV1ErrorCode, message: string) {
    super(message);
    this.name = "ModernSnapshotRuntimeV1Error";
  }
}

/**
 * Compose the only production-shaped modern snapshot path.  It cannot fall
 * back to caller-selected definitions, mutable runtime resolution, V1
 * certification evidence, or unpersisted source rows.
 *
 * Ownership stays with the caller: this function never closes or replaces
 * supplied dependencies, which makes lifecycle management explicit at the
 * environment boundary.
 */
export function composeModernSnapshotRuntimeV1(
  dependenciesValue: ModernSnapshotRuntimeV1Dependencies
): ModernSnapshotRuntimeV1 {
  const dependencies = validateDependencies(dependenciesValue);
  const sourceMaterial = new CapturedSourceMaterialPublisherV1({
    artifacts: dependencies.artifacts,
    material: dependencies.sourceMaterial
  });
  const sourceEvidence = new ArtifactBackedModernSnapshotSourceEvidenceAuthorityV1({
    artifacts: dependencies.artifacts,
    material: dependencies.sourceMaterial
  });
  const capture = new ModernSnapshotCaptureServiceV1({
    sourceDeliveries: tenantFencedSourceDeliveries(dependencies.tenantId, dependencies.sourceDeliveries),
    extraction: tenantFencedExtraction(dependencies.tenantId, dependencies.extraction),
    receipts: tenantFencedImmutableRepository(dependencies.tenantId, dependencies.receipts, "extraction receipt"),
    snapshots: tenantFencedSnapshotRepository(dependencies.tenantId, dependencies.snapshots),
    sourceMaterial,
    now: dependencies.now
  });
  const certification = new ModernSnapshotCertificationService({
    snapshots: tenantFencedImmutableRepository(dependencies.tenantId, dependencies.snapshots, "dataset snapshot"),
    receipts: tenantFencedReceiptAuthority(dependencies.tenantId, dependencies.receipts),
    sourceDeliveries: tenantFencedSourceDeliveries(dependencies.tenantId, dependencies.sourceDeliveries),
    certifiedEvidenceV2: tenantFencedRepository(dependencies.tenantId, dependencies.certifiedEvidenceV2, "V2 certification evidence"),
    attempts: dependencies.attempts,
    artifactStaging: dependencies.artifactStaging,
    sourceEvidence,
    lifecycleDefinitions: dependencies.lifecycleDefinitions,
    runtime: dependencies.certificationRuntime.forCertification({
      tenantId: dependencies.tenantId,
      // This resolver is never used in lifecycle mode. The per-attempt factory
      // below is the authority used by certification, so a static resolver is
      // deliberately unavailable rather than a mutable fallback.
      certifiedAt: "1970-01-01T00:00:00.000Z"
    }),
    certificationRuntime: dependencies.certificationRuntime,
    dimensions: tenantFencedDimensions(dependencies.tenantId, dependencies.dimensions),
    artifacts: dependencies.artifacts,
    now: dependencies.now
  });
  return Object.freeze({ tenantId: dependencies.tenantId, capture, certification });
}

function validateDependencies(value: ModernSnapshotRuntimeV1Dependencies): ModernSnapshotRuntimeV1Dependencies {
  const tenantId = identifier(value?.tenantId, "tenantId");
  requiredMethod(value?.sourceDeliveries, "sourceDeliveries", "resolveGovernedDeliveryForCapture");
  requiredMethod(value?.extraction, "extraction", "extract");
  requiredMethod(value?.receipts, "receipts", "get");
  requiredMethod(value?.receipts, "receipts", "put");
  requiredMethod(value?.snapshots, "snapshots", "get");
  requiredMethod(value?.snapshots, "snapshots", "commitGovernedCapture");
  if (!(value?.certifiedEvidenceV2 instanceof SqliteCertifiedSnapshotEvidenceV2Repository)) {
    invalid("A durable SqliteCertifiedSnapshotEvidenceV2Repository is required");
  }
  if (!(value?.attempts instanceof SqliteSnapshotCertificationAttemptStoreV1)) {
    invalid("A durable SqliteSnapshotCertificationAttemptStoreV1 is required");
  }
  if (!(value?.artifactStaging instanceof SqliteCertificationArtifactStagingStoreV1)) {
    invalid("A durable SqliteCertificationArtifactStagingStoreV1 is required");
  }
  if (!(value?.sourceMaterial instanceof SqliteCapturedSourceMaterialStoreV1)) {
    invalid("A durable SqliteCapturedSourceMaterialStoreV1 is required");
  }
  if (!(value?.lifecycleDefinitions instanceof LifecycleSnapshotCertificationDefinitionAuthorityV1)) {
    invalid("LifecycleSnapshotCertificationDefinitionAuthorityV1 is required; legacy definitions are forbidden");
  }
  if (!(value?.certificationRuntime instanceof CertificationRuntimeAuthorityFactoryV1)) {
    invalid("CertificationRuntimeAuthorityFactoryV1 is required");
  }
  requiredMethod(value?.dimensions, "dimensions", "resolveForMapping");
  if (!(value?.artifacts instanceof ArtifactStore)) invalid("An encrypted ArtifactStore is required");
  if (typeof value?.now !== "function") invalid("A server-owned now function is required");
  return Object.freeze({ ...value, tenantId });
}

function tenantFencedSourceDeliveries(
  tenantId: string,
  authority: GovernedSourceDeliveryCaptureAuthorityV1
): GovernedSourceDeliveryCaptureAuthorityV1 {
  const fenced: GovernedSourceDeliveryCaptureAuthorityV1 = {
    async resolveGovernedDeliveryForCapture(input) {
      assertTenant(tenantId, input.tenantId, "source delivery");
      const resolved = await authority.resolveGovernedDeliveryForCapture(input);
      if (resolved !== undefined && resolved.delivery.tenantId !== tenantId) {
        mismatch("Source-delivery authority returned a cross-tenant delivery");
      }
      return resolved;
    }
  };
  return Object.freeze(fenced);
}

function tenantFencedExtraction(
  tenantId: string,
  authority: TrustedModernSnapshotExtractionAuthorityV1
): TrustedModernSnapshotExtractionAuthorityV1 {
  const fenced: TrustedModernSnapshotExtractionAuthorityV1 = {
    async extract(input) {
      assertTenant(tenantId, input.tenantId, "extraction");
      const result = await authority.extract(input);
      assertTenant(tenantId, result.tenantId, "extraction result");
      return result;
    }
  };
  return Object.freeze(fenced);
}

function tenantFencedReceiptAuthority(
  tenantId: string,
  repository: Pick<ImmutableRepositoryPort<ModernSnapshotExtractionReceiptV1>, "get">
): { get(tenantId: string, receiptId: string): Promise<ModernSnapshotExtractionReceiptV1 | undefined> } {
  const fenced = {
    async get(requestTenantId: string, receiptId: string) {
      assertTenant(tenantId, requestTenantId, "extraction receipt");
      const receipt = await repository.get(requestTenantId, receiptId);
      if (receipt !== undefined) assertTenant(tenantId, receipt.tenantId, "extraction receipt result");
      return receipt;
    }
  };
  return Object.freeze(fenced);
}

function tenantFencedRepository<T extends { readonly tenantId: string }>(
  tenantId: string,
  repository: Pick<ImmutableRepositoryPort<T>, "get" | "put">,
  label: string
): Pick<ImmutableRepositoryPort<T>, "get" | "put"> {
  return Object.freeze({
    async get(requestTenantId: string, recordId: string): Promise<T | undefined> {
      assertTenant(tenantId, requestTenantId, label);
      const record = await repository.get(requestTenantId, recordId);
      if (record !== undefined) assertTenant(tenantId, record.tenantId, `${label} result`);
      return record;
    },
    async put(record: T, context) {
      assertTenant(tenantId, record.tenantId, label);
      assertTenant(tenantId, context.tenantId, `${label} write`);
      const result = await repository.put(record, context);
      assertTenant(tenantId, result.record.tenantId, `${label} write result`);
      return result;
    }
  });
}

function tenantFencedImmutableRepository<T extends { readonly tenantId: string }>(
  tenantId: string,
  repository: ImmutableRepositoryPort<T>,
  label: string
): ImmutableRepositoryPort<T> {
  const standard = tenantFencedRepository(tenantId, repository, label);
  const fenced: ImmutableRepositoryPort<T> = {
    ...standard,
    async list(requestTenantId, page) {
      assertTenant(tenantId, requestTenantId, `${label} list`);
      const result = await repository.list(requestTenantId, page);
      for (const record of result.items) assertTenant(tenantId, record.tenantId, `${label} list result`);
      return result;
    }
  };
  return Object.freeze(fenced);
}

function tenantFencedSnapshotRepository(
  tenantId: string,
  repository: GovernedDatasetSnapshotCommitRepositoryV1
): GovernedDatasetSnapshotCommitRepositoryV1 {
  const standard = tenantFencedImmutableRepository<DatasetSnapshotV2>(tenantId, repository, "dataset snapshot");
  const fenced: GovernedDatasetSnapshotCommitRepositoryV1 = {
    ...standard,
    async commitGovernedCapture(snapshot, lineage, context) {
      assertTenant(tenantId, snapshot.tenantId, "dataset snapshot");
      assertTenant(tenantId, lineage.tenantId, "dataset snapshot lineage");
      assertTenant(tenantId, context.tenantId, "dataset snapshot write");
      const result = await repository.commitGovernedCapture(snapshot, lineage, context);
      assertTenant(tenantId, result.record.tenantId, "dataset snapshot write result");
      return result;
    }
  };
  return Object.freeze(fenced);
}

function tenantFencedDimensions(
  tenantId: string,
  authority: ModernMappingDimensionAuthorityV1
): ModernMappingDimensionAuthorityV1 {
  const fenced: ModernMappingDimensionAuthorityV1 = {
    async resolveForMapping(input) {
      assertTenant(tenantId, input.tenantId, "mapping dimensions");
      return authority.resolveForMapping(input);
    }
  };
  return Object.freeze(fenced);
}

function identifier(value: unknown, label: string): string {
  try {
    return parseWithSchema(IdentifierSchema, value, label);
  } catch {
    invalid(`${label} is invalid`);
  }
}

function requiredMethod(value: unknown, label: string, method: string): void {
  if (!value || typeof value !== "object" || typeof (value as Record<string, unknown>)[method] !== "function") {
    invalid(`${label}.${method} is required`);
  }
}

function assertTenant(expected: string, actual: unknown, label: string): void {
  if (actual !== expected) mismatch(`${label} crossed the configured tenant boundary`);
}

function invalid(message: string): never {
  throw new ModernSnapshotRuntimeV1Error("INVALID_CONFIGURATION", message);
}

function mismatch(message: string): never {
  throw new ModernSnapshotRuntimeV1Error("TENANT_MISMATCH", message);
}
