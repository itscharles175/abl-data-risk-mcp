import {
  canonicalHash,
  canonicalJson,
  deepFreeze,
  parseDatasetSnapshotV2,
  parseGovernedDatasetScopeBindingV1,
  parseSourceContractV1,
  createDatasetSnapshotV2,
  type DatasetSnapshotV2,
  type DatasetSnapshotV2Input,
  type GovernedDatasetScopeBindingV1,
  type Sha256Hash,
  type SourceContractV1
} from "../contracts/index.js";
import type { CapturedSourceSectionArtifactV1Input } from "../contracts/captured-source-section-artifact-v1.js";
import {
  parseGovernedSourceDeliveryRecordV1,
  type GovernedSourceDeliveryRecordV1,
  type GovernedSourceDeliveryResolutionV1
} from "../contracts/source-delivery-authority-v1.js";
import {
  createGovernedSnapshotCommitLineageV1,
  type GovernedDatasetSnapshotCommitRepositoryV1
} from "../repositories/governed-snapshot-commit.js";
import type { ImmutableRepositoryPort } from "../repositories/ports.js";
import { RepositoryError } from "../repositories/ports.js";

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HASH = /^sha256:[a-f0-9]{64}$/;
const CAPTURE_REQUEST_KEYS = new Set(["deliveryId", "sourceContractId"]);
const ACTOR_KEYS = new Set(["actorId", "authority", "identitySource", "tenantId"]);
const EXTRACTION_KEYS = new Set([
  "asOfDate",
  "byteCount",
  "columnCount",
  "correction",
  "datasetId",
  "deliveryId",
  "elapsedMs",
  "facilityId",
  "hashes",
  "knowledge",
  "rowCount",
  "sourceSections",
  "sections",
  "snapshotId",
  "tenantId",
  "watermark"
]);
const EXTRACTION_REQUIRED_KEYS = new Set(
  [...EXTRACTION_KEYS].filter((key) => key !== "sourceSections")
);
const EXTRACTION_HASH_KEYS = new Set([
  "catalogHash",
  "contentHash",
  "parserHash",
  "profileHash",
  "schemaHash"
]);
const EXTRACTION_KNOWLEDGE_KEYS = new Set(["extractedAt", "receivedAt", "sourceObservedAt"]);
const SOURCE_REFERENCE_KEYS = new Set(["revision", "sourceContractHash", "sourceContractId"]);
const BINDING_REFERENCE_KEYS = new Set(["bindingHash", "bindingId", "revision"]);
const DELIVERY_REFERENCE_KEYS = new Set([
  "deliveryHash",
  "deliveryId",
  "deliveryRevision",
  "locatorHash",
  "sourceVersionHash"
]);
const RECEIPT_KEYS = new Set([
  "asOfDate",
  "byteCount",
  "capturedBy",
  "columnCount",
  "contractVersion",
  "correction",
  "datasetId",
  "delivery",
  "deliveryId",
  "elapsedMs",
  "facilityId",
  "hashes",
  "immutableSourceVersion",
  "knowledge",
  "receiptHash",
  "receiptId",
  "rowCount",
  "scopeBinding",
  "sections",
  "snapshotId",
  "sourceContract",
  "sourceDelivery",
  "sourceLocator",
  "tenantId",
  "watermark"
]);
const RECEIPT_REQUIRED_KEYS = new Set(
  [...RECEIPT_KEYS].filter((key) => key !== "immutableSourceVersion")
);

export interface TrustedModernSnapshotCaptureActorV1 {
  readonly tenantId: string;
  readonly actorId: string;
  readonly authority: "platform_operator";
  readonly identitySource: "server_derived";
}

/** Public/operator input. Source data, SQL, paths, hashes, credentials and actor identity are forbidden. */
export interface ModernSnapshotCaptureRequestV1 {
  readonly sourceContractId: string;
  readonly deliveryId: string;
}

interface ResolvedModernSnapshotCaptureRequestV1 extends ModernSnapshotCaptureRequestV1 {
  readonly snapshotId: string;
}

export interface ActivatedSourceContractAuthorityV1 {
  resolveActivatedSourceContract(input: {
    readonly tenantId: string;
    readonly sourceContractId: string;
  }): Promise<SourceContractV1 | undefined>;
}

export interface GovernedDatasetScopeBindingAuthorityV1 {
  resolveGovernedDatasetScopeBinding(input: {
    readonly tenantId: string;
    readonly sourceContract: SourceContractV1;
    readonly deliveryId: string;
  }): Promise<GovernedDatasetScopeBindingV1 | undefined>;
}

/** Resolves the exact active source contract, facility binding, and immutable delivery in one trusted call. */
export interface GovernedSourceDeliveryCaptureAuthorityV1 {
  resolveGovernedDeliveryForCapture(input: {
    readonly tenantId: string;
    readonly sourceContractId: string;
    readonly deliveryId: string;
  }): Promise<GovernedSourceDeliveryResolutionV1 | undefined>;
}

export interface TrustedModernSnapshotExtractionLimitsV1 {
  readonly maximumRows: number;
  readonly maximumColumns: number;
  readonly maximumBytes: number;
  readonly timeoutMs: number;
  readonly cursorRows: number;
}

export interface TrustedModernSnapshotExtractionV1 {
  readonly tenantId: string;
  readonly datasetId: string;
  readonly facilityId: string;
  readonly snapshotId: string;
  readonly deliveryId: string;
  readonly asOfDate: string;
  readonly knowledge: Omit<DatasetSnapshotV2Input["knowledge"], "persistedAt">;
  readonly watermark: DatasetSnapshotV2Input["watermark"];
  readonly hashes: {
    readonly contentHash: Sha256Hash;
    readonly schemaHash: Sha256Hash;
    readonly profileHash: Sha256Hash;
    readonly catalogHash: Sha256Hash;
    readonly parserHash: Sha256Hash;
  };
  readonly rowCount: number;
  readonly columnCount: number;
  readonly byteCount: number;
  readonly elapsedMs: number;
  readonly sections: DatasetSnapshotV2Input["sections"];
  readonly correction: DatasetSnapshotV2Input["correction"];
  /** Exact scalar rows retained only inside a trusted capture boundary. */
  readonly sourceSections?: readonly Readonly<{
    readonly sectionId: string;
    readonly records: readonly Readonly<Record<string, string | boolean | number | null>>[];
  }>[];
}

export interface TrustedModernSnapshotExtractionAuthorityV1 {
  extract(input: {
    readonly tenantId: string;
    readonly actorId: string;
    readonly datasetId: string;
    readonly facilityId: string;
    readonly snapshotId: string;
    readonly deliveryId: string;
    readonly sourceContract: SourceContractV1;
    readonly scopeBinding: GovernedDatasetScopeBindingV1;
    readonly sourceDelivery: GovernedSourceDeliveryRecordV1;
    readonly limits: TrustedModernSnapshotExtractionLimitsV1;
    readonly signal?: AbortSignal;
  }): Promise<TrustedModernSnapshotExtractionV1>;
}

export interface ModernSnapshotExtractionReceiptV1 {
  readonly contractVersion: 1;
  readonly tenantId: string;
  readonly receiptId: string;
  readonly snapshotId: string;
  readonly deliveryId: string;
  readonly datasetId: string;
  readonly facilityId: string;
  readonly sourceContract: DatasetSnapshotV2Input["sourceContract"];
  readonly scopeBinding: {
    readonly bindingId: string;
    readonly revision: number;
    readonly bindingHash: Sha256Hash;
  };
  readonly sourceDelivery: {
    readonly deliveryId: string;
    readonly deliveryRevision: number;
    readonly deliveryHash: Sha256Hash;
    readonly locatorHash: Sha256Hash;
    readonly sourceVersionHash: Sha256Hash;
  };
  readonly delivery: SourceContractV1["delivery"];
  readonly sourceLocator: string;
  readonly immutableSourceVersion?: string;
  readonly asOfDate: string;
  readonly knowledge: DatasetSnapshotV2Input["knowledge"];
  readonly watermark: DatasetSnapshotV2Input["watermark"];
  readonly hashes: TrustedModernSnapshotExtractionV1["hashes"];
  readonly rowCount: number;
  readonly columnCount: number;
  readonly byteCount: number;
  readonly elapsedMs: number;
  readonly sections: DatasetSnapshotV2Input["sections"];
  readonly correction: DatasetSnapshotV2Input["correction"];
  readonly capturedBy: string;
  readonly receiptHash: Sha256Hash;
}

export interface ModernSnapshotCaptureResultV1 {
  readonly receipt: ModernSnapshotExtractionReceiptV1;
  readonly snapshot: DatasetSnapshotV2;
  readonly receiptReplayed: boolean;
  readonly snapshotReplayed: boolean;
}

/** Optional until a composed runtime makes durable source-material mandatory. */
export interface CapturedSourceMaterialCapturePortV1 {
  publish(input: CapturedSourceSectionArtifactV1Input): Promise<unknown>;
  /**
   * Returns the immutable pre-receipt capture identity from any already
   * materialized expected section. The retry must reconstruct that identity
   * exactly before it can fill a crash-interrupted partial section set.
   */
  resolveReplayIdentity?(input: {
    readonly tenantId: string;
    readonly snapshotId: string;
    readonly sourceContract: DatasetSnapshotV2Input["sourceContract"];
    readonly sectionIds: readonly string[];
  }): Promise<{
    readonly snapshotHash: Sha256Hash;
    readonly extractionReceiptHash: Sha256Hash;
    readonly capturedAt: string;
  } | undefined>;
}

export type ModernSnapshotCaptureErrorCode =
  | "INVALID_REQUEST"
  | "OPERATOR_REQUIRED"
  | "SOURCE_CONTRACT_NOT_FOUND"
  | "SOURCE_CONTRACT_NOT_ACTIVE"
  | "SCOPE_BINDING_NOT_FOUND"
  | "SCOPE_BINDING_INVALID"
  | "DELIVERY_NOT_ALLOWED"
  | "EXTRACTION_SUBSTITUTION"
  | "EXTRACTION_LIMIT_EXCEEDED"
  | "REQUIRED_SECTION_MISSING"
  | "EVIDENCE_INVALID"
  | "CORRECTION_LINEAGE_INVALID";

export class ModernSnapshotCaptureError extends Error {
  constructor(readonly code: ModernSnapshotCaptureErrorCode, message: string) {
    super(message);
    this.name = "ModernSnapshotCaptureError";
  }
}

export class ModernSnapshotCaptureServiceV1 {
  readonly #sourceDeliveries: GovernedSourceDeliveryCaptureAuthorityV1;
  readonly #extraction: TrustedModernSnapshotExtractionAuthorityV1;
  readonly #receipts: ImmutableRepositoryPort<ModernSnapshotExtractionReceiptV1>;
  readonly #snapshots: GovernedDatasetSnapshotCommitRepositoryV1;
  readonly #sourceMaterial: CapturedSourceMaterialCapturePortV1 | undefined;
  readonly #now: () => string;

  constructor(input: {
    readonly sourceDeliveries: GovernedSourceDeliveryCaptureAuthorityV1;
    readonly extraction: TrustedModernSnapshotExtractionAuthorityV1;
    readonly receipts: ImmutableRepositoryPort<ModernSnapshotExtractionReceiptV1>;
    readonly snapshots: GovernedDatasetSnapshotCommitRepositoryV1;
    readonly sourceMaterial?: CapturedSourceMaterialCapturePortV1;
    readonly now?: () => string;
  }) {
    this.#sourceDeliveries = input.sourceDeliveries;
    this.#extraction = input.extraction;
    this.#receipts = input.receipts;
    this.#snapshots = input.snapshots;
    this.#sourceMaterial = input.sourceMaterial;
    this.#now = input.now ?? (() => new Date().toISOString());
  }

  async capture(
    actorValue: TrustedModernSnapshotCaptureActorV1,
    requestValue: ModernSnapshotCaptureRequestV1,
    options: { readonly signal?: AbortSignal } = {}
  ): Promise<ModernSnapshotCaptureResultV1> {
    const actor = validateActor(actorValue);
    const publicRequest = validateCaptureRequest(requestValue);
    const request = deepFreeze({
      ...publicRequest,
      snapshotId: derivedSnapshotId(actor.tenantId, publicRequest)
    });
    if (options.signal?.aborted) invalid("EVIDENCE_INVALID", "Snapshot capture was cancelled");

    const replay = await this.#recoverOrReplay(actor, request);
    if (replay !== undefined) return replay;

    const resolutionValue = await this.#sourceDeliveries.resolveGovernedDeliveryForCapture({
      tenantId: actor.tenantId,
      sourceContractId: request.sourceContractId,
      deliveryId: request.deliveryId
    });
    if (resolutionValue === undefined) {
      invalid("SOURCE_CONTRACT_NOT_FOUND", "The active governed source delivery was not found");
    }
    const resolution = validateDeliveryResolution(resolutionValue);
    const source = resolution.sourceContract;
    const binding = resolution.scopeBinding;
    const sourceDelivery = resolution.delivery;
    const sourceReference = sourceIdentity(source);
    if (
      source.tenantId !== actor.tenantId ||
      source.sourceContractId !== request.sourceContractId ||
      sourceDelivery.tenantId !== actor.tenantId ||
      sourceDelivery.deliveryId !== request.deliveryId ||
      sourceDelivery.status !== "usable"
    ) invalid("EXTRACTION_SUBSTITUTION", "Delivery authority substituted governed capture identity");
    if (source.status !== "active") {
      invalid("SOURCE_CONTRACT_NOT_ACTIVE", "Source contract is not active");
    }
    if (source.delivery.mode !== "postgresql_pull" && source.delivery.mode !== "object_storage") {
      invalid("DELIVERY_NOT_ALLOWED", "Modern capture accepts PostgreSQL or immutable object delivery only");
    }

    if (
      binding.tenantId !== actor.tenantId ||
      binding.scope.scopeType !== "facility" ||
      canonicalJson(binding.sourceContract) !== canonicalJson(sourceReference) ||
      canonicalJson(sourceDelivery.sourceContract) !== canonicalJson(sourceReference) ||
      canonicalJson(sourceDelivery.scopeBinding) !== canonicalJson(bindingIdentity(binding)) ||
      sourceDelivery.datasetId !== binding.datasetId ||
      sourceDelivery.facilityId !== binding.scope.scopeId
    ) {
      invalid("SCOPE_BINDING_INVALID", "Delivery did not preserve dataset, facility, binding, and source identity");
    }

    const limits = Object.freeze({
      maximumRows: source.extractionPolicy.maximumRows,
      maximumColumns: source.extractionPolicy.maximumColumns,
      maximumBytes: source.extractionPolicy.maximumBytes,
      timeoutMs: source.extractionPolicy.timeoutMs,
      cursorRows: source.extractionPolicy.cursorRows
    });
    const extractionValue = await this.#extraction.extract({
      tenantId: actor.tenantId,
      actorId: actor.actorId,
      datasetId: binding.datasetId,
      facilityId: binding.scope.scopeId,
      snapshotId: request.snapshotId,
      deliveryId: request.deliveryId,
      sourceContract: source,
      scopeBinding: binding,
      sourceDelivery,
      limits,
      ...(options.signal === undefined ? {} : { signal: options.signal })
    });
    if (options.signal?.aborted) invalid("EVIDENCE_INVALID", "Snapshot capture was cancelled");
    const extraction = validateExtractionEvidence(extractionValue);
    assertExtractionBindings(extraction, actor, request, binding);
    assertEffective(source.effectiveFrom, source.effectiveTo, extraction.asOfDate, "source contract");
    assertEffective(binding.effectiveFrom, binding.effectiveTo, extraction.asOfDate, "dataset binding");
    assertExtractionPolicy(extraction, source);
    assertDeliveryExtraction(extraction, sourceDelivery);

    const replayIdentity = await this.#resolveMaterialReplayIdentity(extraction, actor, request, sourceReference);
    const persistedAt = replayIdentity?.capturedAt ?? this.#now();
    if (
      source.approvedAt === undefined ||
      source.approvedAt > extraction.knowledge.extractedAt ||
      extraction.asOfDate > persistedAt.slice(0, 10)
    ) {
      invalid(
        "EVIDENCE_INVALID",
        "Capture cannot precede source approval or attest a future snapshot period"
      );
    }
    const receipt = createReceipt(extraction, resolution, actor.actorId, persistedAt);
    const snapshot = evidence(() =>
      createDatasetSnapshotV2({
        contractVersion: 2,
        tenantId: actor.tenantId,
        snapshotId: request.snapshotId,
        sourceContract: sourceReference,
        delivery: source.delivery,
        sourceLocator: governedSourceLocator(sourceDelivery),
        ...(immutableSourceVersion(sourceDelivery) === undefined
          ? {}
          : { immutableSourceVersion: immutableSourceVersion(sourceDelivery) }),
        asOfDate: extraction.asOfDate,
        knowledge: receipt.knowledge,
        watermark: extraction.watermark,
        hashes: {
          contentHash: extraction.hashes.contentHash,
          schemaHash: extraction.hashes.schemaHash,
          catalogHash: extraction.hashes.catalogHash,
          parserHash: extraction.hashes.parserHash,
          extractionHash: receipt.receiptHash
        },
        rowCount: extraction.rowCount,
        byteCount: extraction.byteCount,
        sections: extraction.sections,
        correction: extraction.correction,
        createdBy: actor.actorId
      })
    );
    if (
      replayIdentity !== undefined &&
      (snapshot.snapshotHash !== replayIdentity.snapshotHash ||
        receipt.receiptHash !== replayIdentity.extractionReceiptHash)
    ) {
      invalid(
        "EVIDENCE_INVALID",
        "Interrupted capture retry no longer reconstructs its immutable source-material lineage"
      );
    }
    await this.#persistSourceMaterial(extraction, snapshot, receipt);
    const receiptResult = await this.#receipts.put(receipt, {
      tenantId: actor.tenantId,
      actorId: actor.actorId,
      idempotencyKey: `modern-capture:${request.snapshotId}:receipt`
    });
    assertSameRecord(receipt, receiptResult.record, "Extraction receipt repository changed immutable evidence");
    const snapshotResult = await commitSnapshot(
      this.#snapshots,
      snapshot,
      receipt,
      actor.actorId
    );
    const storedSnapshot = evidence(() => parseDatasetSnapshotV2(snapshotResult.record));
    assertSameRecord(snapshot, storedSnapshot, "Snapshot repository changed immutable evidence");
    return deepFreeze({
      receipt: receiptResult.record,
      snapshot: storedSnapshot,
      receiptReplayed: receiptResult.replayed,
      snapshotReplayed: snapshotResult.replayed
    });
  }

  async #persistSourceMaterial(
    extraction: TrustedModernSnapshotExtractionV1,
    snapshot: DatasetSnapshotV2,
    receipt: ModernSnapshotExtractionReceiptV1
  ): Promise<void> {
    if (this.#sourceMaterial === undefined) return;
    const supplied = extraction.sourceSections;
    if (supplied === undefined) {
      invalid("EVIDENCE_INVALID", "Composed capture requires exact source-section records");
    }
    const bySection = new Map<string, readonly Readonly<Record<string, string | boolean | number | null>>[]>();
    for (const section of supplied) {
      if (
        section === null ||
        typeof section !== "object" ||
        Array.isArray(section) ||
        Object.keys(section).length !== 2 ||
        !("sectionId" in section) ||
        !("records" in section) ||
        typeof section.sectionId !== "string" ||
        !Array.isArray(section.records) ||
        bySection.has(section.sectionId)
      ) {
        invalid("EVIDENCE_INVALID", "Source-section material has an invalid shape");
      }
      bySection.set(section.sectionId, section.records);
    }
    const expected = snapshot.sections.filter((section) => section.present);
    if (bySection.size !== expected.length || expected.some((section) => !bySection.has(section.sectionId))) {
      invalid("EVIDENCE_INVALID", "Source-section material does not cover the captured section set");
    }
    for (const section of expected) {
      const records = bySection.get(section.sectionId)!;
      if (
        records.length !== section.rowCount ||
        section.contentHash === undefined ||
        section.schemaHash === undefined ||
        section.controlPopulationHash === undefined ||
        canonicalHash(records) !== section.controlPopulationHash
      ) {
        invalid("EVIDENCE_INVALID", "Source-section records do not match immutable section controls");
      }
      const input: CapturedSourceSectionArtifactV1Input = {
        contractVersion: 1,
        kind: "captured_source_section",
        tenantId: snapshot.tenantId,
        snapshotId: snapshot.snapshotId,
        snapshotHash: snapshot.snapshotHash,
        extractionReceiptHash: receipt.receiptHash,
        sourceContract: snapshot.sourceContract,
        sectionId: section.sectionId,
        sectionContentHash: section.contentHash,
        sectionSchemaHash: section.schemaHash,
        controlPopulationHash: section.controlPopulationHash,
        rowCount: records.length,
        records: records.map((record) => ({ ...record })),
        capturedAt: receipt.knowledge.persistedAt
      };
      try {
        await this.#sourceMaterial.publish(input);
      } catch {
        invalid("EVIDENCE_INVALID", "Captured source-section material could not be persisted");
      }
    }
  }

  async #resolveMaterialReplayIdentity(
    extraction: TrustedModernSnapshotExtractionV1,
    actor: TrustedModernSnapshotCaptureActorV1,
    request: ResolvedModernSnapshotCaptureRequestV1,
    sourceContract: DatasetSnapshotV2Input["sourceContract"]
  ): Promise<
    | {
        readonly snapshotHash: Sha256Hash;
        readonly extractionReceiptHash: Sha256Hash;
        readonly capturedAt: string;
      }
    | undefined
  > {
    const resolve = this.#sourceMaterial?.resolveReplayIdentity;
    if (resolve === undefined) return undefined;
    const sectionIds = extraction.sections
      .filter((section) => section.present)
      .map((section) => section.sectionId)
      .sort();
    try {
      return await resolve({
        tenantId: actor.tenantId,
        snapshotId: request.snapshotId,
        sourceContract,
        sectionIds
      });
    } catch {
      invalid("EVIDENCE_INVALID", "Captured source material could not recover an interrupted capture identity");
    }
  }

  async #recoverOrReplay(
    actor: TrustedModernSnapshotCaptureActorV1,
    request: ResolvedModernSnapshotCaptureRequestV1
  ): Promise<ModernSnapshotCaptureResultV1 | undefined> {
    const [receiptValue, snapshotValue] = await Promise.all([
      this.#receipts.get(actor.tenantId, modernSnapshotExtractionReceiptIdV1(request.snapshotId)),
      this.#snapshots.get(actor.tenantId, request.snapshotId)
    ]);
    if (receiptValue === undefined && snapshotValue === undefined) return undefined;
    if (receiptValue === undefined) {
      invalid(
        "EVIDENCE_INVALID",
        "Snapshot exists without its immutable extraction receipt"
      );
    }
    const receipt = parseModernSnapshotExtractionReceiptV1(receiptValue);
    assertReceiptRequest(receipt, actor, request);
    const expectedSnapshot = snapshotFromReceipt(receipt);
    if (snapshotValue !== undefined) {
      const snapshot = evidence(() => parseDatasetSnapshotV2(snapshotValue));
      assertSameRecord(
        expectedSnapshot,
        snapshot,
        "Replayed snapshot no longer matches its immutable extraction receipt"
      );
      return deepFreeze({
        receipt,
        snapshot,
        receiptReplayed: true,
        snapshotReplayed: true
      });
    }
    const recovered = await commitSnapshot(
      this.#snapshots,
      expectedSnapshot,
      receipt,
      actor.actorId
    );
    const snapshot = evidence(() => parseDatasetSnapshotV2(recovered.record));
    assertSameRecord(
      expectedSnapshot,
      snapshot,
      "Recovered snapshot repository changed immutable receipt evidence"
    );
    return deepFreeze({
      receipt,
      snapshot,
      receiptReplayed: true,
      snapshotReplayed: recovered.replayed
    });
  }

}

function validateActor(value: TrustedModernSnapshotCaptureActorV1): TrustedModernSnapshotCaptureActorV1 {
  assertPlainObject(value, "trusted actor", "OPERATOR_REQUIRED");
  assertExactKeys(value, ACTOR_KEYS, "trusted actor", "OPERATOR_REQUIRED");
  identifier(value.tenantId, "actor tenantId", "OPERATOR_REQUIRED");
  identifier(value.actorId, "actor actorId", "OPERATOR_REQUIRED");
  if (value.authority !== "platform_operator" || value.identitySource !== "server_derived") {
    invalid("OPERATOR_REQUIRED", "Capture requires server-derived platform-operator identity");
  }
  return value;
}

function validateCaptureRequest(value: ModernSnapshotCaptureRequestV1): ModernSnapshotCaptureRequestV1 {
  assertPlainObject(value, "capture request", "INVALID_REQUEST");
  assertExactKeys(value, CAPTURE_REQUEST_KEYS, "capture request", "INVALID_REQUEST");
  identifier(value.sourceContractId, "sourceContractId", "INVALID_REQUEST");
  identifier(value.deliveryId, "deliveryId", "INVALID_REQUEST");
  return value;
}

function derivedSnapshotId(
  tenantId: string,
  request: ModernSnapshotCaptureRequestV1
): string {
  return `snapshot-${canonicalHash({
    contractVersion: 1,
    tenantId,
    sourceContractId: request.sourceContractId,
    deliveryId: request.deliveryId
  }).slice("sha256:".length, "sha256:".length + 32)}`;
}

function validateExtractionEvidence(
  value: TrustedModernSnapshotExtractionV1
): TrustedModernSnapshotExtractionV1 {
  assertPlainObject(value, "trusted extraction evidence", "EVIDENCE_INVALID");
  assertAllowedKeys(
    value,
    EXTRACTION_KEYS,
    EXTRACTION_REQUIRED_KEYS,
    "trusted extraction evidence",
    "EVIDENCE_INVALID"
  );
  assertPlainObject(value.hashes, "extraction hashes", "EVIDENCE_INVALID");
  assertExactKeys(value.hashes, EXTRACTION_HASH_KEYS, "extraction hashes", "EVIDENCE_INVALID");
  for (const [name, hash] of Object.entries(value.hashes)) assertHash(hash, name);
  assertPlainObject(value.knowledge, "extraction knowledge", "EVIDENCE_INVALID");
  assertExactKeys(value.knowledge, EXTRACTION_KNOWLEDGE_KEYS, "extraction knowledge", "EVIDENCE_INVALID");
  identifier(value.tenantId, "extraction tenantId", "EVIDENCE_INVALID");
  identifier(value.datasetId, "extraction datasetId", "EVIDENCE_INVALID");
  identifier(value.facilityId, "extraction facilityId", "EVIDENCE_INVALID");
  identifier(value.snapshotId, "extraction snapshotId", "EVIDENCE_INVALID");
  identifier(value.deliveryId, "extraction deliveryId", "EVIDENCE_INVALID");
  boundedInteger(value.rowCount, "rowCount", 0, 10_000_000, "EVIDENCE_INVALID");
  boundedInteger(value.columnCount, "columnCount", 1, 10_000, "EVIDENCE_INVALID");
  boundedInteger(value.byteCount, "byteCount", 0, 10_000_000_000, "EVIDENCE_INVALID");
  boundedInteger(value.elapsedMs, "elapsedMs", 0, 3_600_000, "EVIDENCE_INVALID");
  return value;
}

function assertExtractionBindings(
  extraction: TrustedModernSnapshotExtractionV1,
  actor: TrustedModernSnapshotCaptureActorV1,
  request: ResolvedModernSnapshotCaptureRequestV1,
  binding: GovernedDatasetScopeBindingV1
): void {
  if (
    extraction.tenantId !== actor.tenantId ||
    extraction.datasetId !== binding.datasetId ||
    extraction.facilityId !== binding.scope.scopeId ||
    extraction.snapshotId !== request.snapshotId ||
    extraction.deliveryId !== request.deliveryId
  ) {
    invalid("EXTRACTION_SUBSTITUTION", "Trusted extraction substituted governed capture identity");
  }
}

function assertExtractionPolicy(
  extraction: TrustedModernSnapshotExtractionV1,
  source: SourceContractV1
): void {
  const policy = source.extractionPolicy;
  if (
    extraction.rowCount > policy.maximumRows ||
    extraction.columnCount > policy.maximumColumns ||
    extraction.byteCount > policy.maximumBytes ||
    extraction.elapsedMs > policy.timeoutMs
  ) {
    invalid("EXTRACTION_LIMIT_EXCEEDED", "Trusted extraction exceeded source-contract bounds");
  }
  const minimumColumns = source.schemaPolicy.columns.filter((column) => column.required).length;
  if (extraction.columnCount < minimumColumns) {
    invalid("EVIDENCE_INVALID", "Extraction omitted required governed columns");
  }
  const expectedParserHash = canonicalHash({
    parserId: source.parserPolicy.parserId,
    parserVersion: source.parserPolicy.parserVersion,
    optionsHash: source.parserPolicy.optionsHash
  });
  if (extraction.hashes.parserHash !== expectedParserHash) {
    invalid("EXTRACTION_SUBSTITUTION", "Parser identity did not match the activated source contract");
  }
  if (policy.mode === "full") {
    if (extraction.watermark.mode !== "none") {
      invalid("EVIDENCE_INVALID", "Full extraction cannot claim a watermark range");
    }
  } else if (
    extraction.watermark.mode !== "bounded" ||
    extraction.watermark.field !== policy.watermarkField
  ) {
    invalid("EVIDENCE_INVALID", "Watermark evidence did not match the source contract");
  }

  if (extraction.sections.length !== source.sections.length) {
    invalid("EVIDENCE_INVALID", "Extraction section set did not match the source contract");
  }
  const sections = new Map(extraction.sections.map((section) => [section.sectionId, section]));
  for (const governed of source.sections) {
    const actual = sections.get(governed.sectionId);
    if (actual === undefined || actual.required !== governed.required) {
      invalid("EXTRACTION_SUBSTITUTION", "Extraction section policy was substituted");
    }
    if (governed.required && !actual.present) {
      invalid("REQUIRED_SECTION_MISSING", `Required section '${governed.sectionId}' is absent`);
    }
    if (
      (governed.minimumRows !== undefined && actual.rowCount < governed.minimumRows) ||
      (governed.maximumRows !== undefined && actual.rowCount > governed.maximumRows)
    ) {
      invalid("EXTRACTION_LIMIT_EXCEEDED", `Section '${governed.sectionId}' violated row bounds`);
    }
  }
}

function validateDeliveryResolution(
  value: GovernedSourceDeliveryResolutionV1
): GovernedSourceDeliveryResolutionV1 {
  const delivery = evidence(() => parseGovernedSourceDeliveryRecordV1(value.delivery));
  const sourceContract = evidence(() => parseSourceContractV1(value.sourceContract));
  const scopeBinding = evidence(() => parseGovernedDatasetScopeBindingV1(value.scopeBinding));
  return deepFreeze({ delivery, sourceContract, scopeBinding });
}

function assertDeliveryExtraction(
  extraction: TrustedModernSnapshotExtractionV1,
  delivery: GovernedSourceDeliveryRecordV1
): void {
  if (
    extraction.knowledge.sourceObservedAt !== delivery.sourceObservedAt ||
    extraction.knowledge.extractedAt < delivery.recordedAt ||
    extraction.knowledge.receivedAt < extraction.knowledge.extractedAt
  ) {
    invalid("EXTRACTION_SUBSTITUTION", "Extraction timestamps did not preserve governed delivery time");
  }
  if (
    delivery.locator.mode === "object_storage" &&
    (extraction.hashes.contentHash !== delivery.locator.contentHash ||
      extraction.byteCount !== delivery.locator.byteCount)
  ) {
    invalid("EXTRACTION_SUBSTITUTION", "Object extraction did not match immutable delivery bytes");
  }
}

function sourceDeliveryReference(delivery: GovernedSourceDeliveryRecordV1) {
  const sourceVersionHash = delivery.locator.mode === "postgresql_pull"
    ? delivery.locator.sourceVersionHash
    : delivery.locator.immutableVersionHash;
  return Object.freeze({
    deliveryId: delivery.deliveryId,
    deliveryRevision: delivery.deliveryRevision,
    deliveryHash: delivery.deliveryHash,
    locatorHash: canonicalHash(delivery.locator),
    sourceVersionHash
  });
}

function governedSourceLocator(delivery: GovernedSourceDeliveryRecordV1): string {
  return `governed-delivery:${delivery.deliveryId}@${delivery.deliveryHash}`;
}

function immutableSourceVersion(delivery: GovernedSourceDeliveryRecordV1): string | undefined {
  return delivery.locator.mode === "object_storage"
    ? delivery.locator.immutableVersionHash
    : undefined;
}

function createReceipt(
  extraction: TrustedModernSnapshotExtractionV1,
  resolution: GovernedSourceDeliveryResolutionV1,
  capturedBy: string,
  persistedAt: string
): ModernSnapshotExtractionReceiptV1 {
  const immutableVersion = immutableSourceVersion(resolution.delivery);
  const body = {
    contractVersion: 1 as const,
    tenantId: extraction.tenantId,
    receiptId: modernSnapshotExtractionReceiptIdV1(extraction.snapshotId),
    snapshotId: extraction.snapshotId,
    deliveryId: extraction.deliveryId,
    datasetId: extraction.datasetId,
    facilityId: extraction.facilityId,
    sourceContract: sourceIdentity(resolution.sourceContract),
    scopeBinding: bindingIdentity(resolution.scopeBinding),
    sourceDelivery: sourceDeliveryReference(resolution.delivery),
    delivery: resolution.sourceContract.delivery,
    sourceLocator: governedSourceLocator(resolution.delivery),
    ...(immutableVersion === undefined
      ? {}
      : { immutableSourceVersion: immutableVersion }),
    asOfDate: extraction.asOfDate,
    knowledge: { ...extraction.knowledge, persistedAt },
    watermark: extraction.watermark,
    hashes: extraction.hashes,
    rowCount: extraction.rowCount,
    columnCount: extraction.columnCount,
    byteCount: extraction.byteCount,
    elapsedMs: extraction.elapsedMs,
    sections: extraction.sections,
    correction: extraction.correction,
    capturedBy
  };
  return deepFreeze({ ...body, receiptHash: canonicalHash(body) }) as ModernSnapshotExtractionReceiptV1;
}

export function modernSnapshotExtractionReceiptIdV1(snapshotIdValue: string): string {
  const snapshotId = identifier(snapshotIdValue, "snapshotId", "INVALID_REQUEST");
  return `${snapshotId}:extraction`;
}

export function parseModernSnapshotExtractionReceiptV1(
  value: unknown
): ModernSnapshotExtractionReceiptV1 {
  canonicalJson(value);
  assertPlainObject(value, "extraction receipt", "EVIDENCE_INVALID");
  assertAllowedKeys(
    value,
    RECEIPT_KEYS,
    RECEIPT_REQUIRED_KEYS,
    "extraction receipt",
    "EVIDENCE_INVALID"
  );
  if (value.contractVersion !== 1) {
    invalid("EVIDENCE_INVALID", "Extraction receipt version is invalid");
  }
  assertHash(value.receiptHash, "receiptHash");
  assertPlainObject(value.sourceContract, "receipt source reference", "EVIDENCE_INVALID");
  assertExactKeys(
    value.sourceContract,
    SOURCE_REFERENCE_KEYS,
    "receipt source reference",
    "EVIDENCE_INVALID"
  );
  assertPlainObject(value.scopeBinding, "receipt binding reference", "EVIDENCE_INVALID");
  assertExactKeys(
    value.scopeBinding,
    BINDING_REFERENCE_KEYS,
    "receipt binding reference",
    "EVIDENCE_INVALID"
  );
  assertPlainObject(value.sourceDelivery, "receipt delivery reference", "EVIDENCE_INVALID");
  assertExactKeys(
    value.sourceDelivery,
    DELIVERY_REFERENCE_KEYS,
    "receipt delivery reference",
    "EVIDENCE_INVALID"
  );
  for (const [name, hash] of Object.entries(value.sourceDelivery).filter(([name]) => name.endsWith("Hash"))) {
    assertHash(hash, `sourceDelivery.${name}`);
  }
  boundedInteger(
    value.sourceDelivery.deliveryRevision,
    "sourceDelivery.deliveryRevision",
    1,
    2,
    "EVIDENCE_INVALID"
  );
  identifier(value.tenantId, "receipt tenantId", "EVIDENCE_INVALID");
  const snapshotId = identifier(value.snapshotId, "receipt snapshotId", "EVIDENCE_INVALID");
  identifier(value.deliveryId, "receipt deliveryId", "EVIDENCE_INVALID");
  identifier(value.datasetId, "receipt datasetId", "EVIDENCE_INVALID");
  identifier(value.facilityId, "receipt facilityId", "EVIDENCE_INVALID");
  if (
    value.receiptId !== modernSnapshotExtractionReceiptIdV1(snapshotId) ||
    value.sourceDelivery.deliveryId !== value.deliveryId
  ) {
    invalid("EVIDENCE_INVALID", "Receipt identity does not match its snapshot and delivery lineage");
  }
  const { receiptHash, ...body } = value;
  if (canonicalHash(body) !== receiptHash) {
    invalid("EVIDENCE_INVALID", "Extraction receipt hash did not verify");
  }
  const receipt = deepFreeze(value as unknown as ModernSnapshotExtractionReceiptV1);
  snapshotFromReceipt(receipt);
  return receipt;
}

function assertReceiptRequest(
  receipt: ModernSnapshotExtractionReceiptV1,
  actor: TrustedModernSnapshotCaptureActorV1,
  request: ResolvedModernSnapshotCaptureRequestV1
): void {
  if (
    receipt.tenantId !== actor.tenantId ||
    receipt.capturedBy !== actor.actorId ||
    receipt.receiptId !== modernSnapshotExtractionReceiptIdV1(request.snapshotId) ||
    receipt.snapshotId !== request.snapshotId ||
    receipt.deliveryId !== request.deliveryId ||
    receipt.sourceContract.sourceContractId !== request.sourceContractId
  ) {
    invalid("EVIDENCE_INVALID", "Snapshot id is already bound to another capture request or actor");
  }
}

function snapshotFromReceipt(receipt: ModernSnapshotExtractionReceiptV1): DatasetSnapshotV2 {
  return evidence(() =>
    createDatasetSnapshotV2({
      contractVersion: 2,
      tenantId: receipt.tenantId,
      snapshotId: receipt.snapshotId,
      sourceContract: receipt.sourceContract,
      delivery: receipt.delivery,
      sourceLocator: receipt.sourceLocator,
      ...(receipt.immutableSourceVersion === undefined
        ? {}
        : { immutableSourceVersion: receipt.immutableSourceVersion }),
      asOfDate: receipt.asOfDate,
      knowledge: receipt.knowledge,
      watermark: receipt.watermark,
      hashes: {
        contentHash: receipt.hashes.contentHash,
        schemaHash: receipt.hashes.schemaHash,
        catalogHash: receipt.hashes.catalogHash,
        parserHash: receipt.hashes.parserHash,
        extractionHash: receipt.receiptHash
      },
      rowCount: receipt.rowCount,
      byteCount: receipt.byteCount,
      sections: receipt.sections,
      correction: receipt.correction,
      createdBy: receipt.capturedBy
    })
  );
}

function sourceIdentity(source: SourceContractV1): DatasetSnapshotV2Input["sourceContract"] {
  return Object.freeze({
    sourceContractId: source.sourceContractId,
    revision: source.revision,
    sourceContractHash: source.sourceContractHash
  });
}

function bindingIdentity(
  binding: GovernedDatasetScopeBindingV1
): ModernSnapshotExtractionReceiptV1["scopeBinding"] {
  return Object.freeze({
    bindingId: binding.bindingId,
    revision: binding.revision,
    bindingHash: binding.bindingHash
  });
}

async function commitSnapshot(
  repository: GovernedDatasetSnapshotCommitRepositoryV1,
  snapshot: DatasetSnapshotV2,
  receipt: ModernSnapshotExtractionReceiptV1,
  actorId: string
) {
  const lineage = createGovernedSnapshotCommitLineageV1({
    contractVersion: 1,
    tenantId: snapshot.tenantId,
    snapshotId: snapshot.snapshotId,
    snapshotHash: snapshot.snapshotHash,
    datasetId: receipt.datasetId,
    facilityId: receipt.facilityId,
    sourceContract: receipt.sourceContract,
    scopeBinding: receipt.scopeBinding,
    sourceDelivery: receipt.sourceDelivery,
    extractionReceipt: {
      receiptId: receipt.receiptId,
      receiptHash: receipt.receiptHash
    },
    asOfDate: snapshot.asOfDate
  });
  try {
    return await repository.commitGovernedCapture(snapshot, lineage, {
      tenantId: snapshot.tenantId,
      actorId,
      idempotencyKey: `modern-capture:${snapshot.snapshotId}:snapshot`
    });
  } catch (error) {
    if (
      error instanceof RepositoryError &&
      (error.code === "ALREADY_EXISTS" || error.code === "CONCURRENCY_CONFLICT")
    ) {
      invalid("CORRECTION_LINEAGE_INVALID", "Atomic governed-period lineage commit was rejected");
    }
    throw error;
  }
}

function assertEffective(from: string, to: string | undefined, asOfDate: string, label: string): void {
  if (from > asOfDate || (to !== undefined && to <= asOfDate)) {
    invalid("SCOPE_BINDING_INVALID", `${label} was not effective for the captured period`);
  }
}

function assertSameRecord(expected: unknown, actual: unknown, message: string): void {
  if (canonicalJson(expected) !== canonicalJson(actual)) invalid("EVIDENCE_INVALID", message);
}

function evidence<T>(operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    if (error instanceof ModernSnapshotCaptureError) throw error;
    invalid("EVIDENCE_INVALID", "Trusted capture evidence failed canonical validation");
  }
}

function assertHash(value: unknown, label: string): asserts value is Sha256Hash {
  if (typeof value !== "string" || !HASH.test(value)) {
    invalid("EVIDENCE_INVALID", `${label} must be a lowercase SHA-256 hash`);
  }
}

function assertPlainObject(
  value: unknown,
  label: string,
  code: ModernSnapshotCaptureErrorCode
): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    invalid(code, `${label} must be an object`);
  }
}

function assertExactKeys(
  value: object,
  allowed: ReadonlySet<string>,
  label: string,
  code: ModernSnapshotCaptureErrorCode
): void {
  const keys = Object.keys(value);
  if (keys.length !== allowed.size || keys.some((key) => !allowed.has(key))) {
    invalid(code, `${label} contains unknown or missing fields`);
  }
}

function assertAllowedKeys(
  value: object,
  allowed: ReadonlySet<string>,
  required: ReadonlySet<string>,
  label: string,
  code: ModernSnapshotCaptureErrorCode
): void {
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.has(key)) || [...required].some((key) => !keys.includes(key))) {
    invalid(code, `${label} contains unknown or missing fields`);
  }
}

function identifier(value: unknown, label: string, code: ModernSnapshotCaptureErrorCode): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) invalid(code, `${label} is invalid`);
  return value;
}

function boundedInteger(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number,
  code: ModernSnapshotCaptureErrorCode
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    invalid(code, `${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return value as number;
}

function invalid(code: ModernSnapshotCaptureErrorCode, message: string): never {
  throw new ModernSnapshotCaptureError(code, message);
}
