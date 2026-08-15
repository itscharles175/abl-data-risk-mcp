import { performance } from "node:perf_hooks";

import {
  PARQUET_MEDIA_TYPE,
  XLSX_MEDIA_TYPE,
  AdapterValidationError,
  ObjectStorageParquetIngestionAdapterV1,
  ObjectStorageXlsxIngestionAdapterV1,
  ParquetIngestionAdapterV1,
  XlsxIngestionAdapterV1,
  type AdapterColumnV1,
  type ConformedDatasetV1,
  type ImmutableObjectDeliveryLoaderV1,
  type ParquetDecoderPortV1,
  type ParquetPartitionExpectationV1,
  type ParquetPartitionValueV1,
  type XlsxDecoderPortV1
} from "../adapters/index.js";
import {
  canonicalHash,
  canonicalJson,
  deepFreeze,
  parseGovernedDatasetScopeBindingV1,
  parseGovernedSourceDeliveryRecordV1,
  parseSourceContractV1,
  type DatasetSnapshotV2Input,
  type GovernedSourceDeliveryRecordV1,
  type Sha256Hash,
  type SourceContractV1
} from "../contracts/index.js";
import type {
  TrustedModernSnapshotExtractionAuthorityV1,
  TrustedModernSnapshotExtractionLimitsV1,
  TrustedModernSnapshotExtractionV1
} from "./modern-snapshot-capture.js";
import {
  SqlSnapshotExtractionError,
  type TrustedSnapshotSource
} from "./sql-snapshot-extraction.js";

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

interface GovernedModernExtractionPlanBaseV1 {
  readonly tenantId: string;
  readonly datasetId: string;
  readonly facilityId: string;
  readonly deliveryId: string;
  readonly deliveryHash: Sha256Hash;
  readonly sourceContractId: string;
  readonly sourceContractRevision: number;
  readonly sourceContractHash: Sha256Hash;
  /** Governed period metadata; it is never inferred from an object key or relation name. */
  readonly asOfDate: string;
  readonly correction?: DatasetSnapshotV2Input["correction"];
}

export interface GovernedPostgresqlExtractionPlanV1
extends GovernedModernExtractionPlanBaseV1 {
  readonly kind: "postgresql";
  /** Constructor-injected source capability; requests never supply connectivity or SQL. */
  readonly source: TrustedSnapshotSource;
  /** Opaque relation/column allowlist IDs understood only by the trusted source. */
  readonly relationId: string;
  readonly columnIds: readonly string[];
  readonly maximumCellBytes?: number;
  readonly watermark?: Readonly<{
    readonly lowerExclusive?: string;
    readonly valueType: "integer" | "decimal" | "date" | "datetime" | "opaque";
  }>;
}

interface GovernedObjectExtractionPlanBaseV1
extends GovernedModernExtractionPlanBaseV1 {
  readonly endpointOrigin: string;
  readonly columns: readonly Readonly<AdapterColumnV1>[];
}

export interface GovernedObjectXlsxExtractionPlanV1
extends GovernedObjectExtractionPlanBaseV1 {
  readonly kind: "object_xlsx";
  readonly headerRow: number;
}

export interface GovernedObjectParquetExtractionPlanV1
extends GovernedObjectExtractionPlanBaseV1 {
  readonly kind: "object_parquet";
  readonly partitions: readonly Readonly<ParquetPartitionValueV1>[];
  readonly partitionExpectations: readonly Readonly<ParquetPartitionExpectationV1>[];
}

export type GovernedModernExtractionPlanV1 =
  | GovernedPostgresqlExtractionPlanV1
  | GovernedObjectXlsxExtractionPlanV1
  | GovernedObjectParquetExtractionPlanV1;

export interface GovernedModernExtractionAuthorityV1Config {
  /** This authority is intentionally single-tenant and single-facility for the local pilot. */
  readonly tenantId: string;
  readonly facilityId: string;
  readonly plans: readonly GovernedModernExtractionPlanV1[];
  readonly objectLoader?: ImmutableObjectDeliveryLoaderV1;
  readonly xlsxDecoder?: XlsxDecoderPortV1;
  readonly parquetDecoder?: ParquetDecoderPortV1;
  readonly now?: () => string;
  readonly monotonicNow?: () => number;
}

export type GovernedModernExtractionErrorCode =
  | "INVALID_CONFIGURATION"
  | "BINDING_MISMATCH"
  | "PLAN_NOT_FOUND"
  | "DELIVERY_NOT_ALLOWED"
  | "EXTRACTION_LIMIT_EXCEEDED"
  | "EXTRACTION_CANCELLED"
  | "EXTRACTION_FAILED";

export class GovernedModernExtractionError extends Error {
  constructor(readonly code: GovernedModernExtractionErrorCode, message: string) {
    super(message);
    this.name = "GovernedModernExtractionError";
  }
}

/**
 * Concrete Bronze extraction boundary for the local governed pilot.
 *
 * Public capture callers provide only source/delivery IDs. By the time this
 * authority runs, the delivery authority has resolved the exact immutable
 * source contract, facility binding and delivery record. This class binds that
 * evidence to server-owned source capabilities and parser plans. It never
 * accepts SQL, filesystem paths, object endpoints or credentials at runtime.
 */
export class GovernedModernExtractionAuthorityV1
implements TrustedModernSnapshotExtractionAuthorityV1 {
  readonly #tenantId: string;
  readonly #facilityId: string;
  readonly #plans: ReadonlyMap<string, GovernedModernExtractionPlanV1>;
  readonly #objectLoader: ImmutableObjectDeliveryLoaderV1 | undefined;
  readonly #xlsxDecoder: XlsxDecoderPortV1 | undefined;
  readonly #parquetDecoder: ParquetDecoderPortV1 | undefined;
  readonly #now: () => string;
  readonly #monotonicNow: () => number;

  constructor(config: GovernedModernExtractionAuthorityV1Config) {
    this.#tenantId = identifier(config?.tenantId, "tenantId");
    this.#facilityId = identifier(config?.facilityId, "facilityId");
    this.#objectLoader = config.objectLoader;
    this.#xlsxDecoder = config.xlsxDecoder;
    this.#parquetDecoder = config.parquetDecoder;
    this.#now = config.now ?? (() => new Date().toISOString());
    this.#monotonicNow = config.monotonicNow ?? (() => performance.now());
    this.#plans = validatePlans(config.plans, this.#tenantId, this.#facilityId, {
      objectLoader: this.#objectLoader,
      xlsxDecoder: this.#xlsxDecoder,
      parquetDecoder: this.#parquetDecoder
    });
  }

  async extract(
    input: Parameters<TrustedModernSnapshotExtractionAuthorityV1["extract"]>[0]
  ): Promise<TrustedModernSnapshotExtractionV1> {
    validateGovernedEvidence(input);
    assertInputBindings(input, this.#tenantId, this.#facilityId);
    const plan = this.#plans.get(input.deliveryId);
    if (plan === undefined) {
      fail("PLAN_NOT_FOUND", "No server-owned extraction plan exists for the governed delivery");
    }
    assertPlanBindings(plan, input);
    assertLimits(input.limits, input.sourceContract);
    assertSourceContractPolicy(input.sourceContract);
    const startedAt = this.#monotonicNow();
    const extractedAt = timestamp(this.#now(), "extractedAt");
    if (input.signal?.aborted === true) {
      fail("EXTRACTION_CANCELLED", "Governed extraction was cancelled");
    }

    const dataset = await withDeadline(
      input.limits.timeoutMs,
      input.signal,
      async (signal) => plan.kind === "postgresql"
        ? this.#extractPostgresql(plan, input, signal)
        : this.#extractObject(plan, input, signal)
    );
    const receivedAt = timestamp(this.#now(), "receivedAt");
    const elapsedMs = elapsedInteger(startedAt, this.#monotonicNow());
    if (elapsedMs > input.limits.timeoutMs) {
      fail("EXTRACTION_LIMIT_EXCEEDED", "Governed extraction exceeded its execution-time bound");
    }
    assertDatasetLimits(dataset, input.limits);
    const section = input.sourceContract.sections[0]!;
    const records = dataset.records.map((record) => Object.freeze({ ...record }));
    const schemaHash = dataset.schemaHash;
    const controlPopulationHash = canonicalHash(records);
    const balance = sectionBalance(records, section);
    const sectionEvidence = Object.freeze({
      sectionId: section.sectionId,
      required: section.required,
      present: true,
      rowCount: records.length,
      contentHash: canonicalHash({ sectionId: section.sectionId, records }),
      schemaHash,
      controlPopulationHash,
      ...balance
    });
    const parserHash = canonicalHash({
      parserId: input.sourceContract.parserPolicy.parserId,
      parserVersion: input.sourceContract.parserPolicy.parserVersion,
      optionsHash: input.sourceContract.parserPolicy.optionsHash
    });
    const extraction = {
      tenantId: input.tenantId,
      datasetId: input.datasetId,
      facilityId: input.facilityId,
      snapshotId: input.snapshotId,
      deliveryId: input.deliveryId,
      asOfDate: plan.asOfDate,
      knowledge: {
        sourceObservedAt: input.sourceDelivery.sourceObservedAt,
        extractedAt,
        receivedAt
      },
      watermark: watermarkEvidence(input.sourceContract, input.sourceDelivery, plan),
      hashes: {
        contentHash: dataset.contentHash,
        schemaHash,
        profileHash: profileHash(records, dataset.columnNames),
        catalogHash: dataset.catalogHash,
        parserHash
      },
      rowCount: records.length,
      columnCount: dataset.columnNames.length,
      byteCount: dataset.byteCount,
      elapsedMs,
      sections: [sectionEvidence],
      correction: plan.correction ?? { kind: "original" as const },
      sourceSections: [{ sectionId: section.sectionId, records }]
    } satisfies TrustedModernSnapshotExtractionV1;
    return deepFreeze(extraction);
  }

  async #extractPostgresql(
    plan: GovernedPostgresqlExtractionPlanV1,
    input: Parameters<TrustedModernSnapshotExtractionAuthorityV1["extract"]>[0],
    signal: AbortSignal
  ): Promise<InternalExtractedDataset> {
    const locator = input.sourceDelivery.locator;
    if (locator.mode !== "postgresql_pull" || input.sourceContract.parserPolicy.format !== "sql_rows") {
      fail("DELIVERY_NOT_ALLOWED", "Governed delivery does not match the PostgreSQL extraction plan");
    }
    if (plan.source.dialect !== "postgres" || plan.source.sourceId !== locator.connectorId) {
      fail("DELIVERY_NOT_ALLOWED", "PostgreSQL source capability does not match the governed connector");
    }
    const maximumCellBytes = Math.min(
      plan.maximumCellBytes ?? 1_000_000,
      input.limits.maximumBytes,
      1_000_000
    );
    let result;
    try {
      result = await plan.source.extract({
        tenantId: input.tenantId,
        datasetId: input.datasetId,
        relationId: plan.relationId,
        columnIds: plan.columnIds,
        ...(input.sourceContract.extractionPolicy.mode === "watermark"
          ? { watermark: { upperBound: requiredPostgresqlWatermark(locator) } }
          : {})
      }, {
        maximumRows: Math.min(input.limits.maximumRows, 1_000_000),
        maximumBytes: Math.min(input.limits.maximumBytes, 100_000_000),
        maximumCellBytes,
        maximumExecutionMs: Math.min(input.limits.timeoutMs, 60_000),
        maximumColumns: Math.min(input.limits.maximumColumns, 2_000)
      }, signal);
    } catch (error) {
      translateExtractionFailure(error);
    }
    if (
      result.tenantId !== input.tenantId ||
      result.datasetId !== input.datasetId ||
      result.sourceId !== locator.connectorId ||
      result.relationId !== plan.relationId ||
      canonicalJson(result.columnIds) !== canonicalJson(plan.columnIds)
    ) {
      fail("BINDING_MISMATCH", "PostgreSQL source substituted the governed extraction identity");
    }
    const expectedNames = governedColumnNames(input.sourceContract);
    if (canonicalJson(result.outputColumns) !== canonicalJson(expectedNames)) {
      fail("BINDING_MISMATCH", "PostgreSQL output columns differ from the governed source schema");
    }
    return Object.freeze({
      records: result.records,
      columnNames: result.outputColumns,
      contentHash: canonicalHash(result.records),
      schemaHash: canonicalHash(input.sourceContract.schemaPolicy),
      catalogHash: canonicalHash({
        deliveryHash: input.sourceDelivery.deliveryHash,
        relationIdentityHash: locator.relationIdentityHash,
        sourceVersionHash: locator.sourceVersionHash,
        queryFingerprint: result.queryFingerprint,
        orderBy: result.orderBy,
        outputColumns: result.outputColumns
      }),
      byteCount: result.byteLength
    });
  }

  async #extractObject(
    plan: GovernedObjectXlsxExtractionPlanV1 | GovernedObjectParquetExtractionPlanV1,
    input: Parameters<TrustedModernSnapshotExtractionAuthorityV1["extract"]>[0],
    signal: AbortSignal
  ): Promise<InternalExtractedDataset> {
    const locator = input.sourceDelivery.locator;
    if (locator.mode !== "object_storage" || this.#objectLoader === undefined) {
      fail("DELIVERY_NOT_ALLOWED", "Governed delivery does not match an immutable object extraction plan");
    }
    if (locator.byteCount > input.limits.maximumBytes) {
      fail("EXTRACTION_LIMIT_EXCEEDED", "Immutable object exceeds the governed extraction byte bound");
    }
    const formatMaximumBytes = plan.kind === "object_xlsx" ? 1_000_000_000 : 2_000_000_000;
    if (locator.byteCount > formatMaximumBytes) {
      fail("EXTRACTION_LIMIT_EXCEEDED", "Immutable object exceeds the format adapter byte bound");
    }
    assertAdapterColumns(plan.columns, input.sourceContract);
    const object = {
      connectorId: locator.connectorId,
      endpointOrigin: plan.endpointOrigin,
      bucket: locator.bucket,
      key: locator.objectKey,
      versionId: locator.immutableVersionId,
      expectedContentHash: locator.contentHash,
      mediaType: plan.kind === "object_xlsx" ? XLSX_MEDIA_TYPE : PARQUET_MEDIA_TYPE
    } as const;
    const parser = {
      parserId: input.sourceContract.parserPolicy.parserId,
      parserVersion: input.sourceContract.parserPolicy.parserVersion,
      optionsHash: input.sourceContract.parserPolicy.optionsHash
    };
    let conformed: ConformedDatasetV1;
    try {
      if (plan.kind === "object_xlsx") {
        if (this.#xlsxDecoder === undefined || input.sourceContract.parserPolicy.format !== "xlsx") {
          fail("DELIVERY_NOT_ALLOWED", "The governed XLSX decoder is unavailable or mismatched");
        }
        const governedDateSystem = input.sourceContract.parserPolicy.dateSystem;
        const decoder = dateSystemFencedXlsxDecoder(this.#xlsxDecoder, governedDateSystem);
        const adapter = new ObjectStorageXlsxIngestionAdapterV1(
          this.#objectLoader,
          new XlsxIngestionAdapterV1({
            decoder,
            parser,
            limits: {
              maximumWorkbookBytes: Math.min(input.limits.maximumBytes, formatMaximumBytes),
              maximumRows: input.limits.maximumRows,
              maximumColumns: input.limits.maximumColumns,
              maximumCellCharacters: Math.min(input.limits.maximumBytes, 1_000_000)
            }
          })
        );
        conformed = await adapter.ingest({
          object,
          sheetName: input.sourceContract.sections[0]!.selector,
          headerRow: plan.headerRow,
          columns: plan.columns,
          signal
        });
      } else {
        if (
          this.#parquetDecoder === undefined ||
          input.sourceContract.parserPolicy.format !== "parquet" ||
          input.sourceContract.parserPolicy.rejectSchemaMerging !== true
        ) {
          fail("DELIVERY_NOT_ALLOWED", "The governed Parquet decoder is unavailable or schema merging is not rejected");
        }
        const adapter = new ObjectStorageParquetIngestionAdapterV1(
          this.#objectLoader,
          new ParquetIngestionAdapterV1({
            decoder: this.#parquetDecoder,
            parser,
            limits: {
              maximumFileBytes: Math.min(input.limits.maximumBytes, formatMaximumBytes),
              maximumFooterBytes: Math.max(
                1,
                Math.min(16 * 1024 * 1024, input.limits.maximumBytes - 1, formatMaximumBytes - 1)
              ),
              maximumRows: input.limits.maximumRows,
              maximumColumns: input.limits.maximumColumns,
              maximumCellCharacters: Math.min(input.limits.maximumBytes, 1_000_000)
            }
          })
        );
        conformed = await adapter.ingest({
          object,
          columns: plan.columns,
          partitions: plan.partitions,
          partitionExpectations: plan.partitionExpectations,
          signal
        });
      }
    } catch (error) {
      translateExtractionFailure(error);
    }
    if (conformed.sourceContentHash !== locator.contentHash) {
      fail("BINDING_MISMATCH", "Object adapter output is not bound to the governed content hash");
    }
    return Object.freeze({
      records: conformed.records,
      columnNames: conformed.columns.map((column) => column.name),
      contentHash: conformed.sourceContentHash,
      schemaHash: conformed.schemaHash,
      catalogHash: canonicalHash({
        deliveryHash: input.sourceDelivery.deliveryHash,
        immutableVersionHash: locator.immutableVersionHash,
        contentHash: locator.contentHash,
        parserFingerprint: conformed.parserFingerprint,
        schemaHash: conformed.schemaHash,
        populationHash: conformed.populationHash
      }),
      byteCount: locator.byteCount
    });
  }
}

interface InternalExtractedDataset {
  readonly records: readonly Readonly<Record<string, string | boolean | number | null>>[];
  readonly columnNames: readonly string[];
  readonly contentHash: Sha256Hash;
  readonly schemaHash: Sha256Hash;
  readonly catalogHash: Sha256Hash;
  readonly byteCount: number;
}

function validateGovernedEvidence(
  input: Parameters<TrustedModernSnapshotExtractionAuthorityV1["extract"]>[0]
): void {
  try {
    parseSourceContractV1(input.sourceContract);
    parseGovernedDatasetScopeBindingV1(input.scopeBinding);
    parseGovernedSourceDeliveryRecordV1(input.sourceDelivery);
  } catch {
    fail("BINDING_MISMATCH", "Extraction input contains invalid governed evidence");
  }
}

function copyPlan(plan: GovernedModernExtractionPlanV1): GovernedModernExtractionPlanV1 {
  const correction = plan.correction === undefined
    ? {}
    : { correction: Object.freeze({ ...plan.correction }) };
  if (plan.kind === "postgresql") {
    return Object.freeze({
      ...plan,
      ...correction,
      columnIds: Object.freeze([...plan.columnIds]),
      ...(plan.watermark === undefined ? {} : { watermark: Object.freeze({ ...plan.watermark }) })
    });
  }
  const columns = Object.freeze(plan.columns.map((column) => Object.freeze({ ...column })));
  if (plan.kind === "object_xlsx") return Object.freeze({ ...plan, ...correction, columns });
  return Object.freeze({
    ...plan,
    ...correction,
    columns,
    partitions: Object.freeze(plan.partitions.map((partition) => Object.freeze({ ...partition }))),
    partitionExpectations: Object.freeze(
      plan.partitionExpectations.map((expectation) => Object.freeze({ ...expectation }))
    )
  });
}

function validatePlans(
  plans: readonly GovernedModernExtractionPlanV1[],
  tenantId: string,
  facilityId: string,
  dependencies: {
    readonly objectLoader: ImmutableObjectDeliveryLoaderV1 | undefined;
    readonly xlsxDecoder: XlsxDecoderPortV1 | undefined;
    readonly parquetDecoder: ParquetDecoderPortV1 | undefined;
  }
): ReadonlyMap<string, GovernedModernExtractionPlanV1> {
  if (!Array.isArray(plans) || plans.length < 1 || plans.length > 10_000) {
    configError("plans must contain 1 through 10,000 governed deliveries");
  }
  const result = new Map<string, GovernedModernExtractionPlanV1>();
  for (const plan of plans) {
    if (plan.tenantId !== tenantId || plan.facilityId !== facilityId) {
      configError("Every extraction plan must match the configured tenant and facility");
    }
    identifier(plan.datasetId, "plan.datasetId");
    identifier(plan.deliveryId, "plan.deliveryId");
    identifier(plan.sourceContractId, "plan.sourceContractId");
    positiveInteger(plan.sourceContractRevision, "plan.sourceContractRevision", 1_000_000);
    hash(plan.deliveryHash, "plan.deliveryHash");
    hash(plan.sourceContractHash, "plan.sourceContractHash");
    isoDate(plan.asOfDate, "plan.asOfDate");
    if (result.has(plan.deliveryId)) configError(`Duplicate extraction plan '${plan.deliveryId}'`);
    if (plan.kind === "postgresql") {
      if (!plan.source || typeof plan.source.extract !== "function") configError("PostgreSQL plan requires a trusted source");
      identifier(plan.relationId, "plan.relationId");
      identifierArray(plan.columnIds, "plan.columnIds");
      if (plan.maximumCellBytes !== undefined) positiveInteger(plan.maximumCellBytes, "plan.maximumCellBytes", 1_000_000);
    } else {
      if (dependencies.objectLoader === undefined) configError("Object extraction plans require an immutable object loader");
      if (plan.kind === "object_xlsx" && dependencies.xlsxDecoder === undefined) configError("XLSX plans require an XLSX decoder");
      if (plan.kind === "object_parquet" && dependencies.parquetDecoder === undefined) configError("Parquet plans require a Parquet decoder");
      if (plan.kind === "object_xlsx") positiveInteger(plan.headerRow, "plan.headerRow", 10_000);
      if (!Array.isArray(plan.columns) || plan.columns.length < 1) configError("Object plans require governed adapter columns");
      if (!/^https:\/\/[A-Za-z0-9.-]+(?::\d+)?$/.test(plan.endpointOrigin)) {
        configError("Object endpointOrigin must be an exact HTTPS origin");
      }
    }
    result.set(plan.deliveryId, copyPlan(plan));
  }
  return result;
}

function assertInputBindings(
  input: Parameters<TrustedModernSnapshotExtractionAuthorityV1["extract"]>[0],
  tenantId: string,
  facilityId: string
): void {
  if (
    input.tenantId !== tenantId ||
    input.facilityId !== facilityId ||
    input.sourceContract.tenantId !== tenantId ||
    input.scopeBinding.tenantId !== tenantId ||
    input.scopeBinding.scope.scopeType !== "facility" ||
    input.scopeBinding.scope.scopeId !== facilityId ||
    input.sourceDelivery.tenantId !== tenantId ||
    input.sourceDelivery.facilityId !== facilityId ||
    input.datasetId !== input.scopeBinding.datasetId ||
    input.datasetId !== input.sourceDelivery.datasetId ||
    input.deliveryId !== input.sourceDelivery.deliveryId ||
    input.sourceDelivery.status !== "usable" ||
    canonicalJson(input.scopeBinding.sourceContract) !== canonicalJson({
      sourceContractId: input.sourceContract.sourceContractId,
      revision: input.sourceContract.revision,
      sourceContractHash: input.sourceContract.sourceContractHash
    }) ||
    canonicalJson(input.sourceDelivery.sourceContract) !== canonicalJson(input.scopeBinding.sourceContract) ||
    canonicalJson(input.sourceDelivery.scopeBinding) !== canonicalJson({
      bindingId: input.scopeBinding.bindingId,
      revision: input.scopeBinding.revision,
      bindingHash: input.scopeBinding.bindingHash
    }) ||
    !deliveryMatchesSourceContract(input.sourceDelivery, input.sourceContract)
  ) {
    fail("BINDING_MISMATCH", "Extraction input is outside the configured tenant/facility delivery binding");
  }
}

function deliveryMatchesSourceContract(
  delivery: GovernedSourceDeliveryRecordV1,
  source: SourceContractV1
): boolean {
  const locator = delivery.locator;
  const governed = source.delivery;
  if (locator.mode === "postgresql_pull" && governed.mode === "postgresql_pull") {
    return (
      locator.connectorId === governed.connectorId &&
      locator.catalog === governed.catalog &&
      locator.schema === governed.schema &&
      locator.relation === governed.relation
    );
  }
  return (
    locator.mode === "object_storage" &&
    governed.mode === "object_storage" &&
    locator.format === governed.format &&
    locator.connectorId === governed.connectorId &&
    locator.bucket === governed.bucket
  );
}

function assertPlanBindings(
  plan: GovernedModernExtractionPlanV1,
  input: Parameters<TrustedModernSnapshotExtractionAuthorityV1["extract"]>[0]
): void {
  if (
    plan.tenantId !== input.tenantId ||
    plan.datasetId !== input.datasetId ||
    plan.facilityId !== input.facilityId ||
    plan.deliveryId !== input.deliveryId ||
    plan.deliveryHash !== input.sourceDelivery.deliveryHash ||
    plan.sourceContractId !== input.sourceContract.sourceContractId ||
    plan.sourceContractRevision !== input.sourceContract.revision ||
    plan.sourceContractHash !== input.sourceContract.sourceContractHash ||
    input.sourceDelivery.sourceContract.sourceContractHash !== plan.sourceContractHash
  ) {
    fail("BINDING_MISMATCH", "Server-owned extraction plan does not match the governed delivery evidence");
  }
  const expectedKind = input.sourceDelivery.locator.mode === "postgresql_pull"
    ? "postgresql"
    : `object_${input.sourceDelivery.locator.format}`;
  if (plan.kind !== expectedKind) {
    fail("DELIVERY_NOT_ALLOWED", "Extraction plan format does not match the governed delivery locator");
  }
}

function assertSourceContractPolicy(source: SourceContractV1): void {
  if (
    source.status !== "active" ||
    source.extractionPolicy.readOnly !== true ||
    source.schemaPolicy.allowUnknownColumns ||
    !source.schemaPolicy.requireStableOrdinals ||
    source.sections.length !== 1
  ) {
    fail(
      "DELIVERY_NOT_ALLOWED",
      "Pilot extraction requires one active, read-only, exact-schema source section"
    );
  }
}

function assertLimits(
  limits: TrustedModernSnapshotExtractionLimitsV1,
  source: SourceContractV1
): void {
  positiveRuntimeLimit(limits.maximumRows, "maximumRows", 10_000_000);
  positiveRuntimeLimit(limits.maximumColumns, "maximumColumns", 10_000);
  positiveRuntimeLimit(limits.maximumBytes, "maximumBytes", 10_000_000_000);
  positiveRuntimeLimit(limits.timeoutMs, "timeoutMs", 3_600_000);
  positiveRuntimeLimit(limits.cursorRows, "cursorRows", 100_000);
  if (canonicalJson(limits) !== canonicalJson({
    maximumRows: source.extractionPolicy.maximumRows,
    maximumColumns: source.extractionPolicy.maximumColumns,
    maximumBytes: source.extractionPolicy.maximumBytes,
    timeoutMs: source.extractionPolicy.timeoutMs,
    cursorRows: source.extractionPolicy.cursorRows
  })) {
    fail("BINDING_MISMATCH", "Runtime extraction limits differ from the active source contract");
  }
}

function assertDatasetLimits(dataset: InternalExtractedDataset, limits: TrustedModernSnapshotExtractionLimitsV1): void {
  if (
    dataset.records.length > limits.maximumRows ||
    dataset.columnNames.length > limits.maximumColumns ||
    dataset.byteCount > limits.maximumBytes
  ) {
    fail("EXTRACTION_LIMIT_EXCEEDED", "Extracted dataset exceeded governed row, column or byte bounds");
  }
}

function assertAdapterColumns(columns: readonly Readonly<AdapterColumnV1>[], source: SourceContractV1): void {
  const governed = [...source.schemaPolicy.columns].sort((left, right) => left.ordinal - right.ordinal);
  if (
    columns.length !== governed.length ||
    columns.some((column, index) =>
      column.name !== governed[index]!.sourceName || column.nullable !== governed[index]!.nullable
    )
  ) {
    fail("BINDING_MISMATCH", "Object adapter columns differ from the governed source schema");
  }
}

function governedColumnNames(source: SourceContractV1): readonly string[] {
  return Object.freeze(
    [...source.schemaPolicy.columns]
      .sort((left, right) => left.ordinal - right.ordinal)
      .map((column) => column.sourceName)
  );
}

function watermarkEvidence(
  source: SourceContractV1,
  delivery: GovernedSourceDeliveryRecordV1,
  plan: GovernedModernExtractionPlanV1
): DatasetSnapshotV2Input["watermark"] {
  if (source.extractionPolicy.mode === "full") return { mode: "none" };
  if (plan.kind !== "postgresql" || plan.watermark === undefined || delivery.locator.mode !== "postgresql_pull") {
    fail("DELIVERY_NOT_ALLOWED", "Watermark extraction requires a server-owned PostgreSQL watermark plan");
  }
  return {
    mode: "bounded",
    field: source.extractionPolicy.watermarkField!,
    ...(plan.watermark.lowerExclusive === undefined ? {} : { lowerExclusive: plan.watermark.lowerExclusive }),
    upperInclusive: requiredPostgresqlWatermark(delivery.locator),
    valueType: plan.watermark.valueType
  };
}

function requiredPostgresqlWatermark(
  locator: Extract<GovernedSourceDeliveryRecordV1["locator"], { readonly mode: "postgresql_pull" }>
): string {
  if (locator.watermark === undefined) {
    fail("DELIVERY_NOT_ALLOWED", "Governed PostgreSQL delivery omitted its required watermark");
  }
  return locator.watermark;
}

function dateSystemFencedXlsxDecoder(
  decoder: XlsxDecoderPortV1,
  governedDateSystem: "1900" | "1904" | "reject_mixed"
): XlsxDecoderPortV1 {
  return Object.freeze({
    async decode(input: Parameters<XlsxDecoderPortV1["decode"]>[0]) {
      const workbook = await decoder.decode(input);
      if (governedDateSystem !== "reject_mixed" && workbook.dateSystem !== governedDateSystem) {
        throw new AdapterValidationError("SCHEMA_MISMATCH", "XLSX date system differs from the governed parser policy");
      }
      return workbook;
    }
  });
}

function sectionBalance(
  records: readonly Readonly<Record<string, string | boolean | number | null>>[],
  section: SourceContractV1["sections"][number]
): Readonly<{ readonly balance?: string; readonly currency?: string }> {
  if (section.balanceField === undefined && section.currencyField === undefined) return {};
  if (section.balanceField === undefined || section.currencyField === undefined) {
    fail("DELIVERY_NOT_ALLOWED", "Section balance and currency controls must be declared together");
  }
  let scale = 0;
  let total = 0n;
  let currency: string | undefined;
  for (const [index, record] of records.entries()) {
    const rawBalance = record[section.balanceField];
    const rawCurrency = record[section.currencyField];
    if (typeof rawBalance !== "string" || !/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/.test(rawBalance)) {
      fail("EXTRACTION_FAILED", `Section balance row ${index + 1} is not an exact decimal string`);
    }
    if (typeof rawCurrency !== "string" || !/^[A-Z]{3}$/.test(rawCurrency)) {
      fail("EXTRACTION_FAILED", `Section currency row ${index + 1} is not an ISO currency code`);
    }
    if (currency !== undefined && currency !== rawCurrency) {
      fail("EXTRACTION_FAILED", "Section balance control cannot aggregate multiple currencies");
    }
    currency = rawCurrency;
    const fraction = rawBalance.includes(".") ? rawBalance.length - rawBalance.indexOf(".") - 1 : 0;
    if (fraction > scale) {
      total *= 10n ** BigInt(fraction - scale);
      scale = fraction;
    }
    const negative = rawBalance.startsWith("-");
    const unsigned = negative ? rawBalance.slice(1) : rawBalance;
    const [whole, decimals = ""] = unsigned.split(".");
    const units = BigInt(`${whole}${decimals.padEnd(scale, "0")}`);
    total += negative ? -units : units;
  }
  if (currency === undefined) return {};
  return Object.freeze({ balance: formatScaledInteger(total, scale), currency });
}

function formatScaledInteger(value: bigint, scale: number): string {
  if (value === 0n) return scale === 0 ? "0" : `0.${"0".repeat(scale)}`;
  const negative = value < 0n;
  const digits = (negative ? -value : value).toString().padStart(scale + 1, "0");
  const body = scale === 0 ? digits : `${digits.slice(0, -scale)}.${digits.slice(-scale)}`;
  return negative ? `-${body}` : body;
}

function profileHash(
  records: readonly Readonly<Record<string, string | boolean | number | null>>[],
  columnNames: readonly string[]
): Sha256Hash {
  return canonicalHash({
    rowCount: records.length,
    columns: columnNames.map((name) => ({
      name,
      nullCount: records.reduce((count, record) => count + (record[name] === null ? 1 : 0), 0),
      valueKinds: [...new Set(records.map((record) => record[name] === null ? "null" : typeof record[name]))].sort()
    }))
  });
}

async function withDeadline<T>(
  timeoutMs: number,
  signal: AbortSignal | undefined,
  operation: (signal: AbortSignal) => Promise<T>
): Promise<T> {
  const deadline = new AbortController();
  const combined = signal === undefined
    ? deadline.signal
    : AbortSignal.any([signal, deadline.signal]);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      deadline.abort();
      reject(new GovernedModernExtractionError(
        "EXTRACTION_LIMIT_EXCEEDED",
        "Governed extraction exceeded its execution-time bound"
      ));
    }, timeoutMs);
    timer.unref();
  });
  try {
    return await Promise.race([operation(combined), timeout]);
  } catch (error) {
    if (signal?.aborted === true) {
      fail("EXTRACTION_CANCELLED", "Governed extraction was cancelled");
    }
    throw error;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function translateExtractionFailure(error: unknown): never {
  if (error instanceof GovernedModernExtractionError) throw error;
  if (error instanceof SqlSnapshotExtractionError) {
    if (error.code === "CANCELLED") fail("EXTRACTION_CANCELLED", "Governed extraction was cancelled");
    if (["ROW_LIMIT_EXCEEDED", "BYTE_LIMIT_EXCEEDED", "CELL_LIMIT_EXCEEDED", "TIME_LIMIT_EXCEEDED"].includes(error.code)) {
      fail("EXTRACTION_LIMIT_EXCEEDED", "PostgreSQL extraction exceeded a governed bound");
    }
    fail("EXTRACTION_FAILED", "PostgreSQL extraction failed its trusted source policy");
  }
  if (error instanceof AdapterValidationError) {
    if (error.code === "LIMIT_EXCEEDED") fail("EXTRACTION_LIMIT_EXCEEDED", "Object extraction exceeded a governed bound");
    if (error.code === "DELIVERY_NOT_ALLOWED") fail("DELIVERY_NOT_ALLOWED", "Object delivery was not allowed");
    fail("EXTRACTION_FAILED", "Object extraction failed parser or integrity validation");
  }
  fail("EXTRACTION_FAILED", "Governed extraction failed");
}

function elapsedInteger(start: number, end: number): number {
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) {
    fail("EXTRACTION_FAILED", "Monotonic extraction clock is invalid");
  }
  return Math.ceil(end - start);
}

function timestamp(value: string, label: string): string {
  const parsed = new Date(value);
  if (!ISO_TIMESTAMP.test(value) || Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) {
    configError(`${label} must be canonical UTC`);
  }
  return value;
}

function isoDate(value: string, label: string): string {
  if (!ISO_DATE.test(value) || new Date(`${value}T00:00:00.000Z`).toISOString().slice(0, 10) !== value) {
    configError(`${label} must be a canonical ISO date`);
  }
  return value;
}

function identifier(value: string, label: string): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) configError(`${label} must be an identifier`);
  return value;
}

function identifierArray(value: readonly string[], label: string): void {
  if (!Array.isArray(value) || value.length < 1 || new Set(value).size !== value.length) configError(`${label} must be a unique non-empty array`);
  value.forEach((entry) => identifier(entry, label));
}

function hash(value: string, label: string): void {
  if (!/^sha256:[a-f0-9]{64}$/.test(value)) configError(`${label} must be a SHA-256 hash`);
}

function positiveInteger(value: number, label: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) configError(`${label} is outside policy`);
  return value;
}

function positiveRuntimeLimit(value: number, label: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    fail("EXTRACTION_LIMIT_EXCEEDED", `${label} is outside supported extraction policy`);
  }
  return value;
}

function configError(message: string): never {
  throw new GovernedModernExtractionError("INVALID_CONFIGURATION", message);
}

function fail(code: Exclude<GovernedModernExtractionErrorCode, "INVALID_CONFIGURATION">, message: string): never {
  throw new GovernedModernExtractionError(code, message);
}
