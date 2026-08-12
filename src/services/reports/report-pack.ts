import {
  createHash,
  createPublicKey,
  sign as ed25519Sign,
  verify as ed25519Verify,
  type KeyObject
} from "node:crypto";

import { Decimal } from "decimal.js";

import type { CertifiedPopulationRefV1 } from "../../domain/abl-v2/contracts.js";
import type {
  AggregateReportCellV1,
  AggregateReportChartV1,
  AggregateReportTableV1,
  ReportCellLineageV1,
  ReportComparisonV1,
  ReportExplanationV1,
  ReportManifestLinkV1,
  ReportPackDraftV1,
  ReportPackV1,
  ReportSigningKeyV1,
  ReportVerificationExpectationV1,
  ReportVerificationKeyV1,
  ReportWarningV1,
  SignedReportPackV1
} from "./contracts.js";

const ExactDecimal = Decimal.clone({
  precision: 256,
  rounding: Decimal.ROUND_HALF_EVEN,
  toExpNeg: -1_000,
  toExpPos: 1_000
});
const HASH = /^[a-f0-9]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const COLUMN = /^[a-z][a-z0-9_]{0,63}$/;
const DECIMAL = /^-?(?:0|[1-9]\d*)(?:\.\d+)?$/;
const MEDIA_TYPE = /^[a-z][a-z0-9!#$&^_.+-]{0,63}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,127}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const FORBIDDEN_DETAIL_COLUMNS = new Set([
  "record_id",
  "loan_id",
  "facility_id",
  "borrower_id",
  "borrower_name",
  "debtor_id",
  "debtor_name",
  "customer_id",
  "customer_name",
  "account_number",
  "tax_id",
  "ssn",
  "email",
  "phone",
  "address"
]);
const MAX_TABLES = 100;
const MAX_ROWS_PER_TABLE = 10_000;
const MAX_TOTAL_ROWS = 100_000;
const SIGNING_DOMAIN = "abl-report-pack-v1\n";

interface LineageContext {
  readonly populationToCertification: ReadonlyMap<string, ReadonlySet<string>>;
}

/** Creates a canonical, immutable aggregate-only report pack. */
export function createReportPackV1(draft: ReportPackDraftV1): ReportPackV1 {
  validateDraft(draft);
  const normalized = normalizeDraft(draft);
  validateDraft(normalized);
  return deepFreeze({ ...normalized, reportHash: fingerprint(normalized) });
}

/** Creates a checked Ed25519 signing key. Raw key bytes are never serialized into a report. */
export function createReportSigningKeyV1(input: {
  readonly keyId: string;
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
}): ReportSigningKeyV1 {
  exactKeys(input, "report signing key", ["keyId", "privateKey", "publicKey"]);
  identifier(input.keyId, "signing keyId");
  assertEd25519Key(input.privateKey, "private", "privateKey");
  assertEd25519Key(input.publicKey, "public", "publicKey");
  const derived = createPublicKey(input.privateKey);
  if (!spkiBytes(derived).equals(spkiBytes(input.publicKey))) {
    throw new Error("Report signing public key does not match its private key");
  }
  return Object.freeze({
    algorithm: "Ed25519" as const,
    keyId: input.keyId,
    publicKeyFingerprint: publicKeyFingerprint(input.publicKey),
    privateKey: input.privateKey,
    publicKey: input.publicKey
  });
}

/** Creates a checked Ed25519 verification key. */
export function createReportVerificationKeyV1(input: {
  readonly keyId: string;
  readonly publicKey: KeyObject;
}): ReportVerificationKeyV1 {
  exactKeys(input, "report verification key", ["keyId", "publicKey"]);
  identifier(input.keyId, "verification keyId");
  assertEd25519Key(input.publicKey, "public", "publicKey");
  return Object.freeze({
    algorithm: "Ed25519" as const,
    keyId: input.keyId,
    publicKeyFingerprint: publicKeyFingerprint(input.publicKey),
    publicKey: input.publicKey
  });
}

/** Signs the full canonical report, binding signer identity and signing time. */
export function signReportPackV1(
  report: ReportPackV1,
  key: ReportSigningKeyV1,
  signedAt: string
): SignedReportPackV1 {
  validateReport(report);
  validateSigningKey(key);
  isoTimestamp(signedAt, "signedAt");
  if (signedAt < report.createdAt) throw new Error("Report cannot be signed before it is created");
  const unsigned = {
    schemaVersion: "1" as const,
    algorithm: "Ed25519" as const,
    keyId: key.keyId,
    publicKeyFingerprint: key.publicKeyFingerprint,
    signedAt,
    report
  };
  const signature = ed25519Sign(null, signingBytes(unsigned), key.privateKey).toString("base64url");
  return deepFreeze({ ...unsigned, signature });
}

/** Verifies signature, report hash, key identity, and optional tenant/report expectations. */
export function verifySignedReportPackV1(
  signed: SignedReportPackV1,
  key: ReportVerificationKeyV1,
  expectation: ReportVerificationExpectationV1 = {}
): ReportPackV1 {
  exactKeys(signed, "signed report pack", [
    "schemaVersion",
    "algorithm",
    "keyId",
    "publicKeyFingerprint",
    "signedAt",
    "report",
    "signature"
  ]);
  if (signed.schemaVersion !== "1" || signed.algorithm !== "Ed25519") {
    throw new Error("Signed report uses an unsupported signature contract");
  }
  validateVerificationKey(key);
  if (signed.keyId !== key.keyId || signed.publicKeyFingerprint !== key.publicKeyFingerprint) {
    throw new Error("Signed report key identity does not match the verification key");
  }
  isoTimestamp(signed.signedAt, "signedAt");
  if (typeof signed.signature !== "string" || !BASE64URL.test(signed.signature)) {
    throw new Error("Signed report signature is not canonical base64url");
  }
  const signature = Buffer.from(signed.signature, "base64url");
  if (signature.toString("base64url") !== signed.signature || signature.length !== 64) {
    throw new Error("Signed report signature is malformed");
  }
  validateReport(signed.report);
  if (signed.signedAt < signed.report.createdAt) throw new Error("Report signature predates report creation");
  const unsigned = {
    schemaVersion: signed.schemaVersion,
    algorithm: signed.algorithm,
    keyId: signed.keyId,
    publicKeyFingerprint: signed.publicKeyFingerprint,
    signedAt: signed.signedAt,
    report: signed.report
  };
  if (!ed25519Verify(null, signingBytes(unsigned), key.publicKey, signature)) {
    throw new Error("Signed report signature verification failed");
  }
  validateExpectation(expectation, signed);
  return signed.report;
}

function normalizeDraft(draft: ReportPackDraftV1): ReportPackDraftV1 {
  return {
    ...draft,
    reportingPeriod: { ...draft.reportingPeriod },
    certifiedPopulations: draft.certifiedPopulations.map((population) => ({ ...population })).sort(
      (left, right) => compareText(left.populationHash, right.populationHash) || compareText(left.populationId, right.populationId)
    ),
    tables: draft.tables.map(normalizeTable).sort((left, right) => compareText(left.tableId, right.tableId)),
    charts: draft.charts.map((chart) => ({
      ...chart,
      series: sortedUnique(chart.series)
    })).sort((left, right) => compareText(left.chartId, right.chartId)),
    warnings: draft.warnings.map((warning) => ({
      ...warning,
      relatedHashes: sortedUnique(warning.relatedHashes)
    })).sort((left, right) => compareText(left.warningId, right.warningId)),
    explanations: draft.explanations.map((explanation) => ({
      ...explanation,
      populationHashes: sortedUnique(explanation.populationHashes)
    })).sort((left, right) => compareText(left.explanationId, right.explanationId)),
    comparisons: draft.comparisons.map((comparison) => ({
      ...comparison,
      lineage: normalizeLineage(comparison.lineage)
    })).sort((left, right) => compareText(left.comparisonId, right.comparisonId)),
    suppression: { ...draft.suppression },
    manifestLinks: draft.manifestLinks.map((link) => ({ ...link })).sort(
      (left, right) => compareText(left.artifactId, right.artifactId) || compareText(left.relationship, right.relationship)
    )
  };
}

function normalizeTable(table: AggregateReportTableV1): AggregateReportTableV1 {
  const dimensionColumns = sortedUnique(table.dimensionColumns);
  const measureColumns = sortedUnique(table.measureColumns);
  const rows = table.rows.map((row) => ({
    dimensions: sortedRecord(row.dimensions),
    measures: sortedRecord(
      Object.fromEntries(Object.entries(row.measures).map(([key, cell]) => [key, {
        ...cell,
        lineage: normalizeLineage(cell.lineage)
      }]))
    ),
    rowPopulationHash: row.rowPopulationHash
  })).sort((left, right) => compareText(stableJson(left.dimensions), stableJson(right.dimensions)));
  return { ...table, dimensionColumns, measureColumns, rows };
}

function normalizeLineage(lineage: ReportCellLineageV1): ReportCellLineageV1 {
  return {
    ...lineage,
    sourcePopulationHashes: sortedUnique(lineage.sourcePopulationHashes),
    certificationHashes: sortedUnique(lineage.certificationHashes)
  };
}

function validateReport(report: ReportPackV1): void {
  exactKeys(report, "report pack", [
    "schemaVersion",
    "reportId",
    "tenantId",
    "portfolioId",
    ...(report.facilityId === undefined ? [] : ["facilityId"]),
    "title",
    "reportDefinitionHash",
    "methodologyBundleHash",
    "reportingPeriod",
    "createdBy",
    "createdAt",
    "certifiedPopulations",
    "tables",
    "charts",
    "warnings",
    "explanations",
    "suppression",
    "comparisons",
    "manifestLinks",
    "reportHash"
  ]);
  const { reportHash, ...draft } = report;
  hash(reportHash, "reportHash");
  validateDraft(draft);
  if (fingerprint(draft) !== reportHash) throw new Error("Report hash does not match its canonical content");
}

function validateDraft(draft: ReportPackDraftV1): void {
  exactKeys(draft, "report pack draft", [
    "schemaVersion",
    "reportId",
    "tenantId",
    "portfolioId",
    ...(draft.facilityId === undefined ? [] : ["facilityId"]),
    "title",
    "reportDefinitionHash",
    "methodologyBundleHash",
    "reportingPeriod",
    "createdBy",
    "createdAt",
    "certifiedPopulations",
    "tables",
    "charts",
    "warnings",
    "explanations",
    "suppression",
    "comparisons",
    "manifestLinks"
  ]);
  if (draft.schemaVersion !== "1") throw new Error("Report pack schemaVersion must be 1");
  identifier(draft.reportId, "reportId");
  identifier(draft.tenantId, "tenantId");
  identifier(draft.portfolioId, "portfolioId");
  if (draft.facilityId !== undefined) identifier(draft.facilityId, "facilityId");
  displayText(draft.title, "report title", 256);
  hash(draft.reportDefinitionHash, "reportDefinitionHash");
  hash(draft.methodologyBundleHash, "methodologyBundleHash");
  validateReportingPeriod(draft.reportingPeriod);
  identifier(draft.createdBy, "createdBy");
  isoTimestamp(draft.createdAt, "createdAt");
  if (draft.createdAt < draft.reportingPeriod.knowledgeCutoff) {
    throw new Error("Report cannot be created before its knowledge cutoff");
  }
  const lineageContext = validateCertifiedPopulations(
    draft.certifiedPopulations,
    draft.tenantId,
    draft.reportingPeriod.from,
    draft.reportingPeriod.to
  );
  if (draft.tables.length === 0 || draft.tables.length > MAX_TABLES) {
    throw new Error(`Report must contain 1-${MAX_TABLES} aggregate tables`);
  }
  const tableIds = new Set<string>();
  let totalRows = 0;
  let suppressedCells = 0;
  for (const table of draft.tables) {
    const stats = validateTable(table, lineageContext);
    if (tableIds.has(table.tableId)) throw new Error("Report table ids must be unique");
    tableIds.add(table.tableId);
    totalRows += table.rows.length;
    suppressedCells += stats.suppressedCells;
  }
  if (totalRows > MAX_TOTAL_ROWS) throw new Error("Report exceeds aggregate row limit");
  validateCharts(draft.charts, draft.tables);
  validateWarnings(draft.warnings);
  validateExplanations(draft.explanations, lineageContext);
  exactKeys(draft.suppression, "report suppression", ["policyHash", "minimumCohortSize", "suppressedCellCount"]);
  hash(draft.suppression.policyHash, "suppression policyHash");
  if (!Number.isSafeInteger(draft.suppression.minimumCohortSize) || draft.suppression.minimumCohortSize < 1 || draft.suppression.minimumCohortSize > 10_000) {
    throw new Error("minimumCohortSize must be a safe integer from 1 through 10000");
  }
  if (!Number.isSafeInteger(draft.suppression.suppressedCellCount) || draft.suppression.suppressedCellCount !== suppressedCells) {
    throw new Error("suppressedCellCount does not match report cells");
  }
  validateComparisons(draft.comparisons, lineageContext);
  validateManifestLinks(draft.manifestLinks);
}

function validateReportingPeriod(period: ReportPackDraftV1["reportingPeriod"]): void {
  exactKeys(period, "reporting period", ["from", "to", "knowledgeCutoff"]);
  isoDate(period.from, "reporting period from");
  isoDate(period.to, "reporting period to");
  if (period.to < period.from) throw new Error("Reporting period is inverted");
  isoTimestamp(period.knowledgeCutoff, "knowledgeCutoff");
  if (period.knowledgeCutoff.slice(0, 10) < period.to) throw new Error("Knowledge cutoff precedes reporting period");
}

function validateCertifiedPopulations(
  populations: readonly CertifiedPopulationRefV1[],
  tenantId: string,
  from: string,
  to: string
): LineageContext {
  if (populations.length === 0 || populations.length > 10_000) {
    throw new Error("Report requires 1-10000 certified populations");
  }
  const pairIds = new Set<string>();
  const populationToCertification = new Map<string, Set<string>>();
  for (const population of populations) {
    exactKeys(population, "report certified population", [
      "schemaVersion",
      "tenantId",
      "populationId",
      "snapshotId",
      "asOfDate",
      "status",
      "populationHash",
      "certificationHash"
    ]);
    if (population.schemaVersion !== "1" || population.status !== "certified") {
      throw new Error("Report source population must be certified");
    }
    identifier(population.tenantId, "population tenantId");
    identifier(population.populationId, "populationId");
    identifier(population.snapshotId, "snapshotId");
    isoDate(population.asOfDate, "population asOfDate");
    hash(population.populationHash, "populationHash");
    hash(population.certificationHash, "certificationHash");
    if (population.tenantId !== tenantId) throw new Error("Report source population belongs to a different tenant");
    if (population.asOfDate < from || population.asOfDate > to) {
      throw new Error("Report source population is outside the reporting period");
    }
    const pairId = `${population.populationHash}:${population.certificationHash}`;
    if (pairIds.has(pairId)) throw new Error("Report certified populations must be unique");
    pairIds.add(pairId);
    const certifications = populationToCertification.get(population.populationHash) ?? new Set<string>();
    certifications.add(population.certificationHash);
    populationToCertification.set(population.populationHash, certifications);
  }
  return { populationToCertification };
}

function validateTable(
  table: AggregateReportTableV1,
  lineageContext: LineageContext
): { readonly suppressedCells: number } {
  exactKeys(table, "aggregate report table", ["tableId", "title", "dimensionColumns", "measureColumns", "rows"]);
  identifier(table.tableId, "tableId");
  displayText(table.title, "table title", 256);
  if (table.dimensionColumns.length === 0 || table.dimensionColumns.length > 2) {
    throw new Error("Aggregate report table must have one or two dimensions");
  }
  if (table.measureColumns.length === 0 || table.measureColumns.length > 20) {
    throw new Error("Aggregate report table must have 1-20 measures");
  }
  validateColumns(table.dimensionColumns, "dimension", true);
  validateColumns(table.measureColumns, "measure", false);
  if (table.rows.length > MAX_ROWS_PER_TABLE) throw new Error("Aggregate table exceeds row limit");
  const rowKeys = new Set<string>();
  let suppressedCells = 0;
  for (const row of table.rows) {
    exactKeys(row, "aggregate report row", ["dimensions", "measures", "rowPopulationHash"]);
    exactKeys(row.dimensions, "aggregate row dimensions", table.dimensionColumns);
    exactKeys(row.measures, "aggregate row measures", table.measureColumns);
    hash(row.rowPopulationHash, "rowPopulationHash");
    for (const value of Object.values(row.dimensions)) displayText(value, "aggregate dimension value", 256);
    const rowKey = stableJson(row.dimensions);
    if (rowKeys.has(rowKey)) throw new Error("Aggregate table contains duplicate dimension rows");
    rowKeys.add(rowKey);
    for (const cell of Object.values(row.measures)) {
      validateCell(cell, lineageContext);
      if (cell.suppressed) suppressedCells += 1;
    }
  }
  return { suppressedCells };
}

function validateColumns(columns: readonly string[], label: string, dimensions: boolean): void {
  const seen = new Set<string>();
  for (const column of columns) {
    if (!COLUMN.test(column)) throw new Error(`${label} column is invalid`);
    if (seen.has(column)) throw new Error(`${label} columns must be unique`);
    seen.add(column);
    if (
      dimensions &&
      (FORBIDDEN_DETAIL_COLUMNS.has(column) || /(?:^id$|_id$|number$|_no$)/u.test(column))
    ) {
      throw new Error(`Record-level dimension ${column} is prohibited in aggregate reports`);
    }
  }
}

function validateCell(cell: AggregateReportCellV1, lineageContext: LineageContext): void {
  exactKeys(cell, "aggregate report cell", [
    "value",
    "unit",
    "coverage",
    "suppressed",
    ...(cell.suppressionReason === undefined ? [] : ["suppressionReason"]),
    "lineage"
  ]);
  validateUnit(cell.unit);
  ratio(cell.coverage, "cell coverage");
  if (typeof cell.suppressed !== "boolean") throw new Error("Cell suppressed must be boolean");
  if (cell.suppressed) {
    if (cell.value !== null || cell.suppressionReason === undefined) {
      throw new Error("Suppressed cells must hide value and provide a reason");
    }
    if (!( ["minimum_cohort", "differencing_risk", "field_policy"] as const).includes(cell.suppressionReason)) {
      throw new Error("Unsupported suppression reason");
    }
  } else {
    if (cell.value === null || cell.suppressionReason !== undefined) {
      throw new Error("Unsuppressed cells require a value and no suppression reason");
    }
    const value = exactDecimal(cell.value, "aggregate cell value");
    if (cell.unit === "count" && !value.isInteger()) throw new Error("Count cells must be integers");
  }
  validateLineage(cell.lineage, lineageContext);
}

function validateLineage(lineage: ReportCellLineageV1, context: LineageContext): void {
  exactKeys(lineage, "report cell lineage", [
    "cellPopulationHash",
    "sourcePopulationHashes",
    "certificationHashes",
    "metricDefinitionHash",
    "methodologyHash"
  ]);
  hash(lineage.cellPopulationHash, "cellPopulationHash");
  hash(lineage.metricDefinitionHash, "metricDefinitionHash");
  hash(lineage.methodologyHash, "methodologyHash");
  if (lineage.sourcePopulationHashes.length === 0 || lineage.sourcePopulationHashes.length > 1_000) {
    throw new Error("Cell lineage requires 1-1000 source populations");
  }
  if (lineage.certificationHashes.length === 0 || lineage.certificationHashes.length > 1_000) {
    throw new Error("Cell lineage requires 1-1000 certification hashes");
  }
  const suppliedCertifications = new Set(lineage.certificationHashes);
  for (const certificationHash of suppliedCertifications) hash(certificationHash, "cell certificationHash");
  const allowedCertifications = new Set<string>();
  for (const populationHash of new Set(lineage.sourcePopulationHashes)) {
    hash(populationHash, "cell sourcePopulationHash");
    const validCertifications = context.populationToCertification.get(populationHash);
    if (!validCertifications || ![...validCertifications].some((item) => suppliedCertifications.has(item))) {
      throw new Error("Cell lineage is not backed by a certified report population");
    }
    for (const certificationHash of validCertifications) allowedCertifications.add(certificationHash);
  }
  for (const certificationHash of suppliedCertifications) {
    if (!allowedCertifications.has(certificationHash)) {
      throw new Error("Cell lineage contains certification evidence unrelated to its source populations");
    }
  }
}

function validateCharts(charts: readonly AggregateReportChartV1[], tables: readonly AggregateReportTableV1[]): void {
  if (charts.length > 100) throw new Error("Too many report charts");
  const ids = new Set<string>();
  const tableById = new Map(tables.map((table) => [table.tableId, table]));
  for (const chart of charts) {
    exactKeys(chart, "aggregate report chart", ["chartId", "title", "chartType", "tableId", "xDimension", "series"]);
    identifier(chart.chartId, "chartId");
    if (ids.has(chart.chartId)) throw new Error("Chart ids must be unique");
    ids.add(chart.chartId);
    displayText(chart.title, "chart title", 256);
    if (!( ["bar", "line", "stacked_bar", "heatmap"] as const).includes(chart.chartType)) {
      throw new Error("Unsupported aggregate chart type");
    }
    const table = tableById.get(chart.tableId);
    if (!table) throw new Error("Chart references an unknown aggregate table");
    if (!table.dimensionColumns.includes(chart.xDimension)) throw new Error("Chart xDimension is not in its table");
    if (chart.series.length === 0 || chart.series.length > 20) throw new Error("Chart requires 1-20 series");
    if (new Set(chart.series).size !== chart.series.length) throw new Error("Chart series must be unique");
    for (const series of chart.series) {
      if (!table.measureColumns.includes(series)) throw new Error("Chart series is not a table measure");
    }
  }
}

function validateWarnings(warnings: readonly ReportWarningV1[]): void {
  if (warnings.length > 1_000) throw new Error("Too many report warnings");
  const ids = new Set<string>();
  for (const warning of warnings) {
    exactKeys(warning, "report warning", ["warningId", "severity", "code", "message", "relatedHashes"]);
    identifier(warning.warningId, "warningId");
    identifier(warning.code, "warning code");
    if (ids.has(warning.warningId)) throw new Error("Warning ids must be unique");
    ids.add(warning.warningId);
    if (!( ["info", "warning", "critical"] as const).includes(warning.severity)) throw new Error("Unsupported warning severity");
    displayText(warning.message, "warning message", 2_000);
    if (warning.relatedHashes.length > 100) throw new Error("Warning has too many related hashes");
    for (const relatedHash of warning.relatedHashes) hash(relatedHash, "warning related hash");
  }
}

function validateExplanations(explanations: readonly ReportExplanationV1[], context: LineageContext): void {
  if (explanations.length > 1_000) throw new Error("Too many report explanations");
  const ids = new Set<string>();
  for (const explanation of explanations) {
    exactKeys(explanation, "report explanation", [
      "explanationId",
      "subjectId",
      "text",
      "methodologyHash",
      "populationHashes"
    ]);
    identifier(explanation.explanationId, "explanationId");
    identifier(explanation.subjectId, "explanation subjectId");
    if (ids.has(explanation.explanationId)) throw new Error("Explanation ids must be unique");
    ids.add(explanation.explanationId);
    displayText(explanation.text, "explanation text", 10_000);
    hash(explanation.methodologyHash, "explanation methodologyHash");
    if (explanation.populationHashes.length === 0 || explanation.populationHashes.length > 1_000) {
      throw new Error("Explanation requires 1-1000 population hashes");
    }
    for (const populationHash of explanation.populationHashes) {
      hash(populationHash, "explanation populationHash");
      if (!context.populationToCertification.has(populationHash)) {
        throw new Error("Explanation references an uncertified population");
      }
    }
  }
}

function validateComparisons(comparisons: readonly ReportComparisonV1[], context: LineageContext): void {
  if (comparisons.length > 1_000) throw new Error("Too many report comparisons");
  const ids = new Set<string>();
  for (const comparison of comparisons) {
    exactKeys(comparison, "report comparison", [
      "comparisonId",
      "label",
      "metricId",
      "unit",
      "leftPeriod",
      "rightPeriod",
      "leftValue",
      "rightValue",
      "delta",
      "lineage"
    ]);
    identifier(comparison.comparisonId, "comparisonId");
    identifier(comparison.metricId, "comparison metricId");
    if (ids.has(comparison.comparisonId)) throw new Error("Comparison ids must be unique");
    ids.add(comparison.comparisonId);
    displayText(comparison.label, "comparison label", 256);
    validateUnit(comparison.unit);
    isoDate(comparison.leftPeriod, "comparison leftPeriod");
    isoDate(comparison.rightPeriod, "comparison rightPeriod");
    const left = exactDecimal(comparison.leftValue, "comparison leftValue");
    const right = exactDecimal(comparison.rightValue, "comparison rightValue");
    const delta = exactDecimal(comparison.delta, "comparison delta");
    if (!right.minus(left).equals(delta)) throw new Error("Comparison delta does not reconcile");
    validateLineage(comparison.lineage, context);
  }
}

function validateManifestLinks(links: readonly ReportManifestLinkV1[]): void {
  if (links.length === 0 || links.length > 1_000) throw new Error("Report requires 1-1000 immutable manifest links");
  const ids = new Set<string>();
  for (const link of links) {
    exactKeys(link, "report manifest link", ["artifactId", "contentHash", "mediaType", "relationship"]);
    identifier(link.artifactId, "manifest artifactId");
    hash(link.contentHash, "manifest contentHash");
    if (!MEDIA_TYPE.test(link.mediaType)) throw new Error("Manifest mediaType is invalid");
    if (!( ["data_manifest", "chart_artifact", "methodology", "certification"] as const).includes(link.relationship)) {
      throw new Error("Unsupported manifest relationship");
    }
    const id = `${link.relationship}:${link.artifactId}`;
    if (ids.has(id)) throw new Error("Manifest links must be unique");
    ids.add(id);
  }
}

function validateUnit(unit: AggregateReportCellV1["unit"]): void {
  if (!( ["currency", "count", "ratio", "percentage", "days"] as const).includes(unit)) {
    throw new Error("Unsupported report measure unit");
  }
}

function validateSigningKey(key: ReportSigningKeyV1): void {
  exactKeys(key, "report signing key", ["algorithm", "keyId", "publicKeyFingerprint", "privateKey", "publicKey"]);
  if (key.algorithm !== "Ed25519") throw new Error("Unsupported report signing algorithm");
  identifier(key.keyId, "signing keyId");
  hash(key.publicKeyFingerprint, "publicKeyFingerprint");
  assertEd25519Key(key.privateKey, "private", "privateKey");
  assertEd25519Key(key.publicKey, "public", "publicKey");
  if (publicKeyFingerprint(key.publicKey) !== key.publicKeyFingerprint) throw new Error("Signing key fingerprint mismatch");
}

function validateVerificationKey(key: ReportVerificationKeyV1): void {
  exactKeys(key, "report verification key", ["algorithm", "keyId", "publicKeyFingerprint", "publicKey"]);
  if (key.algorithm !== "Ed25519") throw new Error("Unsupported report verification algorithm");
  identifier(key.keyId, "verification keyId");
  hash(key.publicKeyFingerprint, "publicKeyFingerprint");
  assertEd25519Key(key.publicKey, "public", "publicKey");
  if (publicKeyFingerprint(key.publicKey) !== key.publicKeyFingerprint) throw new Error("Verification key fingerprint mismatch");
}

function validateExpectation(
  expectation: ReportVerificationExpectationV1,
  signed: SignedReportPackV1
): void {
  exactKeys(expectation, "report verification expectation", [
    ...(expectation.tenantId === undefined ? [] : ["tenantId"]),
    ...(expectation.reportId === undefined ? [] : ["reportId"]),
    ...(expectation.reportHash === undefined ? [] : ["reportHash"]),
    ...(expectation.maximumSignedAt === undefined ? [] : ["maximumSignedAt"])
  ]);
  if (expectation.tenantId !== undefined && signed.report.tenantId !== expectation.tenantId) {
    throw new Error("Signed report tenant expectation failed");
  }
  if (expectation.reportId !== undefined && signed.report.reportId !== expectation.reportId) {
    throw new Error("Signed report id expectation failed");
  }
  if (expectation.reportHash !== undefined) {
    hash(expectation.reportHash, "expected reportHash");
    if (signed.report.reportHash !== expectation.reportHash) throw new Error("Signed report hash expectation failed");
  }
  if (expectation.maximumSignedAt !== undefined) {
    isoTimestamp(expectation.maximumSignedAt, "maximumSignedAt");
    if (signed.signedAt > expectation.maximumSignedAt) throw new Error("Signed report is newer than permitted");
  }
}

function assertEd25519Key(key: KeyObject, type: "private" | "public", label: string): void {
  if (key.type !== type || key.asymmetricKeyType !== "ed25519") {
    throw new Error(`${label} must be an Ed25519 ${type} key`);
  }
}

function spkiBytes(publicKey: KeyObject): Buffer {
  return publicKey.export({ type: "spki", format: "der" });
}

function publicKeyFingerprint(publicKey: KeyObject): string {
  return createHash("sha256").update(spkiBytes(publicKey)).digest("hex");
}

function signingBytes(unsigned: Omit<SignedReportPackV1, "signature">): Buffer {
  return Buffer.from(`${SIGNING_DOMAIN}${stableJson(unsigned)}`, "utf8");
}

function ratio(value: string, label: string): Decimal {
  const decimal = exactDecimal(value, label);
  if (decimal.isNegative() || decimal.greaterThan(1)) throw new Error(`${label} must be between 0 and 1`);
  return decimal;
}

function exactDecimal(value: string, label: string): Decimal {
  if (typeof value !== "string" || !DECIMAL.test(value)) throw new Error(`${label} must be a canonical exact decimal string`);
  const decimal = new ExactDecimal(value);
  const canonical = decimal.isZero() ? "0" : decimal.toFixed();
  if (!decimal.isFinite() || canonical !== value) throw new Error(`${label} must be a canonical exact decimal string`);
  return decimal;
}

function exactKeys(value: object, label: string, expected: readonly string[]): void {
  const actual = Object.keys(value).sort(compareText);
  const allowed = [...expected].sort(compareText);
  if (actual.length !== allowed.length || actual.some((key, index) => key !== allowed[index])) {
    throw new Error(`${label} contains unsupported or missing fields`);
  }
}

function identifier(value: string, label: string): void {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) throw new Error(`${label} is invalid`);
}

function hash(value: string, label: string): void {
  if (typeof value !== "string" || !HASH.test(value)) throw new Error(`${label} must be a SHA-256 hex hash`);
}

function displayText(value: string, label: string, maximumLength: number): void {
  if (
    typeof value !== "string" ||
    value.trim() !== value ||
    value.length === 0 ||
    value.length > maximumLength ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error(`${label} is invalid`);
  }
}

function isoDate(value: string, label: string): void {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) throw new Error(`${label} must be YYYY-MM-DD`);
  const parsed = new Date(`${value}T00:00:00.000Z`);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== value) throw new Error(`${label} is invalid`);
}

function isoTimestamp(value: string, label: string): void {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) {
    throw new Error(`${label} must be a UTC ISO timestamp`);
  }
  if (!Number.isFinite(Date.parse(value))) throw new Error(`${label} is invalid`);
}

function fingerprint(value: unknown): string {
  return createHash("sha256").update(stableJson(value), "utf8").digest("hex");
}

function stableJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("Canonical JSON numbers must be safe integers");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => compareText(left, right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`)
      .join(",")}}`;
  }
  throw new Error("Value cannot be represented in canonical JSON");
}

function sortedRecord<T>(value: Readonly<Record<string, T>>): Readonly<Record<string, T>> {
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) => compareText(left, right)));
}

function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort(compareText);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value as Record<string, unknown>)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}
