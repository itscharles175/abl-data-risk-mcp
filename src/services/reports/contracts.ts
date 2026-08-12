import type { KeyObject } from "node:crypto";

import type { CertifiedPopulationRefV1, DecimalString } from "../../domain/abl-v2/contracts.js";

export type ReportMeasureUnitV1 = "currency" | "count" | "ratio" | "percentage" | "days";

export interface ReportCellLineageV1 {
  readonly cellPopulationHash: string;
  readonly sourcePopulationHashes: readonly string[];
  readonly certificationHashes: readonly string[];
  readonly metricDefinitionHash: string;
  readonly methodologyHash: string;
}

export interface AggregateReportCellV1 {
  readonly value: DecimalString | null;
  readonly unit: ReportMeasureUnitV1;
  readonly coverage: DecimalString;
  readonly suppressed: boolean;
  readonly suppressionReason?: "minimum_cohort" | "differencing_risk" | "field_policy";
  readonly lineage: ReportCellLineageV1;
}

export interface AggregateReportRowV1 {
  /** Governed category labels only; record-level identifiers are prohibited. */
  readonly dimensions: Readonly<Record<string, string>>;
  readonly measures: Readonly<Record<string, AggregateReportCellV1>>;
  readonly rowPopulationHash: string;
}

export interface AggregateReportTableV1 {
  readonly tableId: string;
  readonly title: string;
  readonly dimensionColumns: readonly string[];
  readonly measureColumns: readonly string[];
  readonly rows: readonly AggregateReportRowV1[];
}

export interface AggregateReportChartV1 {
  readonly chartId: string;
  readonly title: string;
  readonly chartType: "bar" | "line" | "stacked_bar" | "heatmap";
  readonly tableId: string;
  readonly xDimension: string;
  readonly series: readonly string[];
}

export interface ReportWarningV1 {
  readonly warningId: string;
  readonly severity: "info" | "warning" | "critical";
  readonly code: string;
  readonly message: string;
  readonly relatedHashes: readonly string[];
}

export interface ReportExplanationV1 {
  readonly explanationId: string;
  readonly subjectId: string;
  readonly text: string;
  readonly methodologyHash: string;
  readonly populationHashes: readonly string[];
}

export interface ReportComparisonV1 {
  readonly comparisonId: string;
  readonly label: string;
  readonly metricId: string;
  readonly unit: ReportMeasureUnitV1;
  readonly leftPeriod: string;
  readonly rightPeriod: string;
  readonly leftValue: DecimalString;
  readonly rightValue: DecimalString;
  readonly delta: DecimalString;
  readonly lineage: ReportCellLineageV1;
}

export interface ReportManifestLinkV1 {
  readonly artifactId: string;
  readonly contentHash: string;
  readonly mediaType: string;
  readonly relationship: "data_manifest" | "chart_artifact" | "methodology" | "certification";
}

export interface ReportPackDraftV1 {
  readonly schemaVersion: "1";
  readonly reportId: string;
  readonly tenantId: string;
  readonly portfolioId: string;
  readonly facilityId?: string;
  readonly title: string;
  readonly reportDefinitionHash: string;
  readonly methodologyBundleHash: string;
  readonly reportingPeriod: {
    readonly from: string;
    readonly to: string;
    readonly knowledgeCutoff: string;
  };
  readonly createdBy: string;
  readonly createdAt: string;
  readonly certifiedPopulations: readonly CertifiedPopulationRefV1[];
  readonly tables: readonly AggregateReportTableV1[];
  readonly charts: readonly AggregateReportChartV1[];
  readonly warnings: readonly ReportWarningV1[];
  readonly explanations: readonly ReportExplanationV1[];
  readonly suppression: {
    readonly policyHash: string;
    readonly minimumCohortSize: number;
    readonly suppressedCellCount: number;
  };
  readonly comparisons: readonly ReportComparisonV1[];
  readonly manifestLinks: readonly ReportManifestLinkV1[];
}

export interface ReportPackV1 extends ReportPackDraftV1 {
  readonly reportHash: string;
}

export interface ReportSigningKeyV1 {
  readonly algorithm: "Ed25519";
  readonly keyId: string;
  readonly publicKeyFingerprint: string;
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
}

export interface ReportVerificationKeyV1 {
  readonly algorithm: "Ed25519";
  readonly keyId: string;
  readonly publicKeyFingerprint: string;
  readonly publicKey: KeyObject;
}

export interface SignedReportPackV1 {
  readonly schemaVersion: "1";
  readonly algorithm: "Ed25519";
  readonly keyId: string;
  readonly publicKeyFingerprint: string;
  readonly signedAt: string;
  readonly report: ReportPackV1;
  readonly signature: string;
}

export interface ReportVerificationExpectationV1 {
  readonly tenantId?: string;
  readonly reportId?: string;
  readonly reportHash?: string;
  readonly maximumSignedAt?: string;
}
