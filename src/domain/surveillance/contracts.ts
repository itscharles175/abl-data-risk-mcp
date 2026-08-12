/**
 * Versioned contracts for deterministic portfolio-surveillance analytics.
 *
 * All quantities crossing this boundary are canonical decimal strings. The
 * engine never accepts JavaScript numbers for balances, rates, or counts that
 * form part of a result.
 */

export type DecimalString = string;
export type CanonicalSurveillanceRecord = Readonly<Record<string, unknown>>;

export type FilterScalarV1 = string | boolean;

export type FilterExpressionV1 =
  | {
      readonly op: "eq" | "neq";
      readonly field: string;
      readonly value: FilterScalarV1;
    }
  | {
      readonly op: "in";
      readonly field: string;
      readonly values: readonly FilterScalarV1[];
    }
  | {
      readonly op: "gt" | "gte" | "lt" | "lte";
      readonly field: string;
      readonly value: DecimalString;
    }
  | {
      readonly op: "is_null";
      readonly field: string;
      readonly value: boolean;
    }
  | {
      readonly op: "and" | "or";
      readonly clauses: readonly FilterExpressionV1[];
    };

export interface DefinitionApprovalV1 {
  readonly status: "approved";
  readonly proposedBy: string;
  readonly approvedBy: string;
  readonly approvedAt: string;
}

export interface MeasureDefinitionV1 {
  readonly label: string;
  readonly aggregation: "count" | "sum" | "weighted_average";
  readonly field?: string;
  readonly predicate?: FilterExpressionV1;
}

export interface MetricWindowV1 {
  readonly kind: "snapshot" | "adjacent_periods" | "ever_to_date" | "event_lag";
  /** Maximum number of ordered snapshots consumed by the calculation. */
  readonly maximumPeriods: number;
}

export interface MetricCoverageRequirementV1 {
  /** Canonical ratio in the inclusive range [0, 1]. */
  readonly minimumRatio: DecimalString;
  readonly minimumObservedRecords: number;
}

export interface MetricPrivacyV1 {
  readonly minimumCellCount: number;
  readonly complementarySuppression: true;
}

export interface CohortDefinitionV1 {
  readonly schemaVersion: "1";
  readonly definitionType: "cohort_definition";
  readonly definitionId: string;
  readonly version: number;
  readonly name: string;
  readonly dateField: string;
  readonly grain: "month" | "quarter" | "year";
  readonly population?: FilterExpressionV1;
  readonly maximumCohorts: number;
  readonly approval: DefinitionApprovalV1;
}

export interface NumericBinV1 {
  readonly label: string;
  readonly lower?: DecimalString;
  readonly upper?: DecimalString;
  readonly includeLower?: boolean;
  readonly includeUpper?: boolean;
}

export interface BinDefinitionV1 {
  readonly schemaVersion: "1";
  readonly definitionType: "bin_definition";
  readonly definitionId: string;
  readonly version: number;
  readonly name: string;
  readonly field: string;
  readonly bins: readonly NumericBinV1[];
  readonly unknownLabel: string;
  readonly otherLabel: string;
  readonly approval: DefinitionApprovalV1;
}

export interface EntityResolutionMappingV1 {
  readonly sourceSystem: string;
  readonly sourceEntityId: string;
  readonly canonicalEntityId: string;
}

export interface EntityResolutionDefinitionV1 {
  readonly schemaVersion: "1";
  readonly definitionType: "entity_resolution_definition";
  readonly definitionId: string;
  readonly version: number;
  readonly tenantId: string;
  readonly sourceField: "borrower_id" | "account_debtor_id";
  readonly mappings: readonly EntityResolutionMappingV1[];
  readonly approval: DefinitionApprovalV1;
}

export interface RollCureConfigurationV1 {
  readonly kind: "roll_cure";
  readonly delinquencyField: string;
  readonly balanceField: string;
  readonly binDefinitionId: string;
}

export interface DefaultEverConfigurationV1 {
  readonly kind: "default_ever";
  readonly defaultFlagField: string;
  readonly daysPastDueField: string;
  readonly balanceField: string;
  readonly everDpdThresholds: readonly number[];
  readonly incidenceBasis: "count" | "balance";
}

export interface LossRecoveryConfigurationV1 {
  readonly kind: "loss_recovery";
  readonly grossLossField: string;
  readonly recoveryField: string;
  readonly denominatorField: string;
  readonly defaultDateField: string;
  readonly flowSemantics: "period" | "cumulative";
}

export interface PaydownPrepaymentConfigurationV1 {
  readonly kind: "paydown_prepayment";
  readonly balanceField: string;
  /** When omitted, paydown is available and prepayment is explicitly unavailable. */
  readonly scheduledPrincipalField?: string;
}

export interface RatingMigrationConfigurationV1 {
  readonly kind: "rating_migration";
  readonly ratingField: string;
  readonly balanceField: string;
}

export interface BalanceUtilizationConfigurationV1 {
  readonly kind: "balance_utilization";
  readonly balanceField: string;
  readonly originalBalanceField: string;
  readonly commitmentField: string;
  /** Optional governed cohort dimension for longitudinal trajectory curves. */
  readonly cohortDefinitionId?: string;
}

export interface MaturityWindowV1 {
  readonly label: string;
  readonly endingMonth: number;
}

export interface MaturityWallConfigurationV1 {
  readonly kind: "maturity_wall";
  readonly maturityDateField: string;
  readonly balanceField: string;
  readonly windows: readonly MaturityWindowV1[];
  readonly includeMatured: boolean;
}

export interface ConcentrationConfigurationV1 {
  readonly kind: "concentration";
  readonly dimensionField: string;
  readonly balanceField: string;
  readonly topN: number;
  readonly binDefinitionId?: string;
  /** Identifier-valued dimensions require this approved, tenant-bound definition. */
  readonly entityResolutionDefinitionId?: string;
}

export interface PeriodComparisonConfigurationV1 {
  readonly kind: "period_comparison";
  readonly balanceField: string;
  readonly dimensionField?: string;
}

export type MetricConfigurationV1 =
  | RollCureConfigurationV1
  | DefaultEverConfigurationV1
  | LossRecoveryConfigurationV1
  | PaydownPrepaymentConfigurationV1
  | RatingMigrationConfigurationV1
  | BalanceUtilizationConfigurationV1
  | MaturityWallConfigurationV1
  | ConcentrationConfigurationV1
  | PeriodComparisonConfigurationV1;

export type MetricFamilyV1 = MetricConfigurationV1["kind"];

export interface MetricDefinitionV1 {
  readonly schemaVersion: "1";
  readonly definitionType: "metric_definition";
  readonly definitionId: string;
  readonly version: number;
  readonly name: string;
  readonly family: MetricFamilyV1;
  readonly grain: "loan" | "entity" | "portfolio";
  readonly unit: "count" | "currency" | "ratio" | "days";
  readonly temporalSemantics: "point_in_time" | "period_flow" | "cumulative" | "transition";
  readonly numerator: MeasureDefinitionV1;
  readonly denominator: MeasureDefinitionV1 | null;
  readonly window: MetricWindowV1;
  readonly population: FilterExpressionV1 | null;
  readonly nullPolicy: "exclude" | "zero" | "unavailable";
  readonly coverage: MetricCoverageRequirementV1;
  readonly privacy: MetricPrivacyV1;
  readonly maximumCells: number;
  readonly configuration: MetricConfigurationV1;
  readonly approval: DefinitionApprovalV1;
}

export interface CertifiedSurveillanceSnapshotV1 {
  readonly schemaVersion: "1";
  readonly snapshotId: string;
  readonly tenantId: string;
  readonly asOfDate: string;
  readonly snapshotHash: string;
  readonly certification: {
    readonly status: "certified";
    readonly certificationId: string;
    readonly certificationHash: string;
    readonly certifiedAt: string;
  };
  readonly records: readonly CanonicalSurveillanceRecord[];
}

export interface SurveillanceMethodologyV1 {
  readonly methodologyId: string;
  readonly methodologyVersion: number;
  readonly methodologyHash: string;
}

export interface SurveillanceExecutionBoundsV1 {
  readonly maxSnapshots: number;
  readonly maxRecords: number;
  readonly maxMetrics: number;
  readonly maxCells: number;
}

export type MetricAvailabilityReasonV1 =
  | "available"
  | "no_records"
  | "missing_required_field"
  | "insufficient_coverage"
  | "unseasoned"
  | "no_prior_period"
  | "division_by_zero"
  | "entity_resolution_unapproved"
  | "suppressed";

export interface MetricCellLineageV1 {
  readonly definitionHash: string;
  readonly supportingDefinitionHashes: readonly string[];
  readonly methodologyId: string;
  readonly methodologyVersion: number;
  readonly methodologyHash: string;
  readonly snapshotHashes: readonly string[];
  readonly populationHash: string;
  readonly entityResolutionHash: string | null;
}

export interface MetricCellV1 {
  readonly cellId: string;
  readonly metric: string;
  readonly unit: "count" | "currency" | "ratio" | "days";
  readonly dimensions: Readonly<Record<string, string>>;
  readonly numerator: DecimalString | null;
  readonly denominator: DecimalString | null;
  readonly value: DecimalString | null;
  readonly coverage: {
    readonly observedCount: DecimalString | null;
    readonly eligibleCount: DecimalString | null;
    readonly ratio: DecimalString | null;
  };
  readonly available: boolean;
  readonly availabilityReason: MetricAvailabilityReasonV1;
  readonly suppressed: boolean;
  readonly lineage: MetricCellLineageV1;
}

export interface SurveillanceMetricResultV1 {
  readonly schemaVersion: "1";
  readonly metricDefinitionId: string;
  readonly metricDefinitionVersion: number;
  readonly family: MetricFamilyV1;
  readonly cells: readonly MetricCellV1[];
  readonly warnings: readonly string[];
  readonly lineage: {
    readonly definitionHash: string;
    readonly supportingDefinitionHashes: readonly string[];
    readonly methodologyId: string;
    readonly methodologyVersion: number;
    readonly methodologyHash: string;
    readonly analysisHash: string;
  };
}

export interface PortfolioSurveillanceInputV1 {
  readonly tenantId: string;
  readonly snapshots: readonly CertifiedSurveillanceSnapshotV1[];
  readonly metricDefinitions: readonly MetricDefinitionV1[];
  readonly cohortDefinitions?: readonly CohortDefinitionV1[];
  readonly binDefinitions?: readonly BinDefinitionV1[];
  readonly entityResolutionDefinitions?: readonly EntityResolutionDefinitionV1[];
  readonly methodology: SurveillanceMethodologyV1;
  readonly bounds: SurveillanceExecutionBoundsV1;
}

export interface PortfolioSurveillanceResultV1 {
  readonly schemaVersion: "1";
  readonly tenantId: string;
  readonly asOfDates: readonly string[];
  readonly metrics: readonly SurveillanceMetricResultV1[];
  readonly lineage: {
    readonly methodologyId: string;
    readonly methodologyVersion: number;
    readonly methodologyHash: string;
    readonly snapshotHashes: readonly string[];
    readonly analysisHash: string;
  };
}
