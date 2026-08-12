export type DecimalString = string;
export type CollateralClassV2 = "accounts_receivable" | "inventory" | "equipment" | "cash";

export interface CertifiedPopulationRefV1 {
  readonly schemaVersion: "1";
  readonly tenantId: string;
  readonly populationId: string;
  readonly snapshotId: string;
  readonly asOfDate: string;
  readonly status: "certified";
  readonly populationHash: string;
  readonly certificationHash: string;
}

interface BaseCollateralRecordV2 {
  readonly recordId: string;
  readonly collateralClass: CollateralClassV2;
  readonly grossValue: DecimalString;
  readonly eligible: boolean;
  /** Approved grouping token, never a raw debtor or customer name. */
  readonly concentrationGroup?: string;
}

export interface AccountsReceivableCollateralV2 extends BaseCollateralRecordV2 {
  readonly collateralClass: "accounts_receivable";
  readonly eligibleAmount: DecimalString;
}

export interface InventoryCollateralV2 extends BaseCollateralRecordV2 {
  readonly collateralClass: "inventory";
  readonly nolv: DecimalString;
}

export interface EquipmentCollateralV2 extends BaseCollateralRecordV2 {
  readonly collateralClass: "equipment";
  readonly appraisedValue: DecimalString;
}

export interface CashCollateralV2 extends BaseCollateralRecordV2 {
  readonly collateralClass: "cash";
  readonly clearedBalance: DecimalString;
}

export type CollateralRecordV2 =
  | AccountsReceivableCollateralV2
  | InventoryCollateralV2
  | EquipmentCollateralV2
  | CashCollateralV2;

export interface CertifiedCollateralPopulationV2 {
  readonly certification: CertifiedPopulationRefV1;
  readonly collateralClass: CollateralClassV2;
  readonly records: readonly CollateralRecordV2[];
}

export interface ApprovalEvidenceV1 {
  readonly status: "approved";
  readonly proposedBy: string;
  readonly approvedBy: string;
  readonly approvedAt: string;
  readonly authorityRef: string;
  readonly rationale: string;
}

export interface ConcentrationTierV2 {
  readonly tierId: string;
  /** Inclusive group amount ceiling. The final tier must be unbounded. */
  readonly upToGroupAmount?: DecimalString;
  readonly maximumShare: DecimalString;
}

export interface TieredConcentrationPolicyV2 {
  readonly ruleId: string;
  readonly tiers: readonly ConcentrationTierV2[];
}

export interface ComponentPolicyV2 {
  readonly componentId: string;
  readonly collateralClass: CollateralClassV2;
  readonly valueBasis: "eligible_amount" | "nolv" | "appraised_value" | "cleared_balance";
  readonly advanceRate: DecimalString;
  readonly componentSublimit?: DecimalString;
  readonly concentration?: TieredConcentrationPolicyV2;
}

export type ReserveFormulaV2 =
  | { readonly kind: "fixed_amount"; readonly amount: DecimalString }
  | {
      readonly kind: "percentage";
      readonly basis: "facility_gross" | "facility_eligible" | "facility_contribution" | "component_gross" | "component_eligible" | "component_contribution";
      readonly rate: DecimalString;
    }
  | {
      readonly kind: "amount_above";
      readonly basis: "facility_gross" | "facility_eligible" | "facility_contribution" | "component_gross" | "component_eligible" | "component_contribution";
      readonly threshold: DecimalString;
      readonly rate: DecimalString;
    }
  | { readonly kind: "sum"; readonly terms: readonly ReserveFormulaV2[] };

export interface FormulaReserveV2 {
  readonly reserveId: string;
  readonly label: string;
  readonly componentId?: string;
  readonly formula: ReserveFormulaV2;
}

export interface AvailabilityTriggerV2 {
  readonly triggerId: string;
  readonly condition:
    | "excess_availability_below"
    | "overadvance_above"
    | "utilization_above";
  readonly threshold: DecimalString;
  readonly action: "availability_block" | "cash_dominion";
  readonly blockAmount?: DecimalString;
}

export interface CovenantTestInputV2 {
  readonly covenantId: string;
  readonly label: string;
  readonly comparator: "gte" | "lte";
  readonly threshold: DecimalString;
  readonly actualValue: DecimalString;
}

export interface DocumentTicklerInputV2 {
  readonly ticklerId: string;
  readonly kind: "appraisal" | "field_exam" | "ucc" | "insurance";
  readonly dueDate: string;
  readonly completedAt?: string;
  readonly waiver?: ApprovalEvidenceV1;
}

export interface BorrowingBasePolicyV2 {
  readonly schemaVersion: "2";
  readonly policyId: string;
  readonly version: string;
  readonly policyHash: string;
  readonly tenantId: string;
  readonly facilityId: string;
  readonly currencyCode: string;
  readonly effectiveFrom: string;
  readonly effectiveTo?: string;
  readonly commitmentAmount: DecimalString;
  readonly components: readonly ComponentPolicyV2[];
  readonly reserves: readonly FormulaReserveV2[];
  readonly triggers: readonly AvailabilityTriggerV2[];
  readonly ticklerWarningDays: number;
  readonly approval: ApprovalEvidenceV1;
}

export type GovernedAdjustmentV2 =
  | {
      readonly adjustmentId: string;
      readonly kind: "advance_rate_override";
      readonly componentId: string;
      readonly value: DecimalString;
      readonly effectiveFrom: string;
      readonly effectiveTo?: string;
      readonly approval: ApprovalEvidenceV1;
    }
  | {
      readonly adjustmentId: string;
      readonly kind: "component_sublimit_override";
      readonly componentId: string;
      readonly value: DecimalString;
      readonly effectiveFrom: string;
      readonly effectiveTo?: string;
      readonly approval: ApprovalEvidenceV1;
    }
  | {
      readonly adjustmentId: string;
      readonly kind: "component_sublimit_waiver";
      readonly componentId: string;
      readonly effectiveFrom: string;
      readonly effectiveTo?: string;
      readonly approval: ApprovalEvidenceV1;
    }
  | {
      readonly adjustmentId: string;
      readonly kind: "reserve_override";
      readonly reserveId: string;
      readonly value: DecimalString;
      readonly effectiveFrom: string;
      readonly effectiveTo?: string;
      readonly approval: ApprovalEvidenceV1;
    }
  | {
      readonly adjustmentId: string;
      readonly kind: "reserve_waiver";
      readonly reserveId: string;
      readonly effectiveFrom: string;
      readonly effectiveTo?: string;
      readonly approval: ApprovalEvidenceV1;
    }
  | {
      readonly adjustmentId: string;
      readonly kind: "availability_block";
      readonly value: DecimalString;
      readonly effectiveFrom: string;
      readonly effectiveTo?: string;
      readonly approval: ApprovalEvidenceV1;
    };

export interface FacilityUsageV2 {
  readonly usageId: string;
  readonly kind: "revolver" | "letters_of_credit" | "swingline" | "other";
  readonly amount: DecimalString;
}

export interface BorrowerSubmittedCertificateV2 {
  readonly certificateId: string;
  readonly submittedAt: string;
  readonly componentContributions: Readonly<Record<string, DecimalString>>;
  readonly totalReserves: DecimalString;
  readonly availabilityBlocks: DecimalString;
  readonly borrowingCapacity: DecimalString;
  readonly totalUsage: DecimalString;
  readonly excessAvailability: DecimalString;
}

export interface ComponentConcentrationResultV2 {
  readonly group: string;
  readonly tierId: string;
  readonly preConcentrationAmount: DecimalString;
  readonly maximumShare: DecimalString;
  readonly capAmount: DecimalString;
  readonly excessAmount: DecimalString;
}

export interface BorrowingBaseComponentResultV2 {
  readonly componentId: string;
  readonly collateralClass: CollateralClassV2;
  readonly recordCount: number | null;
  readonly grossValue: DecimalString | null;
  readonly preConcentrationEligibleValue: DecimalString | null;
  readonly concentrationExcess: DecimalString | null;
  readonly eligibleValue: DecimalString | null;
  readonly advanceRate: DecimalString | null;
  readonly advancedValue: DecimalString | null;
  readonly componentSublimit: DecimalString | null;
  readonly contribution: DecimalString;
  readonly concentrations: readonly ComponentConcentrationResultV2[];
  readonly populationHashes: readonly string[];
}

export interface ReserveResultV2 {
  readonly reserveId: string;
  readonly label: string;
  readonly amount: DecimalString;
  readonly formulaHash: string;
  readonly overridden: boolean;
  readonly waived: boolean;
}

export interface BorrowingBaseStateV2 {
  readonly state: "borrower_submitted" | "system_reperformed" | "approved_adjusted";
  readonly components: readonly BorrowingBaseComponentResultV2[];
  readonly totalComponentContribution: DecimalString;
  readonly reserves: readonly ReserveResultV2[];
  readonly totalReserves: DecimalString;
  readonly availabilityBlocks: DecimalString;
  readonly borrowingCapacity: DecimalString;
  readonly totalUsage: DecimalString;
  readonly excessAvailability: DecimalString;
  readonly overadvance: DecimalString;
  readonly stateHash: string;
}

export interface BorrowingBaseVarianceV2 {
  readonly metric: string;
  readonly leftState: BorrowingBaseStateV2["state"];
  readonly rightState: BorrowingBaseStateV2["state"];
  readonly leftValue: DecimalString;
  readonly rightValue: DecimalString;
  readonly variance: DecimalString;
}

export interface TriggerResultV2 {
  readonly triggerId: string;
  readonly condition: AvailabilityTriggerV2["condition"];
  readonly action: AvailabilityTriggerV2["action"];
  readonly threshold: DecimalString;
  readonly observedValue: DecimalString;
  readonly activated: boolean;
  readonly appliedBlockAmount: DecimalString;
}

export interface CovenantResultV2 {
  readonly covenantId: string;
  readonly label: string;
  readonly comparator: "gte" | "lte";
  readonly threshold: DecimalString;
  readonly actualValue: DecimalString;
  /** Positive or zero passes; a negative value is the amount of the breach. */
  readonly headroom: DecimalString;
  readonly status: "pass" | "breach";
}

export interface TicklerResultV2 {
  readonly ticklerId: string;
  readonly kind: DocumentTicklerInputV2["kind"];
  readonly dueDate: string;
  readonly status: "current" | "due_soon" | "overdue" | "completed" | "waived";
  readonly daysUntilDue: number;
}

export interface CalculateBorrowingBaseV2Input {
  readonly tenantId: string;
  readonly facilityId: string;
  readonly asOfDate: string;
  readonly policy: BorrowingBasePolicyV2;
  readonly populations: readonly CertifiedCollateralPopulationV2[];
  readonly usage: readonly FacilityUsageV2[];
  readonly borrowerSubmitted?: BorrowerSubmittedCertificateV2;
  readonly adjustments?: readonly GovernedAdjustmentV2[];
  readonly covenants?: readonly CovenantTestInputV2[];
  readonly ticklers?: readonly DocumentTicklerInputV2[];
}

export interface BorrowingBaseResultV2 {
  readonly schemaVersion: "2";
  readonly calculationType: "multi_component_borrowing_base";
  readonly tenantId: string;
  readonly facilityId: string;
  readonly asOfDate: string;
  readonly currencyCode: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly policyHash: string;
  readonly states: {
    readonly borrowerSubmitted: BorrowingBaseStateV2 | null;
    readonly systemReperformed: BorrowingBaseStateV2;
    readonly approvedAdjusted: BorrowingBaseStateV2;
  };
  readonly variances: readonly BorrowingBaseVarianceV2[];
  readonly appliedAdjustments: readonly {
    readonly adjustmentId: string;
    readonly kind: GovernedAdjustmentV2["kind"];
    readonly adjustmentHash: string;
    readonly proposedBy: string;
    readonly approvedBy: string;
  }[];
  readonly triggers: readonly TriggerResultV2[];
  readonly covenants: readonly CovenantResultV2[];
  readonly ticklers: readonly TicklerResultV2[];
  readonly cashDominionActive: boolean;
  readonly lineage: {
    readonly certifiedPopulationHashes: readonly string[];
    readonly certificationHashes: readonly string[];
    readonly analysisHash: string;
  };
}

export interface CounterfactualComponentAssumptionV1 {
  readonly componentId: string;
  readonly advanceRateMultiplier?: DecimalString;
  readonly eligibleValueMultiplier?: DecimalString;
}

export interface CounterfactualScenarioV1 {
  readonly schemaVersion: "1";
  readonly scenarioId: string;
  readonly tenantId: string;
  readonly baseAnalysisHash: string;
  readonly createdBy: string;
  readonly createdAt: string;
  readonly componentAssumptions: readonly CounterfactualComponentAssumptionV1[];
  readonly reserveDelta: DecimalString;
  readonly commitmentAmountOverride?: DecimalString;
}

export interface CounterfactualBorrowingBaseResultV1 {
  readonly scenarioId: string;
  readonly baseAnalysisHash: string;
  readonly assumptionsHash: string;
  readonly result: BorrowingBaseResultV2;
  readonly scenarioHash: string;
}

export interface CashTransactionV1 {
  readonly transactionId: string;
  readonly kind: "lockbox_receipt" | "cash_application" | "loan_paydown";
  readonly effectiveDate: string;
  readonly amount: DecimalString;
  readonly referenceId: string;
}

export interface CashReconciliationInputV1 {
  readonly tenantId: string;
  readonly facilityId: string;
  readonly asOfDate: string;
  readonly certification: CertifiedPopulationRefV1;
  readonly openingLoanBalance: DecimalString;
  readonly reportedEndingLoanBalance: DecimalString;
  readonly transactions: readonly CashTransactionV1[];
}

export interface CashReconciliationResultV1 {
  readonly schemaVersion: "1";
  readonly reconciliationType: "lockbox_cash_application_paydown";
  readonly lockboxReceipts: DecimalString;
  readonly cashApplications: DecimalString;
  readonly unappliedCash: DecimalString;
  readonly loanPaydowns: DecimalString;
  readonly cashAppliedVsPaydownDifference: DecimalString;
  readonly expectedEndingLoanBalance: DecimalString;
  readonly reportedEndingLoanBalance: DecimalString;
  readonly endingLoanBalanceDifference: DecimalString;
  readonly passed: boolean;
  readonly breaks: readonly {
    readonly code: "negative_unapplied_cash" | "cash_application_paydown_mismatch" | "ending_balance_mismatch";
    readonly amount: DecimalString;
  }[];
  readonly lineage: {
    readonly populationHash: string;
    readonly certificationHash: string;
    readonly reconciliationHash: string;
  };
}
