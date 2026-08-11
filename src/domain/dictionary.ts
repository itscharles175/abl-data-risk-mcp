/**
 * Canonical field dictionary for loan-tape and asset-based lending (ABL) data.
 *
 * The dictionary is deliberately vendor-neutral. Source-system names belong in
 * `aliases`; canonical ids are stable integration keys and should not be changed
 * casually once persisted in a mapping specification.
 */

export const DICTIONARY_VERSION = "1.0.0" as const;

export type AnalysisProfile =
  | "base"
  | "stratification"
  | "vintage"
  | "borrowing_base";

export type LogicalType =
  | "identifier"
  | "string"
  | "integer"
  | "decimal"
  | "boolean"
  | "date"
  | "datetime"
  | "currency"
  | "percentage";

export type DataSensitivity =
  | "non_sensitive"
  | "internal"
  | "confidential"
  | "restricted";

export type FieldUnit =
  | "none"
  | "identifier"
  | "code"
  | "text"
  | "boolean"
  | "date"
  | "datetime"
  | "currency"
  | "iso_4217_currency_code"
  | "percent"
  | "ratio"
  | "basis_points"
  | "days"
  | "count";

export type AnalysisTag =
  | "identity"
  | "exposure"
  | "pricing"
  | "terms"
  | "performance"
  | "credit_risk"
  | "stratification"
  | "vintage"
  | "collateral"
  | "eligibility"
  | "borrowing_base"
  | "concentration"
  | "receivables"
  | "inventory"
  | "reserves"
  | "lineage";

export interface CanonicalFieldDefinition {
  readonly id: string;
  readonly label: string;
  readonly description: string;
  readonly logicalType: LogicalType;
  readonly aliases: readonly string[];
  /** Analysis profiles for which this field is a minimum readiness requirement. */
  readonly requiredFor: readonly AnalysisProfile[];
  readonly analysisTags: readonly AnalysisTag[];
  readonly sensitivity: DataSensitivity;
  readonly unit: FieldUnit;
  readonly semanticNotes: string;
}

/**
 * A compact but production-oriented first version of the canonical dictionary.
 * Amounts are intentionally currency-valued rather than floating-point-valued;
 * adapters should preserve source precision and currency.
 */
export const CANONICAL_FIELDS = [
  {
    id: "as_of_date",
    label: "As-of Date",
    description: "Effective date of the tape or collateral snapshot.",
    logicalType: "date",
    aliases: ["reporting_date", "snapshot_date", "cutoff_date", "data_date", "period_end_date", "asofdate"],
    requiredFor: ["base", "stratification", "vintage", "borrowing_base"],
    analysisTags: ["lineage", "stratification", "vintage", "borrowing_base"],
    sensitivity: "internal",
    unit: "date",
    semanticNotes: "Use the business-effective date, not the ingestion timestamp.",
  },
  {
    id: "source_system",
    label: "Source System",
    description: "System or platform from which the row originated.",
    logicalType: "string",
    aliases: ["system_of_record", "source", "platform", "src_system"],
    requiredFor: [],
    analysisTags: ["lineage"],
    sensitivity: "internal",
    unit: "text",
    semanticNotes: "Prefer a stable controlled value rather than a connection string or hostname.",
  },
  {
    id: "facility_id",
    label: "Facility ID",
    description: "Stable identifier for the credit facility or lending agreement.",
    logicalType: "identifier",
    aliases: ["facility_number", "facility_no", "credit_facility_id", "line_id", "deal_id", "account_id"],
    requiredFor: ["base", "stratification", "borrowing_base"],
    analysisTags: ["identity", "exposure", "borrowing_base"],
    sensitivity: "confidential",
    unit: "identifier",
    semanticNotes: "Must remain stable across reporting periods; do not reuse display labels as ids.",
  },
  {
    id: "loan_id",
    label: "Loan ID",
    description: "Stable identifier for an individual loan, draw, or note.",
    logicalType: "identifier",
    aliases: ["loan_number", "loan_no", "loan_account_number", "note_id", "contract_id", "instrument_id"],
    requiredFor: ["base", "vintage"],
    analysisTags: ["identity", "exposure", "vintage"],
    sensitivity: "restricted",
    unit: "identifier",
    semanticNotes: "Uniqueness is expected within a source system and as-of date.",
  },
  {
    id: "borrower_id",
    label: "Borrower ID",
    description: "Stable identifier for the legal borrower or borrower group.",
    logicalType: "identifier",
    aliases: ["customer_id", "client_id", "obligor_id", "borrower_number", "customer_number", "party_id"],
    requiredFor: ["base", "stratification"],
    analysisTags: ["identity", "concentration", "credit_risk"],
    sensitivity: "restricted",
    unit: "identifier",
    semanticNotes: "Document whether this represents a legal entity, household, or consolidated group.",
  },
  {
    id: "borrower_name",
    label: "Borrower Name",
    description: "Legal or reporting name of the borrower.",
    logicalType: "string",
    aliases: ["customer_name", "client_name", "obligor_name", "account_name", "legal_name"],
    requiredFor: [],
    analysisTags: ["identity", "concentration"],
    sensitivity: "restricted",
    unit: "text",
    semanticNotes: "May contain personal or commercially sensitive information; prefer ids in exported analysis.",
  },
  {
    id: "currency_code",
    label: "Currency Code",
    description: "Currency in which monetary values on the row are denominated.",
    logicalType: "string",
    aliases: ["currency", "ccy", "iso_currency", "currency_iso_code"],
    requiredFor: ["base", "borrowing_base"],
    analysisTags: ["exposure", "borrowing_base"],
    sensitivity: "non_sensitive",
    unit: "iso_4217_currency_code",
    semanticNotes: "Use an uppercase ISO 4217 code; mixed-currency tapes require row-level currency or explicit conversion.",
  },
  {
    id: "facility_type",
    label: "Facility Type",
    description: "Contractual form of the facility, such as revolver or term loan.",
    logicalType: "string",
    aliases: ["credit_type", "line_type", "facility_product", "loan_facility_type"],
    requiredFor: [],
    analysisTags: ["terms", "stratification"],
    sensitivity: "confidential",
    unit: "code",
    semanticNotes: "Normalize to a governed taxonomy while retaining the raw source value for lineage.",
  },
  {
    id: "product_type",
    label: "Product Type",
    description: "Lending product or instrument classification.",
    logicalType: "string",
    aliases: ["product", "loan_type", "instrument_type", "product_code"],
    requiredFor: [],
    analysisTags: ["stratification", "terms"],
    sensitivity: "internal",
    unit: "code",
    semanticNotes: "Use a consistent taxonomy across source systems before portfolio comparison.",
  },
  {
    id: "loan_status",
    label: "Loan Status",
    description: "Current lifecycle or performance status of the loan.",
    logicalType: "string",
    aliases: ["account_status", "facility_status", "status", "loan_state", "performance_status"],
    requiredFor: ["vintage"],
    analysisTags: ["performance", "credit_risk", "vintage", "stratification"],
    sensitivity: "confidential",
    unit: "code",
    semanticNotes: "Map source values to a governed set such as active, paid_off, defaulted, or charged_off.",
  },
  {
    id: "origination_date",
    label: "Origination Date",
    description: "Date the loan or facility was originated or initially funded.",
    logicalType: "date",
    aliases: ["booking_date", "open_date", "inception_date", "funding_date", "loan_origination_date", "issue_date"],
    requiredFor: ["vintage"],
    analysisTags: ["vintage", "terms", "stratification"],
    sensitivity: "confidential",
    unit: "date",
    semanticNotes: "Choose and document one convention when booking, closing, and first-funding dates differ.",
  },
  {
    id: "maturity_date",
    label: "Maturity Date",
    description: "Contractual final maturity date of the loan or facility.",
    logicalType: "date",
    aliases: ["expiration_date", "expiry_date", "due_date", "contract_maturity_date"],
    requiredFor: [],
    analysisTags: ["terms", "stratification", "credit_risk"],
    sensitivity: "confidential",
    unit: "date",
    semanticNotes: "Use contractual maturity unless the analysis explicitly requests expected maturity.",
  },
  {
    id: "original_balance",
    label: "Original Balance",
    description: "Principal balance at origination or initial funding.",
    logicalType: "currency",
    aliases: ["original_principal", "original_loan_amount", "orig_balance", "funded_amount", "initial_balance"],
    requiredFor: ["vintage"],
    analysisTags: ["exposure", "vintage"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "For revolving facilities, distinguish initial funded amount from commitment amount.",
  },
  {
    id: "commitment_amount",
    label: "Commitment Amount",
    description: "Total contractual lender commitment or line amount.",
    logicalType: "currency",
    aliases: ["committed_amount", "credit_limit", "line_amount", "facility_limit", "commitment", "approved_limit"],
    requiredFor: ["base"],
    analysisTags: ["exposure", "terms", "stratification"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Report gross commitment before usage; clarify lender share versus total syndicate commitment.",
  },
  {
    id: "outstanding_balance",
    label: "Outstanding Balance",
    description: "Principal or funded exposure outstanding at the as-of date.",
    logicalType: "currency",
    aliases: ["current_balance", "principal_balance", "ending_balance", "loan_balance", "funded_balance", "outstanding", "drawn_amount", "utilized_amount"],
    requiredFor: ["base", "stratification", "vintage", "borrowing_base"],
    analysisTags: ["exposure", "performance", "stratification", "vintage", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Use principal outstanding unless the source explicitly includes accrued interest or fees.",
  },
  {
    id: "undrawn_amount",
    label: "Undrawn Amount",
    description: "Committed capacity not funded at the as-of date.",
    logicalType: "currency",
    aliases: ["unused_commitment", "available_to_draw", "unfunded_amount", "remaining_commitment", "undrawn_commitment"],
    requiredFor: [],
    analysisTags: ["exposure", "stratification"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Usually commitment less funded usage, subject to borrowing-base and covenant restrictions.",
  },
  {
    id: "interest_rate",
    label: "Interest Rate",
    description: "All-in annual contractual interest rate at the as-of date.",
    logicalType: "percentage",
    aliases: ["coupon_rate", "all_in_rate", "current_rate", "loan_rate", "effective_interest_rate", "apr"],
    requiredFor: [],
    analysisTags: ["pricing", "stratification"],
    sensitivity: "confidential",
    unit: "percent",
    semanticNotes: "Canonical storage is percentage points (5.25 means 5.25%), not a decimal fraction.",
  },
  {
    id: "benchmark_rate",
    label: "Benchmark Rate",
    description: "Reference index rate underlying a floating-rate loan.",
    logicalType: "percentage",
    aliases: ["index_rate", "base_rate", "reference_rate", "sofr_rate", "prime_rate"],
    requiredFor: [],
    analysisTags: ["pricing"],
    sensitivity: "internal",
    unit: "percent",
    semanticNotes: "Record the applied rate after floors where possible and retain the benchmark name separately in source data.",
  },
  {
    id: "spread_bps",
    label: "Spread",
    description: "Contractual spread over the benchmark rate in basis points.",
    logicalType: "decimal",
    aliases: ["margin_bps", "credit_spread", "loan_spread", "rate_spread", "pricing_spread"],
    requiredFor: [],
    analysisTags: ["pricing", "stratification"],
    sensitivity: "confidential",
    unit: "basis_points",
    semanticNotes: "One percentage point equals 100 basis points.",
  },
  {
    id: "risk_rating",
    label: "Risk Rating",
    description: "Internal or external credit risk grade assigned at the as-of date.",
    logicalType: "string",
    aliases: ["credit_grade", "risk_grade", "internal_rating", "rating", "pd_grade"],
    requiredFor: [],
    analysisTags: ["credit_risk", "stratification"],
    sensitivity: "confidential",
    unit: "code",
    semanticNotes: "Rating scales are institution-specific; persist the scale name or mapping version with the dataset.",
  },
  {
    id: "days_past_due",
    label: "Days Past Due",
    description: "Number of calendar days the oldest contractual payment is past due.",
    logicalType: "integer",
    aliases: ["dpd", "past_due_days", "days_delinquent", "delinquency_days"],
    requiredFor: [],
    analysisTags: ["performance", "credit_risk", "stratification", "vintage"],
    sensitivity: "confidential",
    unit: "days",
    semanticNotes: "Use zero for current accounts; preserve null when delinquency status is unavailable.",
  },
  {
    id: "nonaccrual_flag",
    label: "Nonaccrual Flag",
    description: "Indicates that interest income is no longer being accrued.",
    logicalType: "boolean",
    aliases: ["non_accrual_flag", "nonaccrual", "is_nonaccrual", "non_accrual_indicator"],
    requiredFor: [],
    analysisTags: ["performance", "credit_risk", "vintage"],
    sensitivity: "confidential",
    unit: "boolean",
    semanticNotes: "Normalize source yes/no or status codes to true/false and document null handling.",
  },
  {
    id: "default_flag",
    label: "Default Flag",
    description: "Indicates whether the exposure has entered the governed default state.",
    logicalType: "boolean",
    aliases: ["is_default", "defaulted_flag", "default_indicator", "ever_defaulted"],
    requiredFor: ["vintage"],
    analysisTags: ["performance", "credit_risk", "vintage"],
    sensitivity: "confidential",
    unit: "boolean",
    semanticNotes: "Define whether this is point-in-time or ever-defaulted; the default definition must be versioned.",
  },
  {
    id: "default_date",
    label: "Default Date",
    description: "Date the exposure first met the governed default definition.",
    logicalType: "date",
    aliases: ["date_of_default", "first_default_date", "default_event_date"],
    requiredFor: [],
    analysisTags: ["performance", "credit_risk", "vintage"],
    sensitivity: "confidential",
    unit: "date",
    semanticNotes: "Leave null for never-defaulted loans; avoid replacing missing dates with reporting date.",
  },
  {
    id: "charge_off_amount",
    label: "Charge-off Amount",
    description: "Cumulative principal amount charged off through the as-of date.",
    logicalType: "currency",
    aliases: ["charged_off_amount", "write_off_amount", "chargeoff", "cumulative_charge_off"],
    requiredFor: [],
    analysisTags: ["performance", "credit_risk", "vintage"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "State whether the measure is period activity or life-to-date; canonical meaning is life-to-date.",
  },
  {
    id: "recovery_amount",
    label: "Recovery Amount",
    description: "Cumulative cash recoveries received after default or charge-off.",
    logicalType: "currency",
    aliases: ["recoveries", "recovered_amount", "cumulative_recovery", "post_default_recovery"],
    requiredFor: [],
    analysisTags: ["performance", "credit_risk", "vintage"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Canonical meaning is life-to-date gross recovery unless collection costs are separately identified.",
  },
  {
    id: "industry_code",
    label: "Industry Code",
    description: "Governed industry classification code for the borrower.",
    logicalType: "string",
    aliases: ["naics_code", "sic_code", "sector_code", "industry", "industry_classification"],
    requiredFor: [],
    analysisTags: ["stratification", "concentration", "credit_risk"],
    sensitivity: "internal",
    unit: "code",
    semanticNotes: "Preserve leading zeros and identify the taxonomy and version (for example NAICS 2022).",
  },
  {
    id: "borrower_country_code",
    label: "Borrower Country Code",
    description: "Country of the borrower's primary legal domicile.",
    logicalType: "string",
    aliases: ["country", "country_code", "domicile_country", "borrower_country"],
    requiredFor: [],
    analysisTags: ["stratification", "concentration", "credit_risk"],
    sensitivity: "internal",
    unit: "code",
    semanticNotes: "Prefer ISO 3166-1 alpha-2 codes and distinguish legal domicile from collateral location.",
  },
  {
    id: "borrower_region",
    label: "Borrower Region",
    description: "State, province, or reporting region for the borrower.",
    logicalType: "string",
    aliases: ["state", "province", "region", "borrower_state", "geography"],
    requiredFor: [],
    analysisTags: ["stratification", "concentration"],
    sensitivity: "internal",
    unit: "code",
    semanticNotes: "Use a controlled code set and retain country context where codes can collide.",
  },
  {
    id: "collateral_record_id",
    label: "Collateral Record ID",
    description: "Stable identifier for a collateral, receivable, inventory, or appraisal record.",
    logicalType: "identifier",
    aliases: ["collateral_id", "asset_id", "collateral_number", "borrowing_base_record_id"],
    requiredFor: [],
    analysisTags: ["identity", "collateral", "borrowing_base", "lineage"],
    sensitivity: "confidential",
    unit: "identifier",
    semanticNotes: "Uniqueness grain should be documented because collateral detail may be invoice-, SKU-, or pool-level.",
  },
  {
    id: "collateral_type",
    label: "Collateral Type",
    description: "Asset class securing the exposure.",
    logicalType: "string",
    aliases: ["asset_type", "collateral_category", "asset_class", "borrowing_base_asset_type"],
    requiredFor: [],
    analysisTags: ["collateral", "stratification", "borrowing_base"],
    sensitivity: "confidential",
    unit: "code",
    semanticNotes: "Normalize to a controlled taxonomy such as accounts_receivable, inventory, equipment, or cash.",
  },
  {
    id: "collateral_gross_amount",
    label: "Gross Collateral Amount",
    description: "Gross reported value of collateral before eligibility deductions and advance rates.",
    logicalType: "currency",
    aliases: ["gross_collateral", "gross_asset_value", "collateral_value", "gross_value"],
    requiredFor: [],
    analysisTags: ["collateral", "eligibility", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Valuation basis varies by asset class; pair with collateral type and appraisal conventions.",
  },
  {
    id: "eligible_collateral_amount",
    label: "Eligible Collateral Amount",
    description: "Collateral value remaining after eligibility rules but before the advance rate.",
    logicalType: "currency",
    aliases: ["eligible_collateral", "eligible_asset_value", "eligible_value", "eligible_amount"],
    requiredFor: [],
    analysisTags: ["collateral", "eligibility", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Do not confuse with borrowing-base contribution, which is generally after the advance rate.",
  },
  {
    id: "ineligible_collateral_amount",
    label: "Ineligible Collateral Amount",
    description: "Collateral value excluded under borrowing-base eligibility rules.",
    logicalType: "currency",
    aliases: ["ineligible_collateral", "ineligible_amount", "eligibility_deductions", "excluded_collateral"],
    requiredFor: [],
    analysisTags: ["collateral", "eligibility", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Gross less eligible should reconcile subject to valuation adjustments and category-specific rules.",
  },
  {
    id: "advance_rate",
    label: "Advance Rate",
    description: "Contractual percentage applied to eligible collateral value.",
    logicalType: "percentage",
    aliases: ["collateral_advance_rate", "availability_rate", "lend_rate", "adv_rate"],
    requiredFor: [],
    analysisTags: ["collateral", "borrowing_base"],
    sensitivity: "confidential",
    unit: "percent",
    semanticNotes: "Canonical storage is percentage points; category-specific rates should map to their specific fields when available.",
  },
  {
    id: "borrowing_base_contribution",
    label: "Borrowing-base Contribution",
    description: "Eligible collateral value after applying the applicable advance rate.",
    logicalType: "currency",
    aliases: ["availability_contribution", "advanced_value", "collateral_contribution", "bb_contribution"],
    requiredFor: [],
    analysisTags: ["collateral", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Usually eligible amount multiplied by advance rate, before facility-level reserves and caps.",
  },
  {
    id: "accounts_receivable_gross",
    label: "Gross Accounts Receivable",
    description: "Gross accounts receivable balance before eligibility exclusions.",
    logicalType: "currency",
    aliases: ["gross_ar", "ar_gross", "total_receivables", "accounts_receivable", "a_r_gross"],
    requiredFor: [],
    analysisTags: ["receivables", "collateral", "eligibility", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Define whether credits, contra accounts, and intercompany receivables are netted.",
  },
  {
    id: "accounts_receivable_eligible",
    label: "Eligible Accounts Receivable",
    description: "Accounts receivable satisfying all borrowing-base eligibility rules.",
    logicalType: "currency",
    aliases: ["eligible_ar", "ar_eligible", "eligible_receivables", "eligible_accounts_receivable", "eligible_a_r"],
    requiredFor: ["borrowing_base"],
    analysisTags: ["receivables", "collateral", "eligibility", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Measure after aging, concentration, cross-aging, affiliate, and other contractual exclusions.",
  },
  {
    id: "accounts_receivable_advance_rate",
    label: "Accounts Receivable Advance Rate",
    description: "Advance rate applied to eligible accounts receivable.",
    logicalType: "percentage",
    aliases: ["ar_advance_rate", "receivables_advance_rate", "a_r_advance_rate", "ar_rate"],
    requiredFor: ["borrowing_base"],
    analysisTags: ["receivables", "collateral", "borrowing_base"],
    sensitivity: "confidential",
    unit: "percent",
    semanticNotes: "Canonical storage is percentage points and should reflect the rate effective on the as-of date.",
  },
  {
    id: "inventory_gross",
    label: "Gross Inventory",
    description: "Gross inventory value before eligibility exclusions and valuation haircuts.",
    logicalType: "currency",
    aliases: ["gross_inventory", "inventory_value", "total_inventory", "inventory_balance"],
    requiredFor: [],
    analysisTags: ["inventory", "collateral", "eligibility", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Identify whether value is cost, market, appraised, or net orderly liquidation value.",
  },
  {
    id: "inventory_eligible",
    label: "Eligible Inventory",
    description: "Inventory value satisfying all borrowing-base eligibility rules.",
    logicalType: "currency",
    aliases: ["eligible_inventory", "inventory_eligible_value", "eligible_inv", "eligible_inventory_value"],
    requiredFor: ["borrowing_base"],
    analysisTags: ["inventory", "collateral", "eligibility", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "State the valuation basis and whether category caps have already been applied.",
  },
  {
    id: "inventory_advance_rate",
    label: "Inventory Advance Rate",
    description: "Advance rate applied to eligible inventory.",
    logicalType: "percentage",
    aliases: ["inv_advance_rate", "inventory_rate", "inventory_adv_rate"],
    requiredFor: ["borrowing_base"],
    analysisTags: ["inventory", "collateral", "borrowing_base"],
    sensitivity: "confidential",
    unit: "percent",
    semanticNotes: "Canonical storage is percentage points; borrowing agreements may cap this by NOLV percentage.",
  },
  {
    id: "equipment_appraised_value",
    label: "Equipment Appraised Value",
    description: "Most recent governed appraisal value for eligible machinery and equipment.",
    logicalType: "currency",
    aliases: ["equipment_value", "m_e_appraised_value", "machinery_equipment_value", "equipment_olv"],
    requiredFor: [],
    analysisTags: ["collateral", "eligibility", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Preserve appraisal date and basis (FMV, OLV, or NOLV) in source lineage.",
  },
  {
    id: "equipment_advance_rate",
    label: "Equipment Advance Rate",
    description: "Advance rate applied to eligible equipment appraisal value.",
    logicalType: "percentage",
    aliases: ["m_e_advance_rate", "equipment_rate", "equipment_adv_rate"],
    requiredFor: [],
    analysisTags: ["collateral", "borrowing_base"],
    sensitivity: "confidential",
    unit: "percent",
    semanticNotes: "Canonical storage is percentage points and should reflect contractual amortization or caps.",
  },
  {
    id: "cash_collateral_amount",
    label: "Cash Collateral Amount",
    description: "Eligible controlled cash or cash-equivalent collateral.",
    logicalType: "currency",
    aliases: ["cash_collateral", "eligible_cash", "blocked_cash", "cash_dominion_balance"],
    requiredFor: [],
    analysisTags: ["collateral", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Include only cash subject to enforceable control and available under the borrowing agreement.",
  },
  {
    id: "concentration_reserve",
    label: "Concentration Reserve",
    description: "Reserve or exclusion created by contractual customer or asset concentration limits.",
    logicalType: "currency",
    aliases: ["concentration_deduction", "concentration_overadvance", "concentration_adjustment", "conc_reserve"],
    requiredFor: [],
    analysisTags: ["concentration", "reserves", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Use a positive amount for a deduction; avoid sign ambiguity in downstream arithmetic.",
  },
  {
    id: "dilution_reserve",
    label: "Dilution Reserve",
    description: "Reserve for actual or expected accounts-receivable dilution above permitted levels.",
    logicalType: "currency",
    aliases: ["dilution_deduction", "dilution_adjustment", "ar_dilution_reserve"],
    requiredFor: [],
    analysisTags: ["receivables", "reserves", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Use a positive amount for a deduction and preserve the contractual calculation method.",
  },
  {
    id: "availability_block",
    label: "Availability Block",
    description: "Contractual minimum availability block deducted from borrowing capacity.",
    logicalType: "currency",
    aliases: ["availability_reserve", "minimum_availability_block", "liquidity_block", "bb_block"],
    requiredFor: [],
    analysisTags: ["reserves", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Use a positive deduction and distinguish fixed blocks from formula-based reserves.",
  },
  {
    id: "other_reserves",
    label: "Other Reserves",
    description: "All other lender reserves deducted from gross borrowing-base capacity.",
    logicalType: "currency",
    aliases: ["additional_reserves", "lender_reserves", "other_deductions", "misc_reserves"],
    requiredFor: [],
    analysisTags: ["reserves", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Use a positive deduction; do not include concentration or dilution reserves already reported separately.",
  },
  {
    id: "total_reserves",
    label: "Total Reserves",
    description: "Total facility-level deductions from advanced collateral value.",
    logicalType: "currency",
    aliases: ["reserves_total", "aggregate_reserves", "total_deductions", "bb_reserves"],
    requiredFor: ["borrowing_base"],
    analysisTags: ["reserves", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Use a positive deduction and reconcile to the sum of reserve components where detail exists.",
  },
  {
    id: "borrowing_base_amount",
    label: "Borrowing-base Amount",
    description: "Total collateral-supported borrowing capacity after advance rates, caps, and reserves.",
    logicalType: "currency",
    aliases: ["borrowing_base", "bb_amount", "net_borrowing_base", "borrowing_base_availability"],
    requiredFor: ["borrowing_base"],
    analysisTags: ["borrowing_base", "collateral", "reserves"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Document whether this is before or after the commitment cap; canonical meaning is before funded usage.",
  },
  {
    id: "excess_availability",
    label: "Excess Availability",
    description: "Borrowing capacity remaining after funded usage and applicable availability deductions.",
    logicalType: "currency",
    aliases: ["availability", "available_amount", "remaining_availability", "excess_avail", "liquidity_available"],
    requiredFor: [],
    analysisTags: ["borrowing_base", "credit_risk", "performance"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Reconcile to the lesser of commitment and borrowing base, less usage and applicable blocks.",
  },
  {
    id: "receivable_id",
    label: "Receivable ID",
    description: "Stable invoice or receivable identifier in detailed A/R data.",
    logicalType: "identifier",
    aliases: ["invoice_id", "invoice_number", "receivable_number", "ar_item_id"],
    requiredFor: [],
    analysisTags: ["identity", "receivables", "eligibility"],
    sensitivity: "restricted",
    unit: "identifier",
    semanticNotes: "Expected to be unique with borrower and debtor identifiers; may not be globally unique.",
  },
  {
    id: "account_debtor_id",
    label: "Account Debtor ID",
    description: "Stable identifier for the customer obligated on a receivable.",
    logicalType: "identifier",
    aliases: ["debtor_id", "ar_customer_id", "invoice_customer_id", "account_debtor_number"],
    requiredFor: [],
    analysisTags: ["identity", "receivables", "concentration", "eligibility"],
    sensitivity: "restricted",
    unit: "identifier",
    semanticNotes: "Distinct from borrower_id: this is the borrower's customer or account debtor.",
  },
  {
    id: "account_debtor_name",
    label: "Account Debtor Name",
    description: "Name of the customer obligated on a receivable.",
    logicalType: "string",
    aliases: ["debtor_name", "ar_customer_name", "invoice_customer_name", "account_debtor"],
    requiredFor: [],
    analysisTags: ["receivables", "concentration", "eligibility"],
    sensitivity: "restricted",
    unit: "text",
    semanticNotes: "Commercially sensitive; use the debtor id for concentration analysis where practical.",
  },
  {
    id: "invoice_date",
    label: "Invoice Date",
    description: "Date a receivable invoice was issued.",
    logicalType: "date",
    aliases: ["bill_date", "receivable_date", "invoice_created_date"],
    requiredFor: [],
    analysisTags: ["receivables", "eligibility"],
    sensitivity: "confidential",
    unit: "date",
    semanticNotes: "Use the contractual invoice date; aging methodology should document whether it ages from invoice or due date.",
  },
  {
    id: "invoice_due_date",
    label: "Invoice Due Date",
    description: "Contractual payment due date of a receivable invoice.",
    logicalType: "date",
    aliases: ["receivable_due_date", "ar_due_date", "payment_due_date", "invoice_maturity_date"],
    requiredFor: [],
    analysisTags: ["receivables", "eligibility"],
    sensitivity: "confidential",
    unit: "date",
    semanticNotes: "Do not substitute statement date; eligibility aging may depend on this field.",
  },
  {
    id: "receivable_amount",
    label: "Receivable Amount",
    description: "Open balance of an invoice or receivable at the as-of date.",
    logicalType: "currency",
    aliases: ["invoice_balance", "open_invoice_amount", "ar_balance", "open_receivable", "invoice_amount"],
    requiredFor: [],
    analysisTags: ["receivables", "collateral", "eligibility", "concentration"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Use unpaid open balance rather than original invoice face amount.",
  },
  {
    id: "receivable_age_days",
    label: "Receivable Age (Days)",
    description: "Age of the receivable under the governing borrowing-base convention.",
    logicalType: "integer",
    aliases: ["invoice_age", "ar_age_days", "receivable_days_old", "age_days"],
    requiredFor: [],
    analysisTags: ["receivables", "eligibility", "stratification"],
    sensitivity: "confidential",
    unit: "days",
    semanticNotes: "Document whether calculated from invoice date or due date and whether negative ages are allowed.",
  },
  {
    id: "eligibility_status",
    label: "Eligibility Status",
    description: "Governed eligible, ineligible, or partially eligible classification for a collateral item.",
    logicalType: "string",
    aliases: ["eligible_flag", "is_eligible", "collateral_eligibility", "eligibility", "bb_eligibility_status"],
    requiredFor: [],
    analysisTags: ["eligibility", "collateral", "borrowing_base"],
    sensitivity: "confidential",
    unit: "code",
    semanticNotes: "A status is preferable to a boolean when partial eligibility or review states exist.",
  },
  {
    id: "ineligibility_reason",
    label: "Ineligibility Reason",
    description: "Primary governed reason a collateral item is excluded or limited.",
    logicalType: "string",
    aliases: ["exclusion_reason", "eligibility_reason", "ineligible_reason", "deduction_reason"],
    requiredFor: [],
    analysisTags: ["eligibility", "collateral", "borrowing_base"],
    sensitivity: "confidential",
    unit: "code",
    semanticNotes: "Use a controlled hierarchy; preserve multiple reasons in a child table rather than concatenating values.",
  },
  {
    id: "dilution_rate",
    label: "Dilution Rate",
    description: "Historical or trailing-period A/R dilution as a percentage of gross sales or receivables.",
    logicalType: "percentage",
    aliases: ["ar_dilution_rate", "dilution_pct", "dilution_percentage", "historical_dilution"],
    requiredFor: [],
    analysisTags: ["receivables", "eligibility", "credit_risk"],
    sensitivity: "confidential",
    unit: "percent",
    semanticNotes: "The observation window and numerator/denominator definition must accompany this metric.",
  },
  {
    id: "cross_aging_flag",
    label: "Cross-aging Flag",
    description: "Indicates that otherwise-current receivables are excluded due to delinquency elsewhere for the debtor.",
    logicalType: "boolean",
    aliases: ["cross_aged_flag", "cross_age_indicator", "is_cross_aged", "crossaging_flag"],
    requiredFor: [],
    analysisTags: ["receivables", "eligibility", "concentration"],
    sensitivity: "confidential",
    unit: "boolean",
    semanticNotes: "Apply at the contractual account-debtor grouping and preserve the threshold used.",
  },
  {
    id: "inventory_item_id",
    label: "Inventory Item ID",
    description: "Stable SKU, lot, or inventory pool identifier.",
    logicalType: "identifier",
    aliases: ["sku", "sku_id", "item_id", "inventory_id", "product_item_id"],
    requiredFor: [],
    analysisTags: ["identity", "inventory", "eligibility"],
    sensitivity: "confidential",
    unit: "identifier",
    semanticNotes: "Document whether the grain is SKU, lot, location, or category pool.",
  },
  {
    id: "inventory_category",
    label: "Inventory Category",
    description: "Governed category of inventory collateral.",
    logicalType: "string",
    aliases: ["inventory_type", "inventory_class", "item_category", "stock_category"],
    requiredFor: [],
    analysisTags: ["inventory", "stratification", "eligibility"],
    sensitivity: "confidential",
    unit: "code",
    semanticNotes: "Common categories include raw_material, work_in_process, and finished_goods.",
  },
  {
    id: "inventory_quantity",
    label: "Inventory Quantity",
    description: "On-hand inventory quantity at the as-of date.",
    logicalType: "decimal",
    aliases: ["quantity_on_hand", "on_hand_qty", "inventory_qty", "units_on_hand"],
    requiredFor: [],
    analysisTags: ["inventory", "collateral", "eligibility"],
    sensitivity: "confidential",
    unit: "count",
    semanticNotes: "A separate unit-of-measure column is required when quantities mix units.",
  },
  {
    id: "inventory_nolv",
    label: "Inventory NOLV",
    description: "Net orderly liquidation value of inventory collateral.",
    logicalType: "currency",
    aliases: ["net_orderly_liquidation_value", "nolv", "inventory_liquidation_value", "appraised_nolv"],
    requiredFor: [],
    analysisTags: ["inventory", "collateral", "eligibility", "borrowing_base"],
    sensitivity: "confidential",
    unit: "currency",
    semanticNotes: "Pair with appraisal date, appraiser, and valuation scope in source lineage.",
  },
] as const satisfies readonly CanonicalFieldDefinition[];

export type CanonicalFieldId = (typeof CANONICAL_FIELDS)[number]["id"];

export interface CanonicalFieldFilters {
  readonly logicalType?: LogicalType | readonly LogicalType[];
  readonly requiredFor?: AnalysisProfile;
  readonly analysisTag?: AnalysisTag;
  readonly sensitivity?: DataSensitivity | readonly DataSensitivity[];
}

const FIELD_BY_ID: ReadonlyMap<string, CanonicalFieldDefinition> = new Map(
  CANONICAL_FIELDS.map((field) => [field.id, field]),
);

/** Returns a canonical field by exact, stable id. */
export function getCanonicalField(id: string): CanonicalFieldDefinition | undefined {
  return FIELD_BY_ID.get(id);
}

/** Returns dictionary entries in their stable declaration order. */
export function listCanonicalFields(
  filters: CanonicalFieldFilters = {},
): readonly CanonicalFieldDefinition[] {
  const logicalTypes: ReadonlySet<LogicalType> | undefined = filters.logicalType
    ? new Set<LogicalType>(Array.isArray(filters.logicalType) ? filters.logicalType : [filters.logicalType])
    : undefined;
  const sensitivities: ReadonlySet<DataSensitivity> | undefined = filters.sensitivity
    ? new Set<DataSensitivity>(Array.isArray(filters.sensitivity) ? filters.sensitivity : [filters.sensitivity])
    : undefined;

  return CANONICAL_FIELDS.filter((field) => {
    if (logicalTypes && !logicalTypes.has(field.logicalType)) return false;
    if (sensitivities && !sensitivities.has(field.sensitivity)) return false;
    if (
      filters.requiredFor &&
      !(field.requiredFor as readonly AnalysisProfile[]).includes(filters.requiredFor)
    ) {
      return false;
    }
    if (
      filters.analysisTag &&
      !(field.analysisTags as readonly AnalysisTag[]).includes(filters.analysisTag)
    ) {
      return false;
    }
    return true;
  });
}
