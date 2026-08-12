import { Decimal } from "decimal.js";

const ExactDecimal = Decimal.clone({ precision: 50, rounding: Decimal.ROUND_HALF_EVEN });

export type DecimalString = string;

export type ArReceivableFlag =
  | "affiliate"
  | "contra"
  | "disputed"
  | "duplicate"
  | "foreign"
  | "government"
  | "insolvent_debtor"
  | "lien_not_perfected"
  | "reaged"
  | "unbilled";

export interface ArReceivable {
  readonly receivableId: string;
  readonly debtorId: string;
  /** Open receivable balance in the policy currency. */
  readonly outstandingAmount: DecimalString;
  /** Contractual days past due at the calculation as-of date. */
  readonly daysPastDue: number;
  readonly flags: readonly ArReceivableFlag[];
}

export type ArEligibilityCondition =
  | { readonly kind: "days_past_due_at_least"; readonly days: number }
  | { readonly kind: "flag_present"; readonly flag: ArReceivableFlag }
  | { readonly kind: "debtor_id_in"; readonly debtorIds: readonly string[] }
  | { readonly kind: "all"; readonly conditions: readonly ArEligibilityCondition[] }
  | { readonly kind: "any"; readonly conditions: readonly ArEligibilityCondition[] }
  | { readonly kind: "not"; readonly condition: ArEligibilityCondition };

/**
 * A rule version is active when effectiveFrom <= asOfDate < effectiveTo.
 * `effectiveTo` is intentionally exclusive so adjacent versions can meet at a
 * boundary without both becoming active.
 */
export interface ArEligibilityRuleVersion {
  readonly ruleId: string;
  readonly version: string;
  readonly effectiveFrom: string;
  readonly effectiveTo?: string;
  readonly priority: number;
  readonly reasonCode: string;
  readonly description: string;
  readonly condition: ArEligibilityCondition;
}

export interface CrossAgingRule {
  readonly ruleId: string;
  readonly reasonCode: string;
  readonly daysPastDueAtLeast: number;
  /**
   * Ratio in the inclusive range 0..1. The trigger comparison is >= and is
   * calculated as gross past-due AR / gross debtor AR before other exclusions.
   */
  readonly triggerRatio: DecimalString;
}

export interface ConcentrationRule {
  readonly ruleId: string;
  readonly reasonCode: string;
  /** Maximum debtor balance as a share of pre-concentration eligible AR. */
  readonly maxDebtorShare: DecimalString;
  readonly allocation: "invoice_id" | "largest_first" | "oldest_first";
}

export interface BorrowingBaseReserve {
  readonly reserveId: string;
  readonly reasonCode: string;
  readonly description: string;
  readonly amount: DecimalString;
}

export interface ArBorrowingBasePolicyVersion {
  readonly policyId: string;
  readonly version: string;
  readonly effectiveFrom: string;
  readonly effectiveTo?: string;
  readonly currencyCode: string;
  readonly eligibilityRules: readonly ArEligibilityRuleVersion[];
  readonly crossAging?: CrossAgingRule;
  readonly concentration?: ConcentrationRule;
  /** Ratio in the inclusive range 0..1. */
  readonly advanceRate: DecimalString;
  /** Cap on the AR component after applying the advance rate. */
  readonly componentSublimit?: DecimalString;
  readonly reserves: readonly BorrowingBaseReserve[];
  readonly commitmentAmount: DecimalString;
}

export interface FacilityUsage {
  readonly usageId: string;
  readonly kind: "revolver" | "letters_of_credit" | "swingline" | "other";
  readonly amount: DecimalString;
}

export interface CalculateArBorrowingBaseInput {
  readonly asOfDate: string;
  readonly policyVersions: readonly ArBorrowingBasePolicyVersion[];
  readonly receivables: readonly ArReceivable[];
  readonly usage: readonly FacilityUsage[];
}

export type BorrowingBaseStage =
  | "gross_ar"
  | "eligibility_rule"
  | "cross_aging"
  | "concentration"
  | "advance_rate"
  | "component_sublimit"
  | "reserves"
  | "commitment"
  | "usage";

export interface BorrowingBaseEvidenceItem {
  readonly key: string;
  readonly value: string;
}

export interface BorrowingBaseWaterfallStep {
  readonly sequence: number;
  readonly stepId: string;
  readonly stage: BorrowingBaseStage;
  readonly label: string;
  readonly beforeAmount: DecimalString;
  /** Signed change: deductions are negative and the gross opening is positive. */
  readonly adjustmentAmount: DecimalString;
  readonly afterAmount: DecimalString;
  readonly affectedReceivableIds: readonly string[];
  readonly evidence: readonly BorrowingBaseEvidenceItem[];
}

export interface EligibilityReason {
  readonly stage: "eligibility_rule" | "cross_aging" | "concentration";
  readonly ruleId: string;
  readonly ruleVersion?: string;
  readonly reasonCode: string;
  readonly excludedAmount: DecimalString;
}

export interface ReceivableEligibilityResult {
  readonly receivableId: string;
  readonly debtorId: string;
  readonly grossAmount: DecimalString;
  readonly recordRuleIneligibleAmount: DecimalString;
  readonly crossAgedIneligibleAmount: DecimalString;
  readonly concentrationExcessAmount: DecimalString;
  readonly eligibleAmount: DecimalString;
  readonly reasons: readonly EligibilityReason[];
}

export interface ArBorrowingBaseTotals {
  readonly grossReceivables: DecimalString;
  readonly recordRuleIneligible: DecimalString;
  readonly crossAgedIneligible: DecimalString;
  readonly concentrationExcess: DecimalString;
  readonly eligibleReceivables: DecimalString;
  readonly advanceRate: DecimalString;
  readonly advancedReceivables: DecimalString;
  readonly componentSublimit: DecimalString | null;
  readonly componentContribution: DecimalString;
  readonly totalReserves: DecimalString;
  readonly appliedReserves: DecimalString;
  readonly unappliedReserves: DecimalString;
  readonly borrowingBaseBeforeCommitment: DecimalString;
  readonly commitmentAmount: DecimalString;
  readonly borrowingCapacity: DecimalString;
  readonly totalUsage: DecimalString;
  readonly excessAvailability: DecimalString;
  readonly overadvance: DecimalString;
}

export interface ArBorrowingBaseResult {
  readonly calculationType: "ar_borrowing_base";
  readonly asOfDate: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly currencyCode: string;
  readonly activeEligibilityRules: readonly {
    readonly ruleId: string;
    readonly version: string;
    readonly reasonCode: string;
  }[];
  readonly receivables: readonly ReceivableEligibilityResult[];
  readonly usage: readonly FacilityUsage[];
  readonly waterfall: readonly BorrowingBaseWaterfallStep[];
  readonly totals: ArBorrowingBaseTotals;
}

interface MutableReceivableState {
  readonly receivable: ArReceivable;
  readonly gross: Decimal;
  remaining: Decimal;
  recordRuleIneligible: Decimal;
  crossAgedIneligible: Decimal;
  concentrationExcess: Decimal;
  readonly reasons: EligibilityReason[];
}

interface StepInput {
  readonly stepId: string;
  readonly stage: BorrowingBaseStage;
  readonly label: string;
  readonly before: Decimal;
  readonly after: Decimal;
  readonly affectedReceivableIds?: readonly string[];
  readonly evidence?: readonly BorrowingBaseEvidenceItem[];
}

/** Selects exactly one effective policy version for the requested business date. */
export function selectEffectiveBorrowingBasePolicy(
  policyVersions: readonly ArBorrowingBasePolicyVersion[],
  asOfDate: string
): ArBorrowingBasePolicyVersion {
  assertIsoDate(asOfDate, "asOfDate");
  if (policyVersions.length === 0) throw new Error("At least one borrowing-base policy version is required");

  for (const policy of policyVersions) validatePolicy(policy);
  const active = policyVersions.filter((policy) =>
    isEffective(asOfDate, policy.effectiveFrom, policy.effectiveTo)
  );
  if (active.length !== 1) {
    throw new Error(
      `Expected exactly one effective borrowing-base policy on ${asOfDate}; found ${active.length}`
    );
  }
  return active[0]!;
}

/**
 * Reperforms an AR borrowing base without floating-point arithmetic or hidden
 * predicates. All inputs and outputs representing decimal quantities are plain
 * decimal strings.
 */
export function calculateArBorrowingBase(input: CalculateArBorrowingBaseInput): ArBorrowingBaseResult {
  assertIsoDate(input.asOfDate, "asOfDate");
  const policy = selectEffectiveBorrowingBasePolicy(input.policyVersions, input.asOfDate);
  const receivables = validateAndSortReceivables(input.receivables);
  const usage = validateAndSortUsage(input.usage);
  const activeRules = selectActiveEligibilityRules(policy.eligibilityRules, input.asOfDate);

  const states = new Map<string, MutableReceivableState>();
  for (const receivable of receivables) {
    const amount = nonNegativeDecimal(receivable.outstandingAmount, `receivable ${receivable.receivableId} amount`);
    states.set(receivable.receivableId, {
      receivable,
      gross: amount,
      remaining: amount,
      recordRuleIneligible: zero(),
      crossAgedIneligible: zero(),
      concentrationExcess: zero(),
      reasons: []
    });
  }

  const waterfall: BorrowingBaseWaterfallStep[] = [];
  const pushStep = (step: StepInput): void => {
    waterfall.push({
      sequence: waterfall.length + 1,
      stepId: step.stepId,
      stage: step.stage,
      label: step.label,
      beforeAmount: decimalString(step.before),
      adjustmentAmount: decimalString(step.after.minus(step.before)),
      afterAmount: decimalString(step.after),
      affectedReceivableIds: sortedUnique(step.affectedReceivableIds ?? []),
      evidence: [...(step.evidence ?? [])]
    });
  };

  const grossReceivables = sum([...states.values()].map((state) => state.gross));
  pushStep({
    stepId: "gross_ar",
    stage: "gross_ar",
    label: "Gross accounts receivable",
    before: zero(),
    after: grossReceivables,
    affectedReceivableIds: receivables.map((receivable) => receivable.receivableId),
    evidence: [{ key: "receivable_count", value: String(receivables.length) }]
  });

  let running = grossReceivables;
  let recordRuleIneligible = zero();
  for (const rule of activeRules) {
    const before = running;
    let excluded = zero();
    const matched: string[] = [];
    const affected: string[] = [];

    for (const state of states.values()) {
      if (!matchesCondition(state.receivable, rule.condition)) continue;
      matched.push(state.receivable.receivableId);
      if (state.remaining.isZero()) continue;
      const deduction = state.remaining;
      state.remaining = zero();
      state.recordRuleIneligible = state.recordRuleIneligible.plus(deduction);
      state.reasons.push({
        stage: "eligibility_rule",
        ruleId: rule.ruleId,
        ruleVersion: rule.version,
        reasonCode: rule.reasonCode,
        excludedAmount: decimalString(deduction)
      });
      excluded = excluded.plus(deduction);
      affected.push(state.receivable.receivableId);
    }

    recordRuleIneligible = recordRuleIneligible.plus(excluded);
    running = running.minus(excluded);
    pushStep({
      stepId: `eligibility:${rule.ruleId}:${rule.version}`,
      stage: "eligibility_rule",
      label: rule.description,
      before,
      after: running,
      affectedReceivableIds: affected,
      evidence: [
        { key: "rule_id", value: rule.ruleId },
        { key: "rule_version", value: rule.version },
        { key: "reason_code", value: rule.reasonCode },
        { key: "matched_receivable_count", value: String(matched.length) },
        { key: "excluded_receivable_count", value: String(affected.length) }
      ]
    });
  }

  const crossAgingBefore = running;
  const crossAgingResult = applyCrossAging(states, policy.crossAging);
  running = running.minus(crossAgingResult.excluded);
  pushStep({
    stepId: policy.crossAging ? `cross_aging:${policy.crossAging.ruleId}` : "cross_aging:not_configured",
    stage: "cross_aging",
    label: policy.crossAging ? "Cross-aging exclusions" : "Cross-aging not configured",
    before: crossAgingBefore,
    after: running,
    affectedReceivableIds: crossAgingResult.affected,
    evidence: crossAgingResult.evidence
  });

  const concentrationBefore = running;
  const concentrationResult = applyConcentration(states, policy.concentration);
  running = running.minus(concentrationResult.excluded);
  pushStep({
    stepId: policy.concentration
      ? `concentration:${policy.concentration.ruleId}`
      : "concentration:not_configured",
    stage: "concentration",
    label: policy.concentration ? "Account-debtor concentration excess" : "Concentration not configured",
    before: concentrationBefore,
    after: running,
    affectedReceivableIds: concentrationResult.affected,
    evidence: concentrationResult.evidence
  });

  const eligibleReceivables = running;
  const advanceRate = ratioDecimal(policy.advanceRate, "advanceRate");
  const advancedReceivables = eligibleReceivables.times(advanceRate);
  pushStep({
    stepId: "advance_rate",
    stage: "advance_rate",
    label: "Apply AR advance rate",
    before: eligibleReceivables,
    after: advancedReceivables,
    evidence: [{ key: "advance_rate", value: decimalString(advanceRate) }]
  });

  const sublimit = policy.componentSublimit === undefined
    ? null
    : nonNegativeDecimal(policy.componentSublimit, "componentSublimit");
  const componentContribution = sublimit ? Decimal.min(advancedReceivables, sublimit) : advancedReceivables;
  pushStep({
    stepId: "component_sublimit",
    stage: "component_sublimit",
    label: sublimit ? "Apply AR component sublimit" : "AR component sublimit not configured",
    before: advancedReceivables,
    after: componentContribution,
    evidence: [{ key: "component_sublimit", value: sublimit ? decimalString(sublimit) : "none" }]
  });

  const reserves = policy.reserves.map((reserve) => ({
    ...reserve,
    decimalAmount: nonNegativeDecimal(reserve.amount, `reserve ${reserve.reserveId} amount`)
  }));
  const totalReserves = sum(reserves.map((reserve) => reserve.decimalAmount));
  const appliedReserves = Decimal.min(componentContribution, totalReserves);
  const afterReserves = componentContribution.minus(appliedReserves);
  pushStep({
    stepId: "reserves",
    stage: "reserves",
    label: "Subtract borrowing-base reserves",
    before: componentContribution,
    after: afterReserves,
    evidence: reserves.flatMap((reserve) => [
      { key: `reserve:${reserve.reserveId}:reason`, value: reserve.reasonCode },
      { key: `reserve:${reserve.reserveId}:amount`, value: decimalString(reserve.decimalAmount) }
    ])
  });

  const commitment = nonNegativeDecimal(policy.commitmentAmount, "commitmentAmount");
  const borrowingCapacity = Decimal.min(afterReserves, commitment);
  pushStep({
    stepId: "commitment",
    stage: "commitment",
    label: "Apply facility commitment cap",
    before: afterReserves,
    after: borrowingCapacity,
    evidence: [{ key: "commitment_amount", value: decimalString(commitment) }]
  });

  const usageDecimals = usage.map((item) => ({
    item,
    amount: nonNegativeDecimal(item.amount, `usage ${item.usageId} amount`)
  }));
  const totalUsage = sum(usageDecimals.map(({ amount }) => amount));
  const excessAvailability = borrowingCapacity.minus(totalUsage);
  pushStep({
    stepId: "usage",
    stage: "usage",
    label: "Subtract defined facility usage",
    before: borrowingCapacity,
    after: excessAvailability,
    evidence: usageDecimals.flatMap(({ item, amount }) => [
      { key: `usage:${item.usageId}:kind`, value: item.kind },
      { key: `usage:${item.usageId}:amount`, value: decimalString(amount) }
    ])
  });

  const overadvance = Decimal.max(excessAvailability.negated(), zero());
  const receivableResults = [...states.values()]
    .sort((left, right) => compareText(left.receivable.receivableId, right.receivable.receivableId))
    .map((state): ReceivableEligibilityResult => ({
      receivableId: state.receivable.receivableId,
      debtorId: state.receivable.debtorId,
      grossAmount: decimalString(state.gross),
      recordRuleIneligibleAmount: decimalString(state.recordRuleIneligible),
      crossAgedIneligibleAmount: decimalString(state.crossAgedIneligible),
      concentrationExcessAmount: decimalString(state.concentrationExcess),
      eligibleAmount: decimalString(state.remaining),
      reasons: [...state.reasons]
    }));

  return {
    calculationType: "ar_borrowing_base",
    asOfDate: input.asOfDate,
    policyId: policy.policyId,
    policyVersion: policy.version,
    currencyCode: policy.currencyCode,
    activeEligibilityRules: activeRules.map((rule) => ({
      ruleId: rule.ruleId,
      version: rule.version,
      reasonCode: rule.reasonCode
    })),
    receivables: receivableResults,
    usage,
    waterfall,
    totals: {
      grossReceivables: decimalString(grossReceivables),
      recordRuleIneligible: decimalString(recordRuleIneligible),
      crossAgedIneligible: decimalString(crossAgingResult.excluded),
      concentrationExcess: decimalString(concentrationResult.excluded),
      eligibleReceivables: decimalString(eligibleReceivables),
      advanceRate: decimalString(advanceRate),
      advancedReceivables: decimalString(advancedReceivables),
      componentSublimit: sublimit ? decimalString(sublimit) : null,
      componentContribution: decimalString(componentContribution),
      totalReserves: decimalString(totalReserves),
      appliedReserves: decimalString(appliedReserves),
      unappliedReserves: decimalString(totalReserves.minus(appliedReserves)),
      borrowingBaseBeforeCommitment: decimalString(afterReserves),
      commitmentAmount: decimalString(commitment),
      borrowingCapacity: decimalString(borrowingCapacity),
      totalUsage: decimalString(totalUsage),
      excessAvailability: decimalString(excessAvailability),
      overadvance: decimalString(overadvance)
    }
  };
}

function selectActiveEligibilityRules(
  rules: readonly ArEligibilityRuleVersion[],
  asOfDate: string
): readonly ArEligibilityRuleVersion[] {
  for (const rule of rules) validateEligibilityRule(rule);
  const byRuleId = new Map<string, ArEligibilityRuleVersion[]>();
  for (const rule of rules) {
    const versions = byRuleId.get(rule.ruleId) ?? [];
    versions.push(rule);
    byRuleId.set(rule.ruleId, versions);
  }

  const active: ArEligibilityRuleVersion[] = [];
  for (const [ruleId, versions] of byRuleId) {
    const activeVersions = versions.filter((rule) =>
      isEffective(asOfDate, rule.effectiveFrom, rule.effectiveTo)
    );
    if (activeVersions.length > 1) {
      throw new Error(`Eligibility rule ${ruleId} has ${activeVersions.length} active versions on ${asOfDate}`);
    }
    if (activeVersions[0]) active.push(activeVersions[0]);
  }

  return active.sort(
    (left, right) =>
      left.priority - right.priority ||
      compareText(left.ruleId, right.ruleId) ||
      compareText(left.version, right.version)
  );
}

function applyCrossAging(
  states: ReadonlyMap<string, MutableReceivableState>,
  rule: CrossAgingRule | undefined
): {
  readonly excluded: Decimal;
  readonly affected: readonly string[];
  readonly evidence: readonly BorrowingBaseEvidenceItem[];
} {
  if (!rule) {
    return {
      excluded: zero(),
      affected: [],
      evidence: [{ key: "configured", value: "false" }]
    };
  }

  assertNonEmpty(rule.ruleId, "cross-aging rule id");
  assertNonEmpty(rule.reasonCode, "cross-aging reason code");
  assertNonNegativeInteger(rule.daysPastDueAtLeast, "cross-aging daysPastDueAtLeast");
  const trigger = ratioDecimal(rule.triggerRatio, "cross-aging triggerRatio");
  const groups = groupStatesByDebtor(states);
  let excluded = zero();
  const affected: string[] = [];
  const evidence: BorrowingBaseEvidenceItem[] = [
    { key: "configured", value: "true" },
    { key: "trigger_ratio", value: decimalString(trigger) },
    { key: "days_past_due_at_least", value: String(rule.daysPastDueAtLeast) }
  ];

  for (const debtorId of [...groups.keys()].sort(compareText)) {
    const debtorStates = groups.get(debtorId)!;
    const gross = sum(debtorStates.map((state) => state.gross));
    if (gross.isZero()) continue;
    const pastDue = sum(
      debtorStates
        .filter((state) => state.receivable.daysPastDue >= rule.daysPastDueAtLeast)
        .map((state) => state.gross)
    );
    const actualRatio = pastDue.div(gross);
    if (actualRatio.lt(trigger)) continue;

    let debtorExcluded = zero();
    for (const state of debtorStates) {
      if (state.remaining.isZero()) continue;
      const deduction = state.remaining;
      state.remaining = zero();
      state.crossAgedIneligible = state.crossAgedIneligible.plus(deduction);
      state.reasons.push({
        stage: "cross_aging",
        ruleId: rule.ruleId,
        reasonCode: rule.reasonCode,
        excludedAmount: decimalString(deduction)
      });
      debtorExcluded = debtorExcluded.plus(deduction);
      affected.push(state.receivable.receivableId);
    }
    excluded = excluded.plus(debtorExcluded);
    evidence.push(
      { key: `debtor:${debtorId}:gross`, value: decimalString(gross) },
      { key: `debtor:${debtorId}:past_due`, value: decimalString(pastDue) },
      { key: `debtor:${debtorId}:past_due_ratio`, value: decimalString(actualRatio) },
      { key: `debtor:${debtorId}:excluded`, value: decimalString(debtorExcluded) }
    );
  }

  return { excluded, affected: sortedUnique(affected), evidence };
}

function applyConcentration(
  states: ReadonlyMap<string, MutableReceivableState>,
  rule: ConcentrationRule | undefined
): {
  readonly excluded: Decimal;
  readonly affected: readonly string[];
  readonly evidence: readonly BorrowingBaseEvidenceItem[];
} {
  if (!rule) {
    return {
      excluded: zero(),
      affected: [],
      evidence: [{ key: "configured", value: "false" }]
    };
  }

  assertNonEmpty(rule.ruleId, "concentration rule id");
  assertNonEmpty(rule.reasonCode, "concentration reason code");
  const maxShare = ratioDecimal(rule.maxDebtorShare, "concentration maxDebtorShare");
  const preConcentrationEligible = sum([...states.values()].map((state) => state.remaining));
  const debtorCap = preConcentrationEligible.times(maxShare);
  const groups = groupStatesByDebtor(states);
  let excluded = zero();
  const affected: string[] = [];
  const evidence: BorrowingBaseEvidenceItem[] = [
    { key: "configured", value: "true" },
    { key: "max_debtor_share", value: decimalString(maxShare) },
    { key: "pre_concentration_eligible", value: decimalString(preConcentrationEligible) },
    { key: "debtor_cap", value: decimalString(debtorCap) },
    { key: "allocation", value: rule.allocation }
  ];

  for (const debtorId of [...groups.keys()].sort(compareText)) {
    const debtorStates = groups.get(debtorId)!;
    const debtorEligible = sum(debtorStates.map((state) => state.remaining));
    const excess = Decimal.max(debtorEligible.minus(debtorCap), zero());
    if (excess.isZero()) continue;

    const ordered = [...debtorStates].sort((left, right) => {
      if (rule.allocation === "oldest_first") {
        return (
          right.receivable.daysPastDue - left.receivable.daysPastDue ||
          compareText(left.receivable.receivableId, right.receivable.receivableId)
        );
      }
      if (rule.allocation === "largest_first") {
        const amountComparison = right.remaining.comparedTo(left.remaining);
        return amountComparison || compareText(left.receivable.receivableId, right.receivable.receivableId);
      }
      return compareText(left.receivable.receivableId, right.receivable.receivableId);
    });

    let leftToAllocate = excess;
    for (const state of ordered) {
      if (leftToAllocate.isZero()) break;
      const deduction = Decimal.min(state.remaining, leftToAllocate);
      if (deduction.isZero()) continue;
      state.remaining = state.remaining.minus(deduction);
      state.concentrationExcess = state.concentrationExcess.plus(deduction);
      state.reasons.push({
        stage: "concentration",
        ruleId: rule.ruleId,
        reasonCode: rule.reasonCode,
        excludedAmount: decimalString(deduction)
      });
      leftToAllocate = leftToAllocate.minus(deduction);
      affected.push(state.receivable.receivableId);
    }
    if (!leftToAllocate.isZero()) {
      throw new Error(`Could not allocate concentration excess for debtor ${debtorId}`);
    }
    excluded = excluded.plus(excess);
    evidence.push(
      { key: `debtor:${debtorId}:eligible_before`, value: decimalString(debtorEligible) },
      { key: `debtor:${debtorId}:excess`, value: decimalString(excess) }
    );
  }

  return { excluded, affected: sortedUnique(affected), evidence };
}

function groupStatesByDebtor(
  states: ReadonlyMap<string, MutableReceivableState>
): ReadonlyMap<string, MutableReceivableState[]> {
  const groups = new Map<string, MutableReceivableState[]>();
  for (const state of states.values()) {
    const group = groups.get(state.receivable.debtorId) ?? [];
    group.push(state);
    groups.set(state.receivable.debtorId, group);
  }
  for (const group of groups.values()) {
    group.sort((left, right) =>
      compareText(left.receivable.receivableId, right.receivable.receivableId)
    );
  }
  return groups;
}

function matchesCondition(receivable: ArReceivable, condition: ArEligibilityCondition): boolean {
  switch (condition.kind) {
    case "days_past_due_at_least":
      return receivable.daysPastDue >= condition.days;
    case "flag_present":
      return receivable.flags.includes(condition.flag);
    case "debtor_id_in":
      return condition.debtorIds.includes(receivable.debtorId);
    case "all":
      return condition.conditions.every((item) => matchesCondition(receivable, item));
    case "any":
      return condition.conditions.some((item) => matchesCondition(receivable, item));
    case "not":
      return !matchesCondition(receivable, condition.condition);
  }
}

function validatePolicy(policy: ArBorrowingBasePolicyVersion): void {
  assertNonEmpty(policy.policyId, "policyId");
  assertNonEmpty(policy.version, "policy version");
  assertEffectiveRange(policy.effectiveFrom, policy.effectiveTo, `policy ${policy.policyId}`);
  if (!/^[A-Z]{3}$/.test(policy.currencyCode)) {
    throw new Error(`Policy ${policy.policyId} currencyCode must be an uppercase ISO-style three-letter code`);
  }
  ratioDecimal(policy.advanceRate, `policy ${policy.policyId} advanceRate`);
  if (policy.componentSublimit !== undefined) {
    nonNegativeDecimal(policy.componentSublimit, `policy ${policy.policyId} componentSublimit`);
  }
  nonNegativeDecimal(policy.commitmentAmount, `policy ${policy.policyId} commitmentAmount`);

  const reserveIds = new Set<string>();
  for (const reserve of policy.reserves) {
    assertNonEmpty(reserve.reserveId, "reserveId");
    assertNonEmpty(reserve.reasonCode, `reserve ${reserve.reserveId} reasonCode`);
    if (reserveIds.has(reserve.reserveId)) throw new Error(`Duplicate reserve id: ${reserve.reserveId}`);
    reserveIds.add(reserve.reserveId);
    nonNegativeDecimal(reserve.amount, `reserve ${reserve.reserveId} amount`);
  }
}

function validateEligibilityRule(rule: ArEligibilityRuleVersion): void {
  assertNonEmpty(rule.ruleId, "eligibility rule id");
  assertNonEmpty(rule.version, `eligibility rule ${rule.ruleId} version`);
  assertNonEmpty(rule.reasonCode, `eligibility rule ${rule.ruleId} reasonCode`);
  assertNonEmpty(rule.description, `eligibility rule ${rule.ruleId} description`);
  assertEffectiveRange(rule.effectiveFrom, rule.effectiveTo, `eligibility rule ${rule.ruleId}`);
  assertNonNegativeInteger(rule.priority, `eligibility rule ${rule.ruleId} priority`);
  validateCondition(rule.condition, 0);
}

function validateCondition(condition: ArEligibilityCondition, depth: number): void {
  if (depth > 10) throw new Error("Eligibility condition nesting exceeds 10 levels");
  switch (condition.kind) {
    case "days_past_due_at_least":
      assertNonNegativeInteger(condition.days, "eligibility days threshold");
      return;
    case "flag_present":
      return;
    case "debtor_id_in": {
      if (condition.debtorIds.length === 0) throw new Error("debtor_id_in requires at least one debtor id");
      for (const debtorId of condition.debtorIds) assertNonEmpty(debtorId, "debtor id condition value");
      return;
    }
    case "all":
    case "any":
      if (condition.conditions.length === 0) throw new Error(`${condition.kind} requires at least one condition`);
      for (const item of condition.conditions) validateCondition(item, depth + 1);
      return;
    case "not":
      validateCondition(condition.condition, depth + 1);
  }
}

function validateAndSortReceivables(receivables: readonly ArReceivable[]): readonly ArReceivable[] {
  const ids = new Set<string>();
  for (const receivable of receivables) {
    assertNonEmpty(receivable.receivableId, "receivableId");
    assertNonEmpty(receivable.debtorId, `receivable ${receivable.receivableId} debtorId`);
    if (ids.has(receivable.receivableId)) {
      throw new Error(`Duplicate receivable id: ${receivable.receivableId}`);
    }
    ids.add(receivable.receivableId);
    nonNegativeDecimal(receivable.outstandingAmount, `receivable ${receivable.receivableId} amount`);
    assertNonNegativeInteger(receivable.daysPastDue, `receivable ${receivable.receivableId} daysPastDue`);
    if (new Set(receivable.flags).size !== receivable.flags.length) {
      throw new Error(`Receivable ${receivable.receivableId} contains duplicate flags`);
    }
  }
  return [...receivables].sort((left, right) => compareText(left.receivableId, right.receivableId));
}

function validateAndSortUsage(usage: readonly FacilityUsage[]): readonly FacilityUsage[] {
  const ids = new Set<string>();
  for (const item of usage) {
    assertNonEmpty(item.usageId, "usageId");
    if (ids.has(item.usageId)) throw new Error(`Duplicate usage id: ${item.usageId}`);
    ids.add(item.usageId);
    nonNegativeDecimal(item.amount, `usage ${item.usageId} amount`);
  }
  return [...usage].sort((left, right) => compareText(left.usageId, right.usageId));
}

function isEffective(asOfDate: string, effectiveFrom: string, effectiveTo: string | undefined): boolean {
  return asOfDate >= effectiveFrom && (effectiveTo === undefined || asOfDate < effectiveTo);
}

function assertEffectiveRange(effectiveFrom: string, effectiveTo: string | undefined, label: string): void {
  assertIsoDate(effectiveFrom, `${label} effectiveFrom`);
  if (effectiveTo === undefined) return;
  assertIsoDate(effectiveTo, `${label} effectiveTo`);
  if (effectiveTo <= effectiveFrom) throw new Error(`${label} effectiveTo must be after effectiveFrom`);
}

function assertIsoDate(value: string, label: string): void {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) throw new Error(`${label} must be an ISO date (YYYY-MM-DD)`);
  const parsed = new Date(`${value}T00:00:00.000Z`);
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString().slice(0, 10) !== value) {
    throw new Error(`${label} is not a valid calendar date`);
  }
}

function assertNonNegativeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} must be a non-negative integer`);
}

function assertNonEmpty(value: string, label: string): void {
  if (!value.trim()) throw new Error(`${label} must not be empty`);
}

function nonNegativeDecimal(value: DecimalString, label: string): Decimal {
  const parsed = parseDecimal(value, label);
  if (parsed.isNegative()) throw new Error(`${label} must be non-negative`);
  return parsed;
}

function ratioDecimal(value: DecimalString, label: string): Decimal {
  const parsed = parseDecimal(value, label);
  if (parsed.lt(0) || parsed.gt(1)) throw new Error(`${label} must be between 0 and 1 inclusive`);
  return parsed;
}

function parseDecimal(value: DecimalString, label: string): Decimal {
  if (typeof value !== "string" || !/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/.test(value.trim())) {
    throw new Error(`${label} must be a plain decimal string`);
  }
  try {
    const parsed = new ExactDecimal(value.trim());
    if (!parsed.isFinite()) throw new Error("non-finite decimal");
    return parsed;
  } catch (error) {
    throw new Error(`${label} is not a valid decimal`, { cause: error });
  }
}

function zero(): Decimal {
  return new ExactDecimal(0);
}

function sum(values: readonly Decimal[]): Decimal {
  return values.reduce((total, value) => total.plus(value), zero());
}

function decimalString(value: Decimal): DecimalString {
  return value.isZero() ? "0" : value.toFixed();
}

function sortedUnique(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort(compareText);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
