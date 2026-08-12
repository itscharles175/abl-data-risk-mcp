import { createHash } from "node:crypto";

import { Decimal } from "decimal.js";

import type {
  ApprovalEvidenceV1,
  AvailabilityTriggerV2,
  BorrowerSubmittedCertificateV2,
  BorrowingBaseComponentResultV2,
  BorrowingBasePolicyV2,
  BorrowingBaseResultV2,
  BorrowingBaseStateV2,
  BorrowingBaseVarianceV2,
  CalculateBorrowingBaseV2Input,
  CashReconciliationInputV1,
  CashReconciliationResultV1,
  CertifiedCollateralPopulationV2,
  CertifiedPopulationRefV1,
  CollateralClassV2,
  CollateralRecordV2,
  ComponentConcentrationResultV2,
  ComponentPolicyV2,
  CounterfactualBorrowingBaseResultV1,
  CounterfactualScenarioV1,
  CovenantResultV2,
  DocumentTicklerInputV2,
  FormulaReserveV2,
  GovernedAdjustmentV2,
  ReserveFormulaV2,
  ReserveResultV2,
  TicklerResultV2,
  TriggerResultV2
} from "./contracts.js";

const ExactDecimal = Decimal.clone({
  precision: 256,
  rounding: Decimal.ROUND_HALF_EVEN,
  toExpNeg: -1_000,
  toExpPos: 1_000
});
const CANONICAL_DECIMAL = /^-?(?:0|[1-9]\d*)(?:\.\d+)?$/;
const HASH = /^[a-f0-9]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CURRENCY = /^[A-Z]{3}$/;
const MAX_RECORDS = 2_000_000;
const MAX_COMPONENTS = 20;
const MAX_RESERVES = 100;
const MAX_ADJUSTMENTS = 100;

interface ComponentComputation {
  readonly result: BorrowingBaseComponentResultV2;
  readonly gross: Decimal;
  readonly eligible: Decimal;
  readonly contribution: Decimal;
}

interface BasisContext {
  readonly facilityGross: Decimal;
  readonly facilityEligible: Decimal;
  readonly facilityContribution: Decimal;
  readonly components: ReadonlyMap<string, ComponentComputation>;
}

interface CalculatedState {
  readonly state: BorrowingBaseStateV2;
  readonly triggers: readonly TriggerResultV2[];
  readonly cashDominionActive: boolean;
}

interface ActiveAdjustments {
  readonly advanceRates: ReadonlyMap<string, Decimal>;
  readonly sublimits: ReadonlyMap<string, Decimal | null>;
  readonly reserveAmounts: ReadonlyMap<string, Decimal | null>;
  readonly availabilityBlock: Decimal;
  readonly records: readonly GovernedAdjustmentV2[];
}

/** Reperforms a certified, multi-component ABL borrowing base exactly. */
export function calculateBorrowingBaseV2(
  input: CalculateBorrowingBaseV2Input
): BorrowingBaseResultV2 {
  validateInput(input);
  const sortedPopulations = [...input.populations].sort(
    (left, right) =>
      compareText(left.collateralClass, right.collateralClass) ||
      compareText(left.certification.populationId, right.certification.populationId)
  );
  const usage = [...input.usage].sort((left, right) => compareText(left.usageId, right.usageId));
  const system = calculateState(
    "system_reperformed",
    input.policy,
    sortedPopulations,
    usage,
    emptyAdjustments()
  );
  const activeAdjustments = prepareAdjustments(
    input.adjustments ?? [],
    input.asOfDate,
    input.policy
  );
  const approved = calculateState(
    "approved_adjusted",
    input.policy,
    sortedPopulations,
    usage,
    activeAdjustments
  );
  const borrowerSubmitted = input.borrowerSubmitted
    ? submittedState(input.borrowerSubmitted, input.policy)
    : null;
  const variances = [
    ...(borrowerSubmitted ? compareStates(borrowerSubmitted, system.state) : []),
    ...compareStates(system.state, approved.state)
  ].sort(
    (left, right) =>
      compareText(left.leftState, right.leftState) || compareText(left.metric, right.metric)
  );
  const appliedAdjustments = activeAdjustments.records.map((adjustment) => ({
    adjustmentId: adjustment.adjustmentId,
    kind: adjustment.kind,
    adjustmentHash: fingerprint(adjustment),
    proposedBy: adjustment.approval.proposedBy,
    approvedBy: adjustment.approval.approvedBy
  }));
  const populationHashes = sortedUnique(
    sortedPopulations.map(({ certification }) => certification.populationHash)
  );
  const certificationHashes = sortedUnique(
    sortedPopulations.map(({ certification }) => certification.certificationHash)
  );
  const resultWithoutHash = {
    schemaVersion: "2" as const,
    calculationType: "multi_component_borrowing_base" as const,
    tenantId: input.tenantId,
    facilityId: input.facilityId,
    asOfDate: input.asOfDate,
    currencyCode: input.policy.currencyCode,
    policyId: input.policy.policyId,
    policyVersion: input.policy.version,
    policyHash: input.policy.policyHash,
    states: {
      borrowerSubmitted,
      systemReperformed: system.state,
      approvedAdjusted: approved.state
    },
    variances,
    appliedAdjustments,
    triggers: approved.triggers,
    covenants: evaluateCovenants(input.covenants ?? []),
    ticklers: evaluateTicklers(
      input.ticklers ?? [],
      input.asOfDate,
      input.policy.ticklerWarningDays
    ),
    cashDominionActive: approved.cashDominionActive,
    lineage: { certifiedPopulationHashes: populationHashes, certificationHashes }
  };
  return deepFreeze({
    ...resultWithoutHash,
    lineage: {
      ...resultWithoutHash.lineage,
      analysisHash: fingerprint(resultWithoutHash)
    }
  });
}

/**
 * Runs a bounded counterfactual without mutating or replacing the certified
 * baseline. Scenario outputs retain the baseline hash and assumption hash.
 */
export function runBorrowingBaseScenario(
  baseInput: CalculateBorrowingBaseV2Input,
  baseline: BorrowingBaseResultV2,
  scenario: CounterfactualScenarioV1
): CounterfactualBorrowingBaseResultV1 {
  validateScenario(scenario);
  if (scenario.tenantId !== baseInput.tenantId || baseline.tenantId !== baseInput.tenantId) {
    throw new Error("Counterfactual scenario belongs to a different tenant");
  }
  const recomputedBaseline = calculateBorrowingBaseV2(baseInput);
  if (
    baseline.lineage.analysisHash !== recomputedBaseline.lineage.analysisHash ||
    scenario.baseAnalysisHash !== baseline.lineage.analysisHash
  ) {
    throw new Error("Counterfactual baseline hash does not match the certified calculation");
  }
  const assumptionByComponent = new Map(
    scenario.componentAssumptions.map((assumption) => [assumption.componentId, assumption])
  );
  const knownComponents = new Set(baseInput.policy.components.map(({ componentId }) => componentId));
  for (const componentId of assumptionByComponent.keys()) {
    if (!knownComponents.has(componentId)) throw new Error(`Unknown scenario component ${componentId}`);
  }
  const populations = baseInput.populations.map((population) => {
    const component = baseInput.policy.components.find(
      ({ collateralClass }) => collateralClass === population.collateralClass
    )!;
    const assumption = assumptionByComponent.get(component.componentId);
    if (!assumption?.eligibleValueMultiplier) return population;
    const multiplier = nonNegativeDecimal(
      assumption.eligibleValueMultiplier,
      `scenario component ${component.componentId} eligibleValueMultiplier`,
      new ExactDecimal(10)
    );
    return {
      ...population,
      records: population.records.map((record) => multiplyEligibleBasis(record, multiplier))
    };
  });
  const policy: BorrowingBasePolicyV2 = {
    ...baseInput.policy,
    version: `${baseInput.policy.version}-scenario`,
    policyHash: fingerprint({
      basePolicyHash: baseInput.policy.policyHash,
      scenarioId: scenario.scenarioId,
      assumptions: scenario
    }),
    commitmentAmount: scenario.commitmentAmountOverride ?? baseInput.policy.commitmentAmount,
    components: baseInput.policy.components.map((component) => {
      const multiplier = assumptionByComponent.get(component.componentId)?.advanceRateMultiplier;
      if (!multiplier) return component;
      const rate = ratioDecimal(component.advanceRate, `${component.componentId} advanceRate`).times(
        nonNegativeDecimal(multiplier, `${component.componentId} advanceRateMultiplier`, new ExactDecimal(10))
      );
      if (rate.greaterThan(1)) throw new Error("Counterfactual advance rate cannot exceed 1");
      return { ...component, advanceRate: decimalString(rate) };
    }),
    reserves: [
      ...baseInput.policy.reserves,
      {
        reserveId: `scenario-${scenario.scenarioId}`,
        label: "Counterfactual reserve delta",
        formula: { kind: "fixed_amount", amount: scenario.reserveDelta }
      }
    ]
  };
  const { borrowerSubmitted: _submitted, ...scenarioBase } = baseInput;
  const result = calculateBorrowingBaseV2({
    ...scenarioBase,
    policy,
    populations
  });
  const assumptionsHash = fingerprint(scenario);
  const resultWithoutHash = {
    scenarioId: scenario.scenarioId,
    baseAnalysisHash: scenario.baseAnalysisHash,
    assumptionsHash,
    result
  };
  return deepFreeze({ ...resultWithoutHash, scenarioHash: fingerprint(resultWithoutHash) });
}

/** Reconciles certified lockbox receipts, cash applications, and loan paydowns. */
export function reconcileCashV1(input: CashReconciliationInputV1): CashReconciliationResultV1 {
  exactKeys(input, "cash reconciliation input", [
    "tenantId",
    "facilityId",
    "asOfDate",
    "certification",
    "openingLoanBalance",
    "reportedEndingLoanBalance",
    "transactions"
  ]);
  identifier(input.tenantId, "tenantId");
  identifier(input.facilityId, "facilityId");
  isoDate(input.asOfDate, "asOfDate");
  validateCertification(input.certification, input.tenantId, input.asOfDate);
  const opening = nonNegativeDecimal(input.openingLoanBalance, "openingLoanBalance");
  const reportedEnding = nonNegativeDecimal(
    input.reportedEndingLoanBalance,
    "reportedEndingLoanBalance"
  );
  if (input.transactions.length > 1_000_000) throw new Error("Cash reconciliation exceeds transaction limit");
  const ids = new Set<string>();
  const totals = {
    lockbox_receipt: zero(),
    cash_application: zero(),
    loan_paydown: zero()
  };
  for (const transaction of [...input.transactions].sort((left, right) => compareText(left.transactionId, right.transactionId))) {
    exactKeys(transaction, "cash transaction", [
      "transactionId",
      "kind",
      "effectiveDate",
      "amount",
      "referenceId"
    ]);
    identifier(transaction.transactionId, "transactionId");
    identifier(transaction.referenceId, "referenceId");
    if (ids.has(transaction.transactionId)) throw new Error("Cash transaction ids must be unique");
    ids.add(transaction.transactionId);
    if (!(transaction.kind in totals)) throw new Error("Cash transaction kind is unsupported");
    isoDate(transaction.effectiveDate, "cash transaction effectiveDate");
    if (transaction.effectiveDate > input.asOfDate) throw new Error("Cash transaction is after the reconciliation date");
    totals[transaction.kind] = totals[transaction.kind].plus(
      nonNegativeDecimal(transaction.amount, `transaction ${transaction.transactionId} amount`)
    );
  }
  const unapplied = totals.lockbox_receipt.minus(totals.cash_application);
  const applicationPaydownDifference = totals.cash_application.minus(totals.loan_paydown);
  const expectedEnding = opening.minus(totals.loan_paydown);
  if (expectedEnding.isNegative()) throw new Error("Loan paydowns exceed the opening loan balance");
  const endingDifference = reportedEnding.minus(expectedEnding);
  const breaks: Array<CashReconciliationResultV1["breaks"][number]> = [];
  if (unapplied.isNegative()) {
    breaks.push({ code: "negative_unapplied_cash", amount: decimalString(unapplied) });
  }
  if (!applicationPaydownDifference.isZero()) {
    breaks.push({
      code: "cash_application_paydown_mismatch",
      amount: decimalString(applicationPaydownDifference)
    });
  }
  if (!endingDifference.isZero()) {
    breaks.push({ code: "ending_balance_mismatch", amount: decimalString(endingDifference) });
  }
  const resultWithoutHash = {
    schemaVersion: "1" as const,
    reconciliationType: "lockbox_cash_application_paydown" as const,
    lockboxReceipts: decimalString(totals.lockbox_receipt),
    cashApplications: decimalString(totals.cash_application),
    unappliedCash: decimalString(unapplied),
    loanPaydowns: decimalString(totals.loan_paydown),
    cashAppliedVsPaydownDifference: decimalString(applicationPaydownDifference),
    expectedEndingLoanBalance: decimalString(expectedEnding),
    reportedEndingLoanBalance: decimalString(reportedEnding),
    endingLoanBalanceDifference: decimalString(endingDifference),
    passed: breaks.length === 0,
    breaks,
    lineage: {
      populationHash: input.certification.populationHash,
      certificationHash: input.certification.certificationHash
    }
  };
  return deepFreeze({
    ...resultWithoutHash,
    lineage: {
      ...resultWithoutHash.lineage,
      reconciliationHash: fingerprint(resultWithoutHash)
    }
  });
}

function calculateState(
  stateName: "system_reperformed" | "approved_adjusted",
  policy: BorrowingBasePolicyV2,
  populations: readonly CertifiedCollateralPopulationV2[],
  usage: CalculateBorrowingBaseV2Input["usage"],
  adjustments: ActiveAdjustments
): CalculatedState {
  const componentComputations = policy.components
    .map((component) =>
      calculateComponent(
        component,
        populations.filter(({ collateralClass }) => collateralClass === component.collateralClass),
        adjustments
      )
    )
    .sort((left, right) => compareText(left.result.componentId, right.result.componentId));
  const componentMap = new Map(
    componentComputations.map((component) => [component.result.componentId, component])
  );
  const context: BasisContext = {
    facilityGross: sum(componentComputations.map(({ gross }) => gross)),
    facilityEligible: sum(componentComputations.map(({ eligible }) => eligible)),
    facilityContribution: sum(componentComputations.map(({ contribution }) => contribution)),
    components: componentMap
  };
  const reserves = policy.reserves
    .map((reserve) => evaluateReserve(reserve, context, adjustments))
    .sort((left, right) => compareText(left.reserveId, right.reserveId));
  const totalReserves = sum(reserves.map(({ amount }) => exactDecimal(amount, "reserve amount")));
  const capacityBeforeCommitment = Decimal.max(context.facilityContribution.minus(totalReserves), zero());
  const commitment = nonNegativeDecimal(policy.commitmentAmount, "commitmentAmount");
  const capacityBeforeBlocks = Decimal.min(capacityBeforeCommitment, commitment);
  const totalUsage = sum(usage.map(({ amount, usageId }) => nonNegativeDecimal(amount, `usage ${usageId}`)));
  const preliminaryExcess = capacityBeforeBlocks.minus(totalUsage);
  const preliminaryOveradvance = Decimal.max(preliminaryExcess.negated(), zero());
  const triggerResults = evaluateTriggers(
    policy.triggers,
    capacityBeforeBlocks,
    totalUsage,
    preliminaryExcess,
    preliminaryOveradvance
  );
  const triggerBlocks = sum(
    triggerResults.map(({ appliedBlockAmount }) => exactDecimal(appliedBlockAmount, "trigger block"))
  );
  const availabilityBlocks = triggerBlocks.plus(adjustments.availabilityBlock);
  const borrowingCapacity = Decimal.max(capacityBeforeBlocks.minus(availabilityBlocks), zero());
  const excessAvailability = borrowingCapacity.minus(totalUsage);
  const overadvance = Decimal.max(excessAvailability.negated(), zero());
  const stateWithoutHash = {
    state: stateName,
    components: componentComputations.map(({ result }) => result),
    totalComponentContribution: decimalString(context.facilityContribution),
    reserves,
    totalReserves: decimalString(totalReserves),
    availabilityBlocks: decimalString(availabilityBlocks),
    borrowingCapacity: decimalString(borrowingCapacity),
    totalUsage: decimalString(totalUsage),
    excessAvailability: decimalString(excessAvailability),
    overadvance: decimalString(overadvance)
  };
  return {
    state: deepFreeze({ ...stateWithoutHash, stateHash: fingerprint(stateWithoutHash) }),
    triggers: triggerResults,
    cashDominionActive: triggerResults.some(
      ({ action, activated }) => action === "cash_dominion" && activated
    )
  };
}

function calculateComponent(
  policy: ComponentPolicyV2,
  populations: readonly CertifiedCollateralPopulationV2[],
  adjustments: ActiveAdjustments
): ComponentComputation {
  const records = populations
    .flatMap(({ records }) => records)
    .sort((left, right) => compareText(left.recordId, right.recordId));
  const gross = sum(
    records.map((record) => nonNegativeDecimal(record.grossValue, `record ${record.recordId} grossValue`))
  );
  const eligibleRecords = records.map((record) => ({
    record,
    amount: record.eligible ? collateralBasis(record, policy.valueBasis) : zero(),
    group: record.concentrationGroup ?? "Ungrouped"
  }));
  const preConcentrationEligible = sum(eligibleRecords.map(({ amount }) => amount));
  const concentrationResults: ComponentConcentrationResultV2[] = [];
  let concentrationExcess = zero();
  if (policy.concentration && !preConcentrationEligible.isZero()) {
    const groups = new Map<string, Decimal>();
    for (const record of eligibleRecords) {
      groups.set(record.group, (groups.get(record.group) ?? zero()).plus(record.amount));
    }
    for (const [group, amount] of [...groups.entries()].sort(([left], [right]) => compareText(left, right))) {
      const tier = selectConcentrationTier(amount, policy.concentration.tiers);
      const maximumShare = ratioDecimal(tier.maximumShare, `tier ${tier.tierId} maximumShare`);
      const cap = preConcentrationEligible.times(maximumShare);
      const excess = Decimal.max(amount.minus(cap), zero());
      concentrationExcess = concentrationExcess.plus(excess);
      concentrationResults.push({
        group,
        tierId: tier.tierId,
        preConcentrationAmount: decimalString(amount),
        maximumShare: decimalString(maximumShare),
        capAmount: decimalString(cap),
        excessAmount: decimalString(excess)
      });
    }
  }
  const eligible = Decimal.max(preConcentrationEligible.minus(concentrationExcess), zero());
  const advanceRate = adjustments.advanceRates.get(policy.componentId) ??
    ratioDecimal(policy.advanceRate, `component ${policy.componentId} advanceRate`);
  const advanced = eligible.times(advanceRate);
  const configuredSublimit = adjustments.sublimits.has(policy.componentId)
    ? adjustments.sublimits.get(policy.componentId)!
    : policy.componentSublimit === undefined
      ? null
      : nonNegativeDecimal(policy.componentSublimit, `component ${policy.componentId} sublimit`);
  const contribution = configuredSublimit === null ? advanced : Decimal.min(advanced, configuredSublimit);
  return {
    result: {
      componentId: policy.componentId,
      collateralClass: policy.collateralClass,
      recordCount: records.length,
      grossValue: decimalString(gross),
      preConcentrationEligibleValue: decimalString(preConcentrationEligible),
      concentrationExcess: decimalString(concentrationExcess),
      eligibleValue: decimalString(eligible),
      advanceRate: decimalString(advanceRate),
      advancedValue: decimalString(advanced),
      componentSublimit: configuredSublimit === null ? null : decimalString(configuredSublimit),
      contribution: decimalString(contribution),
      concentrations: concentrationResults,
      populationHashes: sortedUnique(populations.map(({ certification }) => certification.populationHash))
    },
    gross,
    eligible,
    contribution
  };
}

function collateralBasis(record: CollateralRecordV2, basis: ComponentPolicyV2["valueBasis"]): Decimal {
  switch (record.collateralClass) {
    case "accounts_receivable":
      if (basis !== "eligible_amount") throw new Error("Accounts receivable requires eligible_amount basis");
      return nonNegativeDecimal(record.eligibleAmount, `record ${record.recordId} eligibleAmount`);
    case "inventory":
      if (basis !== "nolv") throw new Error("Inventory requires nolv basis");
      return nonNegativeDecimal(record.nolv, `record ${record.recordId} nolv`);
    case "equipment":
      if (basis !== "appraised_value") throw new Error("Equipment requires appraised_value basis");
      return nonNegativeDecimal(record.appraisedValue, `record ${record.recordId} appraisedValue`);
    case "cash":
      if (basis !== "cleared_balance") throw new Error("Cash requires cleared_balance basis");
      return nonNegativeDecimal(record.clearedBalance, `record ${record.recordId} clearedBalance`);
  }
}

function selectConcentrationTier(
  amount: Decimal,
  tiers: NonNullable<ComponentPolicyV2["concentration"]>["tiers"]
): NonNullable<ComponentPolicyV2["concentration"]>["tiers"][number] {
  const selected = tiers.find(
    ({ upToGroupAmount }) =>
      upToGroupAmount === undefined || amount.lessThanOrEqualTo(exactDecimal(upToGroupAmount, "tier ceiling"))
  );
  if (!selected) throw new Error("Concentration tiers require an unbounded final tier");
  return selected;
}

function evaluateReserve(
  reserve: FormulaReserveV2,
  context: BasisContext,
  adjustments: ActiveAdjustments
): ReserveResultV2 {
  const adjusted = adjustments.reserveAmounts.get(reserve.reserveId);
  const waived = adjustments.reserveAmounts.has(reserve.reserveId) && adjusted === null;
  const overridden = adjustments.reserveAmounts.has(reserve.reserveId) && adjusted !== null;
  const amount = waived ? zero() : adjusted ?? evaluateReserveFormula(reserve.formula, reserve.componentId, context, 1);
  return {
    reserveId: reserve.reserveId,
    label: reserve.label,
    amount: decimalString(amount),
    formulaHash: fingerprint(reserve.formula),
    overridden,
    waived
  };
}

function evaluateReserveFormula(
  formula: ReserveFormulaV2,
  componentId: string | undefined,
  context: BasisContext,
  depth: number
): Decimal {
  if (depth > 4) throw new Error("Reserve formula exceeds maximum depth 4");
  if (formula.kind === "fixed_amount") return nonNegativeDecimal(formula.amount, "fixed reserve amount");
  if (formula.kind === "sum") {
    return sum(formula.terms.map((term) => evaluateReserveFormula(term, componentId, context, depth + 1)));
  }
  const basis = reserveBasis(formula.basis, componentId, context);
  const rate = ratioDecimal(formula.rate, "reserve rate");
  if (formula.kind === "percentage") return basis.times(rate);
  const threshold = nonNegativeDecimal(formula.threshold, "reserve threshold");
  return Decimal.max(basis.minus(threshold), zero()).times(rate);
}

function reserveBasis(
  basis: Exclude<ReserveFormulaV2, { readonly kind: "fixed_amount" } | { readonly kind: "sum" }>["basis"],
  componentId: string | undefined,
  context: BasisContext
): Decimal {
  if (basis === "facility_gross") return context.facilityGross;
  if (basis === "facility_eligible") return context.facilityEligible;
  if (basis === "facility_contribution") return context.facilityContribution;
  if (!componentId) throw new Error(`Reserve basis ${basis} requires componentId`);
  const component = context.components.get(componentId);
  if (!component) throw new Error(`Reserve references unknown component ${componentId}`);
  if (basis === "component_gross") return component.gross;
  if (basis === "component_eligible") return component.eligible;
  return component.contribution;
}

function evaluateTriggers(
  triggers: readonly AvailabilityTriggerV2[],
  capacity: Decimal,
  usage: Decimal,
  excess: Decimal,
  overadvance: Decimal
): readonly TriggerResultV2[] {
  const utilization = capacity.isZero() ? (usage.isZero() ? zero() : one()) : usage.dividedBy(capacity);
  return [...triggers]
    .sort((left, right) => compareText(left.triggerId, right.triggerId))
    .map((trigger) => {
      const threshold = nonNegativeDecimal(trigger.threshold, `trigger ${trigger.triggerId} threshold`);
      const observed =
        trigger.condition === "excess_availability_below"
          ? excess
          : trigger.condition === "overadvance_above"
            ? overadvance
            : utilization;
      const activated =
        trigger.condition === "excess_availability_below"
          ? observed.lessThan(threshold)
          : observed.greaterThan(threshold);
      const block =
        activated && trigger.action === "availability_block"
          ? nonNegativeDecimal(trigger.blockAmount!, `trigger ${trigger.triggerId} blockAmount`)
          : zero();
      return {
        triggerId: trigger.triggerId,
        condition: trigger.condition,
        action: trigger.action,
        threshold: decimalString(threshold),
        observedValue: decimalString(observed),
        activated,
        appliedBlockAmount: decimalString(block)
      };
    });
}

function evaluateCovenants(
  covenants: NonNullable<CalculateBorrowingBaseV2Input["covenants"]>
): readonly CovenantResultV2[] {
  const ids = new Set<string>();
  return [...covenants]
    .sort((left, right) => compareText(left.covenantId, right.covenantId))
    .map((covenant) => {
      exactKeys(covenant, "covenant", [
        "covenantId",
        "label",
        "comparator",
        "threshold",
        "actualValue"
      ]);
      identifier(covenant.covenantId, "covenantId");
      text(covenant.label, "covenant label", 256);
      if (ids.has(covenant.covenantId)) throw new Error("Covenant ids must be unique");
      ids.add(covenant.covenantId);
      if (covenant.comparator !== "gte" && covenant.comparator !== "lte") {
        throw new Error("Covenant comparator is unsupported");
      }
      const threshold = exactDecimal(covenant.threshold, `covenant ${covenant.covenantId} threshold`);
      const actual = exactDecimal(covenant.actualValue, `covenant ${covenant.covenantId} actualValue`);
      const headroom = covenant.comparator === "gte" ? actual.minus(threshold) : threshold.minus(actual);
      return {
        covenantId: covenant.covenantId,
        label: covenant.label,
        comparator: covenant.comparator,
        threshold: decimalString(threshold),
        actualValue: decimalString(actual),
        headroom: decimalString(headroom),
        status: headroom.isNegative() ? "breach" as const : "pass" as const
      };
    });
}

function evaluateTicklers(
  ticklers: readonly DocumentTicklerInputV2[],
  asOfDate: string,
  warningDays: number
): readonly TicklerResultV2[] {
  const ids = new Set<string>();
  return [...ticklers]
    .sort((left, right) => compareText(left.ticklerId, right.ticklerId))
    .map((tickler) => {
      exactKeys(tickler, "tickler", [
        "ticklerId",
        "kind",
        "dueDate",
        ...(tickler.completedAt === undefined ? [] : ["completedAt"]),
        ...(tickler.waiver === undefined ? [] : ["waiver"])
      ]);
      identifier(tickler.ticklerId, "ticklerId");
      if (ids.has(tickler.ticklerId)) throw new Error("Tickler ids must be unique");
      ids.add(tickler.ticklerId);
      if (!( ["appraisal", "field_exam", "ucc", "insurance"] as const).includes(tickler.kind)) {
        throw new Error("Tickler kind is unsupported");
      }
      isoDate(tickler.dueDate, `tickler ${tickler.ticklerId} dueDate`);
      if (tickler.completedAt !== undefined) isoTimestamp(tickler.completedAt, "tickler completedAt");
      if (tickler.waiver !== undefined) validateApproval(tickler.waiver);
      if (tickler.completedAt !== undefined && tickler.waiver !== undefined) {
        throw new Error("A tickler cannot be both completed and waived");
      }
      const daysUntilDue = daysBetween(asOfDate, tickler.dueDate);
      const status = tickler.completedAt !== undefined
        ? "completed" as const
        : tickler.waiver !== undefined
          ? "waived" as const
          : daysUntilDue < 0
            ? "overdue" as const
            : daysUntilDue <= warningDays
              ? "due_soon" as const
              : "current" as const;
      return {
        ticklerId: tickler.ticklerId,
        kind: tickler.kind,
        dueDate: tickler.dueDate,
        status,
        daysUntilDue
      };
    });
}

function submittedState(
  submitted: BorrowerSubmittedCertificateV2,
  policy: BorrowingBasePolicyV2
): BorrowingBaseStateV2 {
  exactKeys(submitted, "borrower-submitted certificate", [
    "certificateId",
    "submittedAt",
    "componentContributions",
    "totalReserves",
    "availabilityBlocks",
    "borrowingCapacity",
    "totalUsage",
    "excessAvailability"
  ]);
  identifier(submitted.certificateId, "certificateId");
  isoTimestamp(submitted.submittedAt, "submittedAt");
  const policyComponents = [...policy.components].sort((left, right) => compareText(left.componentId, right.componentId));
  exactKeys(submitted.componentContributions, "submitted componentContributions", policyComponents.map(({ componentId }) => componentId));
  const components = policyComponents.map((component) => ({
    componentId: component.componentId,
    collateralClass: component.collateralClass,
    recordCount: null,
    grossValue: null,
    preConcentrationEligibleValue: null,
    concentrationExcess: null,
    eligibleValue: null,
    advanceRate: null,
    advancedValue: null,
    componentSublimit: null,
    contribution: decimalString(
      nonNegativeDecimal(
        submitted.componentContributions[component.componentId]!,
        `submitted component ${component.componentId}`
      )
    ),
    concentrations: [],
    populationHashes: []
  } satisfies BorrowingBaseComponentResultV2));
  const totalContribution = sum(
    components.map(({ contribution }) => exactDecimal(contribution, "submitted contribution"))
  );
  const totalReserves = nonNegativeDecimal(submitted.totalReserves, "submitted totalReserves");
  const blocks = nonNegativeDecimal(submitted.availabilityBlocks, "submitted availabilityBlocks");
  const capacity = nonNegativeDecimal(submitted.borrowingCapacity, "submitted borrowingCapacity");
  const usage = nonNegativeDecimal(submitted.totalUsage, "submitted totalUsage");
  const excess = exactDecimal(submitted.excessAvailability, "submitted excessAvailability");
  if (!capacity.minus(usage).equals(excess)) {
    throw new Error("Borrower-submitted excess availability does not reconcile to capacity less usage");
  }
  const expectedCapacity = Decimal.max(
    Decimal.min(
      Decimal.max(totalContribution.minus(totalReserves), zero()),
      nonNegativeDecimal(policy.commitmentAmount, "commitmentAmount")
    ).minus(blocks),
    zero()
  );
  if (!capacity.equals(expectedCapacity)) {
    throw new Error("Borrower-submitted capacity does not reconcile to contributions, reserves, blocks, and commitment");
  }
  const stateWithoutHash = {
    state: "borrower_submitted" as const,
    components,
    totalComponentContribution: decimalString(totalContribution),
    reserves: [] as const,
    totalReserves: decimalString(totalReserves),
    availabilityBlocks: decimalString(blocks),
    borrowingCapacity: decimalString(capacity),
    totalUsage: decimalString(usage),
    excessAvailability: decimalString(excess),
    overadvance: decimalString(Decimal.max(excess.negated(), zero()))
  };
  return deepFreeze({ ...stateWithoutHash, stateHash: fingerprint(stateWithoutHash) });
}

function compareStates(
  left: BorrowingBaseStateV2,
  right: BorrowingBaseStateV2
): readonly BorrowingBaseVarianceV2[] {
  const leftComponents = new Map(left.components.map((component) => [component.componentId, component]));
  const rightComponents = new Map(right.components.map((component) => [component.componentId, component]));
  const componentIds = sortedUnique([...leftComponents.keys(), ...rightComponents.keys()]);
  const metrics: Array<readonly [string, string, string]> = componentIds.map((componentId) => [
    `component.${componentId}.contribution`,
    leftComponents.get(componentId)?.contribution ?? "0",
    rightComponents.get(componentId)?.contribution ?? "0"
  ]);
  metrics.push(
    ["total_component_contribution", left.totalComponentContribution, right.totalComponentContribution],
    ["total_reserves", left.totalReserves, right.totalReserves],
    ["availability_blocks", left.availabilityBlocks, right.availabilityBlocks],
    ["borrowing_capacity", left.borrowingCapacity, right.borrowingCapacity],
    ["total_usage", left.totalUsage, right.totalUsage],
    ["excess_availability", left.excessAvailability, right.excessAvailability],
    ["overadvance", left.overadvance, right.overadvance]
  );
  return metrics.map(([metric, leftValue, rightValue]) => ({
    metric,
    leftState: left.state,
    rightState: right.state,
    leftValue,
    rightValue,
    variance: decimalString(exactDecimal(rightValue, metric).minus(exactDecimal(leftValue, metric)))
  }));
}

function prepareAdjustments(
  adjustments: readonly GovernedAdjustmentV2[],
  asOfDate: string,
  policy: BorrowingBasePolicyV2
): ActiveAdjustments {
  if (adjustments.length > MAX_ADJUSTMENTS) throw new Error("Too many governed adjustments");
  const componentIds = new Set(policy.components.map(({ componentId }) => componentId));
  const reserveIds = new Set(policy.reserves.map(({ reserveId }) => reserveId));
  const ids = new Set<string>();
  const activeTargets = new Set<string>();
  const advanceRates = new Map<string, Decimal>();
  const sublimits = new Map<string, Decimal | null>();
  const reserveAmounts = new Map<string, Decimal | null>();
  let availabilityBlock = zero();
  const records: GovernedAdjustmentV2[] = [];
  for (const adjustment of [...adjustments].sort((left, right) => compareText(left.adjustmentId, right.adjustmentId))) {
    validateAdjustment(adjustment, componentIds, reserveIds);
    if (ids.has(adjustment.adjustmentId)) throw new Error("Adjustment ids must be unique");
    ids.add(adjustment.adjustmentId);
    if (!isEffective(asOfDate, adjustment.effectiveFrom, adjustment.effectiveTo)) continue;
    const target = "componentId" in adjustment
      ? adjustment.componentId
      : "reserveId" in adjustment
        ? adjustment.reserveId
        : "facility";
    const family = adjustment.kind.startsWith("component_sublimit_")
      ? "component_sublimit"
      : adjustment.kind.startsWith("reserve_")
        ? "reserve"
        : adjustment.kind;
    const targetKey = `${family}:${target}`;
    if (adjustment.kind !== "availability_block") {
      if (activeTargets.has(targetKey)) throw new Error(`Multiple active adjustments target ${targetKey}`);
      activeTargets.add(targetKey);
    }
    records.push(adjustment);
    switch (adjustment.kind) {
      case "advance_rate_override":
        advanceRates.set(adjustment.componentId, ratioDecimal(adjustment.value, "advance-rate override"));
        break;
      case "component_sublimit_override":
        sublimits.set(adjustment.componentId, nonNegativeDecimal(adjustment.value, "sublimit override"));
        break;
      case "component_sublimit_waiver":
        sublimits.set(adjustment.componentId, null);
        break;
      case "reserve_override":
        reserveAmounts.set(adjustment.reserveId, nonNegativeDecimal(adjustment.value, "reserve override"));
        break;
      case "reserve_waiver":
        reserveAmounts.set(adjustment.reserveId, null);
        break;
      case "availability_block":
        availabilityBlock = availabilityBlock.plus(
          nonNegativeDecimal(adjustment.value, "availability-block adjustment")
        );
    }
  }
  return { advanceRates, sublimits, reserveAmounts, availabilityBlock, records };
}

function emptyAdjustments(): ActiveAdjustments {
  return {
    advanceRates: new Map(),
    sublimits: new Map(),
    reserveAmounts: new Map(),
    availabilityBlock: zero(),
    records: []
  };
}

function validateInput(input: CalculateBorrowingBaseV2Input): void {
  exactKeys(input, "borrowing-base input", [
    "tenantId",
    "facilityId",
    "asOfDate",
    "policy",
    "populations",
    "usage",
    ...(input.borrowerSubmitted === undefined ? [] : ["borrowerSubmitted"]),
    ...(input.adjustments === undefined ? [] : ["adjustments"]),
    ...(input.covenants === undefined ? [] : ["covenants"]),
    ...(input.ticklers === undefined ? [] : ["ticklers"])
  ]);
  identifier(input.tenantId, "tenantId");
  identifier(input.facilityId, "facilityId");
  isoDate(input.asOfDate, "asOfDate");
  validatePolicy(input.policy);
  if (input.policy.tenantId !== input.tenantId || input.policy.facilityId !== input.facilityId) {
    throw new Error("Borrowing-base policy belongs to a different tenant or facility");
  }
  if (!isEffective(input.asOfDate, input.policy.effectiveFrom, input.policy.effectiveTo)) {
    throw new Error("Borrowing-base policy is not effective on the calculation date");
  }
  if (input.populations.length === 0) throw new Error("At least one certified population is required");
  if (input.populations.length > MAX_COMPONENTS * 20) throw new Error("Too many certified populations");
  const populationIds = new Set<string>();
  const recordIds = new Set<string>();
  let recordCount = 0;
  for (const population of input.populations) {
    validatePopulation(population, input.tenantId, input.asOfDate);
    if (populationIds.has(population.certification.populationId)) {
      throw new Error("Certified population ids must be unique");
    }
    populationIds.add(population.certification.populationId);
    recordCount += population.records.length;
    if (recordCount > MAX_RECORDS) throw new Error("Certified collateral record limit exceeded");
    for (const record of population.records) {
      if (recordIds.has(record.recordId)) throw new Error("Collateral record ids must be unique");
      recordIds.add(record.recordId);
    }
  }
  for (const component of input.policy.components) {
    if (!input.populations.some(({ collateralClass }) => collateralClass === component.collateralClass)) {
      throw new Error(`Component ${component.componentId} has no certified population`);
    }
  }
  validateUsage(input.usage);
  if ((input.covenants?.length ?? 0) > 100) throw new Error("Too many covenant tests");
  if ((input.ticklers?.length ?? 0) > 1_000) throw new Error("Too many document ticklers");
}

export function validateBorrowingBasePolicyV2(policy: BorrowingBasePolicyV2): void {
  validatePolicy(policy);
}

function validatePolicy(policy: BorrowingBasePolicyV2): void {
  exactKeys(policy, "borrowing-base policy", [
    "schemaVersion",
    "policyId",
    "version",
    "policyHash",
    "tenantId",
    "facilityId",
    "currencyCode",
    "effectiveFrom",
    ...(policy.effectiveTo === undefined ? [] : ["effectiveTo"]),
    "commitmentAmount",
    "components",
    "reserves",
    "triggers",
    "ticklerWarningDays",
    "approval"
  ]);
  if (policy.schemaVersion !== "2") throw new Error("Borrowing-base policy schemaVersion must be 2");
  identifier(policy.policyId, "policyId");
  identifier(policy.version, "policy version");
  hash(policy.policyHash, "policyHash");
  identifier(policy.tenantId, "policy tenantId");
  identifier(policy.facilityId, "policy facilityId");
  if (!CURRENCY.test(policy.currencyCode)) throw new Error("currencyCode must be ISO-style uppercase");
  isoDate(policy.effectiveFrom, "policy effectiveFrom");
  if (policy.effectiveTo !== undefined) {
    isoDate(policy.effectiveTo, "policy effectiveTo");
    if (policy.effectiveTo < policy.effectiveFrom) throw new Error("Policy effectivity range is inverted");
  }
  nonNegativeDecimal(policy.commitmentAmount, "commitmentAmount");
  if (policy.components.length === 0 || policy.components.length > MAX_COMPONENTS) {
    throw new Error(`Policy must contain 1-${MAX_COMPONENTS} components`);
  }
  const componentIds = new Set<string>();
  const classes = new Set<CollateralClassV2>();
  for (const component of policy.components) {
    validateComponent(component);
    if (componentIds.has(component.componentId)) throw new Error("Component ids must be unique");
    if (classes.has(component.collateralClass)) {
      throw new Error("A collateral class may appear in only one component");
    }
    componentIds.add(component.componentId);
    classes.add(component.collateralClass);
  }
  if (policy.reserves.length > MAX_RESERVES) throw new Error("Too many formula reserves");
  const reserveIds = new Set<string>();
  for (const reserve of policy.reserves) {
    validateReserve(reserve, componentIds);
    if (reserveIds.has(reserve.reserveId)) throw new Error("Reserve ids must be unique");
    reserveIds.add(reserve.reserveId);
  }
  if (policy.triggers.length > 100) throw new Error("Too many availability triggers");
  const triggerIds = new Set<string>();
  for (const trigger of policy.triggers) {
    validateTrigger(trigger);
    if (triggerIds.has(trigger.triggerId)) throw new Error("Trigger ids must be unique");
    triggerIds.add(trigger.triggerId);
  }
  if (!Number.isSafeInteger(policy.ticklerWarningDays) || policy.ticklerWarningDays < 0 || policy.ticklerWarningDays > 365) {
    throw new Error("ticklerWarningDays must be a safe integer from 0 through 365");
  }
  validateApproval(policy.approval);
}

function validateComponent(component: ComponentPolicyV2): void {
  exactKeys(component, "component policy", [
    "componentId",
    "collateralClass",
    "valueBasis",
    "advanceRate",
    ...(component.componentSublimit === undefined ? [] : ["componentSublimit"]),
    ...(component.concentration === undefined ? [] : ["concentration"])
  ]);
  identifier(component.componentId, "componentId");
  const expectedBasis: Record<CollateralClassV2, ComponentPolicyV2["valueBasis"]> = {
    accounts_receivable: "eligible_amount",
    inventory: "nolv",
    equipment: "appraised_value",
    cash: "cleared_balance"
  };
  if (!(component.collateralClass in expectedBasis)) throw new Error("Unsupported collateral class");
  if (component.valueBasis !== expectedBasis[component.collateralClass]) {
    throw new Error(`Invalid value basis for ${component.collateralClass}`);
  }
  ratioDecimal(component.advanceRate, `component ${component.componentId} advanceRate`);
  if (component.componentSublimit !== undefined) {
    nonNegativeDecimal(component.componentSublimit, `component ${component.componentId} sublimit`);
  }
  if (component.concentration !== undefined) validateConcentration(component.concentration);
}

function validateConcentration(policy: NonNullable<ComponentPolicyV2["concentration"]>): void {
  exactKeys(policy, "concentration policy", ["ruleId", "tiers"]);
  identifier(policy.ruleId, "concentration ruleId");
  if (policy.tiers.length === 0 || policy.tiers.length > 20) {
    throw new Error("Concentration policy must contain 1-20 tiers");
  }
  const ids = new Set<string>();
  let priorCeiling: Decimal | null = null;
  for (const [index, tier] of policy.tiers.entries()) {
    exactKeys(tier, "concentration tier", [
      "tierId",
      ...(tier.upToGroupAmount === undefined ? [] : ["upToGroupAmount"]),
      "maximumShare"
    ]);
    identifier(tier.tierId, "concentration tierId");
    if (ids.has(tier.tierId)) throw new Error("Concentration tier ids must be unique");
    ids.add(tier.tierId);
    ratioDecimal(tier.maximumShare, `tier ${tier.tierId} maximumShare`);
    if (tier.upToGroupAmount === undefined) {
      if (index !== policy.tiers.length - 1) throw new Error("Only the final concentration tier may be unbounded");
      continue;
    }
    const ceiling = nonNegativeDecimal(tier.upToGroupAmount, `tier ${tier.tierId} ceiling`);
    if (priorCeiling !== null && !ceiling.greaterThan(priorCeiling)) {
      throw new Error("Concentration tier ceilings must increase strictly");
    }
    priorCeiling = ceiling;
    if (index === policy.tiers.length - 1) throw new Error("Final concentration tier must be unbounded");
  }
}

function validateReserve(reserve: FormulaReserveV2, componentIds: ReadonlySet<string>): void {
  exactKeys(reserve, "formula reserve", [
    "reserveId",
    "label",
    ...(reserve.componentId === undefined ? [] : ["componentId"]),
    "formula"
  ]);
  identifier(reserve.reserveId, "reserveId");
  text(reserve.label, "reserve label", 256);
  if (reserve.componentId !== undefined) {
    identifier(reserve.componentId, "reserve componentId");
    if (!componentIds.has(reserve.componentId)) throw new Error("Reserve references unknown component");
  }
  const nodeCount = validateReserveFormula(reserve.formula, 1);
  if (nodeCount > 100) throw new Error("Reserve formula exceeds 100 nodes");
  if (formulaUsesComponentBasis(reserve.formula) && reserve.componentId === undefined) {
    throw new Error("Component reserve basis requires componentId");
  }
}

function validateReserveFormula(formula: ReserveFormulaV2, depth: number): number {
  if (depth > 4) throw new Error("Reserve formula exceeds maximum depth 4");
  if (formula.kind === "fixed_amount") {
    exactKeys(formula, "fixed reserve formula", ["kind", "amount"]);
    nonNegativeDecimal(formula.amount, "fixed reserve amount");
    return 1;
  }
  if (formula.kind === "sum") {
    exactKeys(formula, "sum reserve formula", ["kind", "terms"]);
    if (formula.terms.length === 0 || formula.terms.length > 20) {
      throw new Error("Sum reserve formula must contain 1-20 terms");
    }
    return 1 + formula.terms.reduce((count, term) => count + validateReserveFormula(term, depth + 1), 0);
  }
  if (formula.kind === "percentage") {
    exactKeys(formula, "percentage reserve formula", ["kind", "basis", "rate"]);
  } else if (formula.kind === "amount_above") {
    exactKeys(formula, "amount-above reserve formula", ["kind", "basis", "threshold", "rate"]);
    nonNegativeDecimal(formula.threshold, "reserve threshold");
  } else {
    throw new Error("Unsupported reserve formula kind");
  }
  if (!RESERVE_BASES.has(formula.basis)) throw new Error("Unsupported reserve basis");
  ratioDecimal(formula.rate, "reserve rate");
  return 1;
}

const RESERVE_BASES = new Set<Exclude<ReserveFormulaV2, { readonly kind: "fixed_amount" } | { readonly kind: "sum" }>["basis"]>([
  "facility_gross",
  "facility_eligible",
  "facility_contribution",
  "component_gross",
  "component_eligible",
  "component_contribution"
]);

function formulaUsesComponentBasis(formula: ReserveFormulaV2): boolean {
  if (formula.kind === "sum") return formula.terms.some(formulaUsesComponentBasis);
  return formula.kind !== "fixed_amount" && formula.basis.startsWith("component_");
}

function validateTrigger(trigger: AvailabilityTriggerV2): void {
  exactKeys(trigger, "availability trigger", [
    "triggerId",
    "condition",
    "threshold",
    "action",
    ...(trigger.blockAmount === undefined ? [] : ["blockAmount"])
  ]);
  identifier(trigger.triggerId, "triggerId");
  if (!( ["excess_availability_below", "overadvance_above", "utilization_above"] as const).includes(trigger.condition)) {
    throw new Error("Unsupported availability trigger condition");
  }
  if (!( ["availability_block", "cash_dominion"] as const).includes(trigger.action)) {
    throw new Error("Unsupported availability trigger action");
  }
  if (trigger.condition === "utilization_above") ratioDecimal(trigger.threshold, "utilization trigger threshold");
  else nonNegativeDecimal(trigger.threshold, "availability trigger threshold");
  if (trigger.action === "availability_block") {
    if (trigger.blockAmount === undefined) throw new Error("Availability-block trigger requires blockAmount");
    nonNegativeDecimal(trigger.blockAmount, "trigger blockAmount");
  } else if (trigger.blockAmount !== undefined) {
    throw new Error("Cash-dominion trigger cannot specify blockAmount");
  }
}

function validatePopulation(
  population: CertifiedCollateralPopulationV2,
  tenantId: string,
  asOfDate: string
): void {
  exactKeys(population, "certified collateral population", ["certification", "collateralClass", "records"]);
  if (!( ["accounts_receivable", "inventory", "equipment", "cash"] as const).includes(population.collateralClass)) {
    throw new Error("Unsupported collateral population class");
  }
  validateCertification(population.certification, tenantId, asOfDate);
  for (const record of population.records) validateCollateralRecord(record, population.collateralClass);
}

function validateCollateralRecord(record: CollateralRecordV2, expectedClass: CollateralClassV2): void {
  if (record.collateralClass !== expectedClass) throw new Error("Collateral record class does not match population");
  const basisKey = record.collateralClass === "accounts_receivable"
    ? "eligibleAmount"
    : record.collateralClass === "inventory"
      ? "nolv"
      : record.collateralClass === "equipment"
        ? "appraisedValue"
        : "clearedBalance";
  exactKeys(record, "collateral record", [
    "recordId",
    "collateralClass",
    "grossValue",
    "eligible",
    ...(record.concentrationGroup === undefined ? [] : ["concentrationGroup"]),
    basisKey
  ]);
  identifier(record.recordId, "collateral recordId");
  if (typeof record.eligible !== "boolean") throw new Error("Collateral eligible must be boolean");
  if (record.concentrationGroup !== undefined) identifier(record.concentrationGroup, "concentrationGroup");
  const gross = nonNegativeDecimal(record.grossValue, `record ${record.recordId} grossValue`);
  const basis = collateralBasis(record, expectedBasisForClass(expectedClass));
  if (basis.greaterThan(gross)) throw new Error("Collateral basis cannot exceed gross value");
}

function expectedBasisForClass(collateralClass: CollateralClassV2): ComponentPolicyV2["valueBasis"] {
  if (collateralClass === "accounts_receivable") return "eligible_amount";
  if (collateralClass === "inventory") return "nolv";
  if (collateralClass === "equipment") return "appraised_value";
  return "cleared_balance";
}

function validateCertification(
  certification: CertifiedPopulationRefV1,
  tenantId: string,
  asOfDate: string
): void {
  exactKeys(certification, "population certification", [
    "schemaVersion",
    "tenantId",
    "populationId",
    "snapshotId",
    "asOfDate",
    "status",
    "populationHash",
    "certificationHash"
  ]);
  if (certification.schemaVersion !== "1" || certification.status !== "certified") {
    throw new Error("Collateral population must be certified");
  }
  identifier(certification.tenantId, "certification tenantId");
  identifier(certification.populationId, "populationId");
  identifier(certification.snapshotId, "snapshotId");
  isoDate(certification.asOfDate, "certification asOfDate");
  hash(certification.populationHash, "populationHash");
  hash(certification.certificationHash, "certificationHash");
  if (certification.tenantId !== tenantId) throw new Error("Certified population belongs to a different tenant");
  if (certification.asOfDate !== asOfDate) throw new Error("Certified population date does not match calculation date");
}

function validateUsage(usage: CalculateBorrowingBaseV2Input["usage"]): void {
  if (usage.length > 1_000) throw new Error("Too many facility usage records");
  const ids = new Set<string>();
  for (const item of usage) {
    exactKeys(item, "facility usage", ["usageId", "kind", "amount"]);
    identifier(item.usageId, "usageId");
    if (ids.has(item.usageId)) throw new Error("Usage ids must be unique");
    ids.add(item.usageId);
    if (!( ["revolver", "letters_of_credit", "swingline", "other"] as const).includes(item.kind)) {
      throw new Error("Unsupported facility usage kind");
    }
    nonNegativeDecimal(item.amount, `usage ${item.usageId} amount`);
  }
}

function validateAdjustment(
  adjustment: GovernedAdjustmentV2,
  componentIds: ReadonlySet<string>,
  reserveIds: ReadonlySet<string>
): void {
  const common = [
    "adjustmentId",
    "kind",
    "effectiveFrom",
    ...(adjustment.effectiveTo === undefined ? [] : ["effectiveTo"]),
    "approval"
  ];
  if (adjustment.kind === "advance_rate_override" || adjustment.kind === "component_sublimit_override") {
    exactKeys(adjustment, "governed adjustment", [...common, "componentId", "value"]);
    if (!componentIds.has(adjustment.componentId)) throw new Error("Adjustment references unknown component");
    if (adjustment.kind === "advance_rate_override") ratioDecimal(adjustment.value, "advance-rate override");
    else nonNegativeDecimal(adjustment.value, "sublimit override");
  } else if (adjustment.kind === "component_sublimit_waiver") {
    exactKeys(adjustment, "governed adjustment", [...common, "componentId"]);
    if (!componentIds.has(adjustment.componentId)) throw new Error("Adjustment references unknown component");
  } else if (adjustment.kind === "reserve_override") {
    exactKeys(adjustment, "governed adjustment", [...common, "reserveId", "value"]);
    if (!reserveIds.has(adjustment.reserveId)) throw new Error("Adjustment references unknown reserve");
    nonNegativeDecimal(adjustment.value, "reserve override");
  } else if (adjustment.kind === "reserve_waiver") {
    exactKeys(adjustment, "governed adjustment", [...common, "reserveId"]);
    if (!reserveIds.has(adjustment.reserveId)) throw new Error("Adjustment references unknown reserve");
  } else if (adjustment.kind === "availability_block") {
    exactKeys(adjustment, "governed adjustment", [...common, "value"]);
    nonNegativeDecimal(adjustment.value, "availability block");
  } else {
    throw new Error("Unsupported governed adjustment kind");
  }
  identifier(adjustment.adjustmentId, "adjustmentId");
  isoDate(adjustment.effectiveFrom, "adjustment effectiveFrom");
  if (adjustment.effectiveTo !== undefined) {
    isoDate(adjustment.effectiveTo, "adjustment effectiveTo");
    if (adjustment.effectiveTo < adjustment.effectiveFrom) throw new Error("Adjustment effectivity range is inverted");
  }
  validateApproval(adjustment.approval);
}

function validateApproval(approval: ApprovalEvidenceV1): void {
  exactKeys(approval, "approval evidence", [
    "status",
    "proposedBy",
    "approvedBy",
    "approvedAt",
    "authorityRef",
    "rationale"
  ]);
  if (approval.status !== "approved") throw new Error("Governed change must be approved");
  identifier(approval.proposedBy, "proposedBy");
  identifier(approval.approvedBy, "approvedBy");
  if (approval.proposedBy === approval.approvedBy) throw new Error("Maker and checker must be different principals");
  isoTimestamp(approval.approvedAt, "approvedAt");
  identifier(approval.authorityRef, "authorityRef");
  text(approval.rationale, "approval rationale", 2_000);
}

function validateScenario(scenario: CounterfactualScenarioV1): void {
  exactKeys(scenario, "counterfactual scenario", [
    "schemaVersion",
    "scenarioId",
    "tenantId",
    "baseAnalysisHash",
    "createdBy",
    "createdAt",
    "componentAssumptions",
    "reserveDelta",
    ...(scenario.commitmentAmountOverride === undefined ? [] : ["commitmentAmountOverride"])
  ]);
  if (scenario.schemaVersion !== "1") throw new Error("Counterfactual scenario schemaVersion must be 1");
  identifier(scenario.scenarioId, "scenarioId");
  identifier(scenario.tenantId, "scenario tenantId");
  hash(scenario.baseAnalysisHash, "baseAnalysisHash");
  identifier(scenario.createdBy, "scenario createdBy");
  isoTimestamp(scenario.createdAt, "scenario createdAt");
  nonNegativeDecimal(scenario.reserveDelta, "scenario reserveDelta");
  if (scenario.commitmentAmountOverride !== undefined) {
    nonNegativeDecimal(scenario.commitmentAmountOverride, "scenario commitmentAmountOverride");
  }
  if (scenario.componentAssumptions.length > MAX_COMPONENTS) throw new Error("Too many scenario component assumptions");
  const ids = new Set<string>();
  for (const assumption of scenario.componentAssumptions) {
    exactKeys(assumption, "scenario component assumption", [
      "componentId",
      ...(assumption.advanceRateMultiplier === undefined ? [] : ["advanceRateMultiplier"]),
      ...(assumption.eligibleValueMultiplier === undefined ? [] : ["eligibleValueMultiplier"])
    ]);
    identifier(assumption.componentId, "scenario componentId");
    if (ids.has(assumption.componentId)) throw new Error("Scenario component assumptions must be unique");
    ids.add(assumption.componentId);
    if (assumption.advanceRateMultiplier === undefined && assumption.eligibleValueMultiplier === undefined) {
      throw new Error("Scenario component assumption must change at least one bounded value");
    }
    if (assumption.advanceRateMultiplier !== undefined) {
      nonNegativeDecimal(assumption.advanceRateMultiplier, "advanceRateMultiplier", new ExactDecimal(10));
    }
    if (assumption.eligibleValueMultiplier !== undefined) {
      nonNegativeDecimal(assumption.eligibleValueMultiplier, "eligibleValueMultiplier", new ExactDecimal(10));
    }
  }
}

function multiplyEligibleBasis(record: CollateralRecordV2, multiplier: Decimal): CollateralRecordV2 {
  if (record.collateralClass === "accounts_receivable") {
    return { ...record, eligibleAmount: decimalString(exactDecimal(record.eligibleAmount, "eligibleAmount").times(multiplier)) };
  }
  if (record.collateralClass === "inventory") {
    return { ...record, nolv: decimalString(exactDecimal(record.nolv, "nolv").times(multiplier)) };
  }
  if (record.collateralClass === "equipment") {
    return { ...record, appraisedValue: decimalString(exactDecimal(record.appraisedValue, "appraisedValue").times(multiplier)) };
  }
  return { ...record, clearedBalance: decimalString(exactDecimal(record.clearedBalance, "clearedBalance").times(multiplier)) };
}

function isEffective(asOfDate: string, from: string, to: string | undefined): boolean {
  return asOfDate >= from && (to === undefined || asOfDate <= to);
}

function exactDecimal(value: string, label: string): Decimal {
  if (typeof value !== "string" || !CANONICAL_DECIMAL.test(value)) {
    throw new Error(`${label} must be a canonical exact decimal string`);
  }
  const decimal = new ExactDecimal(value);
  if (!decimal.isFinite() || decimalString(decimal) !== value) {
    throw new Error(`${label} must be a canonical exact decimal string`);
  }
  return decimal;
}

function nonNegativeDecimal(value: string, label: string, maximum?: Decimal): Decimal {
  const decimal = exactDecimal(value, label);
  if (decimal.isNegative()) throw new Error(`${label} must be non-negative`);
  if (maximum !== undefined && decimal.greaterThan(maximum)) throw new Error(`${label} exceeds its bound`);
  return decimal;
}

function ratioDecimal(value: string, label: string): Decimal {
  return nonNegativeDecimal(value, label, one());
}

function decimalString(value: Decimal): string {
  return value.isZero() ? "0" : value.toFixed();
}

function zero(): Decimal {
  return new ExactDecimal(0);
}

function one(): Decimal {
  return new ExactDecimal(1);
}

function sum(values: readonly Decimal[]): Decimal {
  return values.reduce((total, value) => total.plus(value), zero());
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

function text(value: string, label: string, maximumLength: number): void {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || value.length > maximumLength) {
    throw new Error(`${label} is invalid`);
  }
}

function isoDate(value: string, label: string): void {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) throw new Error(`${label} must be YYYY-MM-DD`);
  const parsed = new Date(`${value}T00:00:00.000Z`);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== value) {
    throw new Error(`${label} is not a valid date`);
  }
}

function isoTimestamp(value: string, label: string): void {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) {
    throw new Error(`${label} must be a UTC ISO timestamp`);
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw new Error(`${label} is not a valid timestamp`);
}

function daysBetween(from: string, to: string): number {
  return Math.trunc((Date.parse(`${to}T00:00:00.000Z`) - Date.parse(`${from}T00:00:00.000Z`)) / 86_400_000);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort(compareText);
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

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value as Record<string, unknown>)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}
