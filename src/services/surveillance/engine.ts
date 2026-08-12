import { Decimal } from "decimal.js";

import {
  classifyBin,
  cohortForRecord,
  matchesFilter,
  stableFingerprint,
  stableJson,
  validateBinDefinitionV1,
  validateCohortDefinitionV1,
  validateEntityResolutionDefinitionV1,
  validateHash,
  validateIsoDate,
  validateMetricDefinitionV1,
  type ValidatedNumericBinV1
} from "../../domain/surveillance/definitions.js";
import type {
  BinDefinitionV1,
  CanonicalSurveillanceRecord,
  CertifiedSurveillanceSnapshotV1,
  CohortDefinitionV1,
  EntityResolutionDefinitionV1,
  MetricAvailabilityReasonV1,
  MetricCellV1,
  MetricDefinitionV1,
  PortfolioSurveillanceInputV1,
  PortfolioSurveillanceResultV1,
  SurveillanceMetricResultV1
} from "../../domain/surveillance/contracts.js";

const CANONICAL_DECIMAL = /^-?(?:0|[1-9]\d*)(?:\.\d+)?$/;
const CANONICAL_INTEGER = /^-?(?:0|[1-9]\d*)$/;
const IDENTIFIER = /^[a-zA-Z][a-zA-Z0-9_.:-]{0,127}$/;
const ExactDecimal = Decimal.clone({
  precision: 256,
  rounding: Decimal.ROUND_HALF_EVEN,
  toExpNeg: -1_000,
  toExpPos: 1_000
});

interface PreparedRecord {
  readonly record: CanonicalSurveillanceRecord;
  readonly recordKey: string;
  readonly populationToken: string;
}

interface PreparedSnapshot {
  readonly snapshot: CertifiedSurveillanceSnapshotV1;
  readonly records: readonly PreparedRecord[];
}

interface ExecutionContext {
  readonly tenantId: string;
  readonly snapshots: readonly PreparedSnapshot[];
  readonly bins: ReadonlyMap<string, { readonly definition: BinDefinitionV1; readonly parsed: readonly ValidatedNumericBinV1[] }>;
  readonly cohorts: ReadonlyMap<string, CohortDefinitionV1>;
  readonly entityResolutions: ReadonlyMap<string, EntityResolutionDefinitionV1>;
  readonly methodologyId: string;
  readonly methodologyVersion: number;
  readonly methodologyHash: string;
  readonly maxCells: number;
}

interface RawCell {
  readonly metric: string;
  readonly unit: MetricCellV1["unit"];
  readonly dimensions: Readonly<Record<string, string>>;
  readonly numerator: Decimal | null;
  readonly denominator: Decimal | null;
  readonly value: Decimal | null;
  readonly observedCount: number;
  readonly eligibleCount: number;
  readonly privacyCount: number;
  readonly populationTokens: readonly string[];
  readonly snapshotHashes: readonly string[];
  readonly entityResolutionHash: string | null;
  readonly availabilityReason: Exclude<MetricAvailabilityReasonV1, "suppressed" | "insufficient_coverage">;
  readonly suppressionGroup: string;
}

interface MutableAmountGroup {
  amount: Decimal;
  count: number;
  readonly tokens: Set<string>;
}

/**
 * Executes approved surveillance definitions over certified immutable
 * snapshots. Input ordering never affects result ordering or hashes.
 */
export function runPortfolioSurveillance(
  input: PortfolioSurveillanceInputV1
): PortfolioSurveillanceResultV1 {
  const context = prepareContext(input);
  const definitions = [...input.metricDefinitions].sort(
    (left, right) =>
      compareText(left.definitionId, right.definitionId) || left.version - right.version
  );
  const metrics = definitions.map((definition) => executeMetric(context, definition));
  const totalCellCount = metrics.reduce((total, metric) => total + metric.cells.length, 0);
  if (totalCellCount > input.bounds.maxCells) {
    throw new Error(
      `Surveillance pack produced ${totalCellCount} cells, exceeding execution maxCells ${input.bounds.maxCells}`
    );
  }
  const asOfDates = context.snapshots.map(({ snapshot }) => snapshot.asOfDate);
  const snapshotHashes = context.snapshots.map(({ snapshot }) => snapshot.snapshotHash);
  const resultWithoutHash = {
    schemaVersion: "1" as const,
    tenantId: input.tenantId,
    asOfDates,
    metrics,
    lineage: {
      methodologyId: input.methodology.methodologyId,
      methodologyVersion: input.methodology.methodologyVersion,
      methodologyHash: input.methodology.methodologyHash,
      snapshotHashes
    }
  };
  return {
    ...resultWithoutHash,
    lineage: {
      ...resultWithoutHash.lineage,
      analysisHash: stableFingerprint(resultWithoutHash)
    }
  };
}

function prepareContext(input: PortfolioSurveillanceInputV1): ExecutionContext {
  identifier(input.tenantId, "tenantId");
  identifier(input.methodology.methodologyId, "methodologyId");
  positiveInteger(input.methodology.methodologyVersion, "methodologyVersion", 1_000_000);
  validateHash(input.methodology.methodologyHash, "methodologyHash");
  positiveInteger(input.bounds.maxSnapshots, "bounds.maxSnapshots", 120);
  positiveInteger(input.bounds.maxRecords, "bounds.maxRecords", 5_000_000);
  positiveInteger(input.bounds.maxMetrics, "bounds.maxMetrics", 1_000);
  positiveInteger(input.bounds.maxCells, "bounds.maxCells", 1_000_000);
  if (input.snapshots.length < 1 || input.snapshots.length > input.bounds.maxSnapshots) {
    throw new Error(`Expected between 1 and ${input.bounds.maxSnapshots} snapshots`);
  }
  if (
    input.metricDefinitions.length < 1 ||
    input.metricDefinitions.length > input.bounds.maxMetrics
  ) {
    throw new Error(`Expected between 1 and ${input.bounds.maxMetrics} metric definitions`);
  }

  const definitionKeys = new Set<string>();
  const definitionIds = new Set<string>();
  for (const definition of input.metricDefinitions) {
    validateMetricDefinitionV1(definition);
    const key = `${definition.definitionId}@${definition.version}`;
    if (definitionKeys.has(key)) throw new Error(`Duplicate metric definition ${key}`);
    if (definitionIds.has(definition.definitionId)) {
      throw new Error(`Only one active version of metric definition ${definition.definitionId} may execute`);
    }
    definitionKeys.add(key);
    definitionIds.add(definition.definitionId);
  }

  const bins = new Map<string, { definition: BinDefinitionV1; parsed: readonly ValidatedNumericBinV1[] }>();
  for (const definition of input.binDefinitions ?? []) {
    const parsed = validateBinDefinitionV1(definition);
    if (bins.has(definition.definitionId)) {
      throw new Error(`Duplicate active bin definition ${definition.definitionId}`);
    }
    bins.set(definition.definitionId, { definition, parsed });
  }
  const cohorts = new Map<string, CohortDefinitionV1>();
  for (const definition of input.cohortDefinitions ?? []) {
    validateCohortDefinitionV1(definition);
    if (cohorts.has(definition.definitionId)) {
      throw new Error(`Duplicate active cohort definition ${definition.definitionId}`);
    }
    cohorts.set(definition.definitionId, definition);
  }
  const entityResolutions = new Map<string, EntityResolutionDefinitionV1>();
  for (const definition of input.entityResolutionDefinitions ?? []) {
    validateEntityResolutionDefinitionV1(definition, input.tenantId);
    if (entityResolutions.has(definition.definitionId)) {
      throw new Error(`Duplicate active entity-resolution definition ${definition.definitionId}`);
    }
    entityResolutions.set(definition.definitionId, definition);
  }

  const sortedSnapshots = [...input.snapshots].sort((left, right) =>
    compareText(left.asOfDate, right.asOfDate)
  );
  let totalRecords = 0;
  let previousDate: string | undefined;
  const snapshotIds = new Set<string>();
  const snapshots: PreparedSnapshot[] = [];
  for (const snapshot of sortedSnapshots) {
    validateSnapshot(snapshot, input.tenantId);
    if (previousDate === snapshot.asOfDate) {
      throw new Error(`Only one certified snapshot may exist for as-of date ${snapshot.asOfDate}`);
    }
    if (snapshotIds.has(snapshot.snapshotId)) throw new Error("Snapshot ids must be unique");
    previousDate = snapshot.asOfDate;
    snapshotIds.add(snapshot.snapshotId);
    totalRecords += snapshot.records.length;
    if (totalRecords > input.bounds.maxRecords) {
      throw new Error(`Snapshot population exceeds maxRecords ${input.bounds.maxRecords}`);
    }
    snapshots.push({ snapshot, records: prepareRecords(snapshot, input.tenantId) });
  }

  return {
    tenantId: input.tenantId,
    snapshots,
    bins,
    cohorts,
    entityResolutions,
    methodologyId: input.methodology.methodologyId,
    methodologyVersion: input.methodology.methodologyVersion,
    methodologyHash: input.methodology.methodologyHash,
    maxCells: input.bounds.maxCells
  };
}

function validateSnapshot(snapshot: CertifiedSurveillanceSnapshotV1, tenantId: string): void {
  if (snapshot.schemaVersion !== "1") throw new Error("Snapshot must use schema version 1");
  identifier(snapshot.snapshotId, "snapshotId");
  if (snapshot.tenantId !== tenantId) throw new Error("Snapshot belongs to a different tenant");
  validateIsoDate(snapshot.asOfDate, "snapshot asOfDate");
  validateHash(snapshot.snapshotHash, "snapshotHash");
  if (snapshot.certification.status !== "certified") {
    throw new Error("Surveillance requires certified snapshots");
  }
  identifier(snapshot.certification.certificationId, "certificationId");
  validateHash(snapshot.certification.certificationHash, "certificationHash");
  isoTimestamp(snapshot.certification.certifiedAt, "certifiedAt");
}

function prepareRecords(
  snapshot: CertifiedSurveillanceSnapshotV1,
  tenantId: string
): readonly PreparedRecord[] {
  const records: PreparedRecord[] = [];
  const keys = new Set<string>();
  for (const [index, record] of snapshot.records.entries()) {
    const asOfDate = requiredString(record.as_of_date, "as_of_date", index);
    validateIsoDate(asOfDate, `Record ${index} as_of_date`);
    if (asOfDate !== snapshot.asOfDate) {
      throw new Error(`Record ${index} does not match its certified snapshot as-of date`);
    }
    const loanId = requiredString(record.loan_id, "loan_id", index);
    boundedText(loanId, `Record ${index} loan_id`, 512);
    const facilityId = optionalText(record.facility_id, `Record ${index} facility_id`) ?? "";
    const sourceSystem = optionalText(record.source_system, `Record ${index} source_system`) ?? "";
    const recordKey = stableJson([sourceSystem, facilityId, loanId]);
    if (keys.has(recordKey)) {
      throw new Error(`Certified snapshot ${snapshot.asOfDate} contains a duplicate loan grain`);
    }
    keys.add(recordKey);
    records.push({
      record,
      recordKey,
      populationToken: stableFingerprint(["population-record-v1", tenantId, recordKey])
    });
  }
  return records.sort((left, right) => compareText(left.recordKey, right.recordKey));
}

function executeMetric(
  context: ExecutionContext,
  definition: MetricDefinitionV1
): SurveillanceMetricResultV1 {
  const snapshots = context.snapshots.slice(-definition.window.maximumPeriods).map((snapshot) => ({
    snapshot: snapshot.snapshot,
    records: definition.population
      ? snapshot.records.filter(({ record }) => matchesFilter(record, definition.population!))
      : snapshot.records
  }));
  const metricContext: ExecutionContext = { ...context, snapshots };
  const rawCells = executeMetricFamily(metricContext, definition);
  if (rawCells.length > definition.maximumCells) {
    throw new Error(
      `Metric ${definition.definitionId} produced ${rawCells.length} cells, exceeding definition maximumCells ${definition.maximumCells}`
    );
  }
  if (rawCells.length > context.maxCells) {
    throw new Error(
      `Metric ${definition.definitionId} produced ${rawCells.length} cells, exceeding execution maxCells ${context.maxCells}`
    );
  }
  const definitionHash = stableFingerprint(definition);
  const supportingDefinitionHashes = supportingDefinitionHashesFor(context, definition);
  const cells = finalizeCells(
    context.tenantId,
    definition,
    definitionHash,
    supportingDefinitionHashes,
    context.methodologyId,
    context.methodologyVersion,
    context.methodologyHash,
    rawCells
  );
  const warnings = warningsFor(definition);
  const resultWithoutHash = {
    schemaVersion: "1" as const,
    metricDefinitionId: definition.definitionId,
    metricDefinitionVersion: definition.version,
    family: definition.family,
    cells,
    warnings,
    lineage: {
      definitionHash,
      supportingDefinitionHashes,
      methodologyId: context.methodologyId,
      methodologyVersion: context.methodologyVersion,
      methodologyHash: context.methodologyHash
    }
  };
  return {
    ...resultWithoutHash,
    lineage: {
      ...resultWithoutHash.lineage,
      analysisHash: stableFingerprint(resultWithoutHash)
    }
  };
}

function executeMetricFamily(
  context: ExecutionContext,
  definition: MetricDefinitionV1
): readonly RawCell[] {
  switch (definition.configuration.kind) {
    case "roll_cure":
      return calculateRollCure(context, definition);
    case "default_ever":
      return calculateDefaultEver(context, definition);
    case "loss_recovery":
      return calculateLossRecovery(context, definition);
    case "paydown_prepayment":
      return calculatePaydownPrepayment(context, definition);
    case "rating_migration":
      return calculateRatingMigration(context, definition);
    case "balance_utilization":
      return calculateBalanceUtilization(context, definition);
    case "maturity_wall":
      return calculateMaturityWall(context, definition);
    case "concentration":
      return calculateConcentration(context, definition);
    case "period_comparison":
      return calculatePeriodComparison(context, definition);
  }
}

function calculateRollCure(
  context: ExecutionContext,
  definition: MetricDefinitionV1
): readonly RawCell[] {
  const config = definition.configuration;
  if (config.kind !== "roll_cure") throw new Error("Invalid roll/cure configuration");
  const bins = context.bins.get(config.binDefinitionId);
  if (!bins) throw new Error(`Missing approved bin definition ${config.binDefinitionId}`);
  if (bins.definition.field !== config.delinquencyField) {
    throw new Error("Roll/cure bin field must match the configured delinquency field");
  }
  const labels = [
    ...bins.parsed.map(({ label }) => label),
    bins.definition.unknownLabel,
    bins.definition.otherLabel
  ];
  const cells: RawCell[] = [];
  for (const [previous, current] of adjacentPairs(context.snapshots)) {
    const currentByLoan = byLoan(current.records);
    const fromTotals = new Map<string, { amount: Decimal; eligible: number; observed: number; tokens: Set<string> }>();
    const transitions = new Map<string, MutableAmountGroup>();
    for (const start of previous.records) {
      const startDpd = optionalDecimal(start.record[config.delinquencyField], config.delinquencyField);
      const startBalance = configuredDecimal(start.record[config.balanceField], config.balanceField, definition.nullPolicy);
      const from = classifyBin(start.record[config.delinquencyField], bins.definition, bins.parsed);
      const total = fromTotals.get(from) ?? { amount: zero(), eligible: 0, observed: 0, tokens: new Set<string>() };
      total.eligible += 1;
      total.tokens.add(start.populationToken);
      if (startDpd !== null && startBalance !== null) {
        const end = currentByLoan.get(start.recordKey);
        const endDpd = end ? optionalDecimal(end.record[config.delinquencyField], config.delinquencyField) : null;
        if (end && endDpd !== null) {
          total.amount = total.amount.plus(startBalance);
          total.observed += 1;
          const to = classifyBin(end.record[config.delinquencyField], bins.definition, bins.parsed);
          const transitionKey = stableJson([from, to]);
          const transition = transitions.get(transitionKey) ?? {
            amount: zero(),
            count: 0,
            tokens: new Set<string>()
          };
          transition.amount = transition.amount.plus(startBalance);
          transition.count += 1;
          transition.tokens.add(start.populationToken);
          transitions.set(transitionKey, transition);
        }
      }
      fromTotals.set(from, total);
    }
    for (const [fromIndex, from] of labels.entries()) {
      const denominator = fromTotals.get(from) ?? { amount: zero(), eligible: 0, observed: 0, tokens: new Set<string>() };
      for (const [toIndex, to] of labels.entries()) {
        const transition = transitions.get(stableJson([from, to])) ?? {
          amount: zero(),
          count: 0,
          tokens: new Set<string>()
        };
        const reason = baseAvailability(definition, denominator.observed, denominator.eligible, denominator.amount, true);
        cells.push({
          metric: "transition_share",
          unit: "ratio",
          dimensions: {
            previousAsOfDate: previous.snapshot.asOfDate,
            currentAsOfDate: current.snapshot.asOfDate,
            fromBand: from,
            toBand: to,
            movement: toIndex > fromIndex ? "roll" : toIndex < fromIndex ? "cure" : "stable"
          },
          numerator: transition.amount,
          denominator: denominator.amount,
          value: reason === "available" ? safeRatio(transition.amount, denominator.amount) : null,
          observedCount: denominator.observed,
          eligibleCount: denominator.eligible,
          privacyCount: transition.count,
          populationTokens: [...transition.tokens].sort(compareText),
          snapshotHashes: [previous.snapshot.snapshotHash, current.snapshot.snapshotHash],
          entityResolutionHash: null,
          availabilityReason: reason,
          suppressionGroup: stableJson([previous.snapshot.asOfDate, current.snapshot.asOfDate, from])
        });
      }
    }
  }
  if (context.snapshots.length < 2) {
    cells.push(unavailableCell("transition_share", "ratio", {}, context.snapshots, "no_prior_period"));
  }
  return cells;
}

function calculateDefaultEver(
  context: ExecutionContext,
  definition: MetricDefinitionV1
): readonly RawCell[] {
  const config = definition.configuration;
  if (config.kind !== "default_ever") throw new Error("Invalid default/ever configuration");
  const cells: RawCell[] = [];
  const history = new Map<string, readonly PreparedRecord[]>();
  let prior: PreparedSnapshot | undefined;
  for (const current of context.snapshots) {
    for (const record of current.records) {
      history.set(record.recordKey, [...(history.get(record.recordKey) ?? []), record]);
    }
    if (!prior) {
      cells.push(
        unavailableCell(
          "default_incidence",
          "ratio",
          { currentAsOfDate: current.snapshot.asOfDate },
          [current],
          "no_prior_period"
        )
      );
    } else {
      const currentByLoan = byLoan(current.records);
      let denominator = zero();
      let numerator = zero();
      let eligible = 0;
      let observed = 0;
      let eventCount = 0;
      const eventTokens = new Set<string>();
      for (const start of prior.records) {
        const startDefault = optionalBoolean(start.record[config.defaultFlagField], config.defaultFlagField);
        const startBalance = configuredDecimal(start.record[config.balanceField], config.balanceField, definition.nullPolicy);
        if (startDefault === true) continue;
        eligible += 1;
        const end = currentByLoan.get(start.recordKey);
        const endDefault = end ? optionalBoolean(end.record[config.defaultFlagField], config.defaultFlagField) : null;
        if (startDefault === null || startBalance === null || !end || endDefault === null) continue;
        observed += 1;
        const weight = config.incidenceBasis === "count" ? one() : startBalance;
        denominator = denominator.plus(weight);
        if (endDefault) {
          numerator = numerator.plus(weight);
          eventCount += 1;
          eventTokens.add(start.populationToken);
        }
      }
      const reason = baseAvailability(definition, observed, eligible, denominator, true);
      cells.push({
        metric: "default_incidence",
        unit: "ratio",
        dimensions: {
          previousAsOfDate: prior.snapshot.asOfDate,
          currentAsOfDate: current.snapshot.asOfDate,
          basis: config.incidenceBasis
        },
        numerator,
        denominator,
        value: reason === "available" ? safeRatio(numerator, denominator) : null,
        observedCount: observed,
        eligibleCount: eligible,
        privacyCount: eventCount,
        populationTokens: [...eventTokens].sort(compareText),
        snapshotHashes: [prior.snapshot.snapshotHash, current.snapshot.snapshotHash],
        entityResolutionHash: null,
        availabilityReason: reason,
        suppressionGroup: stableJson([current.snapshot.asOfDate, "default"])
      });
    }

    for (const threshold of config.everDpdThresholds) {
      let denominator = zero();
      let numerator = zero();
      let eligible = 0;
      let observed = 0;
      let eventCount = 0;
      const eventTokens = new Set<string>();
      for (const currentRecord of current.records) {
        eligible += 1;
        const balance = configuredDecimal(currentRecord.record[config.balanceField], config.balanceField, definition.nullPolicy);
        const observations = history.get(currentRecord.recordKey) ?? [];
        const dpdValues = observations.map((item) => optionalInteger(item.record[config.daysPastDueField], config.daysPastDueField));
        if (balance === null || dpdValues.some((value) => value === null)) continue;
        observed += 1;
        const weight = config.incidenceBasis === "count" ? one() : balance;
        denominator = denominator.plus(weight);
        if (dpdValues.some((value) => value !== null && value >= threshold)) {
          numerator = numerator.plus(weight);
          eventCount += 1;
          eventTokens.add(currentRecord.populationToken);
        }
      }
      const reason = baseAvailability(definition, observed, eligible, denominator, true);
      cells.push({
        metric: "ever_dpd_incidence",
        unit: "ratio",
        dimensions: {
          asOfDate: current.snapshot.asOfDate,
          thresholdDays: String(threshold),
          basis: config.incidenceBasis
        },
        numerator,
        denominator,
        value: reason === "available" ? safeRatio(numerator, denominator) : null,
        observedCount: observed,
        eligibleCount: eligible,
        privacyCount: eventCount,
        populationTokens: [...eventTokens].sort(compareText),
        snapshotHashes: context.snapshots
          .filter(({ snapshot }) => snapshot.asOfDate <= current.snapshot.asOfDate)
          .map(({ snapshot }) => snapshot.snapshotHash),
        entityResolutionHash: null,
        availabilityReason: reason,
        suppressionGroup: stableJson([current.snapshot.asOfDate, "ever_dpd"])
      });
    }
    prior = current;
  }
  return cells;
}

function calculateLossRecovery(
  context: ExecutionContext,
  definition: MetricDefinitionV1
): readonly RawCell[] {
  const config = definition.configuration;
  if (config.kind !== "loss_recovery") throw new Error("Invalid loss/recovery configuration");
  const cells: RawCell[] = [];
  let priorByLoan = new Map<string, PreparedRecord>();
  for (const current of context.snapshots) {
    let gross = zero();
    let recoveries = zero();
    let grossDenominator = zero();
    let denominator = zero();
    let lossObserved = 0;
    let grossObserved = 0;
    let recoveryObserved = 0;
    let recoveryEventCount = 0;
    let lagObserved = 0;
    let lagNumerator = zero();
    let lagDenominator = zero();
    const lossTokens = new Set<string>();
    const grossTokens = new Set<string>();
    const recoveryTokens = new Set<string>();
    const lagTokens = new Set<string>();
    for (const record of current.records) {
      const currentGross = configuredDecimal(
        record.record[config.grossLossField],
        config.grossLossField,
        definition.nullPolicy
      );
      const currentRecovery = configuredDecimal(
        record.record[config.recoveryField],
        config.recoveryField,
        definition.nullPolicy
      );
      const exposure = configuredDecimal(
        record.record[config.denominatorField],
        config.denominatorField,
        definition.nullPolicy
      );
      let periodGross = currentGross;
      let periodRecovery = currentRecovery;
      if (config.flowSemantics === "cumulative") {
        const previous = priorByLoan.get(record.recordKey);
        const previousGross = previous
          ? configuredDecimal(previous.record[config.grossLossField], config.grossLossField, definition.nullPolicy)
          : zero();
        const previousRecovery = previous
          ? configuredDecimal(previous.record[config.recoveryField], config.recoveryField, definition.nullPolicy)
          : zero();
        periodGross = currentGross === null || previousGross === null ? null : currentGross.minus(previousGross);
        periodRecovery =
          currentRecovery === null || previousRecovery === null
            ? null
            : currentRecovery.minus(previousRecovery);
      }
      if (periodGross !== null) {
        gross = gross.plus(periodGross);
        if (exposure !== null) {
          grossDenominator = grossDenominator.plus(exposure);
          grossObserved += 1;
          grossTokens.add(record.populationToken);
        }
      }
      if (periodRecovery !== null) {
        recoveries = recoveries.plus(periodRecovery);
        recoveryObserved += 1;
        recoveryTokens.add(record.populationToken);
      }
      if (periodGross !== null && periodRecovery !== null && exposure !== null) {
        denominator = denominator.plus(exposure);
        lossObserved += 1;
        lossTokens.add(record.populationToken);
      }
      if (periodRecovery !== null && periodRecovery.greaterThan(0)) {
        recoveryEventCount += 1;
        const defaultDate = optionalDate(record.record[config.defaultDateField], config.defaultDateField);
        if (defaultDate !== null) {
          const lagDays = daysBetween(defaultDate, current.snapshot.asOfDate);
          if (lagDays < 0) throw new Error("Recovery default date cannot be after the snapshot date");
          lagNumerator = lagNumerator.plus(periodRecovery.times(lagDays));
          lagDenominator = lagDenominator.plus(periodRecovery);
          lagObserved += 1;
          lagTokens.add(record.populationToken);
        }
      }
    }
    const eligible = current.records.length;
    const grossReason = baseAvailability(definition, grossObserved, eligible, grossDenominator, true);
    const recoveryReason = baseAvailability(definition, recoveryObserved, eligible, null, false);
    const lossReason = baseAvailability(definition, lossObserved, eligible, denominator, true);
    const lagReason: RawCell["availabilityReason"] =
      lagDenominator.isZero()
        ? recoveries.greaterThan(0)
          ? "missing_required_field"
          : "no_records"
        : "available";
    const commonDimensions = {
      asOfDate: current.snapshot.asOfDate,
      flowSemantics: config.flowSemantics
    };
    cells.push(
      rawCell({
        metric: "gross_loss_rate",
        unit: "ratio",
        dimensions: commonDimensions,
        numerator: gross,
        denominator: grossDenominator,
        value: grossReason === "available" ? safeRatio(gross, grossDenominator) : null,
        observedCount: grossObserved,
        eligibleCount: eligible,
        privacyCount: grossTokens.size,
        populationTokens: [...grossTokens],
        snapshotHashes: [current.snapshot.snapshotHash],
        availabilityReason: grossReason,
        suppressionGroup: stableJson([current.snapshot.asOfDate, "loss-rate"])
      }),
      rawCell({
        metric: "net_loss_rate",
        unit: "ratio",
        dimensions: commonDimensions,
        numerator: gross.minus(recoveries),
        denominator,
        value: lossReason === "available" ? safeRatio(gross.minus(recoveries), denominator) : null,
        observedCount: lossObserved,
        eligibleCount: eligible,
        privacyCount: lossTokens.size,
        populationTokens: [...lossTokens],
        snapshotHashes: [current.snapshot.snapshotHash],
        availabilityReason: lossReason,
        suppressionGroup: stableJson([current.snapshot.asOfDate, "loss-rate"])
      }),
      rawCell({
        metric: "recovery_amount",
        unit: "currency",
        dimensions: commonDimensions,
        numerator: recoveries,
        denominator: null,
        value: recoveryReason === "available" ? recoveries : null,
        observedCount: recoveryObserved,
        eligibleCount: eligible,
        privacyCount: recoveryTokens.size,
        populationTokens: [...recoveryTokens],
        snapshotHashes: [current.snapshot.snapshotHash],
        availabilityReason: recoveryReason,
        suppressionGroup: stableJson([current.snapshot.asOfDate, "recovery"])
      }),
      rawCell({
        metric: "recovery_lag_days",
        unit: "days",
        dimensions: commonDimensions,
        numerator: lagNumerator,
        denominator: lagDenominator,
        value: lagReason === "available" ? safeRatio(lagNumerator, lagDenominator) : null,
        observedCount: lagObserved,
        eligibleCount: recoveryEventCount,
        privacyCount: lagTokens.size,
        populationTokens: [...lagTokens],
        snapshotHashes: [current.snapshot.snapshotHash],
        availabilityReason: lagReason,
        suppressionGroup: stableJson([current.snapshot.asOfDate, "recovery"])
      })
    );
    priorByLoan = byLoan(current.records);
  }
  return cells;
}

function calculatePaydownPrepayment(
  context: ExecutionContext,
  definition: MetricDefinitionV1
): readonly RawCell[] {
  const config = definition.configuration;
  if (config.kind !== "paydown_prepayment") throw new Error("Invalid paydown/prepayment configuration");
  if (context.snapshots.length < 2) {
    return [
      unavailableCell("paydown_rate", "ratio", {}, context.snapshots, "no_prior_period"),
      unavailableCell("prepayment_rate", "ratio", {}, context.snapshots, "no_prior_period")
    ];
  }
  const cells: RawCell[] = [];
  for (const [previous, current] of adjacentPairs(context.snapshots)) {
    const currentByLoan = byLoan(current.records);
    let denominator = zero();
    let paydown = zero();
    let prepayment = zero();
    let eligible = 0;
    let paydownObserved = 0;
    let prepaymentObserved = 0;
    let paydownEvents = 0;
    let prepaymentEvents = 0;
    const paydownTokens = new Set<string>();
    const prepaymentTokens = new Set<string>();
    for (const start of previous.records) {
      eligible += 1;
      const end = currentByLoan.get(start.recordKey);
      const startBalance = configuredDecimal(start.record[config.balanceField], config.balanceField, definition.nullPolicy);
      const endBalance = end
        ? configuredDecimal(end.record[config.balanceField], config.balanceField, definition.nullPolicy)
        : zero();
      if (startBalance === null || endBalance === null) continue;
      paydownObserved += 1;
      denominator = denominator.plus(startBalance);
      const decline = Decimal.max(startBalance.minus(endBalance), zero());
      paydown = paydown.plus(decline);
      if (decline.greaterThan(0)) {
        paydownEvents += 1;
        paydownTokens.add(start.populationToken);
      }
      if (config.scheduledPrincipalField !== undefined && end) {
        const scheduled = configuredDecimal(
          end.record[config.scheduledPrincipalField],
          config.scheduledPrincipalField,
          definition.nullPolicy
        );
        if (scheduled !== null) {
          prepaymentObserved += 1;
          const excess = Decimal.max(decline.minus(scheduled), zero());
          prepayment = prepayment.plus(excess);
          if (excess.greaterThan(0)) {
            prepaymentEvents += 1;
            prepaymentTokens.add(start.populationToken);
          }
        }
      }
    }
    const paydownReason = baseAvailability(definition, paydownObserved, eligible, denominator, true);
    const prepaymentReason: RawCell["availabilityReason"] =
      config.scheduledPrincipalField === undefined
        ? "missing_required_field"
        : baseAvailability(definition, prepaymentObserved, eligible, denominator, true);
    const dimensions = {
      previousAsOfDate: previous.snapshot.asOfDate,
      currentAsOfDate: current.snapshot.asOfDate
    };
    cells.push(
      rawCell({
        metric: "paydown_rate",
        unit: "ratio",
        dimensions,
        numerator: paydown,
        denominator,
        value: paydownReason === "available" ? safeRatio(paydown, denominator) : null,
        observedCount: paydownObserved,
        eligibleCount: eligible,
        privacyCount: paydownEvents,
        populationTokens: [...paydownTokens],
        snapshotHashes: [previous.snapshot.snapshotHash, current.snapshot.snapshotHash],
        availabilityReason: paydownReason,
        suppressionGroup: stableJson([previous.snapshot.asOfDate, current.snapshot.asOfDate, "cashflow"])
      }),
      rawCell({
        metric: "prepayment_rate",
        unit: "ratio",
        dimensions,
        numerator: prepayment,
        denominator,
        value: prepaymentReason === "available" ? safeRatio(prepayment, denominator) : null,
        observedCount: prepaymentObserved,
        eligibleCount: eligible,
        privacyCount: prepaymentEvents,
        populationTokens: [...prepaymentTokens],
        snapshotHashes: [previous.snapshot.snapshotHash, current.snapshot.snapshotHash],
        availabilityReason: prepaymentReason,
        suppressionGroup: stableJson([previous.snapshot.asOfDate, current.snapshot.asOfDate, "cashflow"])
      })
    );
  }
  return cells;
}

function calculateRatingMigration(
  context: ExecutionContext,
  definition: MetricDefinitionV1
): readonly RawCell[] {
  const config = definition.configuration;
  if (config.kind !== "rating_migration") throw new Error("Invalid rating-migration configuration");
  if (context.snapshots.length < 2) {
    return [unavailableCell("rating_transition_share", "ratio", {}, context.snapshots, "no_prior_period")];
  }
  const cells: RawCell[] = [];
  for (const [previous, current] of adjacentPairs(context.snapshots)) {
    const currentByLoan = byLoan(current.records);
    const categories = new Set<string>();
    const denominators = new Map<string, { amount: Decimal; eligible: number; observed: number }>();
    const transitions = new Map<string, MutableAmountGroup>();
    for (const start of previous.records) {
      const from = optionalCategory(start.record[config.ratingField], config.ratingField);
      if (from !== null) categories.add(from);
      if (from === null) continue;
      const denominator = denominators.get(from) ?? { amount: zero(), eligible: 0, observed: 0 };
      denominator.eligible += 1;
      const end = currentByLoan.get(start.recordKey);
      const to = end ? optionalCategory(end.record[config.ratingField], config.ratingField) : null;
      const balance = configuredDecimal(start.record[config.balanceField], config.balanceField, definition.nullPolicy);
      if (to !== null) categories.add(to);
      if (end && to !== null && balance !== null) {
        denominator.amount = denominator.amount.plus(balance);
        denominator.observed += 1;
        const key = stableJson([from, to]);
        const transition = transitions.get(key) ?? { amount: zero(), count: 0, tokens: new Set<string>() };
        transition.amount = transition.amount.plus(balance);
        transition.count += 1;
        transition.tokens.add(start.populationToken);
        transitions.set(key, transition);
      }
      denominators.set(from, denominator);
    }
    const orderedCategories = [...categories].sort(compareText);
    for (const from of orderedCategories) {
      const denominator = denominators.get(from) ?? { amount: zero(), eligible: 0, observed: 0 };
      for (const to of orderedCategories) {
        const transition = transitions.get(stableJson([from, to])) ?? {
          amount: zero(),
          count: 0,
          tokens: new Set<string>()
        };
        const reason = baseAvailability(definition, denominator.observed, denominator.eligible, denominator.amount, true);
        cells.push(
          rawCell({
            metric: "rating_transition_share",
            unit: "ratio",
            dimensions: {
              previousAsOfDate: previous.snapshot.asOfDate,
              currentAsOfDate: current.snapshot.asOfDate,
              fromRating: from,
              toRating: to
            },
            numerator: transition.amount,
            denominator: denominator.amount,
            value: reason === "available" ? safeRatio(transition.amount, denominator.amount) : null,
            observedCount: denominator.observed,
            eligibleCount: denominator.eligible,
            privacyCount: transition.count,
            populationTokens: [...transition.tokens],
            snapshotHashes: [previous.snapshot.snapshotHash, current.snapshot.snapshotHash],
            availabilityReason: reason,
            suppressionGroup: stableJson([previous.snapshot.asOfDate, current.snapshot.asOfDate, from])
          })
        );
      }
    }
  }
  return cells;
}

function calculateBalanceUtilization(
  context: ExecutionContext,
  definition: MetricDefinitionV1
): readonly RawCell[] {
  const config = definition.configuration;
  if (config.kind !== "balance_utilization") throw new Error("Invalid balance/utilization configuration");
  const cohortDefinition = config.cohortDefinitionId
    ? context.cohorts.get(config.cohortDefinitionId)
    : undefined;
  if (config.cohortDefinitionId && !cohortDefinition) {
    throw new Error(`Missing approved cohort definition ${config.cohortDefinitionId}`);
  }
  const cells: RawCell[] = [];
  for (const current of context.snapshots) {
    const cohortGroups = new Map<string, PreparedRecord[]>();
    for (const record of current.records) {
      const cohort = cohortDefinition ? cohortForRecord(record.record, cohortDefinition) : "Portfolio";
      if (cohort === null) continue;
      const group = cohortGroups.get(cohort) ?? [];
      group.push(record);
      cohortGroups.set(cohort, group);
    }
    if (cohortDefinition && cohortGroups.size > cohortDefinition.maximumCohorts) {
      throw new Error(
        `Metric ${definition.definitionId} produced more than ${cohortDefinition.maximumCohorts} cohorts`
      );
    }
    for (const [cohort, records] of [...cohortGroups.entries()].sort(([left], [right]) => compareText(left, right))) {
      let balance = zero();
      let original = zero();
      let commitment = zero();
      let observed = 0;
      const tokens = new Set<string>();
      for (const record of records) {
        const currentBalance = configuredDecimal(record.record[config.balanceField], config.balanceField, definition.nullPolicy);
        const originalBalance = configuredDecimal(
          record.record[config.originalBalanceField],
          config.originalBalanceField,
          definition.nullPolicy
        );
        const commitmentAmount = configuredDecimal(
          record.record[config.commitmentField],
          config.commitmentField,
          definition.nullPolicy
        );
        if (currentBalance === null || originalBalance === null || commitmentAmount === null) continue;
        balance = balance.plus(currentBalance);
        original = original.plus(originalBalance);
        commitment = commitment.plus(commitmentAmount);
        observed += 1;
        tokens.add(record.populationToken);
      }
      const eligible = records.length;
      const amountReason = baseAvailability(definition, observed, eligible, null, false);
      const remainingReason = baseAvailability(definition, observed, eligible, original, true);
      const utilizationReason = baseAvailability(definition, observed, eligible, commitment, true);
      const dimensions = cohortDefinition
        ? { asOfDate: current.snapshot.asOfDate, cohort }
        : { asOfDate: current.snapshot.asOfDate };
      const common = {
        dimensions,
        observedCount: observed,
        eligibleCount: eligible,
        privacyCount: observed,
        populationTokens: [...tokens],
        snapshotHashes: [current.snapshot.snapshotHash],
        suppressionGroup: stableJson([current.snapshot.asOfDate, "balance"])
      };
      cells.push(
        rawCell({
          ...common,
          metric: "outstanding_balance",
          unit: "currency",
          numerator: balance,
          denominator: null,
          value: amountReason === "available" ? balance : null,
          availabilityReason: amountReason
        }),
        rawCell({
          ...common,
          metric: "remaining_balance_factor",
          unit: "ratio",
          numerator: balance,
          denominator: original,
          value: remainingReason === "available" ? safeRatio(balance, original) : null,
          availabilityReason: remainingReason
        }),
        rawCell({
          ...common,
          metric: "utilization",
          unit: "ratio",
          numerator: balance,
          denominator: commitment,
          value: utilizationReason === "available" ? safeRatio(balance, commitment) : null,
          availabilityReason: utilizationReason
        })
      );
    }
  }
  return cells;
}

function calculateMaturityWall(
  context: ExecutionContext,
  definition: MetricDefinitionV1
): readonly RawCell[] {
  const config = definition.configuration;
  if (config.kind !== "maturity_wall") throw new Error("Invalid maturity-wall configuration");
  const cells: RawCell[] = [];
  for (const current of context.snapshots) {
    const labels = [
      ...(config.includeMatured ? ["Matured"] : []),
      ...config.windows.map(({ label }) => label),
      "Beyond"
    ];
    const groups = new Map<string, MutableAmountGroup>(
      labels.map((label) => [label, { amount: zero(), count: 0, tokens: new Set<string>() }])
    );
    let denominator = zero();
    let observed = 0;
    for (const record of current.records) {
      const maturityDate = optionalDate(record.record[config.maturityDateField], config.maturityDateField);
      const balance = configuredDecimal(record.record[config.balanceField], config.balanceField, definition.nullPolicy);
      if (maturityDate === null || balance === null) continue;
      const months = monthsUntil(current.snapshot.asOfDate, maturityDate);
      if (months < 0 && !config.includeMatured) continue;
      const label =
        months < 0
          ? "Matured"
          : config.windows.find(({ endingMonth }) => months <= endingMonth)?.label ?? "Beyond";
      const group = groups.get(label)!;
      group.amount = group.amount.plus(balance);
      group.count += 1;
      group.tokens.add(record.populationToken);
      denominator = denominator.plus(balance);
      observed += 1;
    }
    const eligible = current.records.length;
    const reason = baseAvailability(definition, observed, eligible, denominator, true);
    for (const label of labels) {
      const group = groups.get(label)!;
      cells.push(
        rawCell({
          metric: "maturity_balance_share",
          unit: "ratio",
          dimensions: { asOfDate: current.snapshot.asOfDate, maturityWindow: label },
          numerator: group.amount,
          denominator,
          value: reason === "available" ? safeRatio(group.amount, denominator) : null,
          observedCount: observed,
          eligibleCount: eligible,
          privacyCount: group.count,
          populationTokens: [...group.tokens],
          snapshotHashes: [current.snapshot.snapshotHash],
          availabilityReason: reason,
          suppressionGroup: stableJson([current.snapshot.asOfDate, "maturity"])
        })
      );
    }
  }
  return cells;
}

function calculateConcentration(
  context: ExecutionContext,
  definition: MetricDefinitionV1
): readonly RawCell[] {
  const config = definition.configuration;
  if (config.kind !== "concentration") throw new Error("Invalid concentration configuration");
  const identifierDimension = config.dimensionField === "borrower_id" || config.dimensionField === "account_debtor_id";
  const resolution = config.entityResolutionDefinitionId
    ? context.entityResolutions.get(config.entityResolutionDefinitionId)
    : undefined;
  if (
    identifierDimension &&
    (!resolution || resolution.sourceField !== config.dimensionField || resolution.tenantId !== context.tenantId)
  ) {
    return [
      unavailableCell(
        "concentration_share",
        "ratio",
        { dimension: config.dimensionField },
        context.snapshots,
        "entity_resolution_unapproved"
      )
    ];
  }
  if (!identifierDimension && config.dimensionField.endsWith("_id")) {
    throw new Error("Identifier-valued concentration dimensions require an approved resolution contract");
  }
  const bins = config.binDefinitionId ? context.bins.get(config.binDefinitionId) : undefined;
  if (config.binDefinitionId && !bins) throw new Error(`Missing approved bin definition ${config.binDefinitionId}`);
  if (bins && bins.definition.field !== config.dimensionField) {
    throw new Error("Concentration bin field must match its dimension field");
  }
  const resolutionHash = resolution ? normalizedEntityResolutionFingerprint(resolution) : null;
  const resolutionMap = resolution
    ? new Map(
        resolution.mappings.map((mapping) => [
          stableJson([mapping.sourceSystem, mapping.sourceEntityId]),
          mapping.canonicalEntityId
        ])
      )
    : undefined;
  const cells: RawCell[] = [];
  for (const current of context.snapshots) {
    const groups = new Map<string, MutableAmountGroup>();
    let denominator = zero();
    let observed = 0;
    for (const record of current.records) {
      const balance = configuredDecimal(record.record[config.balanceField], config.balanceField, definition.nullPolicy);
      const category = concentrationCategory(
        record,
        config.dimensionField,
        bins,
        resolutionMap,
        identifierDimension
      );
      if (balance === null || category === null) continue;
      const group = groups.get(category) ?? { amount: zero(), count: 0, tokens: new Set<string>() };
      group.amount = group.amount.plus(balance);
      group.count += 1;
      group.tokens.add(record.populationToken);
      groups.set(category, group);
      denominator = denominator.plus(balance);
      observed += 1;
    }
    const ordered = [...groups.entries()].sort(
      ([leftKey, left], [rightKey, right]) =>
        right.amount.comparedTo(left.amount) || compareText(leftKey, rightKey)
    );
    const shown = ordered.slice(0, config.topN);
    const remainder = ordered.slice(config.topN);
    if (remainder.length > 0) {
      const other: MutableAmountGroup = { amount: zero(), count: 0, tokens: new Set<string>() };
      for (const [, group] of remainder) {
        other.amount = other.amount.plus(group.amount);
        other.count += group.count;
        for (const token of group.tokens) other.tokens.add(token);
      }
      shown.push(["Other", other]);
    }
    const eligible = current.records.length;
    const reason = baseAvailability(definition, observed, eligible, denominator, true);
    for (const [category, group] of shown) {
      cells.push(
        rawCell({
          metric: "concentration_share",
          unit: "ratio",
          dimensions: {
            asOfDate: current.snapshot.asOfDate,
            dimension: config.dimensionField,
            category
          },
          numerator: group.amount,
          denominator,
          value: reason === "available" ? safeRatio(group.amount, denominator) : null,
          observedCount: observed,
          eligibleCount: eligible,
          privacyCount: group.count,
          populationTokens: [...group.tokens],
          snapshotHashes: [current.snapshot.snapshotHash],
          entityResolutionHash: resolutionHash,
          availabilityReason: reason,
          suppressionGroup: stableJson([current.snapshot.asOfDate, config.dimensionField])
        })
      );
    }
    const hhi = denominator.isZero()
      ? null
      : ordered.reduce(
          (sum, [, group]) => sum.plus(group.amount.dividedBy(denominator).pow(2)),
          zero()
        );
    cells.push(
      rawCell({
        metric: "concentration_hhi",
        unit: "ratio",
        dimensions: { asOfDate: current.snapshot.asOfDate, dimension: config.dimensionField },
        numerator: hhi,
        denominator: one(),
        value: hhi,
        observedCount: observed,
        eligibleCount: eligible,
        privacyCount: observed,
        populationTokens: current.records.map(({ populationToken }) => populationToken),
        snapshotHashes: [current.snapshot.snapshotHash],
        entityResolutionHash: resolutionHash,
        availabilityReason: reason,
        suppressionGroup: stableJson([current.snapshot.asOfDate, config.dimensionField, "hhi"])
      })
    );
  }
  return cells;
}

function calculatePeriodComparison(
  context: ExecutionContext,
  definition: MetricDefinitionV1
): readonly RawCell[] {
  const config = definition.configuration;
  if (config.kind !== "period_comparison") throw new Error("Invalid period-comparison configuration");
  if (config.dimensionField?.endsWith("_id")) {
    throw new Error("Period comparison cannot expose identifier-valued dimensions");
  }
  if (context.snapshots.length < 2) {
    return [unavailableCell("portfolio_change_amount", "currency", {}, context.snapshots, "no_prior_period")];
  }
  const cells: RawCell[] = [];
  for (const [previous, current] of adjacentPairs(context.snapshots)) {
    const previousGroups = exposureGroups(previous.records, config.balanceField, config.dimensionField, definition);
    const currentGroups = exposureGroups(current.records, config.balanceField, config.dimensionField, definition);
    const categories = [...new Set([...previousGroups.keys(), ...currentGroups.keys()])].sort(compareText);
    for (const category of categories) {
      const start = previousGroups.get(category) ?? new Map<string, { amount: Decimal; token: string }>();
      const end = currentGroups.get(category) ?? new Map<string, { amount: Decimal; token: string }>();
      const startTotal = sum([...start.values()].map(({ amount }) => amount));
      const endTotal = sum([...end.values()].map(({ amount }) => amount));
      const drivers = new Map<string, MutableAmountGroup>(
        ["new_exposure", "exit", "balance_increase", "balance_decrease"].map((driver) => [
          driver,
          { amount: zero(), count: 0, tokens: new Set<string>() }
        ])
      );
      const keys = [...new Set([...start.keys(), ...end.keys()])].sort(compareText);
      for (const key of keys) {
        const before = start.get(key);
        const after = end.get(key);
        let driver: string | null = null;
        let amount = zero();
        let token = before?.token ?? after?.token;
        if (!before && after) {
          driver = "new_exposure";
          amount = after.amount;
        } else if (before && !after) {
          driver = "exit";
          amount = before.amount.negated();
        } else if (before && after) {
          amount = after.amount.minus(before.amount);
          driver = amount.greaterThan(0)
            ? "balance_increase"
            : amount.lessThan(0)
              ? "balance_decrease"
              : null;
        }
        if (driver && token) {
          const group = drivers.get(driver)!;
          group.amount = group.amount.plus(amount);
          group.count += 1;
          group.tokens.add(token);
        }
      }
      const populationTokens = [...new Set([...start.values(), ...end.values()].map(({ token }) => token))].sort(compareText);
      const eligible = Math.max(start.size, end.size);
      const observed = populationTokens.length;
      const change = endTotal.minus(startTotal);
      const amountReason = baseAvailability(definition, observed, eligible, null, false);
      const rateReason = baseAvailability(definition, observed, eligible, startTotal, true);
      const baseDimensions = {
        previousAsOfDate: previous.snapshot.asOfDate,
        currentAsOfDate: current.snapshot.asOfDate,
        segment: category
      };
      cells.push(
        rawCell({
          metric: "portfolio_change_amount",
          unit: "currency",
          dimensions: baseDimensions,
          numerator: change,
          denominator: null,
          value: amountReason === "available" ? change : null,
          observedCount: observed,
          eligibleCount: eligible,
          privacyCount: observed,
          populationTokens,
          snapshotHashes: [previous.snapshot.snapshotHash, current.snapshot.snapshotHash],
          availabilityReason: amountReason,
          suppressionGroup: stableJson([previous.snapshot.asOfDate, current.snapshot.asOfDate, category, "change"])
        }),
        rawCell({
          metric: "portfolio_change_rate",
          unit: "ratio",
          dimensions: baseDimensions,
          numerator: change,
          denominator: startTotal,
          value: rateReason === "available" ? safeRatio(change, startTotal) : null,
          observedCount: observed,
          eligibleCount: eligible,
          privacyCount: observed,
          populationTokens,
          snapshotHashes: [previous.snapshot.snapshotHash, current.snapshot.snapshotHash],
          availabilityReason: rateReason,
          suppressionGroup: stableJson([previous.snapshot.asOfDate, current.snapshot.asOfDate, category, "change"])
        })
      );
      for (const [driver, group] of [...drivers.entries()].sort(([left], [right]) => compareText(left, right))) {
        cells.push(
          rawCell({
            metric: "period_driver_amount",
            unit: "currency",
            dimensions: { ...baseDimensions, driver },
            numerator: group.amount,
            denominator: null,
            value: amountReason === "available" ? group.amount : null,
            observedCount: observed,
            eligibleCount: eligible,
            privacyCount: group.count,
            populationTokens: [...group.tokens],
            snapshotHashes: [previous.snapshot.snapshotHash, current.snapshot.snapshotHash],
            availabilityReason: amountReason,
            suppressionGroup: stableJson([previous.snapshot.asOfDate, current.snapshot.asOfDate, category, "drivers"])
          }),
          rawCell({
            metric: "period_driver_share",
            unit: "ratio",
            dimensions: { ...baseDimensions, driver },
            numerator: group.amount,
            denominator: startTotal,
            value: rateReason === "available" ? safeRatio(group.amount, startTotal) : null,
            observedCount: observed,
            eligibleCount: eligible,
            privacyCount: group.count,
            populationTokens: [...group.tokens],
            snapshotHashes: [previous.snapshot.snapshotHash, current.snapshot.snapshotHash],
            availabilityReason: rateReason,
            suppressionGroup: stableJson([previous.snapshot.asOfDate, current.snapshot.asOfDate, category, "driver-shares"])
          })
        );
      }
    }
  }
  return cells;
}

function finalizeCells(
  tenantId: string,
  definition: MetricDefinitionV1,
  definitionHash: string,
  supportingDefinitionHashes: readonly string[],
  methodologyId: string,
  methodologyVersion: number,
  methodologyHash: string,
  rawCells: readonly RawCell[]
): readonly MetricCellV1[] {
  const ordered = [...rawCells].sort(compareRawCells);
  const suppressed = new Set<number>();
  for (const [index, cell] of ordered.entries()) {
    if (cell.privacyCount > 0 && cell.privacyCount < definition.privacy.minimumCellCount) {
      suppressed.add(index);
    }
  }
  if (definition.privacy.complementarySuppression) {
    const groups = new Map<string, number[]>();
    for (const [index, cell] of ordered.entries()) {
      const indexes = groups.get(cell.suppressionGroup) ?? [];
      indexes.push(index);
      groups.set(cell.suppressionGroup, indexes);
    }
    for (const indexes of groups.values()) {
      const directlySuppressed = indexes.filter((index) => suppressed.has(index));
      if (directlySuppressed.length !== 1 || indexes.length < 2) continue;
      const complement = indexes
        .filter((index) => !suppressed.has(index) && ordered[index]!.privacyCount > 0)
        .sort(
          (left, right) =>
            ordered[left]!.privacyCount - ordered[right]!.privacyCount ||
            compareRawCells(ordered[left]!, ordered[right]!)
        )[0];
      if (complement !== undefined) suppressed.add(complement);
    }
  }

  const minimumCoverage = exactDecimal(definition.coverage.minimumRatio, "minimum coverage");
  return ordered.map((cell, index) => {
    const coverageRatio = cell.eligibleCount === 0
      ? null
      : new ExactDecimal(cell.observedCount).dividedBy(cell.eligibleCount).toSignificantDigits(40);
    let reason: MetricAvailabilityReasonV1 = cell.availabilityReason;
    if (
      reason === "available" &&
      (cell.observedCount < definition.coverage.minimumObservedRecords ||
        coverageRatio === null ||
        coverageRatio.lessThan(minimumCoverage))
    ) {
      reason = "insufficient_coverage";
    }
    if (suppressed.has(index)) reason = "suppressed";
    const available = reason === "available";
    const populationTokens = [...new Set(cell.populationTokens)].sort(compareText);
    const snapshotHashes = [...new Set(cell.snapshotHashes)];
    const populationHash = stableFingerprint({
      schemaVersion: "1",
      tenantId,
      populationTokens
    });
    return {
      cellId: stableFingerprint({
        schemaVersion: "1",
        definitionId: definition.definitionId,
        definitionVersion: definition.version,
        metric: cell.metric,
        dimensions: cell.dimensions
      }),
      metric: cell.metric,
      unit: cell.unit,
      dimensions: sortRecord(cell.dimensions),
      numerator: available ? decimalOrNull(cell.numerator) : null,
      denominator: available ? decimalOrNull(cell.denominator) : null,
      value: available ? decimalOrNull(cell.value) : null,
      coverage: {
        observedCount: reason === "suppressed" ? null : String(cell.observedCount),
        eligibleCount: reason === "suppressed" ? null : String(cell.eligibleCount),
        ratio: reason === "suppressed" ? null : decimalOrNull(coverageRatio)
      },
      available,
      availabilityReason: reason,
      suppressed: reason === "suppressed",
      lineage: {
        definitionHash,
        supportingDefinitionHashes,
        methodologyId,
        methodologyVersion,
        methodologyHash,
        snapshotHashes,
        populationHash,
        entityResolutionHash: cell.entityResolutionHash
      }
    } satisfies MetricCellV1;
  });
}

function rawCell(
  cell: Omit<RawCell, "entityResolutionHash"> & { readonly entityResolutionHash?: string | null }
): RawCell {
  return {
    ...cell,
    populationTokens: [...new Set(cell.populationTokens)].sort(compareText),
    snapshotHashes: [...new Set(cell.snapshotHashes)],
    entityResolutionHash: cell.entityResolutionHash ?? null
  };
}

function unavailableCell(
  metric: string,
  unit: MetricCellV1["unit"],
  dimensions: Readonly<Record<string, string>>,
  snapshots: readonly PreparedSnapshot[],
  reason: Exclude<MetricAvailabilityReasonV1, "available" | "suppressed" | "insufficient_coverage">
): RawCell {
  return rawCell({
    metric,
    unit,
    dimensions,
    numerator: null,
    denominator: null,
    value: null,
    observedCount: 0,
    eligibleCount: snapshots.reduce((total, snapshot) => total + snapshot.records.length, 0),
    privacyCount: 0,
    populationTokens: snapshots.flatMap(({ records }) => records.map(({ populationToken }) => populationToken)),
    snapshotHashes: snapshots.map(({ snapshot }) => snapshot.snapshotHash),
    availabilityReason: reason,
    suppressionGroup: stableJson([metric, dimensions])
  });
}

function warningsFor(definition: MetricDefinitionV1): readonly string[] {
  const common = [
    "All cells are derived from certified immutable snapshots using exact decimal arithmetic.",
    `Cells with fewer than ${definition.privacy.minimumCellCount} contributing records use deterministic complementary suppression.`,
    "Unavailable metrics remain null with an explicit reason; missing observations are never silently converted to business events."
  ];
  if (definition.family === "concentration") {
    return [
      ...common,
      "Identifier-valued concentration is tenant-scoped, approval-bound, and emitted only as opaque entity tokens."
    ];
  }
  return common;
}

function supportingDefinitionHashesFor(
  context: ExecutionContext,
  definition: MetricDefinitionV1
): readonly string[] {
  const hashes: string[] = [];
  const config = definition.configuration;
  if (config.kind === "roll_cure") {
    const bin = context.bins.get(config.binDefinitionId)?.definition;
    if (bin) hashes.push(stableFingerprint(bin));
  }
  if (config.kind === "concentration") {
    if (config.binDefinitionId) {
      const bin = context.bins.get(config.binDefinitionId)?.definition;
      if (bin) hashes.push(stableFingerprint(bin));
    }
    if (config.entityResolutionDefinitionId) {
      const resolution = context.entityResolutions.get(config.entityResolutionDefinitionId);
      if (resolution) hashes.push(normalizedEntityResolutionFingerprint(resolution));
    }
  }
  if (config.kind === "balance_utilization" && config.cohortDefinitionId) {
    const cohort = context.cohorts.get(config.cohortDefinitionId);
    if (cohort) hashes.push(stableFingerprint(cohort));
  }
  return [...new Set(hashes)].sort(compareText);
}

function baseAvailability(
  definition: MetricDefinitionV1,
  observed: number,
  eligible: number,
  denominator: Decimal | null,
  requireNonZeroDenominator: boolean
): RawCell["availabilityReason"] {
  if (eligible === 0) return "no_records";
  if (observed === 0) return "missing_required_field";
  if (definition.nullPolicy === "unavailable" && observed < eligible) return "missing_required_field";
  if (requireNonZeroDenominator && (denominator === null || denominator.isZero())) {
    return "division_by_zero";
  }
  return "available";
}

function concentrationCategory(
  prepared: PreparedRecord,
  fieldName: string,
  bins: { readonly definition: BinDefinitionV1; readonly parsed: readonly ValidatedNumericBinV1[] } | undefined,
  resolutionMap: ReadonlyMap<string, string> | undefined,
  identifierDimension: boolean
): string | null {
  if (bins) return classifyBin(prepared.record[fieldName], bins.definition, bins.parsed);
  if (!identifierDimension) return optionalCategory(prepared.record[fieldName], fieldName);
  const sourceEntityId = optionalText(prepared.record[fieldName], fieldName);
  if (sourceEntityId === null) return null;
  const sourceSystem = optionalText(prepared.record.source_system, "source_system") ?? "default";
  const canonicalEntityId = resolutionMap?.get(stableJson([sourceSystem, sourceEntityId]));
  const opaque = stableFingerprint([
    "resolved-entity-v1",
    canonicalEntityId === undefined ? "unresolved" : "resolved",
    canonicalEntityId ?? sourceSystem,
    canonicalEntityId ?? sourceEntityId
  ]).slice(0, 16);
  return canonicalEntityId === undefined ? `Unresolved-${opaque}` : `Entity-${opaque}`;
}

function normalizedEntityResolutionFingerprint(
  definition: EntityResolutionDefinitionV1
): string {
  return stableFingerprint({
    ...definition,
    mappings: [...definition.mappings].sort(
      (left, right) =>
        compareText(left.sourceSystem, right.sourceSystem) ||
        compareText(left.sourceEntityId, right.sourceEntityId) ||
        compareText(left.canonicalEntityId, right.canonicalEntityId)
    )
  });
}

function exposureGroups(
  records: readonly PreparedRecord[],
  balanceField: string,
  dimensionField: string | undefined,
  definition: MetricDefinitionV1
): Map<string, Map<string, { amount: Decimal; token: string }>> {
  const groups = new Map<string, Map<string, { amount: Decimal; token: string }>>();
  for (const record of records) {
    const amount = configuredDecimal(record.record[balanceField], balanceField, definition.nullPolicy);
    if (amount === null) continue;
    const category = dimensionField === undefined
      ? "Portfolio"
      : optionalCategory(record.record[dimensionField], dimensionField);
    if (category === null) continue;
    const group = groups.get(category) ?? new Map<string, { amount: Decimal; token: string }>();
    group.set(record.recordKey, { amount, token: record.populationToken });
    groups.set(category, group);
  }
  return groups;
}

function configuredDecimal(
  raw: unknown,
  fieldName: string,
  nullPolicy: MetricDefinitionV1["nullPolicy"]
): Decimal | null {
  const parsed = optionalDecimal(raw, fieldName);
  return parsed ?? (nullPolicy === "zero" ? zero() : null);
}

function optionalDecimal(raw: unknown, fieldName: string): Decimal | null {
  if (raw === null || raw === undefined || raw === "") return null;
  if (typeof raw !== "string" || !CANONICAL_DECIMAL.test(raw) || raw.length > 256) {
    throw new Error(`${fieldName} must be an exact canonical decimal string or null`);
  }
  const parsed = new ExactDecimal(raw);
  if (!parsed.isFinite()) throw new Error(`${fieldName} must be finite`);
  return parsed;
}

function optionalInteger(raw: unknown, fieldName: string): number | null {
  if (raw === null || raw === undefined || raw === "") return null;
  if (typeof raw !== "string" || !CANONICAL_INTEGER.test(raw)) {
    throw new Error(`${fieldName} must be a canonical integer string or null`);
  }
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${fieldName} exceeds the safe integer range`);
  return parsed;
}

function optionalBoolean(raw: unknown, fieldName: string): boolean | null {
  if (raw === null || raw === undefined || raw === "") return null;
  if (typeof raw !== "boolean") throw new Error(`${fieldName} must be a canonical boolean or null`);
  return raw;
}

function optionalDate(raw: unknown, fieldName: string): string | null {
  if (raw === null || raw === undefined || raw === "") return null;
  if (typeof raw !== "string") throw new Error(`${fieldName} must be a canonical date string or null`);
  validateIsoDate(raw, fieldName);
  return raw;
}

function optionalCategory(raw: unknown, fieldName: string): string | null {
  if (raw === null || raw === undefined || raw === "") return null;
  if (typeof raw === "boolean") return String(raw);
  if (typeof raw !== "string") throw new Error(`${fieldName} must be a canonical string or boolean`);
  boundedText(raw, fieldName, 256);
  return raw;
}

function requiredString(raw: unknown, fieldName: string, recordIndex: number): string {
  if (typeof raw !== "string" || raw.length === 0) {
    throw new Error(`Record ${recordIndex} field ${fieldName} must be a non-empty string`);
  }
  return raw;
}

function optionalText(raw: unknown, fieldName: string): string | null {
  if (raw === null || raw === undefined || raw === "") return null;
  if (typeof raw !== "string") throw new Error(`${fieldName} must be a string or null`);
  boundedText(raw, fieldName, 512);
  return raw;
}

function boundedText(value: string, label: string, maximum: number): void {
  if (value.trim() !== value || value.length < 1 || value.length > maximum) {
    throw new Error(`${label} must be trimmed and contain between 1 and ${maximum} characters`);
  }
}

function byLoan(records: readonly PreparedRecord[]): Map<string, PreparedRecord> {
  return new Map(records.map((record) => [record.recordKey, record]));
}

function adjacentPairs<T>(values: readonly T[]): readonly (readonly [T, T])[] {
  const pairs: Array<readonly [T, T]> = [];
  for (let index = 1; index < values.length; index += 1) {
    pairs.push([values[index - 1]!, values[index]!]);
  }
  return pairs;
}

function safeRatio(numerator: Decimal, denominator: Decimal): Decimal | null {
  return denominator.isZero()
    ? null
    : numerator.dividedBy(denominator).toSignificantDigits(40, Decimal.ROUND_HALF_EVEN);
}

function sum(values: readonly Decimal[]): Decimal {
  return values.reduce((total, value) => total.plus(value), zero());
}

function zero(): Decimal {
  return new ExactDecimal(0);
}

function one(): Decimal {
  return new ExactDecimal(1);
}

function decimalOrNull(value: Decimal | null): string | null {
  return value === null ? null : decimalString(value);
}

function decimalString(value: Decimal): string {
  const fixed = value.toFixed();
  const normalized = fixed.includes(".") ? fixed.replace(/(?:\.0+|(?:(\.\d*?)0+))$/, "$1") : fixed;
  return normalized === "-0" ? "0" : normalized;
}

function exactDecimal(value: string, label: string): Decimal {
  if (!CANONICAL_DECIMAL.test(value)) throw new Error(`${label} must be a canonical decimal string`);
  return new ExactDecimal(value);
}

function daysBetween(earlier: string, later: string): number {
  return Math.trunc((Date.parse(`${later}T00:00:00Z`) - Date.parse(`${earlier}T00:00:00Z`)) / 86_400_000);
}

function monthsUntil(asOfDate: string, maturityDate: string): number {
  const [asOfYear, asOfMonth, asOfDay] = asOfDate.split("-").map(Number) as [number, number, number];
  const [maturityYear, maturityMonth, maturityDay] = maturityDate.split("-").map(Number) as [number, number, number];
  const wholeMonths = (maturityYear - asOfYear) * 12 + maturityMonth - asOfMonth;
  return maturityDay > asOfDay ? wholeMonths + 1 : wholeMonths;
}

function positiveInteger(value: number, label: string, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${label} must be an integer between 1 and ${maximum}`);
  }
}

function identifier(value: string, label: string): void {
  if (!IDENTIFIER.test(value)) throw new Error(`${label} is not a valid identifier`);
}

function isoTimestamp(value: string, label: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new Error(`${label} must be a valid ISO-8601 UTC timestamp`);
  }
}

function sortRecord(record: Readonly<Record<string, string>>): Readonly<Record<string, string>> {
  return Object.fromEntries(Object.entries(record).sort(([left], [right]) => compareText(left, right)));
}

function compareRawCells(left: RawCell, right: RawCell): number {
  return compareText(left.metric, right.metric) || compareText(stableJson(left.dimensions), stableJson(right.dimensions));
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
