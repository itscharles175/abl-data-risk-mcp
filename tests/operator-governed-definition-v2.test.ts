import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import {
  GovernedDefinitionV2Store,
  GovernedDefinitionV2StoreError
} from "../src/control/governed-definitions-v2.js";
import { runOperatorCli, type OperatorCliIo } from "../src/operator/cli.js";
import {
  OperatorControlPlane,
  type OperatorControlPlaneDependencies,
  type OperatorPrincipal
} from "../src/operator/control-plane.js";
import { OperatorInputError } from "../src/operator/schemas.js";
import { GovernedDefinitionV2Resolver } from "../src/services/governed-definition-v2-resolver.js";

const PRIVATE_DOCUMENT_VALUE = "PRIVATE-RULE-DESCRIPTION";
const PRIVATE_EVIDENCE_VALUE = "PRIVATE-APPROVAL-NOTE";
const cleanups: Array<() => void> = [];

afterEach(() => {
  for (const cleanup of cleanups.splice(0).reverse()) cleanup();
});

test("trusted v2 governance commands enforce maker/checker and return metadata only", () => {
  const context = harness();
  const proposal = metricProposal("roll-rate-v1", "roll-rate", "1.0.0", "2026-01-01");
  const proposed = context.maker.proposeGovernedDefinitionV2(proposal);

  assert.equal(proposed.status, "proposed");
  assert.equal(proposed.proposedBy, "operator-maker");
  assert.equal(proposed.lifecycleRevision, 1);
  assert.equal("document" in proposed, false);
  assert.equal(JSON.stringify(proposed).includes(PRIVATE_DOCUMENT_VALUE), false);
  assert.equal(
    context.store.get("tenant-a", "roll-rate-v1")?.version.proposedBy,
    "operator-maker"
  );

  assert.throws(
    () => context.maker.proposeGovernedDefinitionV2({
      ...metricProposal("forged-v1", "forged", "1.0.0", "2026-01-01"),
      proposedBy: "forged-maker"
    }),
    (error: unknown) => error instanceof OperatorInputError
  );
  assert.throws(
    () => context.maker.transitionGovernedDefinitionV2({
      tenantId: "tenant-a",
      definitionVersionId: "roll-rate-v1",
      toStatus: "validated",
      expectedRevision: 1,
      actor: "forged-checker",
      idempotencyKey: "forged-transition"
    }),
    (error: unknown) => error instanceof OperatorInputError
  );
  assert.throws(
    () => context.maker.transitionGovernedDefinitionV2({
      tenantId: "tenant-a",
      definitionVersionId: "roll-rate-v1",
      toStatus: "validated",
      expectedRevision: 1,
      idempotencyKey: "self-validation"
    }),
    (error: unknown) =>
      error instanceof GovernedDefinitionV2StoreError &&
      error.code === "MAKER_CHECKER_VIOLATION"
  );

  let current = context.checker.transitionGovernedDefinitionV2({
    tenantId: "tenant-a",
    definitionVersionId: "roll-rate-v1",
    toStatus: "validated",
    expectedRevision: 1,
    evidence: { note: PRIVATE_EVIDENCE_VALUE },
    idempotencyKey: "validate-roll-rate-v1"
  });
  current = context.checker.transitionGovernedDefinitionV2({
    tenantId: "tenant-a",
    definitionVersionId: "roll-rate-v1",
    toStatus: "approved",
    expectedRevision: current.lifecycleRevision,
    idempotencyKey: "approve-roll-rate-v1"
  });
  current = context.checker.transitionGovernedDefinitionV2({
    tenantId: "tenant-a",
    definitionVersionId: "roll-rate-v1",
    toStatus: "active",
    expectedRevision: current.lifecycleRevision,
    idempotencyKey: "activate-roll-rate-v1"
  });
  assert.equal(current.status, "active");
  assert.equal(current.approval?.approvedBy, "operator-checker");

  const fetched = context.maker.getGovernedDefinitionV2({
    tenantId: "tenant-a",
    definitionVersionId: "roll-rate-v1"
  });
  const listed = context.maker.listGovernedDefinitionsV2({
    tenantId: "tenant-a",
    kind: "metric_definition",
    definitionKey: "roll-rate",
    limit: 10
  });
  const effective = context.maker.selectEffectiveGovernedDefinitionV2({
    tenantId: "tenant-a",
    kind: "metric_definition",
    definitionKey: "roll-rate",
    asOfDate: "2026-08-12"
  });
  const audit = context.maker.listGovernedDefinitionV2Audit({
    tenantId: "tenant-a",
    afterSequence: 0,
    limit: 20
  });

  assert.deepEqual(listed, [fetched]);
  assert.equal(effective.resolutionVerified, true);
  assert.equal(effective.executionReference.definitionVersionId, "roll-rate-v1");
  assert.equal(effective.executionReference.versionHash, fetched.versionHash);
  assert.equal(effective.executionReference.documentHash, fetched.documentHash);
  assert.equal(audit.length, 4);
  assert.equal(audit.some((event) => "evidence" in event), false);
  for (const result of [fetched, listed, effective, audit]) {
    const serialized = JSON.stringify(result);
    assert.equal(serialized.includes(PRIVATE_DOCUMENT_VALUE), false);
    assert.equal(serialized.includes(PRIVATE_EVIDENCE_VALUE), false);
    assert.equal(serialized.includes("executionDocument"), false);
  }
  assert.throws(
    () => context.maker.getGovernedDefinitionV2({
      tenantId: "tenant-a",
      definitionVersionId: "roll-rate-v1",
      includeDocument: true
    }),
    (error: unknown) => error instanceof OperatorInputError
  );
});

test("v2 withdrawal is exposed as a terminal, non-executable operator transition", () => {
  const context = harness();
  context.maker.proposeGovernedDefinitionV2(
    metricProposal("prepayment-v1", "prepayment", "1.0.0", "2026-01-01")
  );
  const withdrawn = context.checker.transitionGovernedDefinitionV2({
    tenantId: "tenant-a",
    definitionVersionId: "prepayment-v1",
    toStatus: "withdrawn",
    expectedRevision: 1,
    evidence: { reason: PRIVATE_EVIDENCE_VALUE },
    idempotencyKey: "withdraw-prepayment-v1"
  });

  assert.equal(withdrawn.status, "withdrawn");
  assert.throws(
    () => context.checker.transitionGovernedDefinitionV2({
      tenantId: "tenant-a",
      definitionVersionId: "prepayment-v1",
      toStatus: "validated",
      expectedRevision: withdrawn.lifecycleRevision,
      idempotencyKey: "revive-prepayment-v1"
    }),
    (error: unknown) =>
      error instanceof GovernedDefinitionV2StoreError && error.code === "ILLEGAL_TRANSITION"
  );
  assert.throws(
    () => context.maker.selectEffectiveGovernedDefinitionV2({
      tenantId: "tenant-a",
      kind: "metric_definition",
      definitionKey: "prepayment",
      asOfDate: "2026-08-12"
    }),
    (error: unknown) =>
      error instanceof GovernedDefinitionV2StoreError && error.code === "NOT_FOUND"
  );
});

test("CLI dispatches v2 metadata commands and never serializes governed documents", async () => {
  const context = harness();
  context.maker.proposeGovernedDefinitionV2(
    metricProposal("roll-rate-v1", "roll-rate", "1.0.0", "2026-01-01")
  );
  const directory = mkdtempSync(join(tmpdir(), "abl-operator-v2-cli-"));
  cleanups.push(() => rmSync(directory, { recursive: true, force: true }));
  const requestPath = join(directory, "list.json");
  writeFileSync(requestPath, JSON.stringify({ tenantId: "tenant-a", limit: 10 }));
  const output = captureIo();

  assert.equal(
    await runOperatorCli(
      ["definition-v2-list", "--request", requestPath],
      context.maker,
      output.io
    ),
    0
  );
  assert.equal(output.stderr.length, 0);
  assert.equal(output.stdout.length, 1);
  assert.match(output.stdout[0]!, /"command":"definition-v2-list"/);
  assert.equal(output.stdout[0]!.includes(PRIVATE_DOCUMENT_VALUE), false);
  assert.equal(output.stdout[0]!.includes("\"document\""), false);

  const help = captureIo();
  assert.equal(await runOperatorCli(["--help"], context.maker, help.io), 0);
  assert.match(help.stdout[0]!, /definition-v2-select-effective/);
  assert.match(help.stdout[0]!, /definition-v2-audit-list/);
});

interface Harness {
  readonly store: GovernedDefinitionV2Store;
  readonly maker: OperatorControlPlane;
  readonly checker: OperatorControlPlane;
}

function harness(): Harness {
  const directory = mkdtempSync(join(tmpdir(), "abl-operator-v2-"));
  const times = Array.from(
    { length: 32 },
    (_, index) => `2026-08-12T12:${String(index).padStart(2, "0")}:00.000Z`
  );
  let timeIndex = 0;
  const store = new GovernedDefinitionV2Store(join(directory, "control.sqlite"), {
    clock: () => new Date(times[timeIndex++] ?? "2026-08-12T13:00:00.000Z")
  });
  const resolver = new GovernedDefinitionV2Resolver(store);
  const dependencies: Omit<OperatorControlPlaneDependencies, "principal"> = {
    control: unreachable<OperatorControlPlaneDependencies["control"]>("control"),
    definitions: unreachable<OperatorControlPlaneDependencies["definitions"]>("definitions"),
    governedDefinitionsV2: store,
    governedDefinitionV2Resolver: resolver,
    artifacts: unreachable<OperatorControlPlaneDependencies["artifacts"]>("artifacts"),
    memberships: unreachable<OperatorControlPlaneDependencies["memberships"]>("memberships"),
    alerts: unreachable<OperatorControlPlaneDependencies["alerts"]>("alerts"),
    ingestion: unreachable<OperatorControlPlaneDependencies["ingestion"]>("ingestion")
  };
  const maker = new OperatorControlPlane({
    ...dependencies,
    principal: principal("operator-maker")
  });
  const checker = new OperatorControlPlane({
    ...dependencies,
    principal: principal("operator-checker")
  });
  cleanups.push(() => {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  });
  return { store, maker, checker };
}

function principal(principalId: string): OperatorPrincipal {
  return {
    principalId,
    authenticationMethod: "trusted_service_identity",
    authorizationScope: "global_admin"
  };
}

function unreachable<T>(label: string): T {
  return new Proxy(
    {},
    {
      get: () => () => {
        throw new Error(`Unexpected dependency call: ${label}`);
      }
    }
  ) as T;
}

function metricProposal(
  definitionVersionId: string,
  definitionKey: string,
  semanticVersion: string,
  effectiveFrom: string
) {
  return {
    tenantId: "tenant-a",
    definitionVersionId,
    definitionKey,
    kind: "metric_definition" as const,
    semanticVersion,
    effectiveFrom,
    document: {
      schemaVersion: "1",
      definitionType: "metric_definition",
      definitionId: definitionKey,
      version: Number(semanticVersion.split(".")[0]),
      name: PRIVATE_DOCUMENT_VALUE,
      family: "roll_cure",
      grain: "loan",
      unit: "ratio",
      temporalSemantics: "transition",
      numerator: {
        label: "Transitioning",
        aggregation: "sum",
        field: "outstanding_balance"
      },
      denominator: {
        label: "Opening",
        aggregation: "sum",
        field: "outstanding_balance"
      },
      window: { kind: "adjacent_periods", maximumPeriods: 12 },
      population: null,
      nullPolicy: "unavailable",
      coverage: { minimumRatio: "0.95", minimumObservedRecords: 1 },
      privacy: { minimumCellCount: 3, complementarySuppression: true },
      maximumCells: 12,
      configuration: {
        kind: "roll_cure",
        delinquencyField: "days_past_due",
        balanceField: "outstanding_balance",
        binDefinitionId: "dpd-bands"
      },
      approval: {
        status: "pending_durable_approval",
        authority: "governed_definition_v2_lifecycle"
      }
    },
    idempotencyKey: `propose-${definitionVersionId}`
  };
}

function captureIo(): {
  readonly io: OperatorCliIo;
  readonly stdout: string[];
  readonly stderr: string[];
} {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    stdout,
    stderr,
    io: {
      stdout: (line) => stdout.push(line),
      stderr: (line) => stderr.push(line)
    }
  };
}
