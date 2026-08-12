import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import { canonicalHash } from "../src/contracts/canonical.js";
import {
  InputCertificationStoreError,
  type InputCertificationProposalV1,
  type InputCertificationRecordV1
} from "../src/control/input-certifications.js";
import { runOperatorCli, type OperatorCliIo } from "../src/operator/cli.js";
import {
  OperatorControlPlane,
  type OperatorControlPlaneDependencies,
  type OperatorPrincipal
} from "../src/operator/control-plane.js";
import { OperatorInputError } from "../src/operator/schemas.js";
import type {
  CertifyInputRequest,
  ProposeCertifiedInputRequest
} from "../src/services/input-certification.js";

const FIXED_TIME = "2026-08-12T14:00:00.000Z";
const CANDIDATE_ARTIFACT_ID = "a".repeat(64);
const CERTIFIED_ARTIFACT_ID = "c".repeat(64);
const PRIVATE_PURPOSE = "SECRET-CREDIT-COMMITTEE-PURPOSE";
const PRIVATE_DEFINITION_ID = "secret-eligibility-policy";
const PRIVATE_FAILURE = "SECRET-INTERNAL-CERTIFICATION-MESSAGE";
const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("input-certification control-plane commands derive actors from trusted principals and return metadata only", () => {
  const service = new RecordingInputCertificationService();
  const maker = operatorPlane("trusted-maker", service);
  const checker = operatorPlane("trusted-checker", service);

  const proposal = maker.proposeInputCertification(proposalRequest());
  assert.equal(service.proposalRequests[0]?.proposedBy, "trusted-maker");
  assert.deepEqual(Object.keys(proposal).sort(), ["inputId", "inputKind", "proposalHash", "status"]);
  assert.deepEqual(proposal, {
    inputId: "sidecar-certification-1",
    inputKind: "borrowing_base",
    status: "proposed",
    proposalHash: service.proposal?.proposalHash
  });
  assertMetadataOnly(JSON.stringify(proposal));

  assert.throws(
    () => maker.proposeInputCertification({ ...proposalRequest(), proposedBy: "forged-maker" }),
    (error: unknown) => error instanceof OperatorInputError && error.code === "INVALID_INPUT"
  );
  assert.equal(service.proposalRequests.length, 1, "an actor-bearing request must fail before the service");

  assert.throws(
    () => checker.certifyInputCertification({ ...certificationRequest(), certifiedBy: "forged-checker" }),
    (error: unknown) => error instanceof OperatorInputError && error.code === "INVALID_INPUT"
  );
  assert.equal(service.certificationRequests.length, 0, "a forged checker must fail before the service");

  assert.throws(
    () => maker.certifyInputCertification(certificationRequest()),
    (error: unknown) =>
      error instanceof InputCertificationStoreError && error.code === "MAKER_CHECKER_VIOLATION"
  );
  assert.equal(service.certificationRequests[0]?.certifiedBy, "trusted-maker");

  const certified = checker.certifyInputCertification(certificationRequest());
  assert.equal(service.certificationRequests[1]?.certifiedBy, "trusted-checker");
  assert.deepEqual(Object.keys(certified).sort(), [
    "certifiedArtifactId",
    "envelopeHash",
    "inputId",
    "inputKind",
    "lineageHash",
    "proposalHash",
    "status"
  ]);
  assert.deepEqual(certified, {
    inputId: "sidecar-certification-1",
    inputKind: "borrowing_base",
    status: "certified",
    proposalHash: service.proposal?.proposalHash,
    certifiedArtifactId: CERTIFIED_ARTIFACT_ID,
    envelopeHash: canonicalHash("certified envelope"),
    lineageHash: canonicalHash("certified lineage")
  });
  assertMetadataOnly(JSON.stringify(certified));
});

test("CLI routes both input-certification commands, redacts maker/checker failures, and emits only summaries", async () => {
  const service = new RecordingInputCertificationService();
  const maker = operatorPlane("trusted-maker", service);
  const checker = operatorPlane("trusted-checker", service);
  const root = temporaryDirectory();

  const proposed = await executeCli(
    root,
    "input-certification-propose",
    proposalRequest(),
    maker
  );
  assert.equal(proposed.exitCode, 0);
  assert.deepEqual(proposed.stderr, []);
  assert.equal(proposed.stdout.length, 1);
  const proposalResponse = parseCliSuccess(proposed.stdout[0]!);
  assert.equal(proposalResponse.command, "input-certification-propose");
  assert.deepEqual(Object.keys(proposalResponse.result).sort(), [
    "inputId",
    "inputKind",
    "proposalHash",
    "status"
  ]);
  assertMetadataOnly(proposed.stdout[0]!);
  assert.equal(service.proposalRequests[0]?.proposedBy, "trusted-maker");

  const rejected = await executeCli(
    root,
    "input-certification-certify",
    certificationRequest(),
    maker
  );
  assert.equal(rejected.exitCode, 3);
  assert.deepEqual(rejected.stdout, []);
  assert.equal(rejected.stderr.length, 1);
  assert.deepEqual(JSON.parse(rejected.stderr[0]!), {
    error: {
      code: "MAKER_CHECKER_VIOLATION",
      message: "Maker/checker separation rejected the operation"
    },
    ok: false
  });
  assert.equal(rejected.stderr[0]!.includes(PRIVATE_FAILURE), false);
  assert.equal(rejected.stderr[0]!.includes(PRIVATE_PURPOSE), false);
  assert.equal(rejected.stderr[0]!.includes(CANDIDATE_ARTIFACT_ID), false);

  const certified = await executeCli(
    root,
    "input-certification-certify",
    certificationRequest(),
    checker
  );
  assert.equal(certified.exitCode, 0);
  assert.deepEqual(certified.stderr, []);
  const certificationResponse = parseCliSuccess(certified.stdout[0]!);
  assert.equal(certificationResponse.command, "input-certification-certify");
  assert.deepEqual(Object.keys(certificationResponse.result).sort(), [
    "certifiedArtifactId",
    "envelopeHash",
    "inputId",
    "inputKind",
    "lineageHash",
    "proposalHash",
    "status"
  ]);
  assertMetadataOnly(certified.stdout[0]!);
  assert.equal(service.certificationRequests[1]?.certifiedBy, "trusted-checker");
});

class RecordingInputCertificationService {
  readonly proposalRequests: ProposeCertifiedInputRequest[] = [];
  readonly certificationRequests: CertifyInputRequest[] = [];
  proposal: InputCertificationProposalV1 | undefined;

  propose(input: ProposeCertifiedInputRequest): InputCertificationProposalV1 {
    this.proposalRequests.push(input);
    const proposal: InputCertificationProposalV1 = {
      contractVersion: 1,
      tenantId: input.tenantId,
      inputId: input.inputId,
      inputKind: input.inputKind,
      candidateArtifactId: input.candidateArtifactId,
      candidateArtifactHash: canonicalHash("SECRET-CANDIDATE-ARTIFACT-CONTENTS"),
      candidateArtifactKind:
        input.inputKind === "borrowing_base" ? "borrowing_base_input" : "monitoring_input",
      snapshotId: "secret-snapshot-1",
      asOfDate: "2026-07-31",
      purpose: input.purpose,
      primaryCertificationManifestId: input.primaryCertificationManifestId,
      definitionReferences: input.definitionIds.map((definitionId) => ({
        definitionId,
        version: "private-version",
        definitionHash: canonicalHash(`SECRET-DEFINITION:${definitionId}`)
      })),
      declaredControls: input.declaredControls,
      payloadHash: canonicalHash("SECRET-SIDECAR-POPULATION"),
      fieldSetHash: canonicalHash("SECRET-FIELD-SET"),
      rowCount: input.declaredControls.rowCount,
      proposedBy: input.proposedBy,
      status: "proposed",
      proposalHash: canonicalHash({ inputId: input.inputId, proposedBy: input.proposedBy }),
      proposedAt: FIXED_TIME
    };
    this.proposal = proposal;
    return proposal;
  }

  certify(input: CertifyInputRequest): InputCertificationRecordV1 {
    this.certificationRequests.push(input);
    const proposal = this.proposal;
    if (!proposal) {
      throw new InputCertificationStoreError("NOT_FOUND", "SECRET-MISSING-PROPOSAL");
    }
    if (proposal.proposedBy === input.certifiedBy) {
      throw new InputCertificationStoreError("MAKER_CHECKER_VIOLATION", PRIVATE_FAILURE);
    }
    return {
      ...proposal,
      status: "certified",
      certifiedArtifactId: CERTIFIED_ARTIFACT_ID,
      certifiedArtifactHash: canonicalHash("SECRET-CERTIFIED-ARTIFACT"),
      certifiedArtifactKind:
        proposal.inputKind === "borrowing_base"
          ? "certified_borrowing_base_input"
          : "certified_monitoring_input",
      lineageHash: canonicalHash("certified lineage"),
      envelopeHash: canonicalHash("certified envelope"),
      derivationHash: canonicalHash("SECRET-DERIVATION"),
      primaryCertificationHash: canonicalHash("SECRET-PRIMARY-CERTIFICATION"),
      primaryPopulationHash: canonicalHash("SECRET-PRIMARY-POPULATION"),
      sidecarCertificationHash: canonicalHash("SECRET-SIDECAR-CERTIFICATION"),
      sidecarPopulationHash: proposal.payloadHash,
      dataQualityRunId: "secret-sidecar-dq-run",
      dataQualityResultHash: canonicalHash("SECRET-SIDECAR-DQ-RESULT"),
      reconciliationId: "secret-sidecar-reconciliation",
      reconciliationResultHash: canonicalHash("SECRET-SIDECAR-RECONCILIATION-RESULT"),
      certifiedBy: input.certifiedBy,
      certifiedAt: FIXED_TIME
    };
  }
}

function operatorPlane(
  principalId: string,
  inputCertification: RecordingInputCertificationService
): OperatorControlPlane {
  const dependencies: OperatorControlPlaneDependencies = {
    principal: operatorPrincipal(principalId),
    control: unreachable<OperatorControlPlaneDependencies["control"]>("control"),
    definitions: unreachable<OperatorControlPlaneDependencies["definitions"]>("definitions"),
    artifacts: unreachable<OperatorControlPlaneDependencies["artifacts"]>("artifacts"),
    memberships: unreachable<OperatorControlPlaneDependencies["memberships"]>("memberships"),
    alerts: unreachable<OperatorControlPlaneDependencies["alerts"]>("alerts"),
    ingestion: unreachable<OperatorControlPlaneDependencies["ingestion"]>("ingestion"),
    inputCertification
  };
  return new OperatorControlPlane(dependencies);
}

function operatorPrincipal(principalId: string): OperatorPrincipal {
  return {
    principalId,
    authenticationMethod: "trusted_service_identity",
    authorizationScope: "global_admin"
  };
}

function proposalRequest(): Readonly<Record<string, unknown>> {
  return {
    tenantId: "tenant-a",
    inputId: "sidecar-certification-1",
    inputKind: "borrowing_base",
    candidateArtifactId: CANDIDATE_ARTIFACT_ID,
    primaryCertificationManifestId: "primary-certification-1",
    definitionIds: [PRIVATE_DEFINITION_ID],
    purpose: PRIVATE_PURPOSE,
    declaredControls: { rowCount: 3, balance: "987654.32", currency: "USD" },
    idempotencyKey: "propose-sidecar-1"
  };
}

function certificationRequest(): Readonly<Record<string, unknown>> {
  return {
    tenantId: "tenant-a",
    inputId: "sidecar-certification-1",
    idempotencyKey: "certify-sidecar-1"
  };
}

async function executeCli(
  root: string,
  command: "input-certification-propose" | "input-certification-certify",
  request: Readonly<Record<string, unknown>>,
  plane: OperatorControlPlane
): Promise<{
  readonly exitCode: number;
  readonly stdout: readonly string[];
  readonly stderr: readonly string[];
}> {
  const requestPath = join(root, `${command}-${crypto.randomUUID()}.json`);
  writeFileSync(requestPath, JSON.stringify(request), { mode: 0o600 });
  const captured = captureIo();
  const exitCode = await runOperatorCli(
    [command, "--request", requestPath],
    plane,
    captured.io
  );
  return { exitCode, stdout: captured.stdout, stderr: captured.stderr };
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

function parseCliSuccess(value: string): {
  readonly command: string;
  readonly result: Record<string, unknown>;
} {
  const parsed = JSON.parse(value) as {
    readonly ok?: unknown;
    readonly command?: unknown;
    readonly result?: unknown;
  };
  assert.equal(parsed.ok, true);
  assert.equal(typeof parsed.command, "string");
  assert.ok(parsed.result && typeof parsed.result === "object" && !Array.isArray(parsed.result));
  return { command: parsed.command as string, result: parsed.result as Record<string, unknown> };
}

function assertMetadataOnly(serialized: string): void {
  for (const privateValue of [
    PRIVATE_PURPOSE,
    PRIVATE_DEFINITION_ID,
    CANDIDATE_ARTIFACT_ID,
    "987654.32",
    "secret-snapshot-1",
    "secret-sidecar-dq-run",
    "secret-sidecar-reconciliation",
    "SECRET-"
  ]) {
    assert.equal(serialized.includes(privateValue), false, `summary disclosed ${privateValue}`);
  }
  for (const forbiddenField of [
    "candidateArtifactId",
    "candidateArtifactHash",
    "declaredControls",
    "definitionReferences",
    "purpose",
    "payloadHash",
    "fieldSetHash",
    "dataQualityResultHash",
    "reconciliationResultHash",
    "sidecarPopulationHash"
  ]) {
    assert.equal(serialized.includes(forbiddenField), false, `summary disclosed ${forbiddenField}`);
  }
}

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "abl-operator-input-certification-"));
  directories.push(directory);
  return directory;
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
