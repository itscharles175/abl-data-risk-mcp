import assert from "node:assert/strict";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import { runOperatorCli, type OperatorCliIo } from "../src/operator/cli.js";
import {
  OperatorControlPlane,
  type OperatorControlPlaneDependencies
} from "../src/operator/control-plane.js";
import { runOperatorMain } from "../src/operator/main.js";
import { deriveLocalOperatorPrincipal } from "../src/operator/runtime.js";
import { TenantMembershipStoreError } from "../src/security/membership-store.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function directory(): string {
  const path = mkdtempSync(join(tmpdir(), "abl-operator-cli-"));
  directories.push(path);
  return path;
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

function operatorPlane(options: { readonly membershipApprovalFails?: boolean } = {}): OperatorControlPlane {
  const dependencies: OperatorControlPlaneDependencies = {
    principal: {
      principalId: "operator-maker",
      authenticationMethod: "trusted_service_identity",
      authorizationScope: "global_admin"
    },
    control: unreachable<OperatorControlPlaneDependencies["control"]>("control"),
    definitions: unreachable<OperatorControlPlaneDependencies["definitions"]>("definitions"),
    artifacts: unreachable<OperatorControlPlaneDependencies["artifacts"]>("artifacts"),
    alerts: unreachable<OperatorControlPlaneDependencies["alerts"]>("alerts"),
    memberships: {
      propose: (input) => ({
        membershipId: input.membershipId,
        issuer: input.issuer,
        subject: input.subject,
        clientId: input.clientId,
        tenantId: input.tenantId,
        principalId: input.principalId,
        notBefore: input.notBefore ?? null,
        expiresAt: input.expiresAt ?? null,
        status: "proposed",
        proposedBy: input.proposedBy,
        proposedAt: "2026-08-11T12:00:00.000Z",
        approvedBy: null,
        approvedAt: null,
        revokedBy: null,
        revokedAt: null
      }),
      approve: (input) => {
        if (options.membershipApprovalFails) {
          throw new TenantMembershipStoreError(
            "MAKER_CHECKER_VIOLATION",
            "secret-token-and-private-subject"
          );
        }
        return {
          membershipId: input.membershipId,
          issuer: "https://issuer.example.test/",
          subject: "private-subject",
          clientId: "codex-client",
          tenantId: "tenant-a",
          principalId: "analyst-a",
          notBefore: null,
          expiresAt: null,
          status: "active",
          proposedBy: "identity-maker",
          proposedAt: "2026-08-11T12:00:00.000Z",
          approvedBy: input.actor,
          approvedAt: "2026-08-11T12:00:00.000Z",
          revokedBy: null,
          revokedAt: null
        };
      },
      revoke: unreachable<OperatorControlPlaneDependencies["memberships"]["revoke"]>("membership revoke")
    },
    ingestion: {
      registerDeliveredSnapshot: (input) => ({
        snapshot: {
          tenantId: input.tenantId,
          snapshotId: input.snapshotId,
          sourceId: input.sourceId,
          sourceLocator: "abl-artifact://" + "a".repeat(64),
          asOfDate: input.asOfDate,
          contentHash: "b".repeat(64),
          rowCount: input.records.length,
          schema: { columns: ["private_column"] },
          createdBy: input.deliveredBy,
          createdAt: "2026-08-11T12:00:00.000Z"
        },
        sourceArtifact: {
          artifactId: "a".repeat(64),
          tenantBinding: "c".repeat(64),
          kind: "delivered_snapshot",
          mediaType: "application/json",
          contentHash: "b".repeat(64),
          byteLength: 100,
          keyId: "test-key",
          uri: "abl-artifact://" + "a".repeat(64)
        }
      }),
      certifyMappedSnapshot: unreachable<OperatorControlPlaneDependencies["ingestion"]["certifyMappedSnapshot"]>(
        "certification"
      )
    },
    loadLoanTape: (path, options) => ({
      path,
      format: options.format ?? "csv",
      mediaType: "text/csv",
      byteLength: 32,
      sourceHash: "d".repeat(64),
      columns: ["private_column"],
      records: [{ private_column: "RAW-ROW-SECRET" }]
    })
  };
  return new OperatorControlPlane(dependencies);
}

test("CLI executes one strict request-file command and stdout contains metadata only", async () => {
  const root = directory();
  const requestPath = join(root, "request.json");
  writeFileSync(
    requestPath,
    JSON.stringify({
      tenantId: "tenant-a",
      snapshotId: "snapshot-v1",
      sourceId: "operator-file",
      asOfDate: "2026-07-31",
      filePath: "/private/path/loan-tape.csv",
      format: "csv",
      idempotencyKey: "file-ingest-v1"
    })
  );
  const output = captureIo();
  const exitCode = await runOperatorCli(
    ["ingest-file", "--request", requestPath],
    operatorPlane(),
    output.io
  );

  assert.equal(exitCode, 0);
  assert.equal(output.stderr.length, 0);
  assert.equal(output.stdout.length, 1);
  const response = JSON.parse(output.stdout[0]!) as Record<string, unknown>;
  assert.equal(response.ok, true);
  assert.equal(output.stdout[0]!.includes("RAW-ROW-SECRET"), false);
  assert.equal(output.stdout[0]!.includes("private/path"), false);
  assert.equal(output.stdout[0]!.includes("private_column"), false);
});

test("strict request validation requires explicit idempotency and never echoes OAuth identity input", async () => {
  const root = directory();
  const requestPath = join(root, "membership.json");
  writeFileSync(
    requestPath,
    JSON.stringify({
      membershipId: "membership-v1",
      issuer: "https://issuer.example.test/",
      subject: "PRIVATE-OAUTH-SUBJECT",
      clientId: "codex-client",
      tenantId: "tenant-a",
      principalId: "analyst-a"
    })
  );
  const output = captureIo();
  const exitCode = await runOperatorCli(
    ["membership-propose", "--request", requestPath],
    operatorPlane(),
    output.io
  );

  assert.equal(exitCode, 2);
  assert.equal(output.stdout.length, 0);
  assert.match(output.stderr[0]!, /"code":"INVALID_INPUT"/);
  assert.equal(output.stderr[0]!.includes("PRIVATE-OAUTH-SUBJECT"), false);
  assert.equal(output.stderr[0]!.includes("issuer.example"), false);
});

test("known governance failures retain stable codes but redact underlying messages", async () => {
  const root = directory();
  const requestPath = join(root, "approve.json");
  writeFileSync(
    requestPath,
    JSON.stringify({
      membershipId: "membership-v1",
      idempotencyKey: "membership-self-approve"
    })
  );
  const output = captureIo();
  const exitCode = await runOperatorCli(
    ["membership-approve", "--request", requestPath],
    operatorPlane({ membershipApprovalFails: true }),
    output.io
  );

  assert.equal(exitCode, 3);
  assert.match(output.stderr[0]!, /"code":"MAKER_CHECKER_VIOLATION"/);
  assert.equal(output.stderr[0]!.includes("secret-token"), false);
  assert.equal(output.stderr[0]!.includes("private-subject"), false);
});

test("unknown arguments, malformed JSON, and symlink request files fail closed", async () => {
  const root = directory();
  const malformed = join(root, "malformed.json");
  writeFileSync(malformed, "{not-json");

  for (const args of [
    ["unknown", "--request", malformed],
    ["ingest-file", "--request", malformed, "--extra"],
    ["ingest-file", "--request", malformed]
  ]) {
    const output = captureIo();
    assert.equal(await runOperatorCli(args, operatorPlane(), output.io), 2);
    assert.equal(output.stdout.length, 0);
    assert.match(output.stderr[0]!, /"code":"INVALID_INPUT"/);
    assert.equal(output.stderr[0]!.includes("not-json"), false);
  }

  const valid = join(root, "valid.json");
  const linked = join(root, "linked.json");
  writeFileSync(valid, "{}");
  symlinkSync(valid, linked);
  const output = captureIo();
  assert.equal(
    await runOperatorCli(["audit-list", "--request", linked], operatorPlane(), output.io),
    2
  );
  assert.match(output.stderr[0]!, /"code":"INVALID_INPUT"/);
});

test("help documents the exact invocation without opening runtime resources", async () => {
  const output = captureIo();
  assert.equal(await runOperatorMain(["--help"], {}, output.io), 0);
  assert.match(output.stdout[0]!, /abl-operator <command> --request <bounded-json-file>/);
  assert.match(output.stdout[0]!, /extract-sql/);
  assert.match(output.stdout[0]!, /privileged global admin/);
  assert.match(output.stdout[0]!, /tenantId is a resource selector/);
  assert.equal(output.stderr.length, 0);
});

test("local OS identity is stable, non-PII, and fixed to the global-admin boundary", () => {
  const first = deriveLocalOperatorPrincipal({ uid: 501, username: "private-user-name" });
  const replay = deriveLocalOperatorPrincipal({ uid: 501, username: "private-user-name" });
  const renamedAccount = deriveLocalOperatorPrincipal({ uid: 501, username: "second-private-alias" });
  const other = deriveLocalOperatorPrincipal({ uid: 502, username: "private-user-name" });

  assert.deepEqual(replay, first);
  assert.deepEqual(renamedAccount, first);
  assert.notEqual(other.principalId, first.principalId);
  assert.match(first.principalId, /^local-os:[a-f0-9]{64}$/);
  assert.equal(first.principalId.includes("private-user-name"), false);
  assert.equal(first.authenticationMethod, "local_os_account");
  assert.equal(first.authorizationScope, "global_admin");
});
