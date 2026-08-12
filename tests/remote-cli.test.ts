import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";

import {
  RemoteRuntimeError,
  startGovernedJobWorker,
  startRemoteRuntime
} from "../src/remote-cli.js";
import type { ReapedJobRecord } from "../src/control/jobs.js";

const ARTIFACT_SECRET = Buffer.alloc(32, 0x41).toString("base64");
const SIGNING_SECRET = Buffer.alloc(48, 0x53).toString("base64");

test("worker discovery, reaping and execution remain tenant-derived and concurrency bounded", async () => {
  const tenantQueue = ["tenant-a", "tenant-b", "tenant-c"];
  const processed: string[] = [];
  const reaped: ReapedJobRecord[] = [
    {
      tenantId: "tenant-expired",
      jobId: "job-expired",
      status: "failed",
      errorCode: "LEASE_EXPIRED"
    }
  ];
  const audited: ReapedJobRecord[] = [];
  let active = 0;
  let maximumActive = 0;
  let reaperCalled = false;
  const worker = startGovernedJobWorker({
    jobs: {
      listRunnableTenantIds(limit) {
        return tenantQueue.splice(0, limit);
      },
      reapExpiredJobs(limit) {
        if (reaperCalled) return [];
        reaperCalled = true;
        return reaped.slice(0, limit);
      }
    },
    workflow: {
      async processNext(tenantId, workerId) {
        assert.equal(workerId, "worker-test");
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        await delay(20);
        processed.push(tenantId);
        active -= 1;
        return null;
      }
    },
    workerId: "worker-test",
    pollIntervalMs: 50,
    maximumConcurrentJobs: 2,
    onReaped(records) {
      audited.push(...records);
    }
  });

  await eventually(() => processed.length === 3);
  worker.stop();
  await worker.done;

  assert.deepEqual(processed.sort(), ["tenant-a", "tenant-b", "tenant-c"]);
  assert.equal(maximumActive, 2);
  assert.deepEqual(audited, reaped);
  assert.equal(worker.isHealthy(), true);
});

test("production runtime becomes ready only after governed services initialize and drains cleanly", async (context) => {
  const fixture = await runtimeFixture(context);
  assert.equal("ABL_PORTFOLIO_DATABASE_URL" in fixture.environment, false);

  const runtime = await startRemoteRuntime(fixture.environment);
  context.after(() => runtime.close());
  const base = `http://127.0.0.1:${runtime.port}`;

  assert.equal(runtime.isReady(), true);
  assert.equal((await fetch(`${base}/healthz`, { headers: { Host: "probe.invalid" } })).status, 200);
  assert.equal((await fetch(`${base}/readyz`, { headers: { Host: "probe.invalid" } })).status, 200);

  const mcp = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      Host: fixture.publicHost,
      Origin: "https://client.example.test",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} })
  });
  assert.equal(mcp.status, 401);
  assert.match(mcp.headers.get("www-authenticate") ?? "", /resource_metadata=/);

  const metadata = await fetch(`${base}${new URL(runtime.resourceMetadataUrl).pathname}`, {
    headers: { Host: fixture.publicHost, Origin: "https://client.example.test" }
  });
  assert.equal(metadata.status, 200);
  assert.equal((await metadata.json() as { resource?: string }).resource, fixture.publicUrl);
  assert.equal(existsSync(fixture.controlDatabasePath), true);
  assert.equal(existsSync(fixture.jobDatabasePath), true);
  assert.equal(existsSync(fixture.securityDatabasePath), true);
  assert.equal(existsSync(fixture.artifactRoot), true);

  await runtime.close();
  await runtime.close();
  assert.equal(runtime.isReady(), false);
  await assert.rejects(() => fetch(`${base}/healthz`));
});

test("the production entry point handles SIGTERM and closes without leaking configuration", async (context) => {
  const fixture = await runtimeFixture(context);
  const child = spawn(process.execPath, ["--import", "tsx", "src/remote-cli.ts"], {
    cwd: process.cwd(),
    env: { ...process.env, ...fixture.environment },
    stdio: ["ignore", "pipe", "pipe"]
  });
  context.after(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  });
  let standardError = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    standardError += chunk;
  });

  await eventually(() => standardError.includes('"event":"remote_runtime_ready"'), 5_000);
  assert.equal(child.kill("SIGTERM"), true);
  const outcome = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
    (resolveExit, rejectExit) => {
      const timer = setTimeout(() => rejectExit(new Error("remote entry point did not stop")), 5_000);
      child.once("error", (error) => {
        clearTimeout(timer);
        rejectExit(error);
      });
      child.once("exit", (code, signal) => {
        clearTimeout(timer);
        resolveExit({ code, signal });
      });
    }
  );

  assert.deepEqual(outcome, { code: 0, signal: null });
  assert.match(standardError, /"event":"remote_runtime_stopped"/);
  assert.equal(standardError.includes(ARTIFACT_SECRET), false);
  assert.equal(standardError.includes(SIGNING_SECRET), false);
  assert.equal(standardError.includes(fixture.controlDatabasePath), false);
});

test("initialization failures are stable and redact source contents, paths and nested causes", async (context) => {
  const fixture = await runtimeFixture(context);
  const marker = "DO_NOT_LEAK_RUNTIME_SOURCE_SECRET_7be5";
  writeFileSync(fixture.sourceConfigPath, `{\"marker\":\"${marker}\"`, { mode: 0o600 });

  let captured: unknown;
  try {
    await startRemoteRuntime(fixture.environment);
  } catch (error) {
    captured = error;
  }
  assert(captured instanceof RemoteRuntimeError);
  assert.equal(captured.code, "INITIALIZATION_FAILED");
  assert.deepEqual(captured.toJSON(), {
    name: "RemoteRuntimeError",
    code: "INITIALIZATION_FAILED",
    message: "Remote runtime initialization failed"
  });
  const serialized = JSON.stringify(captured);
  assert.equal(serialized.includes(marker), false);
  assert.equal(serialized.includes(fixture.sourceConfigPath), false);
  assert.equal("cause" in captured, false);
  assert.equal(existsSync(fixture.controlDatabasePath), false);
});

interface RuntimeFixture {
  readonly environment: Record<string, string>;
  readonly publicUrl: string;
  readonly publicHost: string;
  readonly sourceConfigPath: string;
  readonly controlDatabasePath: string;
  readonly jobDatabasePath: string;
  readonly securityDatabasePath: string;
  readonly artifactRoot: string;
}

async function runtimeFixture(context: TestContext): Promise<RuntimeFixture> {
  const root = mkdtempSync(join(tmpdir(), "abl-remote-runtime-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const port = await reservePort();
  const publicHost = `127.0.0.1:${port}`;
  const publicUrl = `https://${publicHost}`;
  const sourceConfigPath = join(root, "source-config.json");
  const policyPath = join(root, "policy.json");
  const signingKeysPath = join(root, "signing-keys.json");
  const artifactKeysPath = join(root, "artifact-keys.json");
  const controlDatabasePath = join(root, "state", "control.sqlite3");
  const jobDatabasePath = join(root, "state", "jobs.sqlite3");
  const securityDatabasePath = join(root, "state", "security.sqlite3");
  const artifactRoot = join(root, "artifacts");

  writeFileSync(sourceConfigPath, '{"sources":[],"analysis":{}}\n', { mode: 0o600 });
  writePrivateJson(policyPath, policyDocument());
  writePrivateJson(signingKeysPath, {
    currentKeyId: "signing-v1",
    keys: [{ id: "signing-v1", secret: SIGNING_SECRET }]
  });
  writePrivateJson(artifactKeysPath, {
    activeKeyId: "artifact-v1",
    keys: [{ id: "artifact-v1", secret: ARTIFACT_SECRET }]
  });

  return {
    publicUrl,
    publicHost,
    sourceConfigPath,
    controlDatabasePath,
    jobDatabasePath,
    securityDatabasePath,
    artifactRoot,
    environment: {
      ABL_AUTH_MODE: "oauth",
      ABL_MCP_CONFIG: sourceConfigPath,
      ABL_MCP_HOST: "127.0.0.1",
      ABL_MCP_PORT: String(port),
      ABL_MCP_PUBLIC_URL: publicUrl,
      ABL_MCP_ALLOWED_HOSTS: publicHost,
      ABL_MCP_ALLOWED_ORIGINS: "https://client.example.test",
      ABL_OAUTH_RESOURCE: publicUrl,
      ABL_OAUTH_ISSUERS_JSON: JSON.stringify([
        {
          issuer: "https://issuer.example.test",
          jwksUri: "https://issuer.example.test/.well-known/jwks.json",
          audiences: ["abl-mcp"],
          resources: [publicUrl],
          algorithms: ["RS256"]
        }
      ]),
      ABL_OAUTH_MAX_TOKEN_LENGTH: "16384",
      ABL_OAUTH_SCOPES_SUPPORTED: "abl:catalog abl:analyze abl:monitor",
      ABL_OAUTH_RESOURCE_NAME: "ABL runtime test",
      ABL_MCP_CONTROL_DB_PATH: controlDatabasePath,
      ABL_MCP_JOB_DB_PATH: jobDatabasePath,
      ABL_MCP_SECURITY_DB_PATH: securityDatabasePath,
      ABL_MCP_ARTIFACT_ROOT: artifactRoot,
      ABL_MCP_POLICY_FILE: policyPath,
      ABL_MCP_SIGNING_KEYS_FILE: signingKeysPath,
      ABL_MCP_ARTIFACT_KEYS_FILE: artifactKeysPath,
      ABL_MCP_CODE_VERSION: "0.2.0+runtime-test",
      ABL_MCP_WORKER_ID: "worker-runtime-test",
      ABL_MCP_WORKER_LEASE_SECONDS: "60",
      ABL_MCP_WORKER_POLL_INTERVAL_MS: "50",
      ABL_MCP_RATE_LIMIT_WINDOW_MS: "1000",
      ABL_MCP_RATE_LIMIT_MAX_REQUESTS: "10",
      ABL_MCP_MAX_CONCURRENT_REQUESTS: "4",
      ABL_MCP_MAX_CONCURRENT_JOBS: "2"
    }
  };
}

function policyDocument() {
  return {
    id: "runtime-policy",
    version: "2026-08-11",
    defaultObligations: {
      maxResultRows: 500,
      maxResultBytes: 1_000_000,
      maxExecutionMs: 15_000,
      minimumCohortSize: 10,
      requireImmutableSnapshot: true,
      allowRawRows: false,
      allowExport: false,
      rowFilterRefs: [],
      fieldMasks: {},
      auditTags: ["runtime"]
    },
    rules: [
      {
        id: "runtime-permit",
        effect: "permit",
        tenantIds: ["*"],
        tools: ["*"],
        datasets: ["*"],
        requiredScopes: ["abl:analyze"]
      }
    ]
  };
}

function writePrivateJson(path: string, value: unknown): void {
  writeFileSync(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  if (process.platform !== "win32") chmodSync(path, 0o600);
}

async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  assert(address && typeof address === "object");
  const port = address.port;
  await new Promise<void>((resolveClose, rejectClose) => {
    server.close((error) => (error ? rejectClose(error) : resolveClose()));
  });
  return port;
}

async function eventually(predicate: () => boolean, timeoutMs: number = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) assert.fail("condition did not become true before the deadline");
    await delay(10);
  }
}

async function delay(milliseconds: number): Promise<void> {
  await new Promise<void>((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}
