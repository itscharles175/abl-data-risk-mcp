#!/usr/bin/env node

import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { MonitoringAlertStore } from "./control/alerts.js";
import { ArtifactStore } from "./control/artifacts.js";
import { DefinitionStore } from "./control/definitions.js";
import { InputCertificationStore } from "./control/input-certifications.js";
import { JobStore, type ReapedJobRecord } from "./control/jobs.js";
import { ControlStore, type JsonValue } from "./control/store.js";
import { loadConfig } from "./config.js";
import { buildRemoteServer } from "./remote-server.js";
import {
  loadRuntimeConfiguration,
  RuntimeConfigurationError,
  type RuntimeConfiguration,
  type RuntimeEnvironment
} from "./runtime/config.js";
import { TenantMembershipStore } from "./security/membership-store.js";
import { createJwtOAuthAuthenticator } from "./security/oauth.js";
import { SecurityStateStore } from "./security/state-store.js";
import { GovernedWorkflow } from "./services/governed-workflow.js";
import {
  startRemoteHttp,
  type RemoteHttpServerHandle
} from "./transports/remote-http.js";

export type RemoteRuntimeErrorCode = "INITIALIZATION_FAILED" | "SHUTDOWN_FAILED";

/** Stable runtime lifecycle error that never retains a path, secret, or cause. */
export class RemoteRuntimeError extends Error {
  readonly code: RemoteRuntimeErrorCode;

  constructor(code: RemoteRuntimeErrorCode) {
    super(`Remote runtime ${code === "INITIALIZATION_FAILED" ? "initialization" : "shutdown"} failed`);
    this.name = "RemoteRuntimeError";
    this.code = code;
  }

  toJSON(): Readonly<{ name: string; code: RemoteRuntimeErrorCode; message: string }> {
    return Object.freeze({ name: this.name, code: this.code, message: this.message });
  }
}

export interface RemoteRuntimeHandle {
  readonly host: string;
  readonly port: number;
  readonly resourceMetadataUrl: string;
  isReady(): boolean;
  close(): Promise<void>;
}

export interface GovernedJobWorkerOptions {
  readonly jobs: Pick<JobStore, "listRunnableTenantIds" | "reapExpiredJobs">;
  readonly workflow: Pick<GovernedWorkflow, "processNext">;
  readonly workerId: string;
  readonly pollIntervalMs: number;
  readonly maximumConcurrentJobs: number;
  readonly onReaped?: (records: readonly ReapedJobRecord[]) => void | Promise<void>;
  readonly onHealthChange?: (healthy: boolean) => void;
  readonly onOperationalEvent?: (event: "job_worker_poll_failed") => void;
}

export interface GovernedJobWorkerHandle {
  isHealthy(): boolean;
  stop(): void;
  readonly done: Promise<void>;
}

/**
 * Starts one bounded worker loop. Tenant partitions are discovered exclusively
 * from the durable queue and never accepted from an MCP request.
 */
export function startGovernedJobWorker(options: GovernedJobWorkerOptions): GovernedJobWorkerHandle {
  const pollIntervalMs = boundedInteger(options.pollIntervalMs, "pollIntervalMs", 50, 60_000);
  const maximumConcurrentJobs = boundedInteger(
    options.maximumConcurrentJobs,
    "maximumConcurrentJobs",
    1,
    1_000
  );
  if (!/^[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$/.test(options.workerId)) {
    throw new Error("workerId is invalid");
  }

  const controller = new AbortController();
  let healthy = true;
  const updateHealth = (next: boolean): void => {
    healthy = next;
    try {
      options.onHealthChange?.(next);
    } catch {
      // Health observers cannot interrupt the worker lifecycle.
    }
  };
  const operationalFailure = (): void => {
    try {
      options.onOperationalEvent?.("job_worker_poll_failed");
    } catch {
      // Operational sinks are best-effort and receive no exception details.
    }
  };

  const done = (async (): Promise<void> => {
    while (!controller.signal.aborted) {
      try {
        const reaped = options.jobs.reapExpiredJobs(maximumConcurrentJobs);
        if (reaped.length > 0) await options.onReaped?.(reaped);

        const tenants = options.jobs.listRunnableTenantIds(maximumConcurrentJobs);
        const settled = await Promise.allSettled(
          tenants.map((tenantId) => options.workflow.processNext(tenantId, options.workerId))
        );
        if (settled.some((result) => result.status === "rejected")) {
          updateHealth(false);
          operationalFailure();
        } else {
          updateHealth(true);
        }
      } catch {
        updateHealth(false);
        operationalFailure();
      }
      await waitForPoll(pollIntervalMs, controller.signal);
    }
  })();

  return Object.freeze({
    isHealthy: () => healthy,
    stop: () => controller.abort(),
    done
  });
}

/** Loads, initializes, serves, drains, and closes the complete governed runtime. */
export async function startRemoteRuntime(
  environment: RuntimeEnvironment = process.env
): Promise<RemoteRuntimeHandle> {
  const configuration = loadRuntimeConfiguration(environment);
  return await initializeRemoteRuntime(configuration);
}

async function initializeRemoteRuntime(configuration: RuntimeConfiguration): Promise<RemoteRuntimeHandle> {
  const previousUmask = process.umask(0o077);
  const storeClosers: Array<() => void> = [];
  let http: RemoteHttpServerHandle | undefined;
  let worker: GovernedJobWorkerHandle | undefined;
  let initialized = false;
  let closing = false;
  let workerHealthy = true;
  let umaskRestored = false;
  let keysReleased = false;

  const restoreUmask = (): void => {
    if (umaskRestored) return;
    process.umask(previousUmask);
    umaskRestored = true;
  };
  const releaseArtifactKeys = (): void => {
    if (keysReleased) return;
    for (const material of Object.values(configuration.artifactKeyRing.keys)) material.fill(0);
    keysReleased = true;
  };

  try {
    // Remote tools operate only on certified durable state, but the declared
    // non-secret source allowlist must still be syntactically valid at startup.
    loadConfig(configuration.storage.sourceConfigPath);
    prepareRuntimeDirectories(configuration);

    const control = new ControlStore(configuration.storage.controlDatabasePath);
    storeClosers.push(() => control.close());
    const definitions = new DefinitionStore(configuration.storage.controlDatabasePath);
    storeClosers.push(() => definitions.close());
    const jobs = new JobStore(configuration.storage.jobDatabasePath);
    storeClosers.push(() => jobs.close());
    const securityState = new SecurityStateStore(configuration.storage.securityDatabasePath);
    storeClosers.push(() => securityState.close());
    const monitoringAlerts = new MonitoringAlertStore(configuration.storage.controlDatabasePath);
    storeClosers.push(() => monitoringAlerts.close());
    const inputCertifications = new InputCertificationStore(configuration.storage.controlDatabasePath);
    storeClosers.push(() => inputCertifications.close());
    const tenantMemberships = new TenantMembershipStore(configuration.storage.controlDatabasePath);
    storeClosers.push(() => tenantMemberships.close());
    const artifacts = new ArtifactStore(
      configuration.storage.artifactRoot,
      configuration.artifactKeyRing
    );

    const authenticator = createJwtOAuthAuthenticator({
      issuers: configuration.oauth.issuers,
      tenantMembershipResolver: tenantMemberships,
      maximumTokenLength: configuration.oauth.maximumTokenLength
    });
    const workflow = new GovernedWorkflow(
      {
        control,
        definitions,
        artifacts,
        jobs,
        monitoringAlerts,
        inputCertifications,
        securityState,
        tenantMembershipResolver: tenantMemberships,
        policy: configuration.policy,
        keyRing: configuration.signingKeyRing
      },
      {
        codeVersion: configuration.codeVersion,
        workerLeaseSeconds: configuration.worker.leaseSeconds
      }
    );
    const serverServices = {
      control,
      definitions,
      monitoringAlerts,
      policy: configuration.policy,
      workflow
    };

    http = await startRemoteHttp({
      host: configuration.http.host,
      port: configuration.http.port,
      allowedHosts: configuration.http.allowedHosts,
      allowedOrigins: configuration.http.allowedOrigins,
      resource: configuration.oauth.resource,
      authorizationServers: configuration.oauth.issuers.map((issuer) => issuer.issuer),
      scopesSupported: configuration.oauth.scopesSupported,
      resourceName: configuration.oauth.resourceName,
      ...(configuration.oauth.resourceDocumentation === undefined
        ? {}
        : { resourceDocumentation: configuration.oauth.resourceDocumentation }),
      authenticator,
      serverFactory: (context) => buildRemoteServer(serverServices, context),
      readiness: () => initialized && workerHealthy && !closing,
      rateLimitWindowMs: configuration.limits.rateLimitWindowMs,
      maxRequestsPerWindow: configuration.limits.rateLimitMaximumRequests,
      maxConcurrentRequests: configuration.limits.maximumConcurrentRequests
    });

    worker = startGovernedJobWorker({
      jobs,
      workflow,
      workerId: configuration.worker.id,
      pollIntervalMs: configuration.worker.pollIntervalMs,
      maximumConcurrentJobs: configuration.limits.maximumConcurrentJobs,
      onHealthChange: (healthy) => {
        workerHealthy = healthy;
      },
      onOperationalEvent: (event) => emitOperationalEvent("error", event),
      onReaped: (records) => {
        for (const record of records) {
          control.appendAuditEvent({
            tenantId: record.tenantId,
            eventType:
              record.status === "cancelled"
                ? "governed_job.cancelled_after_lease"
                : "governed_job.failed_after_lease",
            entityType: "job",
            entityId: record.jobId,
            actor: configuration.worker.id,
            details: {
              errorCode: record.errorCode,
              status: record.status
            } as JsonValue,
            idempotencyKey: `runtime-reap:${record.jobId}:${record.status}`
          });
        }
      }
    });
    initialized = true;

    let closePromise: Promise<void> | undefined;
    const close = (): Promise<void> => {
      if (closePromise) return closePromise;
      closing = true;
      initialized = false;
      worker?.stop();
      closePromise = (async (): Promise<void> => {
        let failed = false;
        try {
          await http!.close();
        } catch {
          failed = true;
        }
        try {
          await worker!.done;
        } catch {
          failed = true;
        }
        if (!closeStores(storeClosers)) failed = true;
        releaseArtifactKeys();
        restoreUmask();
        if (failed) throw new RemoteRuntimeError("SHUTDOWN_FAILED");
      })();
      return closePromise;
    };

    return Object.freeze({
      host: http.host,
      port: http.port,
      resourceMetadataUrl: http.resourceMetadataUrl,
      isReady: () => initialized && workerHealthy && !closing,
      close
    });
  } catch {
    initialized = false;
    closing = true;
    worker?.stop();
    try {
      await http?.close();
    } catch {
      // Preserve the stable startup classification.
    }
    try {
      await worker?.done;
    } catch {
      // Preserve the stable startup classification.
    }
    closeStores(storeClosers);
    releaseArtifactKeys();
    restoreUmask();
    throw new RemoteRuntimeError("INITIALIZATION_FAILED");
  }
}

function prepareRuntimeDirectories(configuration: RuntimeConfiguration): void {
  const directories = new Set([
    dirname(configuration.storage.controlDatabasePath),
    dirname(configuration.storage.jobDatabasePath),
    dirname(configuration.storage.securityDatabasePath),
    configuration.storage.artifactRoot
  ]);
  for (const directory of directories) mkdirSync(directory, { recursive: true, mode: 0o700 });
}

function closeStores(closers: readonly (() => void)[]): boolean {
  let succeeded = true;
  for (const close of [...closers].reverse()) {
    try {
      close();
    } catch {
      succeeded = false;
    }
  }
  return succeeded;
}

async function waitForPoll(milliseconds: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return;
  await new Promise<void>((resolveWait) => {
    const finish = (): void => {
      clearTimeout(timer);
      signal.removeEventListener("abort", finish);
      resolveWait();
    };
    const timer = setTimeout(finish, milliseconds);
    signal.addEventListener("abort", finish, { once: true });
    if (signal.aborted) finish();
  });
}

function boundedInteger(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function emitOperationalEvent(level: "info" | "error", event: string): void {
  process.stderr.write(`${JSON.stringify({ level, event })}\n`);
}

function installSignalHandlers(runtime: RemoteRuntimeHandle): void {
  let shuttingDown = false;
  const shutdown = (): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    void runtime
      .close()
      .then(() => emitOperationalEvent("info", "remote_runtime_stopped"))
      .catch(() => {
        process.exitCode = 1;
        emitOperationalEvent("error", "remote_shutdown_failed");
      });
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
}

function startupFailure(error: unknown): Readonly<Record<string, string>> {
  if (error instanceof RuntimeConfigurationError) {
    return Object.freeze({
      level: "error",
      event: "remote_startup_failed",
      code: error.code,
      setting: error.setting
    });
  }
  if (error instanceof RemoteRuntimeError) {
    return Object.freeze({
      level: "error",
      event: "remote_startup_failed",
      code: error.code
    });
  }
  return Object.freeze({
    level: "error",
    event: "remote_startup_failed",
    code: "INITIALIZATION_FAILED"
  });
}

function isDirectExecution(): boolean {
  const entry = process.argv[1];
  return entry !== undefined && resolve(entry) === fileURLToPath(import.meta.url);
}

if (isDirectExecution()) {
  void startRemoteRuntime()
    .then((runtime) => {
      emitOperationalEvent("info", "remote_runtime_ready");
      installSignalHandlers(runtime);
    })
    .catch((error: unknown) => {
      process.stderr.write(`${JSON.stringify(startupFailure(error))}\n`);
      process.exitCode = 1;
    });
}
