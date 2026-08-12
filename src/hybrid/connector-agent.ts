import { Buffer } from "node:buffer";

import {
  verifyConnectorPlan,
  type ConnectorPlanClaimsV1,
  type ConnectorReplayDefense,
  type ConnectorVerificationKey
} from "./connector-protocol.js";

export interface ConnectorMutualTlsConfiguration {
  readonly connectorId: string;
  readonly tenantId: string;
  /** Opaque client certificate/key reference resolved by the client secret manager. */
  readonly clientIdentityRef: string;
  /** Pinned central-control-plane SPKI hashes accepted after normal PKI validation. */
  readonly trustedServerSpkiHashes: readonly string[];
}

export interface ConnectorSessionPeer {
  readonly authenticated: true;
  readonly serverSpkiHash: string;
}

export interface ConnectorOutboundSession {
  readonly peer: ConnectorSessionPeer;
  receivePlan(signal?: AbortSignal): Promise<string | null>;
  submitResult(result: ConnectorExecutionResultV1, signal?: AbortSignal): Promise<void>;
  submitFailure(failure: ConnectorExecutionFailureV1, signal?: AbortSignal): Promise<void>;
  close(): Promise<void>;
}

/** The connector initiates this transport. There is intentionally no listen/bind API. */
export interface ConnectorOutboundTransport {
  connect(configuration: ConnectorMutualTlsConfiguration, signal?: AbortSignal): Promise<ConnectorOutboundSession>;
}

export interface ConnectorExtractionResultV1 {
  readonly action: "extract";
  readonly tenantId: string;
  readonly connectorId: string;
  readonly planId: string;
  readonly artifactId: string;
  readonly artifactContentHash: string;
  readonly snapshotId: string;
  readonly schemaHash: string;
  readonly rowCount: number;
  readonly byteCount: number;
  readonly sectionalControlHash: string;
}

export interface ConnectorInvestigationResultV1 {
  readonly action: "investigate";
  readonly tenantId: string;
  readonly connectorId: string;
  readonly planId: string;
  readonly investigationId: string;
  readonly populationHash: string;
  readonly rows: readonly Readonly<Record<string, null | boolean | string>>[];
  readonly nextOffset: number | null;
}

export type ConnectorExecutionResultV1 = ConnectorExtractionResultV1 | ConnectorInvestigationResultV1;

export interface ConnectorExecutionFailureV1 {
  readonly tenantId: string;
  readonly connectorId: string;
  readonly planId: string | null;
  readonly code:
    | "PLAN_REJECTED"
    | "EXECUTION_FAILED"
    | "RESULT_POLICY_VIOLATION"
    | "CANCELLED";
}

export interface ConnectorPlanExecutor {
  execute(claims: ConnectorPlanClaimsV1, signal?: AbortSignal): Promise<ConnectorExecutionResultV1>;
}

export interface ConnectorAgentOptions {
  readonly configuration: ConnectorMutualTlsConfiguration;
  readonly verificationKeys: readonly ConnectorVerificationKey[];
  readonly replayDefense: ConnectorReplayDefense;
  readonly transport: ConnectorOutboundTransport;
  readonly executor: ConnectorPlanExecutor;
  readonly clock?: () => Date;
}

export class ConnectorAgentError extends Error {
  constructor(
    readonly code: "INVALID_CONFIGURATION" | "PEER_AUTHENTICATION_FAILED" | "SESSION_FAILED",
    message: string
  ) {
    super(message);
    this.name = "ConnectorAgentError";
  }
}

/** Outbound-only, single-plan-at-a-time connector worker. */
export class ConnectorAgent {
  readonly #configuration: ConnectorMutualTlsConfiguration;
  readonly #verificationKeys: readonly ConnectorVerificationKey[];
  readonly #replayDefense: ConnectorReplayDefense;
  readonly #transport: ConnectorOutboundTransport;
  readonly #executor: ConnectorPlanExecutor;
  readonly #clock: () => Date;

  constructor(options: ConnectorAgentOptions) {
    validateConfiguration(options.configuration);
    if (!Array.isArray(options.verificationKeys) || options.verificationKeys.length < 1 || options.verificationKeys.length > 16) invalidConfiguration("Connector verification key ring is invalid");
    this.#configuration = Object.freeze({
      ...options.configuration,
      trustedServerSpkiHashes: Object.freeze([...options.configuration.trustedServerSpkiHashes])
    });
    this.#verificationKeys = Object.freeze([...options.verificationKeys]);
    this.#replayDefense = options.replayDefense;
    this.#transport = options.transport;
    this.#executor = options.executor;
    this.#clock = options.clock ?? (() => new Date());
  }

  async pollOnce(signal?: AbortSignal): Promise<"idle" | "processed" | "rejected"> {
    const session = await this.#transport.connect(this.#configuration, signal);
    try {
      this.#assertPeer(session.peer);
      const token = await session.receivePlan(signal);
      if (token === null) return "idle";
      let claims: ConnectorPlanClaimsV1;
      try {
        claims = await verifyConnectorPlan(
          this.#verificationKeys,
          token,
          { tenantId: this.#configuration.tenantId, connectorId: this.#configuration.connectorId },
          this.#replayDefense,
          { nowEpochSeconds: Math.floor(this.#clock().getTime() / 1_000) }
        );
      } catch {
        await session.submitFailure({
          tenantId: this.#configuration.tenantId,
          connectorId: this.#configuration.connectorId,
          planId: null,
          code: "PLAN_REJECTED"
        }, signal);
        return "rejected";
      }
      try {
        const result = await this.#executor.execute(claims, signal);
        assertResult(result, claims);
        await session.submitResult(result, signal);
        return "processed";
      } catch (error) {
        const code = signal?.aborted
          ? "CANCELLED"
          : error instanceof ConnectorResultPolicyError ? "RESULT_POLICY_VIOLATION" : "EXECUTION_FAILED";
        await session.submitFailure({
          tenantId: claims.tenantId,
          connectorId: claims.connectorId,
          planId: claims.planId,
          code
        }, signal);
        return "rejected";
      }
    } finally {
      await session.close();
    }
  }

  #assertPeer(peer: ConnectorSessionPeer): void {
    if (
      peer?.authenticated !== true ||
      !this.#configuration.trustedServerSpkiHashes.some((hash) => secureEqual(hash, peer.serverSpkiHash))
    ) {
      throw new ConnectorAgentError("PEER_AUTHENTICATION_FAILED", "Control-plane peer authentication failed");
    }
  }
}

class ConnectorResultPolicyError extends Error {}

function assertResult(result: ConnectorExecutionResultV1, claims: ConnectorPlanClaimsV1): void {
  if (
    !result || result.tenantId !== claims.tenantId || result.connectorId !== claims.connectorId ||
    result.planId !== claims.planId || result.action !== claims.operation.action
  ) resultViolation();
  const serializedBytes = Buffer.byteLength(JSON.stringify(result), "utf8");
  if (serializedBytes > claims.operation.maximumBytes) resultViolation();
  if (result.action === "extract" && claims.operation.action === "extract") {
    exactHash(result.artifactContentHash);
    exactHash(result.schemaHash);
    exactHash(result.sectionalControlHash);
    boundedInteger(result.rowCount, 0, claims.operation.maximumRows);
    boundedInteger(result.byteCount, 0, claims.operation.maximumBytes);
    safeIdentifier(result.artifactId);
    safeIdentifier(result.snapshotId);
    return;
  }
  if (result.action !== "investigate" || claims.operation.action !== "investigate") resultViolation();
  if (result.investigationId !== claims.operation.investigationId || result.populationHash !== claims.operation.populationHash) resultViolation();
  if (!Array.isArray(result.rows) || result.rows.length > claims.operation.rowLimit) resultViolation();
  for (const row of result.rows) {
    const keys = Object.keys(row).sort();
    const expected = [...claims.operation.requestedFields].sort();
    if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) resultViolation();
    for (const [field, value] of Object.entries(row)) {
      if (value !== null && typeof value !== "boolean" && typeof value !== "string") resultViolation();
      if (typeof value === "string" && Buffer.byteLength(value, "utf8") > 4_096) resultViolation();
      const mask = claims.operation.masks[field];
      if (mask === "redact" && value !== "[REDACTED]") resultViolation();
    }
  }
  const expectedNext = claims.operation.rowOffset + result.rows.length;
  if (result.nextOffset !== null && result.nextOffset !== expectedNext) resultViolation();
  if (result.nextOffset !== null && result.nextOffset >= 1_000) resultViolation();
}

function validateConfiguration(configuration: ConnectorMutualTlsConfiguration): void {
  safeIdentifier(configuration.connectorId);
  safeIdentifier(configuration.tenantId);
  safeIdentifier(configuration.clientIdentityRef);
  if (!Array.isArray(configuration.trustedServerSpkiHashes) || configuration.trustedServerSpkiHashes.length < 1 || configuration.trustedServerSpkiHashes.length > 8) {
    invalidConfiguration("At least one trusted server SPKI hash is required");
  }
  for (const hash of configuration.trustedServerSpkiHashes) exactHash(hash);
}

function boundedInteger(value: number, minimum: number, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) resultViolation();
}

function safeIdentifier(value: string): void {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u.test(value)) resultViolation();
}

function exactHash(value: string): void {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) resultViolation();
}

function secureEqual(left: string, right: string): boolean {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) difference |= a[index]! ^ b[index]!;
  return difference === 0;
}

function resultViolation(): never {
  throw new ConnectorResultPolicyError("Connector result violated signed egress policy");
}

function invalidConfiguration(message: string): never {
  throw new ConnectorAgentError("INVALID_CONFIGURATION", message);
}
