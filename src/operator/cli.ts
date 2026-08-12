import type { OperatorControlPlane } from "./control-plane.js";
import {
  OperatorControlPlaneError,
  readBoundedJsonFile
} from "./control-plane.js";
import { OperatorInputError } from "./schemas.js";

export const OPERATOR_COMMANDS = [
  "ingest-file",
  "extract-sql",
  "mapping-propose",
  "mapping-transition",
  "definition-propose",
  "definition-transition",
  "certify-snapshot",
  "put-input-artifact",
  "input-certification-propose",
  "input-certification-certify",
  "membership-propose",
  "membership-approve",
  "membership-revoke",
  "alerts-list",
  "alert-transition",
  "audit-list"
] as const;

export type OperatorCommand = (typeof OPERATOR_COMMANDS)[number];

type OperatorControlPlanePort = Pick<
  OperatorControlPlane,
  | "approveMembership"
  | "certifySnapshot"
  | "extractSqlSnapshot"
  | "ingestLoanTape"
  | "listAlerts"
  | "listAudit"
  | "proposeDefinition"
  | "proposeMapping"
  | "proposeMembership"
  | "putInputArtifact"
  | "proposeInputCertification"
  | "certifyInputCertification"
  | "revokeMembership"
  | "transitionAlert"
  | "transitionDefinition"
  | "transitionMapping"
>;

export interface OperatorCliIo {
  readonly stdout: (line: string) => void;
  readonly stderr: (line: string) => void;
}

export interface OperatorCliOptions {
  readonly readRequest?: typeof readBoundedJsonFile;
  readonly signal?: AbortSignal;
}

export interface OperatorCliSuccess {
  readonly ok: true;
  readonly command: OperatorCommand;
  readonly result: unknown;
}

export interface OperatorCliFailure {
  readonly ok: false;
  readonly error: {
    readonly code: string;
    readonly message: string;
  };
}

/** Executes one strict operator command. Request bodies are accepted only from bounded JSON files. */
export async function runOperatorCli(
  argv: readonly string[],
  controlPlane: OperatorControlPlanePort,
  io: OperatorCliIo,
  options: OperatorCliOptions = {}
): Promise<number> {
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "help")) {
    io.stdout(
      stableJson({
        ok: true,
        usage: "abl-operator <command> --request <bounded-json-file>",
        authorization: "privileged global admin; tenantId is a resource selector, not authentication",
        commands: OPERATOR_COMMANDS
      })
    );
    return 0;
  }

  try {
    const { command, requestPath } = parseArguments(argv);
    const request = (options.readRequest ?? readBoundedJsonFile)(requestPath, 1_000_000);
    const result = await executeCommand(command, request, controlPlane, options.signal);
    const response: OperatorCliSuccess = { ok: true, command, result };
    io.stdout(stableJson(response));
    return 0;
  } catch (error) {
    const response = safeFailure(error);
    io.stderr(stableJson(response));
    return failureExitCode(response.error.code);
  }
}

function parseArguments(argv: readonly string[]): {
  readonly command: OperatorCommand;
  readonly requestPath: string;
} {
  if (argv.length !== 3 || argv[1] !== "--request") {
    throw new OperatorInputError("Expected exactly: <command> --request <json-file>");
  }
  const command = argv[0];
  if (!command || !(OPERATOR_COMMANDS as readonly string[]).includes(command)) {
    throw new OperatorInputError("Operator command is invalid");
  }
  const requestPath = argv[2];
  if (!requestPath || requestPath.length > 4_096 || /[\u0000\r\n]/.test(requestPath)) {
    throw new OperatorInputError("Operator request path is invalid");
  }
  return { command: command as OperatorCommand, requestPath };
}

async function executeCommand(
  command: OperatorCommand,
  request: unknown,
  controlPlane: OperatorControlPlanePort,
  signal?: AbortSignal
): Promise<unknown> {
  switch (command) {
    case "ingest-file":
      return controlPlane.ingestLoanTape(request);
    case "extract-sql":
      return controlPlane.extractSqlSnapshot(request, signal === undefined ? {} : { signal });
    case "mapping-propose":
      return controlPlane.proposeMapping(request);
    case "mapping-transition":
      return controlPlane.transitionMapping(request);
    case "definition-propose":
      return controlPlane.proposeDefinition(request);
    case "definition-transition":
      return controlPlane.transitionDefinition(request);
    case "certify-snapshot":
      return controlPlane.certifySnapshot(request);
    case "put-input-artifact":
      return controlPlane.putInputArtifact(request);
    case "input-certification-propose":
      return controlPlane.proposeInputCertification(request);
    case "input-certification-certify":
      return controlPlane.certifyInputCertification(request);
    case "membership-propose":
      return controlPlane.proposeMembership(request);
    case "membership-approve":
      return controlPlane.approveMembership(request);
    case "membership-revoke":
      return controlPlane.revokeMembership(request);
    case "alerts-list":
      return controlPlane.listAlerts(request);
    case "alert-transition":
      return controlPlane.transitionAlert(request);
    case "audit-list":
      return controlPlane.listAudit(request);
  }
}

const KNOWN_EXTERNAL_ERROR_CODES = new Set([
  "ALERT_NOT_FOUND",
  "ARTIFACT_NOT_FOUND",
  "ARTIFACT_TOO_LARGE",
  "BYTE_LIMIT_EXCEEDED",
  "CANCELLED",
  "COLUMN_NOT_ALLOWED",
  "CONFLICT",
  "DEFINITION_INVALID",
  "DEFINITION_NOT_EFFECTIVE",
  "FILE_NOT_REGULAR",
  "FILE_TOO_LARGE",
  "IDEMPOTENCY_CONFLICT",
  "ILLEGAL_TRANSITION",
  "INTEGRITY_FAILURE",
  "INVALID_ARGUMENT",
  "INVALID_DOCUMENT",
  "INVALID_INPUT",
  "INVALID_POLICY",
  "INVALID_REQUEST",
  "INVALID_TRANSITION",
  "INVALID_UTF8",
  "LIMIT_EXCEEDED",
  "MAKER_CHECKER_VIOLATION",
  "MAPPING_NOT_READY",
  "NOT_FOUND",
  "READ_ONLY_REQUIRED",
  "RELATION_NOT_ALLOWED",
  "ROW_LIMIT_EXCEEDED",
  "SNAPSHOT_MISMATCH",
  "SNAPSHOT_NOT_FOUND",
  "SOURCE_FAILURE",
  "SOURCE_NOT_CONFIGURED",
  "STORE_CLOSED",
  "TIME_LIMIT_EXCEEDED",
  "UNKNOWN_KEY",
  "UNSUPPORTED_FORMAT",
  "UNSUPPORTED_SCHEMA",
  "UNSUPPORTED_VALUE",
  "WATERMARK_NOT_ALLOWED",
  "WATERMARK_REQUIRED"
]);

function safeFailure(error: unknown): OperatorCliFailure {
  if (error instanceof OperatorInputError || error instanceof OperatorControlPlaneError) {
    return { ok: false, error: { code: error.code, message: publicMessage(error.code) } };
  }
  if (error && typeof error === "object") {
    const code = (error as { readonly code?: unknown }).code;
    if (typeof code === "string" && KNOWN_EXTERNAL_ERROR_CODES.has(code)) {
      return { ok: false, error: { code, message: publicMessage(code) } };
    }
  }
  return { ok: false, error: { code: "INTERNAL_ERROR", message: "Operator command failed" } };
}

function publicMessage(code: string): string {
  if (code === "INVALID_INPUT" || code === "INVALID_ARGUMENT" || code === "INVALID_REQUEST") {
    return "Operator request was rejected";
  }
  if (code === "MAKER_CHECKER_VIOLATION") return "Maker/checker separation rejected the operation";
  if (code === "IDEMPOTENCY_CONFLICT") return "Idempotency key conflicts with an earlier request";
  if (code === "SOURCE_NOT_CONFIGURED") return "Trusted SQL source is not configured";
  if (code === "MAPPING_NOT_READY") return "Mapping did not pass deterministic validation";
  if (code === "DEFINITION_NOT_EFFECTIVE") return "Required governed definition is not effective";
  if (code === "SNAPSHOT_NOT_FOUND" || code === "NOT_FOUND" || code === "ALERT_NOT_FOUND") {
    return "Requested governed resource was not found";
  }
  if (code.endsWith("LIMIT_EXCEEDED") || code === "FILE_TOO_LARGE" || code === "ARTIFACT_TOO_LARGE") {
    return "Configured operator limit was exceeded";
  }
  if (code === "CANCELLED") return "Operator command was cancelled";
  return "Governed operator operation was rejected";
}

function failureExitCode(code: string): number {
  if (code === "INTERNAL_ERROR") return 1;
  if (code === "INVALID_INPUT" || code === "INVALID_ARGUMENT" || code === "INVALID_REQUEST") return 2;
  return 3;
}

function stableJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, nested]) => nested !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalize(nested)])
    );
  }
  return value;
}
