import { spawnSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const TRUE_VALUES = new Set(["1", "true", "yes"]);
const FALSE_VALUES = new Set(["0", "false", "no"]);

export function rootTestFiles(patterns) {
  const directory = join(repositoryRoot, "tests");
  return readdirSync(directory)
    .filter((name) => name.endsWith(".test.ts") && patterns.some((pattern) => pattern.test(name)))
    .sort()
    .map((name) => join("tests", name));
}

export function commandGate(id, description, argv, options = {}) {
  return Object.freeze({ id, description, argv: Object.freeze([...argv]), ...options });
}

export function checkGate(id, description, check, options = {}) {
  return Object.freeze({ id, description, check, ...options });
}

export function manifestGate(id, description, optInEnv) {
  return Object.freeze({ id, description, optInEnv, manifestGateId: id });
}

export async function runVerificationSuite(configuration) {
  process.chdir(repositoryRoot);
  const mode = parseArguments(process.argv.slice(2));
  if (mode === "help") {
    printHelp(configuration);
    return;
  }

  validateGates(configuration.gates);
  const commit = capture(["git", "rev-parse", "HEAD"]).trim();
  const startedAt = new Date();
  const results = [];
  let failed = false;
  let skippedExternal = false;

  process.stdout.write(`\n${configuration.title}\n`);
  process.stdout.write(`commit: ${commit || "unavailable"}\n`);
  process.stdout.write(`policy: operator-run only; GitHub Actions is not used\n\n`);

  for (const gate of configuration.gates) {
    const enabled = gate.optInEnv ? environmentFlag(gate.optInEnv) : true;
    if (gate.optInEnv && !enabled) {
      skippedExternal = true;
      results.push(result(gate, "skipped_external", 0, `set ${gate.optInEnv}=1 to opt in`));
      printGate("SKIP-EXTERNAL", gate, `set ${gate.optInEnv}=1 to opt in`);
      continue;
    }
    if (mode === "list") {
      results.push(result(gate, "listed", 0, gate.manifestGateId ? "external manifest command" : summarizeGate(gate)));
      printGate(gate.optInEnv ? "OPT-IN" : "REQUIRED", gate, gate.manifestGateId ?? summarizeGate(gate));
      continue;
    }

    const gateStarted = Date.now();
    printGate("RUN", gate);
    try {
      if (gate.manifestGateId) {
        runManifestGate(gate.manifestGateId);
      } else if (gate.argv) {
        runCommand(gate.argv, gate.timeoutSeconds);
      } else {
        await gate.check();
      }
      const duration = Date.now() - gateStarted;
      results.push(result(gate, "passed", duration));
      printGate("PASS", gate, `${duration}ms`);
    } catch (error) {
      const duration = Date.now() - gateStarted;
      const message = safeError(error);
      results.push(result(gate, "failed", duration, message));
      printGate("FAIL", gate, message);
      failed = true;
      if (gate.continueOnFailure !== true) break;
    }
  }

  const finishedAt = new Date();
  const outcome = failed
    ? "failed"
    : mode === "list"
      ? "listed_not_executed"
      : skippedExternal
        ? "local_pass_external_not_run"
        : "passed";
  const evidence = Object.freeze({
    evidenceVersion: 1,
    suite: configuration.name,
    outcome,
    commit,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    operatorRun: true,
    githubActionsUsed: false,
    results: Object.freeze(results)
  });
  maybeWriteEvidence(evidence);
  process.stdout.write(`\noutcome: ${outcome}\n`);
  if (skippedExternal && mode !== "list") {
    process.stdout.write("scope: local/conformance evidence only; this is not live-environment or promotion evidence\n");
  }
  if (mode === "list") process.stdout.write("scope: listing only; no verification evidence was produced\n");
  if (failed) process.exitCode = 1;
}

export function assertNoGithubActions() {
  const workflowDirectory = join(repositoryRoot, ".github", "workflows");
  if (existsSync(workflowDirectory)) {
    const workflows = readdirSync(workflowDirectory).filter((name) => /\.ya?ml$/i.test(name));
    if (workflows.length > 0) throw new Error("GitHub Actions workflow files are prohibited");
  }
  const tracked = capture(["git", "ls-files", ".github/workflows"]);
  if (tracked.trim()) throw new Error("Tracked GitHub Actions workflow files are prohibited");
}

export function assertCleanReleaseTree() {
  const status = capture(["git", "status", "--porcelain=v1", "--untracked-files=all"]);
  if (status.trim()) throw new Error("release verification requires a clean working tree");
  const head = capture(["git", "rev-parse", "HEAD"]).trim();
  const branch = capture(["git", "symbolic-ref", "--quiet", "--short", "HEAD"], true).trim();
  if (!/^[a-f0-9]{40}$/.test(head)) throw new Error("release verification requires an immutable Git commit");
  if (!branch) throw new Error("release verification requires a named branch, not detached HEAD");
}

function runManifestGate(gateId) {
  const manifestPath = process.env.ABL_VERIFY_EXTERNAL_MANIFEST;
  if (!manifestPath) throw new Error("ABL_VERIFY_EXTERNAL_MANIFEST is required for opted-in external gates");
  if (!isAbsolute(manifestPath)) throw new Error("ABL_VERIFY_EXTERNAL_MANIFEST must be an absolute path");
  const stat = lstatSync(manifestPath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 128 * 1024) {
    throw new Error("external verification manifest must be a regular, non-symlink file no larger than 128 KiB");
  }
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch {
    throw new Error("external verification manifest is not valid JSON");
  }
  if (!isRecord(manifest) || manifest.schemaVersion !== 1 || !isRecord(manifest.gates)) {
    throw new Error("external verification manifest must use schemaVersion 1 and a gates object");
  }
  const entry = manifest.gates[gateId];
  if (!isRecord(entry)) throw new Error(`external verification manifest is missing gate ${gateId}`);
  const allowedKeys = new Set(["argv", "cwd", "timeoutSeconds"]);
  if (Object.keys(entry).some((key) => !allowedKeys.has(key))) {
    throw new Error(`external gate ${gateId} contains unsupported fields`);
  }
  if (!Array.isArray(entry.argv) || entry.argv.length < 1 || entry.argv.length > 64) {
    throw new Error(`external gate ${gateId} argv must contain 1 through 64 strings`);
  }
  const argv = entry.argv.map((value) => {
    if (typeof value !== "string" || value.length < 1 || value.length > 8_192 || value.includes("\0")) {
      throw new Error(`external gate ${gateId} argv is invalid`);
    }
    return value;
  });
  if (!isAbsolute(argv[0])) throw new Error(`external gate ${gateId} executable must be an absolute path`);
  const cwd = entry.cwd === undefined ? repositoryRoot : entry.cwd;
  if (typeof cwd !== "string" || !isAbsolute(cwd) || !lstatSync(cwd).isDirectory()) {
    throw new Error(`external gate ${gateId} cwd must be an existing absolute directory`);
  }
  const timeoutSeconds = entry.timeoutSeconds === undefined
    ? 1_800
    : boundedInteger(entry.timeoutSeconds, 1, 7_200, `external gate ${gateId} timeoutSeconds`);
  runCommand(argv, timeoutSeconds, cwd);
}

function runCommand(argv, timeoutSeconds = 1_800, cwd = repositoryRoot) {
  const seconds = boundedInteger(timeoutSeconds, 1, 7_200, "timeoutSeconds");
  const completed = spawnSync(argv[0], argv.slice(1), {
    cwd,
    env: process.env,
    stdio: "inherit",
    shell: false,
    timeout: seconds * 1_000,
    killSignal: "SIGTERM"
  });
  if (completed.error) {
    if (completed.error.code === "ETIMEDOUT") throw new Error(`gate timed out after ${seconds}s`);
    throw new Error(`could not execute ${argv[0]}`);
  }
  if (completed.signal) throw new Error(`gate terminated by ${completed.signal}`);
  if (completed.status !== 0) throw new Error(`gate exited with status ${completed.status ?? "unknown"}`);
}

function capture(argv, allowFailure = false) {
  const completed = spawnSync(argv[0], argv.slice(1), {
    cwd: repositoryRoot,
    env: process.env,
    encoding: "utf8",
    shell: false,
    timeout: 30_000
  });
  if (completed.error || (!allowFailure && completed.status !== 0)) {
    throw new Error(`preflight command ${argv[0]} failed`);
  }
  return completed.stdout ?? "";
}

function environmentFlag(name) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return false;
  const normalized = raw.toLowerCase();
  if (TRUE_VALUES.has(normalized)) return true;
  if (FALSE_VALUES.has(normalized)) return false;
  throw new Error(`${name} must be one of 1,true,yes,0,false,no`);
}

function maybeWriteEvidence(evidence) {
  const directory = process.env.ABL_VERIFY_EVIDENCE_DIR;
  if (!directory) return;
  if (!isAbsolute(directory)) throw new Error("ABL_VERIFY_EVIDENCE_DIR must be an absolute path");
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const timestamp = evidence.finishedAt.replace(/[:.]/g, "-");
  const path = join(directory, `${evidence.suite}-${timestamp}.json`);
  writeFileSync(path, `${JSON.stringify(evidence, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  process.stdout.write(`evidence: ${path}\n`);
}

function validateGates(gates) {
  const identifiers = new Set();
  for (const gate of gates) {
    if (!/^[a-z][a-z0-9.-]{2,127}$/.test(gate.id) || identifiers.has(gate.id)) {
      throw new Error(`invalid or duplicate gate id ${gate.id}`);
    }
    identifiers.add(gate.id);
    if (typeof gate.description !== "string" || gate.description.length < 3 || gate.description.length > 240) {
      throw new Error(`invalid description for gate ${gate.id}`);
    }
    const implementations = Number(Boolean(gate.argv)) + Number(Boolean(gate.check)) + Number(Boolean(gate.manifestGateId));
    if (implementations !== 1) throw new Error(`gate ${gate.id} must have exactly one implementation`);
    if (gate.optInEnv && !/^ABL_VERIFY_[A-Z0-9_]+$/.test(gate.optInEnv)) {
      throw new Error(`gate ${gate.id} uses an invalid opt-in variable`);
    }
  }
}

function parseArguments(argv) {
  if (argv.length === 0) return "run";
  if (argv.length === 1 && argv[0] === "--list") return "list";
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) return "help";
  throw new Error("supported arguments are --list and --help");
}

function printHelp(configuration) {
  process.stdout.write(`${configuration.title}\n\n`);
  process.stdout.write("Usage: node scripts/verify-<suite>.mjs [--list|--help]\n\n");
  process.stdout.write("External and live gates are skipped unless their documented ABL_VERIFY_* variable is true.\n");
  process.stdout.write("When enabled, manifest-backed gates are mandatory and any missing or failed command fails the suite.\n");
}

function summarizeGate(gate) {
  if (gate.argv) return `${gate.argv[0]} (${gate.argv.length - 1} args)`;
  if (gate.check) return "in-process policy check";
  return "external manifest command";
}

function printGate(status, gate, detail) {
  process.stdout.write(`[${status}] ${gate.id} — ${gate.description}${detail ? ` (${detail})` : ""}\n`);
}

function result(gate, status, durationMilliseconds, detail) {
  return Object.freeze({
    gateId: gate.id,
    status,
    durationMilliseconds,
    ...(detail ? { detail } : {})
  });
}

function safeError(error) {
  if (!(error instanceof Error)) return "verification gate failed";
  return error.message.replace(/[\r\n\t]+/g, " ").slice(0, 300);
}

function boundedInteger(value, minimum, maximum, name) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
