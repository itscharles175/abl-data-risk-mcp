#!/usr/bin/env node

import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { RuntimeConfigurationError, type RuntimeEnvironment } from "../runtime/config.js";
import { runOperatorCli, type OperatorCliIo } from "./cli.js";
import type { OperatorControlPlane } from "./control-plane.js";
import { createOperatorRuntime, OperatorRuntimeError } from "./runtime.js";

export async function runOperatorMain(
  argv: readonly string[] = process.argv.slice(2),
  environment: RuntimeEnvironment = process.env,
  io: OperatorCliIo = {
    stdout: (line) => process.stdout.write(`${line}\n`),
    stderr: (line) => process.stderr.write(`${line}\n`)
  }
): Promise<number> {
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "help")) {
    return runOperatorCli(argv, {} as OperatorControlPlane, io);
  }
  let runtime: ReturnType<typeof createOperatorRuntime> | undefined;
  try {
    runtime = createOperatorRuntime(environment);
    return await runOperatorCli(argv, runtime.controlPlane, io);
  } catch (error) {
    if (error instanceof RuntimeConfigurationError) {
      io.stderr(
        JSON.stringify({
          ok: false,
          error: {
            code: error.code,
            message: "Runtime configuration was rejected",
            setting: error.setting
          }
        })
      );
      return 2;
    }
    if (error instanceof OperatorRuntimeError) {
      io.stderr(
        JSON.stringify({
          ok: false,
          error: { code: error.code, message: "Operator runtime configuration was rejected" }
        })
      );
      return 2;
    }
    io.stderr(JSON.stringify({ ok: false, error: { code: "STARTUP_FAILED", message: "Operator startup failed" } }));
    return 1;
  } finally {
    await runtime?.close();
  }
}

function isDirectExecution(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  return pathToFileURL(resolve(entry)).href === import.meta.url;
}

if (isDirectExecution()) {
  process.exitCode = await runOperatorMain();
}
