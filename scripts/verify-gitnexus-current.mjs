#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { lstatSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
export const repositoryRoot = resolve(scriptDirectory, "..");

export function gitNexusStatusCommand(root = repositoryRoot) {
  const localRunner = join(root, ".gitnexus", "run.cjs");
  try {
    const stat = lstatSync(localRunner);
    if (stat.isFile() && !stat.isSymbolicLink()) {
      return Object.freeze([process.execPath, localRunner, "status"]);
    }
  } catch {
    // A clean clone intentionally has no ignored .gitnexus runner.
  }
  return Object.freeze(["gitnexus", "status"]);
}

export function verifyGitNexusCurrent(root = repositoryRoot) {
  const argv = gitNexusStatusCommand(root);
  const completed = spawnSync(argv[0], argv.slice(1), {
    cwd: root,
    env: process.env,
    stdio: "inherit",
    shell: process.platform === "win32",
    timeout: 120_000,
    killSignal: "SIGTERM"
  });
  if (completed.error) {
    if (completed.error.code === "ENOENT" && argv[0] === "gitnexus") {
      throw new Error(
        "GitNexus CLI is required for release verification. Install gitnexus on PATH, run `gitnexus analyze`, then retry."
      );
    }
    if (completed.error.code === "ETIMEDOUT") {
      throw new Error("GitNexus status check timed out after 120 seconds");
    }
    throw new Error("GitNexus status check could not start");
  }
  if (completed.signal) throw new Error(`GitNexus status check terminated by ${completed.signal}`);
  if (completed.status !== 0) {
    throw new Error(
      "GitNexus index is missing or stale. Run `gitnexus analyze` for this checkout, review the refreshed graph, then retry."
    );
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : undefined;
if (invokedPath === import.meta.url) {
  try {
    verifyGitNexusCurrent();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "GitNexus verification failed"}\n`);
    process.exitCode = 1;
  }
}
