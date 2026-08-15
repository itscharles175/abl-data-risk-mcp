import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { gitNexusStatusCommand } from "../scripts/verify-gitnexus-current.mjs";

test("release GitNexus preflight uses an owned local runner when present", (context) => {
  const root = temporaryDirectory("abl-release-gitnexus-local-");
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const directory = join(root, ".gitnexus");
  const runner = join(directory, "run.cjs");
  mkdirSync(directory);
  writeFileSync(runner, "", { mode: 0o700 });

  assert.deepEqual(gitNexusStatusCommand(root), [process.execPath, runner, "status"]);
});

test("release GitNexus preflight falls back to the installed CLI in a clean clone", (context) => {
  const root = temporaryDirectory("abl-release-gitnexus-clean-");
  context.after(() => rmSync(root, { recursive: true, force: true }));
  assert.deepEqual(gitNexusStatusCommand(root), ["gitnexus", "status"]);
});

test("release GitNexus preflight refuses a symlinked local runner", (context) => {
  const root = temporaryDirectory("abl-release-gitnexus-symlink-");
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const directory = join(root, ".gitnexus");
  const target = join(root, "runner.cjs");
  const runner = join(directory, "run.cjs");
  mkdirSync(directory);
  writeFileSync(target, "", { mode: 0o700 });
  symlinkSync(target, runner);

  assert.deepEqual(gitNexusStatusCommand(root), ["gitnexus", "status"]);
});

function temporaryDirectory(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}
