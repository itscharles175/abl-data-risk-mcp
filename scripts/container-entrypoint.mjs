#!/nodejs/bin/node

import { constants } from "node:fs";
import { access, chmod, lstat, open, readFile, rename, stat, unlink } from "node:fs/promises";

class EntrypointError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const mode = process.argv[2];
const destinations = Object.freeze({
  "artifact-keys": process.env.ABL_MCP_ARTIFACT_KEYS_FILE ?? "/run/runtime-secrets/artifact-keys",
  "signing-keys": process.env.ABL_MCP_SIGNING_KEYS_FILE ?? "/run/runtime-secrets/signing-keys",
  policy: process.env.ABL_MCP_POLICY_FILE ?? "/run/runtime-secrets/policy"
});

try {
  if (mode === "prepare-secrets") {
    await stageSecrets("/run/projected-secrets");
  } else if (mode === "serve-remote") {
    requireSettings([
      "ABL_MCP_PUBLIC_URL",
      "ABL_OAUTH_RESOURCE",
      "ABL_OAUTH_ISSUERS_JSON",
      "ABL_OAUTH_SCOPES_SUPPORTED",
      "ABL_MCP_ALLOWED_HOSTS",
      "ABL_MCP_ALLOWED_ORIGINS",
      "ABL_MCP_ARTIFACT_KEYS_FILE",
      "ABL_MCP_SIGNING_KEYS_FILE",
      "ABL_MCP_POLICY_FILE"
    ]);
    if (!(await allDestinationsReady())) await stageSecrets("/run/secrets");
    await requireRegularFile("/app/dist/remote-cli.js");
    process.argv.splice(1, process.argv.length - 1, "/app/dist/remote-cli.js");
    await import("/app/dist/remote-cli.js");
  } else {
    fail("container mode is invalid");
  }
} catch (error) {
  if (error instanceof EntrypointError) {
    process.stderr.write(`${JSON.stringify({ level: "error", event: "container_startup_failed", code: error.code })}\n`);
  } else {
    process.stderr.write(`${JSON.stringify({ level: "error", event: "container_startup_failed", code: "PRECONDITION_FAILED" })}\n`);
  }
  process.exitCode = 78;
}

async function stageSecrets(sourceDirectory) {
  for (const [name, destination] of Object.entries(destinations)) {
    const source = `${sourceDirectory}/${name}`;
    const contents = await boundedSecret(source);
    const temporary = `${destination}.tmp-${process.pid}`;
    let handle;
    try {
      handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o400);
      await handle.writeFile(contents);
      await handle.sync();
      await handle.close();
      handle = undefined;
      await chmod(temporary, 0o400);
      await rename(temporary, destination);
    } catch {
      await handle?.close().catch(() => undefined);
      await unlink(temporary).catch(() => undefined);
      fail("SECRET_STAGING_FAILED");
    } finally {
      contents.fill(0);
    }
  }
}

async function boundedSecret(path) {
  let metadata;
  try {
    metadata = await stat(path);
  } catch {
    fail("SECRET_SOURCE_MISSING");
  }
  if (!metadata.isFile() || metadata.size < 1 || metadata.size > 1_048_576) {
    fail("SECRET_SOURCE_INVALID");
  }
  try {
    return await readFile(path);
  } catch {
    fail("SECRET_SOURCE_UNREADABLE");
  }
}

async function allDestinationsReady() {
  for (const path of Object.values(destinations)) {
    try {
      const metadata = await lstat(path);
      if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 1) return false;
    } catch {
      return false;
    }
  }
  return true;
}

async function requireRegularFile(path) {
  let metadata;
  try {
    metadata = await lstat(path);
    await access(path, constants.R_OK);
  } catch {
    fail("ENTRYPOINT_MISSING");
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) fail("ENTRYPOINT_INVALID");
}

function requireSettings(names) {
  for (const name of names) {
    const value = process.env[name];
    if (typeof value !== "string" || value.trim().length === 0) fail("REQUIRED_SETTING_MISSING");
  }
}

function fail(code) {
  throw new EntrypointError(code);
}
