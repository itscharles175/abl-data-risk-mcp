import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const entrypoint = fileURLToPath(new URL("../scripts/container-entrypoint.mjs", import.meta.url));
const requiredSettings = [
  "ABL_MCP_PUBLIC_URL",
  "ABL_OAUTH_RESOURCE",
  "ABL_OAUTH_ISSUERS_JSON",
  "ABL_OAUTH_SCOPES_SUPPORTED",
  "ABL_MCP_ALLOWED_HOSTS",
  "ABL_MCP_ALLOWED_ORIGINS",
  "ABL_MCP_ARTIFACT_KEYS_FILE",
  "ABL_MCP_SIGNING_KEYS_FILE",
  "ABL_MCP_POLICY_FILE"
] as const;

test("container entrypoint fails closed with a stable redacted error before remote startup", () => {
  const environment = { ...process.env };
  for (const name of requiredSettings) delete environment[name];

  const result = spawnSync(process.execPath, [entrypoint, "serve-remote"], {
    encoding: "utf8",
    env: environment
  });

  assert.equal(result.status, 78);
  assert.equal(result.signal, null);
  assert.equal(result.stdout, "");
  assert.equal(
    result.stderr,
    '{"level":"error","event":"container_startup_failed","code":"REQUIRED_SETTING_MISSING"}\n'
  );
  assert.equal(result.stderr.includes(process.cwd()), false);
});
