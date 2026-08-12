import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";

import {
  loadRuntimeConfiguration,
  RuntimeConfigurationError,
  type RuntimeConfigurationErrorCode,
} from "../src/runtime/config.js";
import { isCompiledAuthorizationPolicy } from "../src/security/policy.js";

const ARTIFACT_SECRET = Buffer.alloc(32, 0x41).toString("base64");
const SIGNING_SECRET = Buffer.alloc(48, 0x53).toString("base64");

interface RuntimeFixture {
  readonly root: string;
  readonly env: Record<string, string>;
  readonly policyPath: string;
  readonly signingKeysPath: string;
  readonly artifactKeysPath: string;
}

test("loads a complete fail-closed runtime configuration without creating targets", (context) => {
  const fixture = runtimeFixture(context);
  const configuration = loadRuntimeConfiguration(fixture.env);

  assert.equal(configuration.authMode, "oauth");
  assert.equal(configuration.codeVersion, "0.2.0+test");
  assert.deepEqual(configuration.http, {
    host: "0.0.0.0",
    port: 3333,
    publicUrl: "https://abl.example.test",
    allowedHosts: ["abl.example.test"],
    allowedOrigins: ["https://claude.example.test", "https://codex.example.test"],
  });
  assert.equal(configuration.oauth.resource, "https://abl.example.test");
  assert.equal(configuration.oauth.maximumTokenLength, 16_384);
  assert.deepEqual(configuration.oauth.scopesSupported, ["abl:analyze", "abl:catalog", "abl:monitor"]);
  assert.equal(configuration.oauth.resourceName, "ABL test resource");
  assert.equal(configuration.oauth.resourceDocumentation, "https://docs.example.test/abl");
  assert.equal(configuration.oauth.issuers.length, 1);
  assert.deepEqual(configuration.oauth.issuers[0], {
    issuer: "https://issuer.example.test",
    jwksUri: "https://issuer.example.test/.well-known/jwks.json",
    audiences: ["abl-api", "abl-mcp"],
    resources: ["https://abl.example.test"],
    algorithms: ["ES256", "RS256"],
    requiredClaims: ["client_id", "tenant_membership_version"],
    acceptedTokenTypes: ["at+jwt"],
    clientIdClaims: ["azp", "client_id"],
    scopeClaim: "scope",
    maximumTokenLifetimeSeconds: 900,
    remoteJwks: {
      timeoutDurationMs: 2_000,
      cooldownDurationMs: 30_000,
      cacheMaxAgeMs: 600_000,
    },
  });
  assert.equal(isCompiledAuthorizationPolicy(configuration.policy), true);
  assert.equal(configuration.policy.id, "production-policy");
  assert.equal(configuration.signingKeyRing.currentKeyId, "signing-v1");
  assert.deepEqual(configuration.signingKeyRing.keyIds, ["signing-v1"]);
  assert.equal(configuration.artifactKeyRing.activeKeyId, "artifact-v1");
  assert.deepEqual(
    Buffer.from(configuration.artifactKeyRing.keys["artifact-v1"]!),
    Buffer.from(ARTIFACT_SECRET, "base64"),
  );
  assert.deepEqual(configuration.worker, {
    id: "worker-01",
    leaseSeconds: 60,
    pollIntervalMs: 250,
  });
  assert.deepEqual(configuration.limits, {
    rateLimitWindowMs: 60_000,
    rateLimitMaximumRequests: 120,
    maximumConcurrentRequests: 32,
    maximumConcurrentJobs: 4,
  });
  assert.equal(Object.isFrozen(configuration), true);
  assert.equal(Object.isFrozen(configuration.oauth.issuers), true);

  assert.equal(existsSync(configuration.storage.controlDatabasePath), false);
  assert.equal(existsSync(configuration.storage.jobDatabasePath), false);
  assert.equal(existsSync(configuration.storage.securityDatabasePath), false);
  assert.equal(existsSync(configuration.storage.artifactRoot), false);
  assert.equal(existsSync(join(fixture.root, "state")), false);
});

test("requires every production setting and rejects permissive auth modes and numeric bounds", (context) => {
  const fixture = runtimeFixture(context);

  const missing = { ...fixture.env };
  delete missing.ABL_OAUTH_RESOURCE;
  expectConfigurationError(
    () => loadRuntimeConfiguration(missing),
    "MISSING_SETTING",
    "ABL_OAUTH_RESOURCE",
  );

  expectConfigurationError(
    () => loadRuntimeConfiguration({ ...fixture.env, ABL_AUTH_MODE: "development" }),
    "INVALID_SETTING",
    "ABL_AUTH_MODE",
  );
  expectConfigurationError(
    () => loadRuntimeConfiguration({ ...fixture.env, ABL_MCP_PORT: "0" }),
    "INVALID_SETTING",
    "ABL_MCP_PORT",
  );
  expectConfigurationError(
    () => loadRuntimeConfiguration({ ...fixture.env, ABL_MCP_WORKER_LEASE_SECONDS: "4" }),
    "INVALID_SETTING",
    "ABL_MCP_WORKER_LEASE_SECONDS",
  );
  expectConfigurationError(
    () => loadRuntimeConfiguration({ ...fixture.env, ABL_MCP_RATE_LIMIT_WINDOW_MS: "999" }),
    "INVALID_SETTING",
    "ABL_MCP_RATE_LIMIT_WINDOW_MS",
  );
  expectConfigurationError(
    () => loadRuntimeConfiguration({ ...fixture.env, ABL_MCP_MAX_CONCURRENT_JOBS: "1001" }),
    "INVALID_SETTING",
    "ABL_MCP_MAX_CONCURRENT_JOBS",
  );
});

test("validates canonical HTTPS topology, exact hosts, origins, scopes and OAuth resource binding", (context) => {
  const fixture = runtimeFixture(context);

  expectConfigurationError(
    () => loadRuntimeConfiguration({ ...fixture.env, ABL_MCP_PUBLIC_URL: "http://abl.example.test" }),
    "INVALID_SETTING",
    "ABL_MCP_PUBLIC_URL",
  );
  expectConfigurationError(
    () =>
      loadRuntimeConfiguration({
        ...fixture.env,
        ABL_MCP_PUBLIC_URL: "https://user:password@abl.example.test",
      }),
    "INVALID_SETTING",
    "ABL_MCP_PUBLIC_URL",
  );
  expectConfigurationError(
    () => loadRuntimeConfiguration({ ...fixture.env, ABL_MCP_ALLOWED_HOSTS: "*.example.test" }),
    "INVALID_SETTING",
    "ABL_MCP_ALLOWED_HOSTS",
  );
  expectConfigurationError(
    () => loadRuntimeConfiguration({ ...fixture.env, ABL_MCP_ALLOWED_HOSTS: "other.example.test" }),
    "INVALID_SETTING",
    "ABL_MCP_ALLOWED_HOSTS",
  );
  expectConfigurationError(
    () => loadRuntimeConfiguration({ ...fixture.env, ABL_MCP_ALLOWED_ORIGINS: "http://client.test" }),
    "INVALID_SETTING",
    "ABL_MCP_ALLOWED_ORIGINS",
  );
  expectConfigurationError(
    () => loadRuntimeConfiguration({ ...fixture.env, ABL_OAUTH_SCOPES_SUPPORTED: "abl:read bad scope!" }),
    "INVALID_SETTING",
    "ABL_OAUTH_SCOPES_SUPPORTED",
  );

  const issuers = JSON.parse(fixture.env.ABL_OAUTH_ISSUERS_JSON!) as Array<Record<string, unknown>>;
  issuers[0]!.resources = ["https://different.example.test"];
  expectConfigurationError(
    () =>
      loadRuntimeConfiguration({
        ...fixture.env,
        ABL_OAUTH_ISSUERS_JSON: JSON.stringify(issuers),
      }),
    "INVALID_SETTING",
    "ABL_OAUTH_ISSUERS_JSON",
  );
});

test("OAuth issuer documents are strict, asymmetric, unique and bounded", (context) => {
  const fixture = runtimeFixture(context);
  const base = JSON.parse(fixture.env.ABL_OAUTH_ISSUERS_JSON!) as Array<Record<string, unknown>>;

  const unknownField = structuredClone(base);
  unknownField[0]!.unexpected = true;
  expectConfigurationError(
    () =>
      loadRuntimeConfiguration({
        ...fixture.env,
        ABL_OAUTH_ISSUERS_JSON: JSON.stringify(unknownField),
      }),
    "INVALID_SETTING",
    "ABL_OAUTH_ISSUERS_JSON",
  );

  const hmac = structuredClone(base);
  hmac[0]!.algorithms = ["HS256"];
  expectConfigurationError(
    () =>
      loadRuntimeConfiguration({ ...fixture.env, ABL_OAUTH_ISSUERS_JSON: JSON.stringify(hmac) }),
    "INVALID_SETTING",
    "ABL_OAUTH_ISSUERS_JSON",
  );

  expectConfigurationError(
    () =>
      loadRuntimeConfiguration({
        ...fixture.env,
        ABL_OAUTH_ISSUERS_JSON: JSON.stringify([...base, ...base]),
      }),
    "INVALID_SETTING",
    "ABL_OAUTH_ISSUERS_JSON",
  );

  const duplicateAudience = structuredClone(base);
  duplicateAudience[0]!.audiences = ["abl-mcp", "abl-mcp"];
  expectConfigurationError(
    () =>
      loadRuntimeConfiguration({
        ...fixture.env,
        ABL_OAUTH_ISSUERS_JSON: JSON.stringify(duplicateAudience),
      }),
    "INVALID_SETTING",
    "ABL_OAUTH_ISSUERS_JSON",
  );
});

test("secret key files require private regular files and reject symlink substitution", (context) => {
  const fixture = runtimeFixture(context);
  if (process.platform === "win32") {
    context.skip("POSIX ownership and mode checks are intentionally unavailable on Windows");
    return;
  }

  chmodSync(fixture.signingKeysPath, 0o640);
  expectConfigurationError(
    () => loadRuntimeConfiguration(fixture.env),
    "INSECURE_FILE",
    "ABL_MCP_SIGNING_KEYS_FILE",
  );
  chmodSync(fixture.signingKeysPath, 0o600);

  const linkPath = join(fixture.root, "signing-link.json");
  symlinkSync(fixture.signingKeysPath, linkPath);
  expectConfigurationError(
    () => loadRuntimeConfiguration({ ...fixture.env, ABL_MCP_SIGNING_KEYS_FILE: linkPath }),
    "INVALID_FILE",
    "ABL_MCP_SIGNING_KEYS_FILE",
  );
});

test("key files require strict schemas, canonical base64 and usable key selections", (context) => {
  const fixture = runtimeFixture(context);

  writePrivateJson(fixture.artifactKeysPath, {
    activeKeyId: "artifact-v1",
    keys: [{ id: "artifact-v1", secret: ARTIFACT_SECRET }],
    extra: "forbidden",
  });
  expectConfigurationError(
    () => loadRuntimeConfiguration(fixture.env),
    "INVALID_FILE",
    "ABL_MCP_ARTIFACT_KEYS_FILE",
  );

  writePrivateJson(fixture.artifactKeysPath, {
    activeKeyId: "artifact-v1",
    keys: [{ id: "artifact-v1", secret: ARTIFACT_SECRET.replace(/=+$/, "") }],
  });
  expectConfigurationError(
    () => loadRuntimeConfiguration(fixture.env),
    "INVALID_FILE",
    "ABL_MCP_ARTIFACT_KEYS_FILE",
  );

  writePrivateJson(fixture.artifactKeysPath, {
    activeKeyId: "artifact-v1",
    keys: [{ id: "artifact-v1", secret: Buffer.alloc(33, 0x41).toString("base64") }],
  });
  expectConfigurationError(
    () => loadRuntimeConfiguration(fixture.env),
    "INVALID_FILE",
    "ABL_MCP_ARTIFACT_KEYS_FILE",
  );

  writePrivateJson(fixture.artifactKeysPath, {
    activeKeyId: "missing",
    keys: [{ id: "artifact-v1", secret: ARTIFACT_SECRET }],
  });
  expectConfigurationError(
    () => loadRuntimeConfiguration(fixture.env),
    "INVALID_FILE",
    "ABL_MCP_ARTIFACT_KEYS_FILE",
  );

  writePrivateJson(fixture.artifactKeysPath, {
    activeKeyId: "artifact-v1",
    keys: [{ id: "artifact-v1", secret: ARTIFACT_SECRET }],
  });
  writePrivateJson(fixture.signingKeysPath, {
    currentKeyId: "signing-v1",
    keys: [
      {
        id: "signing-v1",
        secret: SIGNING_SECRET,
        notBeforeEpochSeconds: 200,
        notAfterEpochSeconds: 100,
      },
    ],
  });
  expectConfigurationError(
    () => loadRuntimeConfiguration(fixture.env),
    "INVALID_FILE",
    "ABL_MCP_SIGNING_KEYS_FILE",
  );
});

test("policy JSON is structurally strict and compiled through the authorization engine", (context) => {
  const fixture = runtimeFixture(context);
  const policy = policyDocument() as Record<string, unknown>;
  policy.unexpected = "forbidden";
  writePrivateJson(fixture.policyPath, policy);
  expectConfigurationError(
    () => loadRuntimeConfiguration(fixture.env),
    "INVALID_FILE",
    "ABL_MCP_POLICY_FILE",
  );

  const illegalPolicy = policyDocument();
  illegalPolicy.rules[0]!.effect = "deny";
  illegalPolicy.rules[0]!.requiredScopes = ["abl:analyze"];
  writePrivateJson(fixture.policyPath, illegalPolicy);
  expectConfigurationError(
    () => loadRuntimeConfiguration(fixture.env),
    "INVALID_FILE",
    "ABL_MCP_POLICY_FILE",
  );
});

test("remote policy startup rejects obligations the runtime cannot enforce completely", (context) => {
  const fixture = runtimeFixture(context);
  const base = policyDocument();
  const unsupportedPolicies = [
    {
      ...base,
      defaultObligations: { ...base.defaultObligations, allowRawRows: true },
    },
    {
      ...base,
      defaultObligations: { ...base.defaultObligations, allowExport: true },
    },
    {
      ...base,
      defaultObligations: {
        ...base.defaultObligations,
        fieldMasks: { borrower_id: "redact" },
      },
    },
    {
      ...base,
      defaultObligations: {
        ...base.defaultObligations,
        rowFilterRefs: ["portfolio-entitlement"],
      },
    },
    {
      ...base,
      rules: [
        {
          ...base.rules[0]!,
          obligations: { fieldMasks: { borrower_id: "hash" } },
        },
      ],
    },
    {
      ...base,
      rules: [
        {
          ...base.rules[0]!,
          obligations: { rowFilterRefs: ["tenant-boundary", "facility-entitlement"] },
        },
      ],
    },
    {
      ...base,
      defaultObligations: { ...base.defaultObligations, maxResultBytes: 1_023 },
    },
    {
      ...base,
      rules: [
        {
          ...base.rules[0]!,
          obligations: { maxResultBytes: 1_023 },
        },
      ],
    },
  ];

  for (const unsupported of unsupportedPolicies) {
    writePrivateJson(fixture.policyPath, unsupported);
    expectConfigurationError(
      () => loadRuntimeConfiguration(fixture.env),
      "INVALID_FILE",
      "ABL_MCP_POLICY_FILE",
    );
  }

  writePrivateJson(fixture.policyPath, {
    ...base,
    defaultObligations: {
      ...base.defaultObligations,
      rowFilterRefs: ["tenant-boundary"],
    },
  });
  assert.equal(loadRuntimeConfiguration(fixture.env).policy.id, base.id);
});

test("target paths must be absolute, distinct, type-correct and remain untouched", (context) => {
  const fixture = runtimeFixture(context);

  expectConfigurationError(
    () => loadRuntimeConfiguration({ ...fixture.env, ABL_MCP_CONTROL_DB_PATH: "relative.sqlite3" }),
    "INVALID_TARGET_PATH",
    "ABL_MCP_CONTROL_DB_PATH",
  );
  expectConfigurationError(
    () =>
      loadRuntimeConfiguration({
        ...fixture.env,
        ABL_MCP_JOB_DB_PATH: fixture.env.ABL_MCP_CONTROL_DB_PATH,
      }),
    "INVALID_TARGET_PATH",
    "ABL_MCP_JOB_DB_PATH",
  );
  expectConfigurationError(
    () => loadRuntimeConfiguration({ ...fixture.env, ABL_MCP_ARTIFACT_ROOT: fixture.policyPath }),
    "INVALID_TARGET_PATH",
    "ABL_MCP_ARTIFACT_ROOT",
  );
  assert.equal(existsSync(join(fixture.root, "state")), false);
});

test("configuration errors redact secret contents, paths, JSON and nested causes", (context) => {
  const fixture = runtimeFixture(context);
  const marker = "DO_NOT_LEAK_SUPER_SECRET_7fdcab";
  writeFileSync(fixture.signingKeysPath, `{\"secret\":\"${marker}\"`, { mode: 0o600 });
  chmodSync(fixture.signingKeysPath, 0o600);

  let captured: unknown;
  try {
    loadRuntimeConfiguration(fixture.env);
  } catch (error) {
    captured = error;
  }
  assert(captured instanceof RuntimeConfigurationError);
  assert.equal(captured.code, "INVALID_FILE");
  assert.equal(captured.setting, "ABL_MCP_SIGNING_KEYS_FILE");
  const serialized = JSON.stringify(captured);
  assert.equal(serialized.includes(marker), false);
  assert.equal(serialized.includes(fixture.signingKeysPath), false);
  assert.equal("cause" in captured, false);
});

function runtimeFixture(context: TestContext): RuntimeFixture {
  const root = mkdtempSync(join(tmpdir(), "abl-runtime-config-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));

  const sourceConfigPath = join(root, "source-config.json");
  const policyPath = join(root, "policy.json");
  const signingKeysPath = join(root, "signing-keys.json");
  const artifactKeysPath = join(root, "artifact-keys.json");
  writeFileSync(sourceConfigPath, "{\"sources\":[],\"analysis\":{}}\n", { mode: 0o644 });
  writePrivateJson(policyPath, policyDocument());
  writePrivateJson(signingKeysPath, {
    currentKeyId: "signing-v1",
    keys: [
      {
        id: "signing-v1",
        secret: SIGNING_SECRET,
        notBeforeEpochSeconds: 100,
        notAfterEpochSeconds: 4_102_444_800,
      },
    ],
  });
  writePrivateJson(artifactKeysPath, {
    activeKeyId: "artifact-v1",
    keys: [{ id: "artifact-v1", secret: ARTIFACT_SECRET }],
  });

  const env: Record<string, string> = {
    ABL_AUTH_MODE: "oauth",
    ABL_MCP_CONFIG: sourceConfigPath,
    ABL_MCP_HOST: "0.0.0.0",
    ABL_MCP_PORT: "3333",
    ABL_MCP_PUBLIC_URL: "https://abl.example.test",
    ABL_MCP_ALLOWED_HOSTS: "abl.example.test",
    ABL_MCP_ALLOWED_ORIGINS: JSON.stringify([
      "https://codex.example.test",
      "https://claude.example.test",
    ]),
    ABL_OAUTH_RESOURCE: "https://abl.example.test",
    ABL_OAUTH_ISSUERS_JSON: JSON.stringify([
      {
        issuer: "https://issuer.example.test",
        jwksUri: "https://issuer.example.test/.well-known/jwks.json",
        audiences: ["abl-mcp", "abl-api"],
        resources: ["https://abl.example.test"],
        algorithms: ["RS256", "ES256"],
        requiredClaims: ["tenant_membership_version", "client_id"],
        acceptedTokenTypes: ["at+jwt"],
        clientIdClaims: ["client_id", "azp"],
        scopeClaim: "scope",
        maximumTokenLifetimeSeconds: 900,
        remoteJwks: {
          timeoutDurationMs: 2_000,
          cooldownDurationMs: 30_000,
          cacheMaxAgeMs: 600_000,
        },
      },
    ]),
    ABL_OAUTH_MAX_TOKEN_LENGTH: "16384",
    ABL_OAUTH_SCOPES_SUPPORTED: "abl:monitor,abl:catalog abl:analyze",
    ABL_OAUTH_RESOURCE_NAME: "ABL test resource",
    ABL_OAUTH_RESOURCE_DOCUMENTATION: "https://docs.example.test/abl",
    ABL_MCP_CONTROL_DB_PATH: join(root, "state", "control.sqlite3"),
    ABL_MCP_JOB_DB_PATH: join(root, "state", "jobs.sqlite3"),
    ABL_MCP_SECURITY_DB_PATH: join(root, "state", "security.sqlite3"),
    ABL_MCP_ARTIFACT_ROOT: join(root, "artifacts"),
    ABL_MCP_POLICY_FILE: policyPath,
    ABL_MCP_SIGNING_KEYS_FILE: signingKeysPath,
    ABL_MCP_ARTIFACT_KEYS_FILE: artifactKeysPath,
    ABL_MCP_CODE_VERSION: "0.2.0+test",
    ABL_MCP_WORKER_ID: "worker-01",
    ABL_MCP_WORKER_LEASE_SECONDS: "60",
    ABL_MCP_WORKER_POLL_INTERVAL_MS: "250",
    ABL_MCP_RATE_LIMIT_WINDOW_MS: "60000",
    ABL_MCP_RATE_LIMIT_MAX_REQUESTS: "120",
    ABL_MCP_MAX_CONCURRENT_REQUESTS: "32",
    ABL_MCP_MAX_CONCURRENT_JOBS: "4",
  };
  return { root, env, policyPath, signingKeysPath, artifactKeysPath };
}

function policyDocument() {
  return {
    id: "production-policy",
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
      auditTags: ["production"],
    },
    rules: [
      {
        id: "analyst-read",
        effect: "permit" as "permit" | "deny",
        tenantIds: ["tenant-a"],
        tools: ["*"],
        datasets: ["*"],
        requiredScopes: ["abl:analyze"],
      },
    ],
  };
}

function writePrivateJson(path: string, value: unknown): void {
  writeFileSync(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  if (process.platform !== "win32") chmodSync(path, 0o600);
}

function expectConfigurationError(
  operation: () => unknown,
  code: RuntimeConfigurationErrorCode,
  setting: string,
): RuntimeConfigurationError {
  let captured: unknown;
  try {
    operation();
  } catch (error) {
    captured = error;
  }
  assert(captured instanceof RuntimeConfigurationError);
  assert.equal(captured.code, code);
  assert.equal(captured.setting, setting);
  assert.deepEqual(captured.toJSON(), {
    name: "RuntimeConfigurationError",
    code,
    setting,
    message: `Runtime configuration rejected: ${setting}`,
  });
  return captured;
}
