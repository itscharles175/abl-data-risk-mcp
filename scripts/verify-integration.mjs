#!/usr/bin/env node
import {
  commandGate,
  manifestGate,
  rootTestFiles,
  runVerificationSuite
} from "./verify-common.mjs";

const integrationTests = rootTestFiles([
  /^adapters-/,
  /^analyst-mcp-tools\./,
  /^certification-postgres\./,
  /^composite-governed-workflow-router\./,
  /^governed-certified-snapshot-publication-v2\./,
  /^governed-modern-extraction-authority-v1\./,
  /^hybrid-connector\./,
  /^local-preview-v2\./,
  /^mcp-integration\./,
  /^modern-snapshot-runtime-v1\./,
  /^modern-snapshot-extraction-receipts-v1\./,
  /^operator-governance-commands\./,
  /^operator-runtime-modern-v2\./,
  /^pilot-vertical-acceptance\./,
  /^portfolio-surveillance-workflow-v4\./,
  /^postgres-snapshot-source\./,
  /^remote-http\./,
  /^reports-signing\./,
  /^synthetic-abs-auto-acceptance\./,
  /^shared-/,
  /^single-facility-v2-surveillance-runtime\./,
  /^sql-snapshot-extraction\./,
  /^stdio-integration\./,
  /^surveillance-production-authority-v2\./,
  /^surveillance-publication-v2-read-adapter\./
]);

await runVerificationSuite({
  name: "integration",
  title: "ABL platform integration verification",
  gates: [
    commandGate(
      "integration.typecheck",
      "Type-check root runtime and test contracts",
      ["pnpm", "exec", "tsc", "-p", "tsconfig.test.json", "--noEmit"]
    ),
    commandGate(
      "integration.local-conformance",
      "Run MCP, connector, adapter, PostgreSQL-port and object-store conformance tests",
      ["pnpm", "exec", "tsx", "--test", ...integrationTests]
    ),
    commandGate(
      "integration.console-bff",
      "Run console, BFF and shared platform-contract fixture tests",
      ["pnpm", "run", "test:platform"]
    ),
    manifestGate(
      "integration.live-postgresql",
      "Certify least-privileged live PostgreSQL, RLS, cursor, timeout and cancellation behavior",
      "ABL_VERIFY_INTEGRATION_LIVE"
    ),
    manifestGate(
      "integration.live-object-storage",
      "Certify versioned object storage, KMS, retention and legal-hold behavior",
      "ABL_VERIFY_INTEGRATION_LIVE"
    ),
    manifestGate(
      "integration.live-oidc",
      "Exercise the real OIDC issuer, PKCE, step-up and TLS gateway",
      "ABL_VERIFY_INTEGRATION_LIVE"
    ),
    manifestGate(
      "integration.live-connector",
      "Exercise the outbound-only client-VPC connector against an approved canary source",
      "ABL_VERIFY_INTEGRATION_LIVE"
    ),
    manifestGate(
      "integration.live-browser-e2e",
      "Run browser E2E against the deployed console and BFF",
      "ABL_VERIFY_INTEGRATION_LIVE"
    ),
    manifestGate(
      "integration.live-codex-claude",
      "Run real Codex and Claude MCP discovery and bounded-call smokes",
      "ABL_VERIFY_INTEGRATION_LIVE"
    )
  ]
});
