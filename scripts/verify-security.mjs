#!/usr/bin/env node
import {
  assertNoGithubActions,
  checkGate,
  commandGate,
  manifestGate,
  rootTestFiles,
  runVerificationSuite
} from "./verify-common.mjs";

const securityTests = rootTestFiles([
  /^adapters-/,
  /^analyst-mcp-tools\./,
  /^automation\./,
  /^certification-postgres\./,
  /^container-entrypoint\./,
  /^data-quality-v2\./,
  /^disclosure-ledger\./,
  /^hybrid-connector\./,
  /^investigations\./,
  /^mapping-v2-executor\./,
  /^observability-privacy\./,
  /^operation-registry\./,
  /^pipelines\./,
  /^remote-http\./,
  /^remote-server\./,
  /^security-/,
  /^shared-/,
  /^sqlite-component-schema\./
]);

await runVerificationSuite({
  name: "security",
  title: "ABL platform security verification",
  gates: [
    checkGate(
      "security.no-github-actions",
      "Enforce the repository policy prohibiting GitHub Actions workflows",
      assertNoGithubActions
    ),
    commandGate(
      "security.local-adversarial",
      "Run tenant, identity, policy, replay, disclosure, fencing and redaction tests",
      ["pnpm", "exec", "tsx", "--test", ...securityTests]
    ),
    commandGate(
      "security.production-advisories",
      "Query the production dependency advisory registry at high severity",
      ["pnpm", "audit", "--prod", "--audit-level", "high"],
      { optInEnv: "ABL_VERIFY_ADVISORY_AUDIT" }
    ),
    manifestGate(
      "security.live-tenant-canary",
      "Prove zero cross-tenant leakage across API, queue, cache, handle, artifact and telemetry boundaries",
      "ABL_VERIFY_SECURITY_LIVE"
    ),
    manifestGate(
      "security.live-rls-role",
      "Prove live database roles are SELECT-only, non-owner, NOSUPERUSER and NOBYPASSRLS",
      "ABL_VERIFY_SECURITY_LIVE"
    ),
    manifestGate(
      "security.live-egress",
      "Prove connector and control-plane network paths enforce the approved egress policy",
      "ABL_VERIFY_SECURITY_LIVE"
    ),
    manifestGate(
      "security.live-worm-audit",
      "Prove WORM audit delivery, independent administration and fail-closed buffering",
      "ABL_VERIFY_SECURITY_LIVE"
    )
  ]
});
