#!/usr/bin/env node
import {
  assertCleanReleaseTree,
  assertNoGithubActions,
  checkGate,
  commandGate,
  manifestGate,
  runVerificationSuite
} from "./verify-common.mjs";

const artifactGate = (id, description) => manifestGate(id, description, "ABL_VERIFY_RELEASE_ARTIFACTS");
const liveGate = (id, description) => manifestGate(id, description, "ABL_VERIFY_RELEASE_LIVE");

await runVerificationSuite({
  name: "release",
  title: "ABL platform release verification",
  gates: [
    checkGate(
      "release.clean-commit",
      "Require a clean named branch bound to an immutable commit",
      assertCleanReleaseTree
    ),
    checkGate(
      "release.no-github-actions",
      "Enforce the repository policy prohibiting GitHub Actions workflows",
      assertNoGithubActions
    ),
    commandGate(
      "release.gitnexus-current",
      "Require a current GitNexus index for the release commit",
      ["node", ".gitnexus/run.cjs", "status"]
    ),
    commandGate(
      "release.locked-install",
      "Resolve the exact workspace from the frozen pnpm lockfile",
      ["pnpm", "install", "--frozen-lockfile"],
      { timeoutSeconds: 1_800 }
    ),
    commandGate(
      "release.deterministic-verify",
      "Run type checks, unit/conformance tests, platform tests and builds",
      ["pnpm", "run", "verify"],
      { timeoutSeconds: 3_600 }
    ),
    commandGate(
      "release.production-advisories",
      "Query the production dependency advisory registry at high severity",
      ["pnpm", "audit", "--prod", "--audit-level", "high"],
      { optInEnv: "ABL_VERIFY_ADVISORY_AUDIT" }
    ),
    artifactGate("release.compose-render", "Render the operator Compose profile with reviewed inputs"),
    artifactGate("release.kubernetes-schema", "Render Kubernetes overlays and apply strict schema validation"),
    artifactGate("release.iac-scan", "Scan deployment configuration with the approved IaC policy"),
    artifactGate("release.container-build-smoke", "Build the commit-bound OCI image and run hardened non-root/read-only smokes"),
    artifactGate("release.sbom", "Generate a commit- and digest-bound CycloneDX or SPDX SBOM"),
    artifactGate("release.image-vulnerability", "Scan the exact OCI digest and reject unapproved HIGH/CRITICAL findings"),
    artifactGate("release.secret-scan", "Scan repository history and the built image for secrets"),
    liveGate("release.multiarch", "Reproduce amd64 and arm64 images from the same reviewed commit"),
    liveGate("release.signature-provenance", "Verify registry digest, signature, SBOM and provenance binding"),
    liveGate("release.migration-rehearsal", "Rehearse forward migration and rollback on production-equivalent state"),
    liveGate("release.restore-rehearsal", "Restore application-consistent state and measure approved RPO/RTO"),
    liveGate("release.client-smokes", "Run authenticated Codex and Claude smokes through the real gateway"),
    liveGate("release.tenant-canary", "Run production-equivalent tenant-isolation canaries and audit-receipt checks")
  ]
});
