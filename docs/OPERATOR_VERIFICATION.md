# Operator-Run Verification

This repository does not use GitHub Actions. GitHub Actions is disabled, workflow files are prohibited by the security and release scripts, and all evidence is produced from a trusted local or separately approved build environment.

The verification entrypoints are:

```sh
node scripts/verify-integration.mjs
node scripts/verify-security.mjs
node scripts/verify-release.mjs
```

Run `--list` to inspect a suite without executing it:

```sh
node scripts/verify-integration.mjs --list
node scripts/verify-security.mjs --list
node scripts/verify-release.mjs --list
```

`--list` is an orchestration check, not verification evidence.

## Outcome semantics

Each suite fails immediately when a required local gate fails. An opted-in external gate also fails closed if its manifest entry is missing, malformed, times out, or exits nonzero.

External and live gates are deliberately skipped until their opt-in variable is true. A successful default run therefore reports:

```text
outcome: local_pass_external_not_run
scope: local/conformance evidence only; this is not live-environment or promotion evidence
```

Only `outcome: passed` means every gate declared by that invocation ran. It still proves only the commands in the evidence record; release approval remains governed by `docs/RELEASE_CHECKLIST.md`.

Optional JSON evidence can be written outside the repository:

```sh
export ABL_VERIFY_EVIDENCE_DIR=/approved/release-evidence/abl-mcp
node scripts/verify-security.mjs
```

The destination must be absolute. Evidence files are created with mode `0600` and contain gate names, status, duration, commit, and timestamps—not environment values, credentials, or command arguments.

## Local suites

### Integration

The default integration run performs:

- root runtime/test type checking;
- MCP STDIO/HTTP, analyst-tool, connector, PostgreSQL-port, SQL extraction, adapter, immutable-object, and shared-persistence conformance tests;
- console, BFF, and shared platform-contract fixture tests.

These tests use fixtures or injected fakes for PostgreSQL, S3-compatible storage, KMS, OIDC, and connector edges. They do not certify a live service.

### Security

The default security run performs:

- the no-GitHub-Actions repository policy check;
- tenant, identity, OAuth, policy, replay, signed-plan, investigation, disclosure, fenced-lease, artifact-integrity, component-schema, connector, HTTP, and telemetry-redaction tests.

The production advisory query is external to the repository and is enabled separately:

```sh
ABL_VERIFY_ADVISORY_AUDIT=1 node scripts/verify-security.mjs
```

Network or registry failure fails this opted-in gate; it is never silently downgraded.

### Release

The default release run requires a clean working tree on a named branch, rejects GitHub Actions workflows, checks GitNexus freshness, performs a frozen pnpm install, and runs `pnpm run verify`. Run it only after committing the intended release changes.

GitNexus freshness uses the checkout-local runner when one exists and otherwise requires the installed `gitnexus` CLI on `PATH`. A fresh clone must run `gitnexus analyze` before release verification; a missing or stale index fails the gate without a silent downgrade.

The default run does not build, publish, sign, scan, deploy, migrate, or restore production infrastructure. Those gates require approved tools, registries, identities, clusters, and evidence destinations and are opt-in as described below.

## External command manifest

External gates execute trusted operator-owned commands without invoking a shell. Enable a family of gates and point the scripts to one absolute JSON manifest:

```sh
export ABL_VERIFY_EXTERNAL_MANIFEST=/approved/abl/verification-commands.json
export ABL_VERIFY_INTEGRATION_LIVE=1
node scripts/verify-integration.mjs
```

Manifest schema:

```json
{
  "schemaVersion": 1,
  "gates": {
    "integration.live-postgresql": {
      "argv": ["/opt/abl-verifiers/postgres-certify", "--environment", "staging"],
      "cwd": "/opt/abl-verifiers",
      "timeoutSeconds": 1800
    }
  }
}
```

Rules:

- the manifest must be an absolute, regular, non-symlink file no larger than 128 KiB;
- `argv[0]` must be an absolute executable path;
- no shell string, environment override, interpolation, or redirect is supported;
- secrets must come from the approved workload identity or secret manager, never from the manifest or command arguments;
- command output becomes operator-visible evidence and must not print tokens, connection strings, raw portfolio records, or direct identifiers;
- enabling a gate family makes every gate in that family mandatory.

## Opt-in gate families

`ABL_VERIFY_INTEGRATION_LIVE=1` requires all of:

- `integration.live-postgresql`;
- `integration.live-object-storage`;
- `integration.live-oidc`;
- `integration.live-connector`;
- `integration.live-browser-e2e`;
- `integration.live-codex-claude`.

`ABL_VERIFY_SECURITY_LIVE=1` requires all of:

- `security.live-tenant-canary`;
- `security.live-rls-role`;
- `security.live-egress`;
- `security.live-worm-audit`.

`ABL_VERIFY_RELEASE_ARTIFACTS=1` requires all of:

- `release.compose-render`;
- `release.kubernetes-schema`;
- `release.iac-scan`;
- `release.container-build-smoke`;
- `release.sbom`;
- `release.image-vulnerability`;
- `release.secret-scan`.

`ABL_VERIFY_RELEASE_LIVE=1` requires all of:

- `release.multiarch`;
- `release.signature-provenance`;
- `release.migration-rehearsal`;
- `release.restore-rehearsal`;
- `release.client-smokes`;
- `release.tenant-canary`.

The production dependency advisory gate is controlled independently with `ABL_VERIFY_ADVISORY_AUDIT=1`.

## Recommended evidence sequence

1. On the working branch, run integration and security verification and resolve every local failure.
2. Run the relevant live integration/security families in an approved synthetic or canary environment.
3. Review GitNexus impact and security evidence, commit the exact scope, and ensure the tree is clean.
4. Run release verification with advisory and release-artifact gates enabled.
5. Run live migration, restore, client, and tenant-canary gates against production-equivalent staging.
6. Bind the evidence directory to the reviewed commit and immutable image digest, complete `docs/RELEASE_CHECKLIST.md`, and obtain the required human approvals.

None of these scripts pushes an image, changes a cluster, signs an artifact, or deploys by itself. External commands perform only the actions separately authorized for their environment.
