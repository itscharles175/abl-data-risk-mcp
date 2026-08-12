# Portfolio Risk Platform Upgrade Checkpoint

Status date: 2026-08-12

This is the handoff point for the next implementation session. It records what is safely present in the repository, what has been verified, and which gaps must be closed before any production-readiness claim. The current upgrade goal remains active.

## Start here next session

1. Re-run `git status --short --branch`, `pnpm run check`, and `pnpm run test` before editing.
2. Read this document and `docs/UPGRADE_IMPLEMENTATION.md` together.
3. Use GitNexus impact/context before changing existing workflow, definition-store, operator, or remote-runtime symbols.
4. Close the certified-sidecar integrity blocker first.
5. Wire one vertical production slice at a time, with focused tests and a full verification run after each slice.
6. Keep `.github/workflows` absent. All checks remain operator-run.

## Checkpoint contents

The repository contains additive, strict TypeScript implementations and tests for:

- `SourceContractV1`, `DatasetSnapshotV2`, dictionary-v2, `MappingSpecV2`, `MappingApplicationV1`, historical bundles, certified-population lineage, and repository ports;
- mapping transform execution, data-quality-v2 findings, operation metadata, and deterministic local/governed snapshot-analysis parity;
- a React review/admin console, shared browser contracts, and an Express OIDC BFF with secure server-side sessions, CSRF/origin checks, step-up state, role checks, maker/checker approvals, and opaque secret references;
- portfolio-surveillance definitions and deterministic metric families, approved entity resolution, cell lineage/suppression, multi-component ABL-v2, counterfactuals, cash reconciliation, and signed aggregate report packs;
- governed investigation persistence, masking, bounded cursors, disclosure evidence, adaptive-query controls, and an additive MCP analyst-tool registry;
- pipeline state, monitoring-v2, governed notification contracts, hybrid connector plans, XLSX/Parquet/object-storage preflight adapters, PostgreSQL certification harnesses, shared PostgreSQL coordination primitives, immutable encrypted object artifacts, and privacy-safe telemetry;
- operator-run integration, security, and release orchestration with explicit opt-in external gates.

These modules compile and have deterministic/conformance coverage. Presence in the repository does not mean every module is composed into the current production runtime.

## First blocker: certified sidecar enforcement

Severity: high integrity / release blocker.

`GovernedWorkflow` currently accepts `borrowing_base_input` and `monitoring_input` artifacts after checking tenant, kind, snapshot ID, and as-of date. It does not call the new `assertCertifiedAnalysisInputs` gate or otherwise prove that each sidecar population has a published DQ result, passing reconciliation, matching population hash, and certification evidence. Existing workflow fixtures demonstrate that arbitrary sidecars execute successfully and can emit alerts.

Required next change:

- define an additive input-artifact envelope containing payload plus `AnalysisInputLineageV1`;
- verify its canonical lineage hash and call `assertCertifiedAnalysisInputs` at submission and worker reload;
- bind tenant, canonical snapshot hash/content hash, mapping application/hash, sidecar population hash, row count, purpose, as-of date, and governed definition hashes;
- persist those references in the signed execution envelope and result manifest;
- keep old artifacts readable for historical inspection, but reject them for new borrowing-base or monitoring execution;
- update the operator artifact command so it can create only a fully certified envelope, or provide a separate maker/checker certification operation;
- add negative tests for missing, blocked, cross-tenant, cross-snapshot, stale, tampered, and reconciliation-mismatched lineage.

Do not weaken the contract by accepting a caller boolean such as `certified: true`.

## Production-composition backlog

After the sidecar gate, close these vertical slices in order:

1. Extend the durable governed-definition store and operator schemas additively for source contracts, mapping specs/applications, metrics, cohorts, bins, reconciliations, entity resolution, reports, scenarios, and covenants. Use a new component migration and preserve v1 rows.
2. Compose the surveillance engine and ABL-v2 engine into signed governed jobs, with operation-registry metadata and complete result-envelope accounting.
3. Construct the investigation/report workflow in `remote-cli`, then enable the additive analyst MCP tools with real policy, audit, artifact, and lifecycle dependencies. The tool registry alone is not a production capability.
4. Replace the BFF fixture adapter with a tenant-aware authenticated control API; add durable sessions, tenant-scoped approval records, audit receipts, and browser E2E against that API.
5. Connect pipeline state, correction/backfill handling, monitoring-v2, report generation, and the transactional notification outbox. Keep delivery destinations server-governed.
6. Add production XLSX/Parquet decoders behind the hardened ports and certify real PostgreSQL/object-storage adapters with operator-provided environments.
7. Implement the mutually authenticated outbound client-VPC connector service and compose shared PostgreSQL/object-artifact repositories into multi-replica APIs/workers.

## External gates that code cannot self-certify

- real OIDC registration, TLS edge, JWKS rotation, and authenticated remote Codex/Claude acceptance;
- live PostgreSQL role/grant/RLS/cursor/cancellation/canary evidence;
- live object storage, KMS, retention lock, legal hold, and restoration;
- client-VPC network/egress proof and zero inbound database path;
- cross-tenant canaries, WORM audit export, backup/restore, migration rehearsal, measured RPO/RTO, capacity/SLO, incident drills, and owner sign-offs;
- commit-bound multi-architecture image rebuild, SBOM, vulnerability/secret/IaC scans, signing, provenance, registry promotion, and deployment overlays.

## Verification commands

Checkpoint evidence captured on 2026-08-12:

- `pnpm run verify`: passed; 305 root tests passed, one opt-in live PostgreSQL test skipped, and all 21 platform tests passed; both strict TypeScript configurations and production builds passed;
- `pnpm run verify:integration`: passed local conformance; 68 tests passed, one live PostgreSQL test skipped, and all 21 platform tests passed; external services were not run;
- `pnpm run verify:security`: passed local adversarial checks; 123 tests passed and one opt-in test skipped; external tenant/RLS/egress/WORM gates were not run;
- `pnpm run audit:prod`: no known production dependency vulnerabilities;
- GitNexus: index current, zero dependency cycles, staged change classified `critical` because this is a 118-file greenfield platform expansion affecting 108 modeled flows. That blast radius received independent domain, runtime, and adversarial review; the unresolved sidecar finding is recorded above rather than waived;
- console fixture browser QA covered sign-in, role-filtered navigation, source profiling, responsive layout, and a clean browser console;
- `.github/workflows` contains no tracked workflow files.

These results establish a reproducible source checkpoint. They are not live-environment, release-artifact, or production-promotion evidence.

Fast deterministic gate:

```sh
pnpm run verify
```

Local integration and security orchestration:

```sh
pnpm run verify:integration
pnpm run verify:security
```

Release orchestration intentionally requires a clean named-branch commit and fails closed otherwise:

```sh
pnpm run release:verify
```

Optional live gates require an absolute operator-controlled manifest as documented in `docs/OPERATOR_VERIFICATION.md`. A result of `local_pass_external_not_run` is local evidence only.

## Non-negotiable boundaries

- No arbitrary SQL or source-system writes.
- No model-activated mappings, policies, monitors, destinations, or credit decisions.
- No raw bulk export.
- Detail access remains separately scoped, capped, masked, purpose-bound, principal-bound, tenant-bound, expiring, and audited.
- Secrets stay in client secret managers and appear only as opaque references.
- Existing MCP and artifact contracts evolve additively with explicit compatibility windows.
- GitHub Actions stays disabled; do not add workflow files.
