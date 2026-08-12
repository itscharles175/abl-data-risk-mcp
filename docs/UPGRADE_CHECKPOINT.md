# Portfolio Risk Platform Upgrade Checkpoint

Status date: 2026-08-12

This is the handoff point for the next implementation session. It records what is safely present in the repository, what has been verified, and which gaps must be closed before any production-readiness claim. The current upgrade goal remains active.

## Start here next session

1. Re-run `git status --short --branch`, `pnpm run check`, and `pnpm run test` before editing.
2. Read this document and `docs/UPGRADE_IMPLEMENTATION.md` together.
3. Use GitNexus impact/context before changing existing workflow, definition-store, operator, or remote-runtime symbols.
4. The certified-sidecar integrity blocker is closed; begin with production-composition backlog item 1.
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

## Completed slice: certified sidecar enforcement

Status: closed in source and local verification on 2026-08-12.

`GovernedWorkflow` now accepts only additive `certified_borrowing_base_input` and `certified_monitoring_input` artifacts for new execution. Raw v1 artifacts remain encrypted and readable for historical/operator inspection but cannot enqueue or reach either engine.

Implemented controls:

- strict canonical `CertifiedOperationInputV1` envelopes contain the legacy payload plus `AnalysisInputLineageV1`, payload and envelope hashes;
- `InputCertificationStore` durably locks proposal evidence and enforces immutable records, exact idempotency, tenant scope, schema attestation, and different maker/checker identities;
- `InputCertificationService` builds the primary v1 compatibility bridge server-side, derives sidecar DQ and exact reconciliation evidence, assembles the lineage/envelope, and revalidates authoritative state at submission and worker reload;
- v3 execution/result envelopes bind the artifact, lineage, derivation, primary and sidecar population/certification hashes; submission, worker reload, and crash recovery revalidate authoritative input evidence, while completed historical reads use the frozen encrypted result plus immutable manifest so later definition activation cannot invalidate prior results;
- monitoring certification requires one unique observation for every governed metric, an exact reference to the primary normalized population, and only allowlisted supplementary mapping, reconciliation, artifact, or policy references; monitoring alerts name the sidecar reconciliation and certification time;
- operator commands `input-certification-propose` and `input-certification-certify` derive actor identity from the trusted process boundary and never accept actor fields;
- certification and proposal retries use durable actor-scoped idempotency receipts, even after a governed definition is retired;
- legacy, purpose-mismatched, tampered, self-hashed fake, deleted-evidence, missing/duplicate metric, and direct-worker bypass cases fail closed; a failed monitoring reload emits no alert;
- queued v2 stratification/vintage envelopes continue to produce v2 results and remain retrievable and crash-recoverable after the upgrade.

There is no caller boolean such as `certified: true`; canonical self-hashes alone are not authority.

## Production-composition backlog

Continue with these vertical slices in order:

1. Extend the durable governed-definition store and operator schemas additively for source contracts, mapping specs/applications, metrics, cohorts, bins, reconciliations, entity resolution, reports, scenarios, and covenants. Use a new component migration and preserve v1 rows.
2. Compose the surveillance engine and ABL-v2 engine into signed governed jobs, with operation-registry metadata and complete result-envelope accounting. Add durable metric-run records so monitoring values are derived from governed metric populations rather than merely population-anchored external observations.
3. Construct the investigation/report workflow in `remote-cli`, then enable the additive analyst MCP tools with real policy, audit, artifact, and lifecycle dependencies. The tool registry alone is not a production capability.
4. Replace the BFF fixture adapter with a tenant-aware authenticated control API; add durable sessions, tenant-scoped approval records, audit receipts, and browser E2E against that API.
5. Connect pipeline state, correction/backfill handling, monitoring-v2, report generation, and the transactional notification outbox. Keep delivery destinations server-governed.
6. Add production XLSX/Parquet decoders behind the hardened ports and certify real PostgreSQL/object-storage adapters with operator-provided environments.
7. Implement the mutually authenticated outbound client-VPC connector service and compose shared PostgreSQL/object-artifact repositories into multi-replica APIs/workers.

The external-sidecar bridge intentionally does not infer facility-specific entity relationships. Before customer production approval, each source contract must define the applicable receivable/debtor/facility crosswalk and independent tie-out controls; the platform must verify those governed controls rather than inventing a generic loan-to-receivable relationship. Monitoring observations now carry an exact normalized-population reference, but production monitoring still requires durable metric-run derivation evidence for each value.

## External gates that code cannot self-certify

- real OIDC registration, TLS edge, JWKS rotation, and authenticated remote Codex/Claude acceptance;
- live PostgreSQL role/grant/RLS/cursor/cancellation/canary evidence;
- live object storage, KMS, retention lock, legal hold, and restoration;
- client-VPC network/egress proof and zero inbound database path;
- cross-tenant canaries, WORM audit export, backup/restore, migration rehearsal, measured RPO/RTO, capacity/SLO, incident drills, and owner sign-offs;
- commit-bound multi-architecture image rebuild, SBOM, vulnerability/secret/IaC scans, signing, provenance, registry promotion, and deployment overlays.

## Verification commands

Latest evidence captured on 2026-08-12:

- `pnpm run verify`: passed; 335 root tests passed, one opt-in live PostgreSQL test skipped, and all 21 platform tests passed; both strict TypeScript configurations and production builds passed;
- `pnpm run verify:integration`: passed local conformance; 68 tests passed, one live PostgreSQL test skipped, and all 21 platform tests passed; external services were not run;
- `pnpm run verify:security`: passed local adversarial checks; 123 tests passed and one opt-in test skipped; external tenant/RLS/egress/WORM gates were not run;
- `pnpm run audit:prod`: no known production dependency vulnerabilities;
- GitNexus pre-edit impact was LOW for the input loaders, operation fingerprint, worker entry, operator methods, runtime composition, result retrieval, and recovery. The rebuilt PDG contains 28,423 nodes, 66,966 edges, and no import cycles; staged change detection classified this 21-file/278-symbol slice `critical` across 26 modeled flows because governed start/process/recovery paths are deliberately affected. The focused 38-test workflow/recovery suite and an independent read-only adversarial audit found no remaining blocker;
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
