# Portfolio Risk Platform Upgrade Checkpoint

Status date: 2026-08-13

This is the handoff point for the next implementation session. It records what is safely present in the repository, what has been verified, and which gaps must be closed before any production-readiness claim.

## Start here next session

1. Re-run `git status --short --branch`, `pnpm run check`, and `pnpm run test` before editing.
2. Read this document and `docs/UPGRADE_IMPLEMENTATION.md` together.
3. Use GitNexus impact/context before changing existing workflow, definition-store, operator, or remote-runtime symbols.
4. The sidecar, definition/longitudinal/metric-evidence, publication-reader, metadata-preflight, post-policy-materialization, dedicated v4 durability, and modern capture/certification foundation slices are closed at the local/conformance boundary. An IDs-only lifecycle-backed source-delivery registration service now verifies effective source-contract and dataset-binding versions before catalog persistence, and immutable certification-attempt receipts lock retry timestamps/content addresses. Neither is yet composed into a production connector/runtime. Begin the next production slice by wiring those services and adding lifecycle-backed control, runtime, methodology, dimension, and FX authorities plus cross-store certification publication recovery; do not enable the remote seam.
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
- operator-run integration, security, and release orchestration with explicit opt-in external gates;
- an additive governed-definition v2 component and frozen resolver, including maker/checker/effective-dated `dataset_scope_binding` governance; correction-aware longitudinal certification bundles; governed metric projections; and maker/checker metric-run evidence derived only from signed result-cell authority;
- canonical `NormalizedSnapshotArtifactV2` and `CertifiedSnapshotEvidenceRecordV1` contracts plus immutable, tenant-scoped SQLite `DatasetSnapshotV2` and certification-evidence repositories with schema attestation, idempotency receipts, correction-chain controls, indexed-lineage verification, and reopen/tamper coverage;
- `SourceAccessPolicyV1`; data-lineage-only `CertifiedSnapshotPublicationV1`; an IDs-only trusted publication service and repository-backed tenant/artifact/evidence verifier; an immutable tenant catalog with disable-only events, exact scope indexes, actor-scoped idempotency, schema attestation, and hash-chained audit; metadata-only preflight that derives fields, resolves terminal corrections and current governed source/scope/policy authority, and obtains a runtime-issued aggregate-only permit without reading artifact bytes;
- a post-policy materializer that rechecks publication-disable and lineage state before its first tenant-scoped artifact read, verifies and projects only server-derived fields, and persists an exact encrypted governance-bound plan; standalone v4 preflight/envelope/result/manifest finalizers with deterministic accounting and exact ArtifactStore-byte binding; and an additive pointer-only v4 state component, bounded worker entry, and dedicated durable workflow with exact audit pointers, stranded-submission repair, later-lease result/manifest adoption, cancellation fencing, queue-success/audit reconciliation, and frozen execution provenance.
- IDs-only modern capture and certification services plus strict `extract-sql-v2` and `certify-snapshot-v2` operator commands whose actor and derived identifiers are server-owned; an append-only source-delivery catalog and an uncomposed lifecycle-backed delivery-registration service; atomic facility/dataset/scope/delivery-bound snapshot correction commits; artifact-backed historical runtime replay; active mapping projection; default-disabled trusted-import certification-set selection; and lifecycle-governed, replayable exact-decimal FX-rate definition contracts. These are local foundations, not a composed production authority chain.

These modules compile and have deterministic/conformance coverage. Presence in the repository does not mean every module is composed into the current production runtime.

Production enablement remains intentionally absent. Local services now create the modern capture and certification records under injected authorities, certification uses the exact receipt/delivery/facility-bound selector, immutable attempt receipts prevent timestamp-drift retries, the staging ledger records prepared artifacts/failure recovery/one evidence commit, and the FX store freezes definition-bound rate selection at a knowledge cutoff. The checked-in production runtime does not compose those ports and the available source/control registration paths are trusted-import foundations rather than independently approved lifecycle authority. Required before enablement: governed source/scope, DQ, reconciliation, methodology, dimension, compiler-compatibility, and FX provider/rate authority; capture-material persistence; certification-to-staging composition; historical activation-at-use replay; concrete production adapters; operator runtime composition; and a composite opaque-handle router for the fifth operation. Production `remote-cli` omits the optional portfolio-surveillance workflow and continues to advertise and execute only the four legacy governed operations.

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

The append-only `withdrawn` terminal state and trusted `definition-v2-*` operator/runtime bridge are complete. The bridge accepts no request-supplied actor, keeps maker/checker and effectivity enforcement store-side, verifies effective selections through the durable resolver, and returns metadata rather than documents or transition evidence. It remains intentionally absent from MCP and the remote runtime.

1. Replace trusted source/scope and certification-set imports with durable maker/checker lifecycle adapters. Govern DQ, reconciliation, methodology, content-addressed dimensions, compiler compatibility, and FX-rate persistence/selection; bind every executable reference and approval event into certification evidence.
2. Finish the certification transaction protocol: support activation-at-use historical replay, execute or attest the exact frozen compiler/methodology, bind the certification-set/control/runtime approval lineage into durable evidence, normalize zero-length/exclusive-end registration semantics, and add staged artifact/outbox recovery so a crash cannot strand an untracked timestamp-dependent artifact.
3. Implement and certify concrete read-only PostgreSQL/RLS, XLSX, Parquet, PDF-control, object-storage, and KMS adapters. Compose the v2 operator ports only in the separately authorized ingestion topology after those live gates pass.
4. Compose the publication verifier, metadata-only preflight, post-policy materializer, and dedicated v4 lifecycle in an environment-backed operator/worker deployment. Implement composite opaque-handle routing for start/status/result/cancel, then and only then inject the fifth remote workflow. Add ABL-v2 as a separate certified-input operation.
5. Implement the production `MetricRunAuthorityResolver` over signed surveillance result artifacts/manifests and expose only the IDs-only `MetricRunEvidenceService` creation/approval path. Bind monitoring-v2 observations to exact certified metric-run IDs; never expose the internal metric-run store as an authority.
6. Construct the investigation/report workflow in `remote-cli`, then enable the additive analyst MCP tools with real policy, audit, artifact, and lifecycle dependencies. The tool registry alone is not a production capability.
7. Replace the BFF fixture adapter with a tenant-aware authenticated control API; add durable sessions, tenant-scoped approval records, audit receipts, and browser E2E against that API.
8. Connect pipeline state, correction/backfill handling, monitoring-v2, report generation, the external scheduler/delivery events, and the transactional email/webhook outbox. Keep delivery destinations server-governed.
9. Implement the mutually authenticated outbound client-VPC connector service and compose shared PostgreSQL/object-artifact repositories into multi-replica APIs/workers.

The external-sidecar bridge intentionally does not infer facility-specific entity relationships. Before customer production approval, each source contract must define the applicable receivable/debtor/facility crosswalk and independent tie-out controls; the platform must verify those governed controls rather than inventing a generic loan-to-receivable relationship. Monitoring observations now carry an exact normalized-population reference, but production monitoring still requires durable metric-run derivation evidence for each value.

## External gates that code cannot self-certify

- real OIDC registration, TLS edge, JWKS rotation, and authenticated remote Codex/Claude acceptance;
- live PostgreSQL role/grant/RLS/cursor/cancellation/canary evidence;
- live object storage, KMS, retention lock, legal hold, and restoration;
- client-VPC network/egress proof and zero inbound database path;
- cross-tenant canaries, WORM audit export, backup/restore, migration rehearsal, measured RPO/RTO, capacity/SLO, incident drills, and owner sign-offs;
- commit-bound multi-architecture image rebuild, SBOM, vulnerability/secret/IaC scans, signing, provenance, registry promotion, and deployment overlays.

## Verification commands

Latest evidence captured on 2026-08-13:

- `pnpm run verify`: passed; 533 root tests passed, one opt-in live PostgreSQL test skipped, and all 21 platform tests passed; both strict TypeScript configurations and production builds passed;
- `pnpm run verify:integration`: passed local conformance; 68 tests passed, one live PostgreSQL test skipped, and all 21 platform tests passed; external services were not run;
- `pnpm run verify:security`: passed local adversarial checks; 127 tests passed and one opt-in test skipped; external tenant/RLS/egress/WORM gates were not run;
- `pnpm run audit:prod`: no known production dependency vulnerabilities;
- the focused modern capture/certification, delivery, runtime, FX, repository, and operator checkpoint suite passed 51/51, including compromised source/scope documents, replay after live-delivery disable, receipt/delivery/facility substitution, half-open effectivity, correction races, replay/tamper reopen, and 256-significant-digit FX boundaries;
- the focused v4 state/workflow checkpoint suite passed 20/20. Its injected crash windows cover durable submission-before-audit repair, result-only and manifest-persisted later-lease adoption without recomputation, original signed-plan/code-version provenance, cancellation after completion preparation, queue-success audit/state repair before disclosure, and authorization-before-artifact-read ordering;
- the current GitNexus index contains 7,864 nodes, 22,352 relationships, and 242 modeled execution flows. Staged impact detection classified this 30-file, 687-symbol checkpoint `critical` across 238 conservatively affected processes, driven by the shared SQLite repository and operator control-plane seams plus broad shared-helper propagation. The production remote path remains disabled, and the full, focused, integration, security, migration, schema-adversarial, and independent review gates above cover the real local blast radius;
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
