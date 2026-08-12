# Portfolio Risk Platform Upgrade — Implementation Status

Status date: 2026-08-12

This document distinguishes code and deterministic conformance coverage from live-environment certification. “Implemented” means a bounded source contract or engine exists in this repository and is covered by local tests. It does not mean a client database, identity provider, object store, registry, Kubernetes cluster, or disaster-recovery process has been certified or deployed.

## Status vocabulary

| Status | Meaning |
|---|---|
| Implemented | Runtime/domain code and deterministic tests exist. |
| Fixture/conformance | The boundary is exercised through injected fakes or representative fixtures, not a live managed service. |
| Partially integrated | The component exists but is not wired through every production surface or persistent backend. |
| External gate | Requires environment authority, infrastructure, credentials, client data, or human approval not held by this repository. |

## Release-by-release status

### Release 0 — correctness and extensibility foundation

Implemented or conformance-backed:

- additive `SourceContractV1`, `DatasetSnapshotV2`, `MappingSpecV2`, `MappingApplicationV1`, certified-lineage, canonical hashing, dictionary-v2, and immutable bundle contracts;
- reusable mapping specifications separated from snapshot-specific applications;
- historical bundle/replay contracts and certified-population references;
- an independent immutable governed-definition v2 component with strict semantic versions, semantic diffs and impact previews, maker/checker lifecycle evidence, activated-only historical frozen resolution, fail-closed rollback-target retirement, an append-only non-executable `withdrawn` state for abandoned pending versions, and additive kinds for source/mapping/methodology/borrowing-base/metric/projection/cohort/bin/reconciliation/entity/report/scenario/covenant governance;
- trusted metadata-only `definition-v2-*` operator commands and runtime construction for proposal, transition, get, list, resolver-verified effective selection, and audit; request documents cannot supply actors, and no definition document or transition evidence is returned;
- correction-aware longitudinal certification bundles that bind one dataset, source contract, governed scope, delivery identity, full replacement chain, dictionary, mapping runtime/compiler, normalized population, and frozen methodology;
- a pure `portfolio_surveillance_v1` operation module with an IDs-only request, correction-aware source expansion, frozen v2 definition resolution, least-privilege record projection, declared-family compatibility checks, certified field/dimension authorization, aggregate-only result validation, exact byte/cell/population accounting, and explicit v4 job-envelope handoff metadata; the module is not yet registered in the durable worker or MCP runtime;
- surveillance-engine privacy hardening with tenant-scoped entity tokens, denominator-based zero-event and complementary suppression, distinct numerator/denominator population hashes, observed-only HHI populations, certification chronology checks, and a cumulative execution cell budget;
- governed metric projections and durable maker/checker metric-run evidence whose public creation request contains identifiers only; every value, unit, scope, numerator, denominator, coverage figure, source, and population hash is resolved from a frozen signed result cell, with ratio operands, certified-population coverage, tenant identity, and chronology verified independently;
- repository ports plus in-memory conformance implementations for control, definitions, memberships, jobs, alerts, security, artifacts, and audit;
- bounded mapping-v2 executor and operation-registry contracts;
- local stratification-v2 and vintage-v2 previews materialize bounded allowlisted rows and invoke the same deterministic snapshot engines used by governed jobs, with identical golden hashes;
- maker/checker-certified borrowing-base and monitoring input populations, strict canonical envelopes, authoritative submission/worker/recovery revalidation, mandatory normalized-population evidence for monitoring, and v3 result lineage; completed historical reads rely on their frozen encrypted result and immutable manifest, while raw legacy sidecars remain readable but cannot execute;
- v1 sources remain present; the upgrade is additive rather than an in-place historical rewrite.

Not yet production-certified:

- richer source-contract-specific entity/control crosswalks between independently certified external sidecars and canonical snapshots; the current bridge binds snapshot, mapping, governed definitions, exact controls, population hashes, purpose, DQ, reconciliation, and normalized-population evidence but does not infer facility-specific receivable-to-loan relationships or yet persist a derived metric-run for every monitoring value;
- migration of an existing customer control plane into the v2 contracts;
- migration and restore rehearsal for existing customer control planes using the additive v2 definition component and trusted operator commands;
- durable persistence and runtime composition of longitudinal bundles (the strict builder/verifier exists, but no production repository or job envelope currently owns it);
- registration of the pure portfolio-surveillance operation in the signed durable workflow/worker and remote MCP surface with backward-compatible v4 envelope/result recovery;
- production implementation of the metric-result-cell authority over signed surveillance artifacts and binding of monitoring-v2 to certified metric-run IDs;
- an independent production replay of customer certifications after dictionary/mapping upgrades.

### Release 1 — administration and onboarding console

Implemented or fixture-backed:

- pnpm workspace with React/TypeScript console, Express BFF, and shared contracts package;
- six governed roles, permission-filtered navigation, secure-session/CSRF/origin controls, OIDC Authorization Code/PKCE primitives, step-up state, maker/checker enforcement, opaque secret references, source-contract onboarding forms, and fixture review journeys;
- mapping-v2 transforms, source/data-quality v2 contracts, materiality fields, semantic hashes, and deterministic validation tests.

Boundary:

- the BFF data adapter and console workbench currently use clearly labeled fixture data; they are not connected to a live control API or portfolio database;
- production OIDC discovery/token exchange code exists, but a real issuer, client registration, TLS gateway, secure session store, and browser E2E remain external gates;
- full persistent administration, approval queues, rollback execution, connector/key rotation, and deployment configuration are not yet end-to-end production integrations.

### Release 2 — portfolio surveillance flagship

Implemented or conformance-backed:

- governed metric, cohort, bin, reconciliation, entity-resolution, and report definition contracts;
- exact-decimal deterministic surveillance for roll/cure, default/ever-delinquent incidence, gross/net loss and recovery lag, paydown/prepayment, rating migration, balance/utilization trajectories, maturity walls, concentrations, and period comparisons;
- approved entity-resolution evidence, explicit unavailable reasons, coverage/numerator/denominator fields, cell-level population hashes, lineage, and deterministic ordering;
- signed aggregate report-pack contracts with tables, charts, warnings, suppression, comparisons, explanations, and manifest references.

Boundary:

- the engines are library surfaces with golden fixtures; they are not yet backed by a production longitudinal portfolio or independently signed workbook evidence;
- not every requested business segmentation or chart is exposed through the console/MCP;
- correction/restatement bridges and cross-facility resolution require approved live definitions and customer evidence.

### Release 3 — governed drill-through and analyst workflow

Implemented or conformance-backed:

- tenant/principal/purpose-bound `InvestigationV1` persistence, certified population revalidation, bounded filter AST, 100-row pages, 1,000-row investigation budget, 20-column limit, 15-minute handles, deterministic masking, signed cursors, close/expiry behavior, and immutable disclosure evidence;
- disclosure-ledger and adaptive/differencing controls with privacy-safe evidence;
- analyst MCP registration module for metric/job/event/result explanation, investigation, and report tools;
- report packs and investigation services have adversarial local tests.

Boundary:

- the remote server can accept an additive analyst-workflow implementation and the nine requested tools have a typed registration module, but the production remote runtime does not yet construct that workflow or its report catalog;
- console investigation/review assignment, notes, bookmarks, decision signing, immutable distribution, and durable job progress are not all end-to-end production journeys;
- reveal policies and step-up are conformance behavior, not authorization evidence from a deployed IdP.

### Release 4 — automation, ABL depth, and adapters

Implemented or conformance-backed:

- durable pipeline state for detect → extract → profile → map → DQ → reconcile → certify → analyze → monitor → report, ordered trust gates, corrections/backfills, retries, cancellation state, stage evidence, and transactional outbox references;
- schedule/delivery coordinator, governed notification directory/template contracts, minimized payload controls, SLA detection, and monitoring-v2 rules for absolute/change/rolling/consecutive/compound/stale/missing data, hysteresis, cooldown, and reset;
- ABL-v2 exact-decimal engine for borrower-submitted, reperformed, and approved-adjusted states; multi-component AR/inventory/equipment/cash bases; concentration tiers; formula reserves; sublimits; overrides/waivers; availability blocks; dominion triggers; covenants/ticklers; counterfactuals; and cash/lockbox/paydown reconciliation;
- XLSX, Parquet, and immutable object-delivery adapter contracts, strict safety validation, exact scalar normalization, and deterministic conformance kit.

Boundary:

- schedules need an external scheduler and real delivery detector; notification dispatch needs approved destinations/transports;
- adapter tests use injected decoders/object-store fakes. They do not certify a particular production XLSX/Parquet library, S3 endpoint, Snowflake, SQL Server, BigQuery, or Databricks;
- ABL policy/rule content still requires lender legal/domain approval and customer golden BBCs.

### Release 5 — hybrid scale and production operations

Implemented or conformance-backed:

- signed, bounded, replay-protected extraction/investigation connector plans and an outbound connector agent boundary;
- additive PostgreSQL schema and injected-pool repositories for monotonic fenced leases, weighted fair tenant scheduling, transactional outbox, replay reservations, and maker/checker artifact deletion state;
- S3-compatible immutable, version-bound artifact repository with AES-256-GCM data encryption, KMS envelope-key port, tenant-bound object keys, integrity verification, retention, legal hold, and governed deletion workflow;
- OpenTelemetry-neutral privacy-safe events, metrics, and spans with HMAC identity hashing, strict attribute allowlists, bounded buffers, and metric-cardinality limits;
- operator-run integration, security, and release orchestration described in `docs/OPERATOR_VERIFICATION.md`.

Boundary:

- PostgreSQL, S3-compatible storage, and KMS tests are conformance fakes; no live service certification is claimed;
- the connector protocol is not a deployed mutually authenticated client-VPC service and no inbound/egress network proof exists yet;
- MCP/control/analytics/connector/notification processes are not yet independently deployed against the shared repositories;
- production quotas, multi-replica partition/crash tests, target-volume SLOs, WORM export, application-consistent backup/restore, measured RPO/RTO, migration rehearsal, legal-hold operations, and deletion evidence are external gates;
- amd64/arm64 image reproduction, registry promotion, signing, SBOM/provenance binding, and live canaries require an approved build and deployment environment.

## Verification surfaces

| Surface | Current evidence | What remains external |
|---|---|---|
| Fast deterministic | `pnpm run verify`, root tests, platform fixture tests | Production data golden packs and customer acceptance |
| Integration | `node scripts/verify-integration.mjs` | Live PostgreSQL/S3/KMS/OIDC/connector/browser/Codex/Claude gates |
| Security | `node scripts/verify-security.mjs` | Live tenant/RLS/egress/WORM canaries and approved security scanners |
| Release | `node scripts/verify-release.mjs` on a clean commit | OCI/scanner evidence, signatures/provenance, migration/restore and deployment canaries |

The scripts intentionally report `local_pass_external_not_run` when optional external gates are skipped. That outcome must never be represented as production certification or deployment approval.

The exact next-session order, including the closed certified-sidecar slice and remaining production-composition backlog, is maintained in `docs/UPGRADE_CHECKPOINT.md`.

## Preserved boundaries

- No arbitrary SQL surface and no source-system writes.
- No model-activated rules, destinations, credentials, mappings, or autonomous credit decisions.
- No raw bulk export; drill-through remains separately scoped, capped, masked, purpose-bound, and audited.
- Secrets remain opaque references managed outside the browser and repository.
- Existing MCP contracts remain additive; historical v1 code and artifacts are not silently rewritten.
- GitHub Actions remains disabled and no workflow files are introduced.

## Production-readiness decision

The repository now contains a broad, testable platform foundation and operator verification framework. It is not production-certified or deployed. Production approval requires the live and release-artifact gate families, customer-specific data/methodology evidence, environment threat review, migration and restore rehearsals, measured capacity/RPO/RTO, and the human sign-offs in `docs/RELEASE_CHECKLIST.md`.
