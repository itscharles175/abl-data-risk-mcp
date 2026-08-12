# Product and Delivery Roadmap

## Outcome

Deliver a governed semantic and analytical control plane for loan and ABL data through MCP-capable clients.

The system is not a general natural-language SQL agent. Models may interpret intent, propose mappings, explain variances, and draft narratives. Deterministic code owns identity, authorization, source access, mapping validation, certification, reconciliation, borrowing-base calculations, monitoring, suppression, lineage, and audit.

This roadmap separates implemented software from the external evidence required for a real production claim. A feature existing in code does not prove that a database role, IdP, cloud environment, or client product has been certified.

## Current implementation baseline

The greenfield platform foundation is implemented and covered by the repository verification suite.

| Capability | Code status | Remaining external evidence |
|---|---|---|
| Remote MCP resource server | Implemented: OAuth/JWT/JWKS, membership, policy, Host/Origin, rate/concurrency bounds, protected-resource metadata, readiness | Real IdP, TLS gateway, cross-tenant staging, and authenticated remote-client smokes |
| Local MCP | Implemented: STDIO and loopback HTTP, legacy/current protocol-era tests, nine direct-source tools; real Codex CLI tool use and Claude Code connection health | Claude Desktop plus per-release host UX acceptance |
| Immutable data plane | Implemented: encrypted write-once artifacts, immutable snapshots, DQ, reconciliation, certification and analysis manifests | Production keys, retention, backup/restore, WORM audit export |
| Governance | Implemented: maker/checker mappings, definitions, memberships; effective dates and supersession | Institution-owned roles, approval policy, operating procedures |
| Ingestion | Implemented: bounded CSV/JSON/NDJSON, SQLite extraction, PostgreSQL injected-pool extraction | Real source contracts and live PostgreSQL certification |
| Loan analytics | Implemented: exact snapshot stratification and longitudinal vintage | Real longitudinal portfolio and independent reproduction |
| AR borrowing base | Implemented: eligibility, cross-aging, concentration, advance rate, sublimit, reserves, commitment, usage and availability | Credit-agreement rule pack and parallel BBC reconciliation |
| Monitoring | Implemented: typed thresholds, certification gate, durable deduplicated cases and transitions | External schedule, owners/SLAs, approved notification delivery |
| Durable execution | Implemented: signed replay-protected plans, principal-bound handles, durable queue/leases/reaping/results/audit | Load/failure testing in target infrastructure; shared-store design for scale |
| Deployment | Implemented: Dockerfile, Compose, Kubernetes base, CI/security checks, operations/release docs; current working-tree image passed local runtime, SBOM, vulnerability, secret, IaC, and schema gates | Immutable post-commit target-architecture build, registry/signing/provenance, live cloud deployment and restore |

There remains no arbitrary SQL, raw-row MCP tool, source-system write, calendar scheduler, notification dispatcher, or autonomous credit decision.

## Product wedge

The commercial sequence remains:

1. certify one longitudinal loan portfolio and repeatedly produce defensible stratification/vintage outputs;
2. reperform one receivables-led ABL facility, explaining every exclusion and availability change;
3. operate those workflows through recurring external orchestration and reviewable alerts;
4. expand into detailed inventory and cross-facility risk only after the underlying data contracts are reliable.

The working user is a lender collateral analyst with a portfolio/credit reviewer. A borrower/controller or asset-buyer deployment changes source authority, entitlements, approvals, and output requirements and needs an explicit product decision.

## Milestone 1 — Real data certification pilot

**Objective:** replace synthetic/fake-adapter confidence with one independently reconciled loan-tape and AR pilot.

### Work

- Select one source owner, steward, portfolio, facility, tenant, and source-of-truth hierarchy.
- Document grain, as-of convention, currency, stable identifiers, history coverage, and authoritative control totals.
- Certify the PostgreSQL adapter against a real least-privileged role or choose and certify the pilot warehouse explicitly.
- Prove read-only/non-owner role configuration, `NOSUPERUSER`, `NOBYPASSRLS`, role-assumption restrictions, SELECT grants, network policy, timeouts, cancellation, exact numeric behavior, and failure cleanup.
- Ingest at least one current tape and the history needed for requested vintages. Use `loan_history` through-cutoff certification where the artifact contains multiple observation dates.
- Approve and activate the mapping, DQ profile, stratification/vintage recipes, AR policy, and monitor definitions through different makers/checkers.
- Reconcile declared count/balance/currency through the normalized artifact and every published population.
- Reperform at least three consecutive borrowing-base periods from actual agreement/amendment/waiver inputs.

### Exit criteria

- Re-running the same immutable inputs produces the same hashes and exact results.
- An independent analyst reproduces agreed stratification totals and at least one seasoned vintage metric.
- Unseasoned/unavailable vintage metrics remain `null`; cohort membership and denominators are fixed and disclosed.
- Every borrowing-base stage reconciles and every excluded/eligible dollar is attributable to an approved rule and population.
- Failed DQ or reconciliation cannot start a governed analysis or monitoring signal.
- Restricted identifiers and small/complementary cells do not leak through outputs or repeated approved recipes under the pilot threat model.
- The pilot user completes two reporting cycles without hidden spreadsheet logic required to explain a material result.
- Live PostgreSQL evidence is recorded; until then PostgreSQL remains “implemented, not certified.”

## Milestone 2 — Production environment certification

**Objective:** prove the existing governed runtime in the chosen deployment model.

### Work

- Decide client VPC, vendor SaaS, or hybrid, plus residency, retention, deletion, and tenant-isolation tier.
- Replace placeholder image/repository values and promote a digest-pinned, signed, provenance-attested image with SBOM.
- Configure a managed TLS gateway, exact public URL/Host/Origin policy, real OAuth resource/issuer/JWKS/audience/resource/scopes, and approved tenant memberships.
- Populate production policy and key rings from an approved secret manager; rehearse artifact/signing key rotation.
- Deploy the one-replica SQLite/filesystem base only where its availability and scale limits are accepted. Otherwise migrate control/job/security/artifact stores before production.
- Establish application-consistent backup, isolated restore, measured RPO/RTO, audit export, dashboards, alerts, and incident runbooks.
- Run cross-tenant canaries, auth-deny cases, replay/handle attacks, crash-window/lease recovery, disk pressure, and maximum-bound load tests.
- Complete authenticated Streamable HTTP smokes through the real gateway and local STDIO smokes for every supported Codex/Claude release train.

### Exit criteria

- Every item in [RELEASE_CHECKLIST.md](./RELEASE_CHECKLIST.md) is evidenced or explicitly owned as an approved exception.
- Tenant A cannot enumerate, start, poll, cancel, retrieve, infer, or audit tenant B state.
- Startup fails closed for invalid auth/policy/key/storage configuration; readiness and graceful drain behave under dependency failure.
- Restore reproduces a known certified analysis and preserves tenant bindings, replay state, historical keys, alerts, and audit continuity.
- Real Claude Code/Desktop acceptance is complete for any release that advertises those clients.
- The production claim names the exact environment, image digest, client versions, adapter certifications, and limitations.

## Milestone 3 — External orchestration and notification delivery

**Objective:** turn operator-invoked workflows into a controlled recurring operating process without moving scheduling logic into prompts.

### Work

- Integrate an external scheduler/event detector for delivery or watermark arrival.
- Invoke idempotent operator ingestion/extraction, mapping drift review, certification, and governed job start.
- Add run calendars, owners, SLA, backfill policy, late/corrected-delivery policy, and observable retry/escalation behavior.
- Compare current certified results with prior snapshot, policy, plan, and approved historical baseline.
- Build an external notification dispatcher with allowlisted destinations/templates, minimized payloads, delivery receipts, and no recipient/URL authority from source data or model text.
- Export append-only application audit to a separately administered WORM destination.
- Add an operational dashboard over durable run, DQ, reconciliation, job, result, and alert metadata without exposing raw artifacts.

### Exit criteria

- Scheduled runs are idempotent and never publish after a failed certification gate.
- Corrections create new immutable artifacts/manifests and do not rewrite earlier decision-time evidence.
- Alert occurrence deduplication and case transitions remain stable across repeat runs.
- Every notification maps to an approved destination/template and durable alert occurrence; delivery failure cannot mutate analytical truth.
- Operators can distinguish source failure, DQ block, policy deny, execution failure, and notification failure without inspecting secrets or raw rows.

## Milestone 4 — Product depth and scale

**Objective:** expand only after pilot semantics, operating controls, and source quality are proven.

Candidate work:

- detailed inventory by SKU/location/lot, ownership, condition, age, cost, salability, appraisal, and NOLV;
- inventory eligibility, sublimits, reserves, turnover, sell-through, shrink/write-down and NOLV scenarios;
- lockbox/cash-receipt and loan-paydown reconciliation;
- field-exam, appraisal, lien/UCC, insurance, waiver, covenant, and annual-review ticklers;
- approved period-over-period attribution and scenario analysis without mutating baseline policy/results;
- cross-facility borrower/account-debtor/industry/geography concentration after governed entity resolution;
- external transactional control/job/security stores and object storage for horizontal scale;
- additional adapters selected by buyer demand, each with independent dialect/precision/read-only/cancellation/live certification;
- optional document-assisted rule proposals with citations, never self-activation;
- product field packs for mortgage, consumer/installment, equipment, specialty finance, accounting/CECL, and regulatory views.

XLSX, Parquet, Snowflake, BigQuery, SQL Server, MySQL, Databricks, and similar names remain candidates—not current support claims.

## Metrics for delivery decisions

Do not collapse progress into one opaque score. Track:

- percentage of required fields covered by active approved mappings;
- delivered-to-normalized count/balance/currency reconciliation variance;
- certified versus blocked runs and blocker dollars;
- deterministic replay/hash success;
- unmapped and unknown balance share;
- time from delivery to certification and from job start to durable result;
- suppression coverage and attempted over-cardinality requests;
- AR eligible percentage and ineligibles by reason;
- submitted-versus-reperformed borrowing-base variance;
- capacity, defined usage, excess availability, and overadvance;
- alert recurrence, acknowledgement/resolution time, false-positive review, and notification delivery outcome;
- auth/policy denies, replay detections, lease expiries, artifact integrity failures, audit gaps, and restore success.

## Decisions still required

| Decision | Working recommendation | Deadline |
|---|---|---|
| Primary pilot user | Lender collateral analyst with portfolio/credit checker | Before pilot data contract |
| First portfolio | Longitudinal portfolio with stable IDs and authoritative exact controls | Before live adapter certification |
| First facility | Receivables-led revolver with invoice detail, usage, three BBCs, agreement/amendments/waivers | Before AR parallel run |
| Source hierarchy | Explicit servicing/warehouse/GL/BBC/lockbox/approved-adjustment precedence | Before mapping activation |
| Production source | PostgreSQL only if the selected client environment supports real certification | Before production claim |
| Deployment model | Client VPC or tightly controlled hybrid is the conservative first posture | Before IdP/TLS/storage design |
| Detail access | Aggregate-only remains the MCP default | Before threat-model approval |
| Currency | Single-currency pilot unless an approved replayable FX definition exists | Before certification |
| Notification channel | Choose only after recipient ownership, minimization, retention, and delivery audit are approved | Before recurring monitoring |

## Definition of success

The product succeeds when a real user repeatedly makes a review decision from certified outputs, can explain every material number and exception from immutable evidence, and can reproduce that evidence later. It does not succeed merely because an LLM generates a plausible narrative, the test suite passes, or deployment YAML renders.
