# Product and Delivery Roadmap

## Outcome

Build the governed semantic and analytical control plane for lending data, exposed through MCP.

The product is not a general natural-language SQL agent. The model may interpret intent, propose mappings, explain variances, and draft narratives. Deterministic code must own source access, transformations, reconciliations, borrowing-base calculations, metrics, suppression, and lineage.

This roadmap turns the [Product Blueprint](./PRODUCT_BLUEPRINT.md) into delivery phases and release gates. A phase is complete only when its acceptance criteria are evidenced in automated tests, pilot artifacts, or documented user approval; shipping code alone is not the exit condition.

## Product wedge

The product enters the market through two consecutive workflows:

1. **Governed longitudinal loan-tape analysis.** Map a lender or servicer tape, certify its grain and totals, and produce reproducible stratifications and vintage analysis. This proves the common platform: controlled source access, canonical semantics, immutable snapshots, mapping governance, reconciliation, recipes, and lineage.
2. **Accounts-receivable-first ABL monitoring.** Reperform one facility's receivables eligibility and borrowing base, explain every excluded dollar and submitted-versus-calculated variance, and compare current and prior certificates. This creates a high-value daily operating workflow for collateral analysts.

Detailed inventory follows only after a pilot can supply reliable SKU/location/lot, ownership, condition, cost, sales, appraisal, and NOLV data. A general-ledger inventory balance is not enough for collateral monitoring.

The working pilot persona is a lender collateral analyst supported by a portfolio or credit officer. If the initial buyer is instead a borrower/controller or asset buyer, the team must revisit the source-of-truth hierarchy, approval model, entitlement boundary, and required outputs before Phase 1 scope is frozen.

## Current baseline

The repository is version `0.1.0` and already contains a functioning greenfield vertical slice:

- STDIO and Streamable HTTP MCP transports with legacy 2025-era and modern 2026-era client tests;
- operator-allowlisted, read-only SQLite and PostgreSQL adapters;
- a 67-field canonical loan-tape and ABL dictionary;
- deterministic field-mapping suggestions and readiness validation;
- aggregate-only stratification for an explicit snapshot date;
- sparse vintage analysis from repeated loan snapshots;
- minimum-cell and complementary suppression;
- structured MCP results plus JSON text fallbacks;
- no arbitrary SQL tool, raw-row preview, source write path, scheduler, or autonomous credit action.

Important gaps are explicit: analyses query live tables rather than immutable snapshots, mappings are supplied per request rather than approved and persisted, PostgreSQL has not been certified against a live pilot environment, data-quality and reconciliation manifests are not yet durable, and the borrowing-base engine is not implemented.

## Release principles

- **Correct before broad.** Add database dialects and product packs only after the existing path is certified on real data.
- **No publication without reconciliation.** A critical data-quality or reconciliation failure stops downstream risk reporting and returns `data_not_fit_for_publication`.
- **No hidden semantics.** Every published metric identifies its population, as-of date, denominator, weighting basis, currency, mapping version, and recipe or policy version.
- **No silent activation.** Model-proposed mappings and document-extracted rules require maker/checker approval before use.
- **Explainable dollars.** Every aggregate must trace to a governed population; every borrowing-base deduction must trace to a rule and source amount.
- **Time travel by design.** Corrections and late data supersede prior snapshots without erasing what was known at the time of an earlier decision.
- **MCP is not the scheduler.** External orchestration invokes stable MCP/domain operations; it does not move control logic into a prompt.
- **Adapters earn certification.** “Supported” means the dialect has integration, precision, timeout, cancellation, and golden-result evidence.

## Phase 0 — Safe analytical vertical slice

**Status:** implemented in the current repository; maintain as the regression baseline.

### Scope

- Governed source discovery and metadata inspection.
- Canonical dictionary lookup.
- Evidence-backed, deterministic mapping suggestions.
- Mapping validation for base, stratification, vintage, and borrowing-base readiness profiles.
- Aggregate stratification with explicit dates and numeric bins.
- Longitudinal vintage analysis with fixed origination cohorts, original-balance denominators, and sparse unseasoned cells.
- SQLite golden fixture plus STDIO and HTTP MCP interoperability tests.

### Exit criteria

- `pnpm run verify` passes from a clean install on the supported Node.js version.
- Both tested MCP protocol eras can list tools and execute a representative analysis over STDIO and Streamable HTTP.
- Golden stratification totals and vintage points reconcile exactly to the fixture.
- Source allowlists, result limits, identifier quoting, restricted-column classification, and SQLite read-only behavior remain covered by tests. PostgreSQL read-only transactions and timeouts remain implemented and receive live integration evidence in Phase 1.
- Tool results continue to expose warnings and mapping/query fingerprints.
- No generic SQL, raw-row preview, credentials-in-arguments, or source-write capability is introduced.

### Deliberately deferred

- Audit-reproducible snapshots.
- Mapping persistence and approval.
- Flat-file production ingestion.
- Durable DQ/reconciliation findings.
- Borrowing-base rules and monitoring.
- Remote production authentication and tenant isolation.

## Phase 1 — Loan-tape MVP and snapshot-backed pilot

**Objective:** turn the vertical slice into a reproducible, reviewable loan-tape workflow on one real portfolio.

### Product scope

1. **Immutable dataset snapshots**
   - Register a source watermark or delivered file with content hash, schema fingerprint, row count, control totals, as-of date, observed time, and supersession link.
   - Separate event time, source as-of time, and ingestion time.
   - Preserve exact-decimal monetary values and native currency; prohibit mixed-currency aggregation without an approved FX basis.

2. **Persisted mapping lifecycle**
   - Add `proposed -> validated -> approved -> active -> retired` mapping states.
   - Store field-level evidence, transformation, owner, reviewer, effective dates, and version.
   - Support a restricted transformation AST for cast, date parsing, scale/unit conversion, code mapping, coalesce, conditional logic, and explicitly approved joins.
   - Show mapping changes and their affected row count and balance before activation.

3. **Data-quality and reconciliation gates**
   - Confirm declared grain and unique `loan_id x as_of_date` keys.
   - Check required completeness, type/unit validity, date ordering, referential integrity, status/DPD consistency, duplicate keys, source freshness, and schema/code drift.
   - Reconcile delivery controls to source, source to normalized snapshot, and snapshot to each published population by count and balance.
   - Rank findings by affected balance and analytical impact, not row count alone.

4. **Versioned analysis recipes**
   - Persist stratification dimensions, buckets, filters, measures, weights, suppression rules, and currency basis.
   - Persist vintage cohort definition, horizon, denominator, delinquency threshold, and metric availability.
   - Add period-over-period comparison and a portable run manifest containing snapshot, dictionary, mapping, recipe, compiler, query-plan, and output hashes.

5. **First certified production source path**
   - Certify PostgreSQL against a real least-privileged read-only environment unless the pilot decision selects a different first warehouse.
   - Exercise cancellation, statement/lock timeout, numeric precision, date/time behavior, catalog allowlists, large-group protection, and failure cleanup.

### MVP acceptance criteria

The loan-tape MVP is accepted only when all of the following are true:

- One real pilot portfolio has a documented source owner, grain, source-of-truth hierarchy, control totals, and sufficient repeated snapshots or events for the requested vintage metrics.
- One current snapshot and the agreed historical window are immutable, content-addressed, and replayable.
- Every canonical field required by an active recipe is mapped, validated, and maker/checker approved; no defaulted or ambiguous critical field is silently accepted.
- Every published count and monetary total reconciles from report to snapshot and snapshot to its authoritative control within a source-specific, documented rounding tolerance. All differences are zero or explicitly reason-coded and approved.
- `Unknown/Unmapped` remains visible in each applicable analysis, and material unmapped balance blocks certification.
- Re-running the same snapshot, mapping, recipe, and compiler version produces the same output hash.
- An independent analyst reproduces the agreed stratification totals and at least one seasoned vintage metric from the pilot data.
- Unseasoned vintage cells are absent/`null`, cohort membership is fixed, and all loss/delinquency metrics disclose their denominators and input availability.
- Small-cell and complementary suppression prevents reconstruction through totals or repeated recipe variants under the agreed pilot threat model.
- The certified source account cannot write, the MCP exposes no credential or raw-data path, and restricted fields cannot be selected as dimensions or measures.
- A run manifest is exportable and sufficient for a reviewer to identify the exact data, mappings, methodology, warnings, and reconciliations used.
- The full automated verification suite and live-adapter certification suite pass.

### Pilot operating gate

Before Phase 2 work becomes the main delivery track, the pilot user must process at least two reporting cycles end to end and sign off that:

- previously approved mappings are reusable and drift is isolated for review;
- the strat/vintage pack answers an actual recurring credit or investment decision;
- reconciliation breaks are understandable and actionable;
- no material result requires an off-platform spreadsheet calculation to explain it.

## Phase 2 — AR-first borrowing-base pilot

**Objective:** reperform and explain the borrowing base for one receivables-led ABL facility.

### Product scope

1. **Facility and collateral model**
   - Add facility, borrower, account-debtor, receivable, receivable snapshot/event, borrowing-base certificate, usage, reserve, covenant, exception, waiver, and policy-version entities.
   - Maintain original invoice currency and any approved reporting-currency conversion.

2. **Versioned policy engine**
   - Represent the agreement, amendments, and waivers as an ordered, effective-dated rule graph.
   - Support record-level eligibility, past-due rules, cross-aging, account-debtor concentration, affiliate/foreign/government/unbilled/disputed treatment, advance rates, sublimits, reserves, commitment caps, usage, availability blocks, and overadvances.
   - Store rule provenance and maker/checker approval; regulatory or industry examples remain non-operative context.

3. **Explainable reperformance**
   - Keep `borrower_reported`, `system_reperformed`, and `approved_adjusted` values separate.
   - Persist the before/after amount, applied rule, reason, and policy version for every waterfall step.
   - Reconcile invoice detail to AR aging, AR aging to certificate, certificate to system reperformance, and usage to the lender source.
   - Provide submitted-versus-calculated variance and current-versus-prior change explanations.

4. **Scenario analysis**
   - Simulate approved changes to advance rate, cross-aging, concentration cap, reserves, collections, and usage without modifying the operative policy or baseline result.
   - Report the affected population and dollar delta for every scenario.

5. **Initial facility monitoring**
   - Save recurring AR and facility KPI definitions.
   - Evaluate data/control, borrowing-base, liquidity, and receivable alerts after quality gates pass.

### AR pilot acceptance criteria

- The governing agreement, effective amendments, waivers, latest certified BBC, AR detail, facility usage, and authoritative control totals are available for the pilot facility.
- All operative rule definitions and formula ordering are independently reviewed and approved; each rule links to its governing source and effective period.
- At least three historical or consecutive BBCs are re-performed. Each agrees to the certified result within documented rounding tolerance or has a complete, approved variance bridge.
- One hundred percent of excluded and eligible AR dollars can be attributed to source invoices, rule steps, and reason codes; rule-level totals reconcile to certificate components and the final borrowing base.
- Golden tests cover boundary dates, partial and full cross-aging, concentration excess, rule precedence, reserve order, sublimits, commitment caps, negative availability, amendments, waivers, and late corrections.
- Availability is calculated from approved capacity and defined usage without suppressing negative values; overadvance is derived explicitly.
- Baseline calculations are deterministic and unchanged by scenario runs. Scenario deltas reconcile to affected source populations.
- A collateral analyst can answer “why is this amount ineligible?”, “what changed?”, and “why do we differ from the borrower?” using platform evidence without reconstructing the waterfall in a spreadsheet.
- Critical DQ or reconciliation failures stop publication and prevent risk alerts from being presented as valid facility signals.
- The pilot user signs off on rule accuracy, variance explainability, alert usefulness, and the maker/checker workflow.

## Phase 3 — Continuous monitoring and inventory depth

**Objective:** operate the pilot workflows across reporting cycles and expand from AR reperformance into controlled monitoring.

### Product scope

- External-orchestrator integration for idempotent delivery detection, snapshot creation, quality gates, saved recipes, and monitor evaluation.
- Historical comparison across data, mapping, policy, and facility changes.
- Alert deduplication, evidence bundles, owner, severity, acknowledgement, SLA, resolution, and remediation actions.
- Approved notification integrations that disclose minimized information only.
- Lockbox/cash-receipt and loan-paydown reconciliation.
- Detailed inventory by SKU/location/lot, ownership, raw/WIP/finished-goods class, age, condition, cost, salability, appraisal, and NOLV.
- Inventory eligibility, sublimits, reserves, turnover, sell-through, write-down, shrink, appraisal-aging, and NOLV stress scenarios.
- Field-exam, appraisal, UCC, insurance, landlord/bailee waiver, covenant, and annual-review ticklers.
- Availability trend and trailing-minimum analysis; forecasting remains clearly labeled as an estimate rather than a certified BBC.

### Exit criteria

- Scheduled runs are idempotent, observable, retryable, and incapable of publishing after a critical gate failure.
- Late or corrected data creates a superseding snapshot and does not rewrite prior decision-time artifacts.
- Every alert contains affected dollars, metric/rule version, threshold source, baseline, evidence, lineage, owner, status, and deduplication key.
- Alert acknowledgement and resolution are auditable; alerts never change a credit term, activate a mapping/rule, or contact an unapproved recipient.
- Lockbox, collections, AR, usage, and loan application reconcile for the agreed pilot scope.
- Inventory is enabled only for facilities that meet the documented data contract and independent appraisal/valuation requirements.
- At least one complete monitoring cycle demonstrates that alerts are timely, non-duplicative, and actionable; false positives and missed known events are reviewed before broader rollout.
- Business-continuity and recovery tests prove that snapshots, policies, manifests, cases, and approvals can be restored.

## Phase 4 — Institutional platform and domain expansion

**Objective:** graduate from a single-portfolio pilot to a controlled multi-portfolio platform.

### Product scope

- Production identity, tenant isolation, scoped authorization, audit export, retention, residency, key management, and client-VPC/SaaS deployment pattern.
- Cross-facility party resolution and borrower/account-debtor/industry/geography concentration views.
- Participations, shared borrowing bases, first-out/last-out structures, and additional collateral classes.
- Additional certified SQL adapters based on buyer demand; likely candidates are Snowflake, SQL Server, BigQuery, and Databricks before broad long-tail support.
- Governed flat-file adapters for CSV/XLSX/Parquet when delivery workflows require them.
- Product field packs for mortgage, consumer/installment, equipment, and specialty finance.
- Accounting/CECL and regulatory-reporting mappings with separate accounting-policy governance.
- Document-assisted policy extraction that proposes cited rules but cannot activate them.
- Portfolio stress tests, common-seasoning comparisons, risk-rating migration, and cross-facility counterfactual analysis.
- Institution-specific synonym and mapping memory isolated by tenant and limited to approved examples.

### Exit criteria

- Independent security and architecture reviews approve the selected deployment model and tenant boundary.
- Authorization is enforced at tenant, source, table, field, facility, tool, purpose, and export levels where applicable.
- Every newly claimed adapter passes the common golden suite and dialect-specific precision, temporal, cancellation, and read-only integration tests.
- Cross-portfolio aggregates reconcile to their constituent certified snapshots and preserve drill-through lineage without exposing prohibited detail.
- Model-assisted rule or mapping proposals remain distinguishable from approved operative definitions in storage, UI, API, and audit exports.
- Operational SLOs, support ownership, incident response, change management, backup/recovery, and evidence retention are approved for production.

## KPI delivery roadmap

Metric definitions must be versioned and publish their population, as-of date, denominator, weight, currency, and source lineage. Do not collapse data-control health into one opaque score.

| Phase | KPI set | Initial measures |
|---|---|---|
| 0 | Analytical correctness | Population count/balance, bucket share, weighted averages, original cohort balance, current balance, remaining-balance factor, cumulative net loss when inputs exist, delinquent-balance rate when inputs exist. |
| 1 | Loan portfolio and data controls | Delinquency/nonaccrual/default, gross/net loss and recovery, risk grade, score/LTV/DSCR/FCCR/leverage, maturity/refinance bands, concentration by borrower/product/industry/geography/vintage; freshness, duplicate/orphan/unknown-code rates, mapping approval coverage, unmapped balance, reconciliation variance, lineage/reproducibility coverage. |
| 2 | Facility health and AR | Borrowing base, capacity, usage, excess availability, availability percentage, overadvance, coverage, submitted-versus-reperformed variance, trailing minimum availability; eligible AR, ineligibles by reason, aging/cross-aging, top-1/top-5 concentration, DSO, AR turnover, collection effectiveness, dilution, disputes, credits, returns, re-aging, unbilled and affiliate/foreign/government shares. |
| 3 | Inventory and operations | Eligible inventory, raw/WIP/finished-goods mix, turnover, days inventory, aged/obsolete/damaged/slow-moving share, growth versus sales, write-down, shrink, NOLV factor, book-to-NOLV variance, appraisal age, location/SKU concentration; lockbox and cash-application reconciliation, document and review timeliness. |
| 4 | Enterprise risk | Cross-facility borrower and account-debtor concentration, rating migration, policy-exception/override trends, maturity wall, portfolio stress, common-seasoning vintage comparison, participation/lender share, and accounting/regulatory views where governed. |

## Alert delivery roadmap

Threshold precedence is always: governing agreement/covenant, approved lender policy, facility-specific plan or historical baseline, then external benchmark as context only.

| Phase | Alert behavior | Initial catalog |
|---|---|---|
| 0 | No persistent operational alerts. Tool warnings describe live-source, mapping, suppression, and metric limitations. | Missing required fields, incompatible mapping, excessive groups/points, unavailable vintage inputs. |
| 1 | Blocking findings and reviewable data-quality events; no external dispatch. | Missing/late snapshot, schema/type/code/unit drift, duplicate or mixed grain, material reconciliation break, historical rewrite, lineage gap, material unmapped balance, impossible date/balance/status combinations. |
| 2 | Facility and AR alerts after quality certification. | Availability below soft/hard block, overadvance/out-of-formula, rapid availability decline, usage above system capacity, material BBC variance, repeated policy override, concentration/cross-aging breach, aging/DSO/dilution/returns/disputes spike, top-debtor deterioration, duplicate invoice, unapplied/diverted cash. |
| 3 | Persistent case lifecycle and approved notifications. | Unsupported inventory buildup, falling turnover, rising WIP/obsolescence, prime inventory sell-off, write-down/shrink, stale or declining NOLV/appraisal, location/ownership/prior-lien anomaly, overdue field exam/UCC/insurance/waiver/review, cutoff clustering and manual-adjustment anomalies. |
| 4 | Cross-portfolio and correlated-risk monitoring. | Common-debtor and borrower-group concentration, correlated geography/industry deterioration, risk-rating migration, policy-exception clustering, adapter/source systemic failures, and portfolio stress-limit breaches. |

## Decisions and decision deadlines

| Decision | Recommended working answer | Needed by | Consequence if deferred |
|---|---|---|---|
| Primary pilot user | Lender collateral analyst, with portfolio/credit officer as reviewer. | Phase 1 kickoff | Source hierarchy, UX, approvals, and acceptance criteria remain unstable. |
| First real portfolio | One longitudinal portfolio with stable IDs, at least the agreed seasoning history, and authoritative count/balance controls. | Phase 1 kickoff | Vintage and reconciliation claims cannot be validated. |
| First production source | PostgreSQL unless the selected buyer's warehouse is clearly different. | Before Phase 1 implementation freeze | Adapter work may be discarded or pilot integration delayed. |
| Source-of-truth hierarchy | Explicit ordering for servicing/core system, warehouse, GL, certified BBC, lockbox, and approved adjustments. | Phase 1 mapping approval | Variances cannot be resolved consistently. |
| First ABL facility | Receivables-led revolver with invoice detail, three BBC periods, usage, agreement/amendments, and control totals. | Before Phase 2 | Borrowing-base rules remain theoretical. |
| Mapping/rule approval model | Maker/checker with segregated activation authority and effective dates. | Phase 1 design | Auditability and safe reuse are blocked. |
| Detail access policy | Aggregate-only by default; add narrowly scoped invoice/loan evidence views only if the pilot workflow requires them. | Phase 1 threat model | Explainability may conflict with privacy or client expectations. |
| Deployment model | Decide client VPC/outbound connector, vendor SaaS, or hybrid after pilot data residency review. | Before Phase 3 notifications | Production identity, networking, and tenant design cannot be finalized. |
| Jurisdiction | U.S. commercial lending/ABL for the initial policy pack; legal counsel controls lien and agreement interpretation. | Before Phase 2 | Rule library and documentation requirements may diverge. |
| Currency policy | Single-currency pilot where possible; otherwise approved FX source, date, rounding, and replay rules. | Phase 1 data contract | Aggregate and borrowing-base reconciliation can be invalid. |
| Performance/SLO targets | Set from representative pilot volumes and review cadence, then make them release gates. | End of Phase 1 | Arbitrary latency claims replace measured requirements. |

## External dependencies

### Data and business inputs

- A named source owner and data steward.
- Real sample tapes and historical snapshots or event records.
- Stable facility, loan, borrower, invoice, account-debtor, and inventory identifiers.
- File/source control totals and authoritative GL/servicing/BBC/lockbox comparators.
- Credit agreement, amendments, waivers, covenant definitions, and policy exceptions for the ABL phase.
- Field-exam, appraisal/NOLV, lien, insurance, and waiver data for later monitoring.
- Business-approved definitions for defaults, delinquency, losses, recoveries, dilution, DSO, availability, and materiality.

### Platform and control dependencies

- Durable metadata and artifact storage for snapshots, mappings, recipes, policies, approvals, findings, manifests, and cases.
- An approved secrets manager and least-privileged database identities.
- Production authentication/authorization gateway for any remote MCP deployment.
- External orchestration, queueing, retry, and notification systems for Phase 3.
- Audit logging, encryption, retention, backup, recovery, and observability.
- Legal, compliance, information-security, and model-risk review appropriate to the selected institution and deployment.

## Cross-phase test strategy

- **Unit tests:** dictionary, mapping evidence, type compatibility, transformation AST, formulas, rule ordering, bins, denominators, suppression, reason codes, and severity/materiality.
- **Golden domain tests:** fixed loan-tape vintages, AR aging, cross-aging, concentration, reserve/sublimit waterfalls, amendments, corrections, and scenarios with hand-calculated expected outputs.
- **Adapter contract tests:** catalog allowlists, identifier quoting, exact decimals, dates/timezones, read-only enforcement, timeouts, cancellation, truncation, and cleanup.
- **Protocol tests:** legacy and current MCP clients over STDIO and Streamable HTTP with schema-valid structured and text fallbacks.
- **Reconciliation tests:** delivery-to-source, source-to-snapshot, snapshot-to-analysis, invoice-to-aging, aging-to-BBC, BBC-to-reperformance, and cash-to-loan application.
- **Security tests:** credential leakage, prompt/data injection boundaries, restricted fields, minimum-cell differencing, tenant/source isolation, Host/Origin validation, and export authorization.
- **Replay tests:** identical versions yield identical hashes; corrected data creates a new superseding result without mutating prior evidence.
- **Pilot parallel runs:** compare the platform with the institution's current spreadsheet or system, investigate every difference, and document which source controls.

## Definition of pilot success

The pilot succeeds when users repeatedly make a real review decision from certified outputs, can explain every material number and exception without hidden spreadsheet logic, and can reproduce the evidence later. It does not succeed merely because an LLM can answer questions or generate plausible SQL.
