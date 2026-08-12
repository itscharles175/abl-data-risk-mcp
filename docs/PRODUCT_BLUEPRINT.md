# Product Blueprint

## Product thesis

Build the governed semantic and analytical control plane for lending data, exposed through MCP.

The defensible product is not natural-language SQL. It is the combination of:

1. mapping heterogeneous loan, facility, receivable, inventory, and servicing data into a governed semantic model;
2. reconciling every reported dollar and population back to a source snapshot;
3. applying versioned, deal-specific eligibility and borrowing-base rules;
4. producing repeatable stratification, cohort, and performance analytics; and
5. monitoring changes with explainable, materiality-aware alerts.

The LLM is valuable at the edges: it interprets user intent, proposes mappings, explains breaks, compares periods, and drafts narratives. It is not the calculator, policy engine, entitlement system, or source of truth.

## Implementation status

This blueprint is the product/domain north star, not a list of unimplemented ideas. The repository now implements the governed technical foundation:

- authenticated remote Streamable HTTP MCP plus a separate local STDIO compatibility surface;
- encrypted immutable delivered/normalized/result artifacts and immutable lineage manifests;
- maker/checker mappings, governed definitions, and OAuth tenant memberships;
- DQ and exact control-total certification, including longitudinal `loan_history` through-cutoff semantics;
- durable, signed, replay-protected, principal-bound analysis jobs;
- exact snapshot stratification, vintage, AR borrowing-base, monitoring, alert deduplication, and case transitions;
- bounded CSV/JSON/NDJSON and allowlisted SQLite/PostgreSQL snapshot extraction;
- operator CLI and hardened deployment templates.

Implementation is not the same as external certification. A real portfolio/credit agreement, live PostgreSQL environment, IdP/TLS edge, deployed infrastructure, restore exercise, external scheduler/notification service, authenticated remote-client acceptance, and Claude Desktop acceptance remain outstanding. Real Codex CLI tool use and Claude Code connection health are complete. The durable schema below also includes future entities—inventory, documents, covenants, scenarios, notifications, and broader party resolution—that are not all present in code. See [ARCHITECTURE.md](./ARCHITECTURE.md) for the exact boundary and [ROADMAP.md](./ROADMAP.md) for remaining delivery gates.

## Clarifying “ABL”

The initial idea spans two related but different domains:

- Asset-backed or specialty-finance loan-tape analysis usually starts with one row per loan per snapshot or a loan event history. Core work includes mapping, data quality, stratifications, vintages, roll rates, losses, recoveries, and prepayments.
- Asset-based lending usually centers on a revolving facility plus rapidly changing collateral beneath it: receivables, account debtors, inventory, equipment, cash, reserves, sublimits, utilization, and availability. The governing credit agreement and amendments determine the calculation.

The platform should share ingestion, mapping, governance, lineage, and analytical primitives across both. It should not pretend that a facility-origination vintage answers an invoice-collection or inventory sell-through question. ABL-specific cohorts include invoice/due-date vintage, inventory receipt vintage, facility renewal cohort, and months since a borrowing-base or availability event.

## Initial wedge

The implemented sequence began with a generic longitudinal loan-tape analyzer and then added an accounts-receivable-first borrowing-base engine. The product rollout should still certify them in that order on real data.

This sequence works because the loan-tape foundation proves the cross-cutting platform primitives—source introspection, canonical mappings, immutable snapshots, reconciliation, saved analyses, and lineage—while AR creates immediate ABL value through aging, cross-aging, concentration, dilution, collections, and eligibility.

Detailed inventory should follow once clients can supply reliable SKU/location/lot, ownership, condition, cost, sales, appraisal, and NOLV data. A GL-level inventory balance alone does not support meaningful collateral monitoring.

## Users and high-value jobs

### Collateral analyst

- Ingest a new BBC, AR aging, inventory report, or loan tape.
- Reuse a prior approved mapping and review only drift/ambiguity.
- Reperform eligibility and the borrowing base.
- Explain every ineligible dollar and every difference from the borrower-submitted BBC.
- Compare current and prior collateral positions.

### Portfolio or credit officer

- Review availability, utilization, concentrations, DSO, dilution, turnover, covenant headroom, risk migration, and data quality.
- Ask what changed, why it changed, and whether the change is data, mix, performance, policy, or an override.
- Stress advance rates, NOLV, concentration caps, reserves, and collections.
- Open an evidence-backed case from an alert.

### Securitization or investment analyst

- Map a servicer tape into a repeatable canonical schema.
- Generate an investment-committee strat pack.
- Compare pools and tapes on the same definitions.
- Build cumulative loss, delinquency, prepayment, and remaining-balance vintages at common seasoning.
- Trace a report cell to its source population and methodology.

### Data engineer or model-risk reviewer

- Inspect grain, schema, units, categories, and source drift.
- Version mapping and transformation logic.
- Reconcile source, canonical model, analysis mart, and published artifact.
- Reproduce a historical run using the exact data and rules known at the time.

## Canonical domain model

The durable model separates contracts, parties, observations, events, collateral, policy, and analytical artifacts.

### Governance and ingestion

- `tenant`: institution boundary, residency, retention, and entitlement namespace.
- `data_source`: database/file/API, owner, source timezone, currency convention, approved network location.
- `source_object`: schema/table/file/sheet, declared grain, inferred grain, and catalog fingerprint.
- `ingestion_run`: source watermark, file/content hash, row count, control totals, timestamps, status, and retry/idempotency key.
- `dataset_snapshot`: immutable normalized population with `as_of_date`, observed time, content hash, schema fingerprint, and supersession link.
- `canonical_field`: business definition, entity, grain, type, unit, temporal semantics, sensitivity, owner, tests, and effective dates.
- `source_field_profile`: name, native type, null/distinct rates, ranges, code distribution, and safe fingerprints.
- `mapping_spec` and `mapping_rule`: source expression to canonical field, restricted transform AST, confidence, evidence, approval, version, and tests.
- `metric_definition`, `bin_definition`, and `recipe_definition`: versioned formulas, denominators, weights, filters, owners, and approvals.

### Parties, facilities, and exposures

- `party`: borrower, account debtor, guarantor, sponsor, servicer, originator, supplier, appraiser, lender.
- `party_role`: a party acting in a defined role for a facility, exposure, collateral pool, or event.
- `party_relationship`: parent/subsidiary, affiliate, common control, guaranty, or concentration group.
- `credit_agreement`: governing agreement plus effective-dated amendments, waivers, and notices.
- `facility`: borrower, type, close/maturity dates, commitment, currency, reporting cadence, and cash-dominion mode.
- `tranche`: lien/priority, first-out/last-out terms, participation, pricing, and commitment.
- `loan_account`: stable identity, origination/acquisition dates, product, terms, original balance.
- `loan_snapshot`, grain `loan_id × as_of_date`: current balance, accrued amounts, delinquency, status, risk grade, allowance, and utilization.
- `loan_event`: draw, payment, modification, default, charge-off, recovery, sale, payoff, or status change.

### Collateral

- `collateral_pool`: facility, collateral class, currency, ownership/perfection requirements.
- `receivable`: invoice, debtor, issue/due/ship dates, terms, original/open amount, and eligibility-relevant flags.
- `receivable_snapshot`, grain `invoice_id × as_of_date`: open amount, age, status, dispute, and eligibility observations.
- `receivable_event`: cash collection, credit memo, return, allowance, dispute, re-aging, or write-off.
- `inventory_item`: SKU/lot/category, raw/WIP/finished-goods class, owner, and location.
- `inventory_snapshot`, grain `SKU × location × lot × as_of_date`: units, cost, book value, age, condition, and salability.
- `collateral_valuation`: cost, market value, FMV, NOLV, appraiser, date, scope, and method.
- `lien`: collateral scope, priority, jurisdiction, filing dates, and continuation dates.
- `document_tickler`: UCC, insurance, landlord/bailee waiver, appraisal, field exam, and annual review.

### Borrowing-base policy and results

- `borrowing_base_certificate`: facility, as-of date, submitted/certified timestamps, borrower totals, and source artifact.
- `policy_version`: agreement/amendment/waiver provenance plus effective and knowledge dates.
- `eligibility_rule`: scope, predicate, aggregation level, precedence, exclusion method, and reason code.
- `advance_rate_rule`, `concentration_rule`, `cross_age_rule`, `sublimit`, `reserve_rule`, and `availability_trigger`.
- `eligibility_evaluation`: run header with exact data, mapping, and policy versions.
- `eligibility_result`: collateral record, applied rule, pre-rule amount, excluded amount, eligible amount, and explanation.
- `borrowing_base_component`: collateral class, gross value, ineligibles, eligible value, rate, contribution, and sublimit.
- `borrowing_base_result`: capacity, defined usage, excess availability, overadvance, and reported-versus-calculated variance.
- `covenant_definition`, `covenant_test`, `exception`, `waiver`, and `override`.

### Analytical and operational artifacts

- `data_quality_run`, `data_quality_finding`, and `reconciliation_break`.
- `stratification_run`, `stratification_cell`, and `bin_version`.
- `vintage_run`, `cohort_definition`, and `metric_observation`.
- `monitor_definition`, `monitor_run`, `alert`, `case`, `remediation_action`, and `notification_delivery`.
- `run_manifest`: source snapshot, mappings, metric/bin/rule versions, filters, compiler, policy, SQL/plan hash, output hash, and approvals.

Facts should retain source identifiers and bitemporal fields such as `effective_at`, `observed_at`, `system_from`, and `system_to`. A corrected late tape must not erase what the institution knew when it made an earlier decision.

## Data dictionary design

A canonical field is a governed semantic contract, not a normalized header. Each definition needs:

- stable canonical ID, label, business definition, and aliases;
- entity and expected grain;
- point-in-time versus period-flow meaning;
- effective/as-of convention and timezone;
- logical type, unit, scale, sign convention, and currency semantics;
- allowed values and normalization maps;
- authoritative source and steward;
- derivation or permitted transformation;
- required quality and reconciliation tests;
- direct/quasi-identifier and sensitivity classification;
- allowed purposes, roles, masks, aggregation rules, retention, and residency;
- version and effective dates.

Keep a small lending core and add field packs rather than one universal physical schema:

- core exposure and performance;
- consumer/installment;
- mortgage;
- equipment and specialty finance;
- receivables and invoice collections;
- inventory and appraisal/NOLV;
- facility, borrowing base, covenant, and availability;
- accounting/CECL and regulatory mappings.

External standards such as FIBO or MISMO can inform terminology and relationships, but should not be copied wholesale into the transactional schema.

## Mapping workflow

Current implementation persists immutable mapping versions, deterministic validation evidence, and the maker/checker lifecycle `proposed -> validated -> approved -> active`, with atomic supersession of the previous active version. The richer transformation AST, distribution profiling, and continuous drift monitoring described below remain expansion work.

Mapping is a controlled lifecycle:

1. Profile the source and infer whether its grain is facility, loan snapshot, event, invoice, inventory item, or a mixed/duplicated export.
2. Suggest candidates from names, aliases, types, units, distributions, codes, relationships, and institution-approved prior mappings.
3. Show alternatives, evidence, confidence, affected balance, and a transformation preview.
4. Validate keys, chronology, units, signs, values, identities, transitions, and control totals.
5. Require maker/checker approval for critical, ambiguous, derived, composite, or defaulted fields.
6. Compile a restricted declarative mapping AST into the database dialect.
7. Reconcile source totals to canonical totals before certification.
8. Version the mapping and continuously monitor schema, category, null, unit, sparsity, and distribution drift.

Useful future transformation classifications are `exact`, `renamed`, `derived`, `composite`, `defaulted`, `unmapped`, and `ignored`. The implemented operational status is separate: `proposed → validated → approved → active`, after which a replacement version marks the old version `superseded`. Confidence is evidence, not approval.

The transformation language should support only governed operations such as rename, cast, date parse, scale/unit conversion, code map, coalesce, conditional logic, approved split/combine, and approved joins. It should not accept generated JavaScript, Python, or unrestricted SQL.

## Stratification design

Current implementation performs this design over encrypted normalized canonical records, with exact decimals, explicit bucket validation/order, deterministic hashes, record/group bounds, restricted-field rejection, and primary plus complementary suppression. Currency/FX conversion and a broad saved recipe catalog remain institution-owned extensions.

Every stratification request must state:

- immutable snapshot/as-of date and population;
- dimension and versioned bin set;
- measures and weighting bases;
- current/original/eligible balance denominator;
- currency and FX basis;
- filters and cohort definition;
- null/unknown handling;
- minimum-cell and complementary suppression policy;
- metric, mapping, and recipe versions.

Every output should have a totals row, an `Unknown/Unmapped` bucket, and a reconciliation to its declared population. Weight underwriting attributes by original balance and current exposure attributes by current balance unless a governed recipe says otherwise.

### Core loan-tape cuts

- origination, acquisition, or modification vintage;
- months on book and remaining term;
- product, purpose, channel, originator, and servicer;
- original/current balance and utilization bands;
- fixed/floating, index, spread, and coupon;
- internal risk grade and external score;
- LTV, DTI, DSCR, FCCR, and leverage;
- delinquency, nonaccrual, default, modification, and workout;
- industry, geography, borrower group, and concentration;
- policy exception, maturity, and refinance-risk bands.

### ABL-specific cuts

- collateral class, eligibility status, and ineligibility reason;
- AR aging by contractual due date;
- account debtor, industry, geography, and top-N concentration;
- affiliate, government, foreign, unbilled, disputed, and re-aged status;
- dilution, credits, returns, and dispute bands;
- inventory raw/WIP/finished-goods type;
- SKU/category/location, age, turnover, and salability;
- appraisal/NOLV vintage;
- utilization, availability, and overadvance bands;
- field-exam/appraisal recency and exception status.

## Vintage and cohort design

Current implementation fixes origination cohorts and original-balance denominators, chooses deterministic latest monthly observations, enforces record/point limits, and returns `null` for unseasoned or globally unavailable metrics. Roll rates, cures, prepayment curves, and ABL-specific invoice/inventory cohorts remain future metric packs.

A single point-in-time tape can produce an age distribution. It cannot produce a defensible performance curve unless lifetime event fields carry enough history. True vintages, roll rates, cures, paydowns, and losses usually require repeated snapshots or an event ledger.

Retain original origination and acquisition cohorts after modification, and add separate modification/restructure cohorts. For revolvers, add close, renewal, and first-draw cohorts.

Useful loan matrices include:

- remaining-balance factor;
- cumulative gross/net loss;
- default and ever-30/60/90 incidence;
- current delinquency and nonaccrual;
- cure and delinquency-transition rates;
- paydown/prepayment curves;
- recovery amount and lag;
- rating migration;
- utilization and excess-availability trajectories.

Useful ABL analogues include invoice/due-date collection curves, dispute/dilution curves, debtor payment behavior, inventory sell-through and write-down curves, NOLV realization against appraisal vintage, and facility availability since close or renewal.

Every metric must publish its denominator. Examples:

```text
cumulative_net_loss_rate = (cumulative_charge_offs - cumulative_recoveries)
                           / original_cohort_balance

remaining_balance_factor = current_balance / original_cohort_balance

current_90_balance_rate = current_90_plus_balance / current_cohort_balance

roll_rate_i_to_j = count_or_balance_moving_i_to_j / starting_count_or_balance_in_i
```

Use `null`, not zero, for unseasoned cells. Fix cohort membership at inception to avoid survivorship bias, and compare vintages at common seasoning horizons.

## Borrowing-base engine

Current implementation provides an exact AR waterfall for effective-dated record eligibility, cross-aging, debtor concentration, advance rate, component sublimit, reserves, commitment, defined usage, excess availability, and overadvance. It records reason-coded before/after steps in the governed result. Agreement extraction, multi-collateral/inventory rules, covenants, waivers/overrides, submitted-versus-system variance workflows, and scenario orchestration remain pilot/domain expansion work.

Model a borrowing base as an ordered, effective-dated rule graph. Ordering matters economically and legally.

A typical waterfall is:

1. normalize and deduplicate collateral;
2. establish ownership, lien, location, currency, and legal eligibility;
3. apply record-level ineligibles;
4. apply debtor-level cross-aging and concentration rules;
5. calculate eligible collateral;
6. apply advance rates;
7. apply component caps and sublimits;
8. subtract reserves;
9. apply facility commitment and availability blocks;
10. subtract revolver usage, LCs, swingline, and other defined usage.

A generalized formula is:

```text
borrowing_capacity = min(
  commitment,
  Σ min(component_sublimit, eligible_value × advance_rate) - reserves
)

excess_availability = borrowing_capacity - defined_usage - availability_block
overadvance = max(0, -excess_availability)
```

The credit agreement, amendments, waivers, and latest certified BBC are authoritative for definitions, formula order, thresholds, cures, and overrides. Industry or regulatory examples are context, never software defaults.

Persist every rule step so the MCP can answer:

- Why is this invoice ineligible?
- Which five rules reduced availability most?
- Why does the system differ from the submitted BBC?
- Which source rows constitute this amount?
- What is the effect of a tighter debtor cap or lower NOLV?

Maintain distinct values for `borrower_reported`, `system_reperformed`, and `approved_adjusted`.

## Data quality and reconciliation

Current implementation persists immutable DQ findings and exact row-count/balance/currency reconciliation during snapshot certification. Profiles cover required fields, grain uniqueness, exact decimals, non-negative values, dates/order, allowed codes, null limits, status/DPD consistency, freshness, and currency. Point-in-time populations use exact dates; `loan_history` defaults to a through-cutoff population and blocks future rows or a missing cutoff observation. The full GL/BBC/lockbox reconciliation ladder below remains a source-specific rollout goal.

Build a reconciliation ladder:

1. delivery hash/control totals;
2. source detail to source ledger;
3. source to canonical;
4. canonical to analytical mart;
5. mart to published artifact;
6. loan/collateral subledger to GL;
7. submitted BBC to system reperformance;
8. cash receipts to lockbox and loan paydowns.

Reconcile by facility, legal entity, currency, status, and collateral class—not only grand total—because compensating errors can conceal breaks.

High-value checks include:

- unique `loan_id × as_of_date`, `invoice_id × as_of_date`, and `SKU × location × lot × as_of_date`;
- required completeness and referential integrity;
- date ordering and period continuity;
- DPD/status/nonaccrual/default consistency;
- beginning balance + draws/adjustments − payments − charge-offs = ending balance;
- receivable open amount versus invoice, collections, and credits;
- inventory units × cost versus reported value;
- line-item eligibility to BBC component/header totals;
- capacity and usage to reported availability;
- freshness, volume, schema, code, sparsity, and distribution drift;
- mapping and historical rewrite/backfill drift.

Severity should reflect dollars, availability, covenant headroom, and affected decisions—not only row counts.

## Automation model

MCP is the interaction contract, not the scheduler. The repository includes a durable queue, fenced worker leases, signed-plan replay protection, encrypted results, manifests, and durable monitoring cases. An external orchestrator—workflow engine, data platform, or approved scheduled agent—still detects deliveries/watermarks and invokes the pipeline:

1. detect delivery or watermark;
2. ingest idempotently and hash the payload;
3. profile schema/grain and compare with the approved template;
4. apply the current mapping version;
5. run critical data-quality and reconciliation gates;
6. materialize an immutable normalized snapshot;
7. execute saved analysis/borrowing-base/monitor recipes;
8. compare against prior, policy, plan, and historical baseline;
9. persist artifacts and lineage;
10. create deduplicated alerts/cases;
11. ask a separate approved dispatcher to send minimized notifications;
12. track acknowledgement, resolution, and SLA.

If a critical quality or reconciliation gate fails, monitoring must stop and report “data not fit for publication.” It must never silently emit a risk signal from incomplete data.

The implemented workflow enforces that gate from the certification manifest rather than a caller-provided claim. Recurring schedules and outbound delivery are not in this process.

## KPI framework

### Facility health

- excess availability and availability percentage;
- borrowing-base coverage;
- submitted-versus-reperformed BBC variance;
- trailing minimum availability;
- utilization and out-of-formula/overadvance status;
- covenant headroom and waiver frequency.

### Receivables

- eligible AR percentage and ineligibles by reason/dollar impact;
- current, past-due, and cross-aged percentages;
- top-1/top-5 debtor, industry, and geography concentration;
- DSO, AR turnover, and collection effectiveness;
- dilution, credits, returns, disputes, re-aging, and bad debt;
- unbilled/affiliate/foreign/government shares;
- lockbox collections versus expected and cash application.

### Inventory

- eligible inventory percentage;
- raw/WIP/finished-goods mix;
- turnover and days inventory outstanding;
- aging, obsolete, damaged, and slow-moving share;
- inventory growth versus sales;
- write-down, shrink, and adjustment rates;
- NOLV factor, appraisal age, and book-to-NOLV variance;
- location, SKU, and category concentration.

### Loan and portfolio

- delinquency, nonaccrual, default, gross/net loss, and recovery;
- risk-rating migration;
- weighted DSCR/FCCR/leverage/LTV/score;
- maturity and refinance wall;
- policy exception/override share;
- exposure by borrower group, industry, geography, product, and vintage.

### Data controls

- critical-field mapping approval coverage;
- source-to-canonical balance/count variance;
- detail-to-GL and detail-to-BBC variance;
- freshness lag and delivery completeness;
- duplicate/orphan/unknown-code rates;
- unmapped-balance share;
- manual override volume/value;
- historical rewrite volume;
- lineage and reproducibility coverage.

Avoid one opaque “data quality score.” Show failing dimensions, materiality, affected analyses, and blocking status.

## Alert framework

Current implementation persists typed monitoring runs, immutable occurrences, stable deduplication evidence, recurrence, and reviewable case transitions (`open`, `acknowledged`, `escalated`, `resolved`, `suppressed`, with recurrence reopening where appropriate). Notification dispatch, recipient directories, SLA timers, and the broader catalog below remain external or future work.

Threshold precedence should be:

1. agreement/covenant;
2. approved lender policy/risk appetite;
3. facility-specific historical baseline and plan;
4. peer or regulatory benchmark for context only.

### Data and control alerts

- missing/late delivery or BBC;
- schema/type/code/unit drift;
- duplicate identifiers or mixed grain;
- material reconciliation break;
- unexplained historical rewrite;
- lineage gap;
- new unmapped category carrying material balance;
- impossible balance/date/status combination.

### Borrowing base and liquidity alerts

- availability below soft/hard block;
- overadvance or out-of-formula status;
- rapid availability decline or unstable trailing minimum;
- usage exceeding system capacity;
- collateral mix shift from AR toward inventory;
- repeated eligibility/advance-rate liberalization;
- unexpected reserve reduction or override;
- borrowing growth unsupported by collections, sales, or eligible collateral.

### Receivable and inventory alerts

- rising delinquency/cross-aging, DSO, dilution, returns, credits, or disputes;
- account-debtor/industry/geographic concentration breach;
- re-aging, unbilled, affiliate, foreign, or government exposure growth;
- deterioration in a top account debtor;
- duplicate invoices, cutoff clustering, or diverted/unapplied cash;
- inventory buildup unsupported by sales;
- falling turnover, rising WIP/obsolescence, prime inventory sell-off, write-downs, shrink;
- stale/declining appraisal or NOLV;
- excluded-location, ownership, or prior-lien anomaly.

### Documentation and fraud alerts

- overdue field exam, appraisal, annual review, UCC continuation, waiver, or insurance;
- adverse field-exam/appraisal finding;
- invoices preceding shipment or circular/contra growth;
- sudden new debtor concentration;
- end-of-period collateral inflation;
- high manual-adjustment or override activity.

Alerts should carry affected dollars, rule/metric definition, baseline, evidence, lineage, severity, owner, SLA, and deduplication key. They should create a reviewable case, not autonomously alter credit terms or contact arbitrary recipients.

## Differentiators worth protecting

- Materiality-aware mapping and data quality: prioritize issues by balances, availability, covenant headroom, and decision impact.
- Explainable dollars: every chart, KPI, cell, and BBC component drills to a governed population and rule steps.
- Policy time travel: reproduce historical results using the agreement, waiver, mapping, and data known then.
- Semantic drift: “new status code affects 8% of AR” instead of merely “column changed.”
- Collateral digital twin: connect borrower, account debtor, supplier, collateral, lien, cash, and exposure relationships.
- Counterfactual simulator: quantify changes to advance rates, concentration, cross-aging, reserves, NOLV, and eligibility.
- Cross-facility concentration after governed entity resolution.
- Evidence-backed narratives whose claims link to metric and run manifests.
- Golden rule packs for each deal policy.
- Model-independent operation with the same deterministic results from Codex, Claude, or another MCP host.

## Non-goals

- No autonomous underwriting, adverse action, or borrower-level credit decision.
- No generic production `execute_sql` tool.
- No silent activation of an LLM-proposed mapping or contract-extracted rule.
- No claim that one current tape supports vintage/roll-rate history it does not contain.
- No internet-facing local server with embedded master credentials.
- No source-system writes in the initial product.
- No assertion that “all databases” are certified; adapters graduate through dialect-specific golden tests.
- No claim that deployment templates prove a live cloud deployment or that fake-pool PostgreSQL tests prove a live role/database configuration.
- No claim that every LLM supports MCP; compatibility depends on the host/client transport and protocol implementation.

## Decisions still needed

- Primary buyer and user: lender collateral team, portfolio risk team, borrower/controller, or asset buyer.
- First source-of-truth hierarchy: servicing system, warehouse, GL, BBC, lockbox, or document platform.
- First real portfolio and its reliable history/control totals.
- U.S.-only initial legal/regulatory boundary or broader jurisdictional requirements.
- Deployment model: vendor SaaS, client VPC, outbound connector, or hybrid.
- Required tenant/data isolation tier.
- Which client workflows need raw detail, and which can remain aggregate-only.
- Whether Postgres is the first certified warehouse or whether Snowflake/SQL Server has higher buyer value.
- Institution-specific role assignments and approval policy for mappings, definitions, memberships, overrides, alerts, and exports; the code-level maker/checker mechanism is implemented.

## Reference anchors

- The OCC’s current [Asset-Based Lending booklet](https://www.occ.treas.gov/publications-and-resources/publications/comptrollers-handbook/files/asset-based-lending/pub-ch-asset-based-lending.pdf) emphasizes borrowing-base monitoring, collateral controls, field audits/appraisals, timely accurate information, and early-warning indicators.
- The Basel Committee’s [BCBS 239 principles](https://www.bis.org/basel_framework/chapter/SRP/36.htm) provide useful anchors for integrated taxonomies, reconciliation, lineage, completeness, timeliness, and adaptable reporting.
- FASB’s [credit-losses resources](https://fasb.org/page/PageContent?pageId=%2Fstandards%2FTransition%2Fcredit-losses-transition.html) help distinguish accounting vintage disclosures from broader management cohorts.

These references inform governance and analytical design. They are not substitutes for deal documents, institution policy, legal advice, or accounting conclusions.
