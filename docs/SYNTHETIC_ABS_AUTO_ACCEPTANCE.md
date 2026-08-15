# Synthetic ABS Auto Acceptance Contract

This package provides a deterministic, repository-safe acceptance contract for the single-facility auto-ABS pilot. A private reference case motivated the control categories, but this package is not a reproduction of that facility or its data.

> This fixture is original synthetic test data created for Aegis Ledger. It contains no copied, sampled, transformed, perturbed, or statistically fitted borrower records, report values, dictionary prose, identifiers, hashes, or source-system metadata. Similarity is limited to public ABS-EE concepts and deliberately constructed control behaviors. It is not private case-study data, production data, certification evidence, or an authority for any real facility.

## What the contract proves

The fixture deliberately exercises the pilot's highest-risk semantics:

- a 25-field mapping ledger spanning exact, semantic, transformed, ambiguous, missing-target, and proposed-new-field states;
- maker/checker-safe lifecycle states with no approved mapping and no self-approval;
- immutable text identity, month-versus-day date precision, per-field zero/sentinel handling, raw DPD retention, and distinct dash/blank/null/zero states;
- deterministic pool balance, score-coverage, weighted-average, and nested DPD controls;
- zero-tolerance exception visibility through designed `-6` and `-2` count differences on wholly artificial populations;
- a generated 27-period vintage cadence using artificial 2031–2033 dates and fixed synthetic deltas;
- explicit unavailability for repurchase, liquidation, waterfall, reserve, tranche, and adjustment sections when supplemental evidence is absent.

The designed count offsets test behavior only. They are not report values and must not be described as evidence about any transaction.

## Files and verification

- `tests/fixtures/synthetic-abs-auto-v1/fixture.json` contains the synthetic contract and generator inputs.
- `tests/fixtures/synthetic-abs-auto-v1/manifest.json` pins only that generated fixture, its generator version, and its seed.
- `tests/synthetic-abs-auto-acceptance.test.ts` recomputes the controls and materializes the 27-period scenario.

Run the bounded acceptance test with:

```bash
pnpm exec tsx --test tests/synthetic-abs-auto-acceptance.test.ts
```

The repository fixture can validate code paths, schemas, failure modes, and deterministic replay. It can never certify a real facility. Real-facility acceptance requires separately governed source receipts, mappings, approvals, reconciliations, and signed evidence supplied through the production data boundary; those materials remain outside this repository.

No separate license is asserted for this fixture. Repository licensing remains an owner decision.
