# Portfolio Risk Platform Upgrade Checkpoint

Status date: 2026-08-15

This is the current engineering handoff. It separates the usable local pilot from capabilities that still require environment authority or additional product integration.

## Solid stopping point

The repository now has one coherent, locally executable single-facility vertical:

1. register governed delivery/runtime authority;
2. capture immutable V2 source evidence and an extraction receipt;
3. map, test, reconcile, and certify the captured snapshot;
4. publish the certified evidence through the V2-only publication authority;
5. authorize and materialize aggregate-only surveillance inputs;
6. execute `portfolio_surveillance_v1` through the durable V4 workflow;
7. retrieve status/result or cancel through a principal-bound opaque handle;
8. disable a publication, register a correction, and reopen the durable result after process restart.

`tests/pilot-vertical-acceptance.test.ts` exercises that chain with local durable stores. The composition in `composeProductionDisabledSingleFacilityV2SurveillanceRuntime` deliberately reports:

```ts
{ productionEnabled: false, remoteAdvertised: false }
```

That is the product boundary, not a temporary documentation caveat. The pilot is usable for development, deterministic review, and synthetic acceptance; it is not permission to expose a client facility or claim a production deployment.

## Current integration map

| Area | Current state | Fail-closed boundary |
|---|---|---|
| Capture and certification | IDs-only services, immutable evidence, extraction receipts, staging recovery, lifecycle/runtime authorities, and operator schemas | Modern runtime must be injected into the trusted operator topology |
| Publication | IDs-only V2 publication, disable-only lifecycle, immutable audit, and V2-only read adapters | Disabled, obsolete, cross-tenant, and cross-facility evidence is rejected |
| Surveillance | Local single-facility composition, metadata-only preflight, least-privilege materialization, durable V4 worker/state, and correction replay | Composition is production-disabled and not advertised by default |
| Job routing | Durable composite handle catalog routes legacy and V4 status/result/cancel without workflow probing | Tenant/principal binding is checked before route disclosure |
| Remote MCP | Conditional fifth-operation schema and composite workflow injection seam | Checked-in `remote-cli` does not inject the pilot workflow |
| BFF and console | Optional IDs-only pilot job port and browser workflow, alongside existing fixture review journeys | Default BFF does not inject a live control API or pilot job service |
| Acceptance | Repository-safe synthetic ABS/auto golden plus vertical, adversarial, restart, correction, and capacity tests | Synthetic evidence cannot certify a real facility |
| Public composition API | Root package exports `./contracts`, `./repositories`, and `./services` | Other source paths remain internal; package remains private |

## What remains for production enablement

Complete these in order; each step must retain the fail-closed default until its own release evidence exists.

1. Compose the modern delivery, historical runtime, capture, certification, publication, V4 workflow, route catalog, security, audit, and artifact dependencies from one reviewed environment configuration. Bind the operator to an IdP/workload identity before cross-host use.
2. Replace remaining trusted-import authority with maker/checker lifecycle governance for DQ, reconciliation, methodology, dimensions, compiler compatibility, and FX provider/rate selection. Prove activation-at-use historical replay.
3. Certify concrete PostgreSQL/RLS, XLSX, Parquet, PDF-control, object-store, and KMS adapters in the client environment. PDF controls may corroborate report lines; they may not invent missing source facts.
4. Run the private reference materials through the governed boundary and independently approve mappings, source/report exceptions, and every available report section. Keep private source data and derived evidence outside the public repository.
5. Inject the composite workflow into an authenticated remote deployment only after tenant/facility fencing, crash recovery, tamper, revoke/deny, cancellation-race, correction, capacity, and client acceptance gates pass.
6. Replace the fixture administration adapter and in-memory browser sessions with a tenant-aware control API and approved durable session/approval/audit stores. Complete browser E2E under a real OIDC issuer and TLS edge.
7. Build `MetricRunAuthorityResolver` over signed result artifacts, bind monitoring to certified metric-run IDs, and then compose investigation/report surfaces on the same policy and audit stack.
8. Add ABL-v2 as a separate certified-input workflow and complete at least three independently reproduced monthly borrowing bases for the pilot facility.
9. Connect the correction-aware pipeline to an external scheduler/delivery detector and transactional email/webhook outbox with server-governed destinations.
10. Migrate transactional state and artifacts to approved shared PostgreSQL/object/KMS infrastructure; prove backup/restore, WORM export, multi-replica leases, RPO/RTO, capacity/SLOs, signing/provenance, registry promotion, canary, rollback, and incident drills.

## External gates

The repository cannot self-certify:

- real OIDC registration, TLS edge, JWKS rotation, or authenticated Codex/Claude remote acceptance;
- live PostgreSQL grants/RLS/cursors/cancellation, object-storage immutability, KMS, legal hold, or restoration;
- client-VPC ingress/egress posture, cross-tenant canaries, WORM export, backup/restore, migration rehearsal, or incident ownership;
- customer methodology, legal interpretation, facility crosswalks, source hierarchy, report reproduction, or release sign-off;
- commit-bound multi-architecture images, registry signing, SBOM/provenance binding, canary promotion, or rollback in the target environment.

## Verification commands

Run from the repository root:

```sh
pnpm install --frozen-lockfile
pnpm run verify
pnpm run verify:integration
pnpm run verify:security
pnpm run audit:prod
```

Run `pnpm run release:verify` only from a clean named-branch commit. It checks GitNexus freshness and rejects tracked GitHub Actions workflows. Optional live gates require an explicitly authorized absolute manifest as documented in [Operator verification](./OPERATOR_VERIFICATION.md). A result of `local_pass_external_not_run` is local conformance evidence only.

## Non-negotiable boundaries

- No arbitrary SQL, source-system writes, or raw bulk export.
- No model-activated mapping, policy, monitor, destination, credential, or credit decision.
- Detail access remains separately scoped, capped, masked, purpose-bound, principal-bound, tenant/facility-bound, expiring, and audited.
- Private case-study and client data never enters the public repository.
- Existing contracts evolve additively with explicit compatibility windows.
- GitHub Actions remains disabled; verification and promotion are operator-run.
