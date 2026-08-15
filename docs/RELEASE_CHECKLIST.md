# Release Checklist

Record every checked item in a release-evidence bundle tied to the immutable commit and image digest. “Not applicable” requires an owner and reason. The Kubernetes and Compose templates have not been live-deployed merely because they render successfully.

## 1. Scope and code intelligence

- [ ] Release version, commit, change owner, reviewer, target tenants/regions, and rollback owner are recorded.
- [ ] GitNexus index is current (`node scripts/verify-gitnexus-current.mjs`); a clean clone has GitNexus installed on `PATH`, and stale indexes are rebuilt with PDG enabled for security review.
- [ ] GitNexus `detect_changes` matches the intended symbols and execution flows; every HIGH/CRITICAL blast radius has explicit review evidence.
- [ ] GitNexus circular-import check, relevant traces, API/tool maps, shape checks, and taint/PDG findings were reviewed.
- [ ] No unrelated working-tree changes, generated secrets, local databases, raw tapes, or customer data are included.

## 2. Determinism and domain correctness

- [ ] `pnpm install --frozen-lockfile`, `pnpm run verify`, and `pnpm run audit:prod` pass on the release commit.
- [ ] Golden stratification, vintage, data-quality, reconciliation, borrowing-base, cross-aging, concentration, reserve, sublimit, commitment, usage, and monitoring cases pass where implemented.
- [ ] Nulls, duplicates, negative balances, charge-offs/recoveries, restructures, currencies, leap/month-end dates, stale data, unseasoned vintages, and rule ordering are covered.
- [ ] Exact-decimal totals, stable ordering, suppression, rounding, lineage, mapping/policy/ruleset versions, and artifact digests match approved fixtures.
- [ ] A failed or stale mandatory quality gate blocks certification and monitoring publication.

## 3. MCP interoperability

- [ ] Tool schemas, structured results, JSON text fallback, resources, error codes, cancellation, pagination/bounds, and progress behavior pass the generic MCP integration suite.
- [ ] Codex STDIO smoke succeeds from a clean client configuration.
- [ ] Claude Code/Desktop STDIO smoke succeeds from a clean client configuration.
- [ ] Authenticated Streamable HTTP smoke succeeds through the real TLS gateway for each supported client; session/reconnect behavior is verified.
- [ ] A token for tenant A cannot list, start, poll, cancel, fetch, or infer tenant B sources, jobs, handles, artifacts, logs, errors, or cache entries.

## 4. Authentication and policy

- [ ] `ABL_AUTH_MODE=oauth`; no remote anonymous/development fallback can start.
- [ ] Public URL, resource identifier, issuer, JWKS URI, allowed asymmetric algorithms, audiences, resources, scopes, Host, and Origin policy are exact and environment-owned.
- [ ] Unknown issuer/key/algorithm, wrong audience/resource, missing scope, expired/not-yet-valid token, oversized token, malformed claims, and JWKS outage all fail closed.
- [ ] Tenant membership is resolved only from the fixed `oauth_tenant_memberships` control-store table and cannot be selected through an environment variable, claim alone, or tool argument.
- [ ] Queued execution and every job status/result/cancel request revalidate current membership and current policy; revocation and policy tightening deny stale handles/jobs.
- [ ] Policy denies by default and binds obligations to tenant, principal, tool, source/dataset, purpose, rows, columns, minimum groups, time, and result bounds.
- [ ] Signing/replay tests cover expiry, nonce reuse, key rotation, tenant/principal mismatch, request mutation, and concurrent replay.

## 5. Data-plane controls

- [ ] Every source/table/column/function is allowlisted; there is no generic SQL, source write, raw export, arbitrary path, callback URL, or model-supplied credential surface.
- [ ] Each SQL source policy is bound to one tenant and a dedicated physical table; views/materialized views and cross-tenant policy/request mismatches fail closed.
- [ ] Runtime PostgreSQL roles are non-owner, `NOSUPERUSER`, `NOBYPASSRLS`, cannot `SET ROLE`, and have only required SELECT grants on a replica/snapshot.
- [ ] Read-only transactions, statement/lock timeouts, cursor bounds, row/column/cell/byte/group limits, cancellation, and database-side resource governance are independently verified.
- [ ] Cross-tenant canary rows prove RLS/security views, pools, caches, jobs, files, handles, logs, and errors do not leak.
- [ ] Prompt-injection/exfiltration payloads in filenames, headers, comments, values, encodings, errors, links, and catalog names remain inert.

## 6. Image and supply chain

- [ ] Docker build uses reviewed digest-pinned build/runtime bases and the exact pnpm/lockfile; the final shell-free distroless image runs as UID/GID `65532` with non-writable application files.
- [ ] Image contains no shell history, source secrets, `.env`, customer config, test fixtures, Git metadata, package-manager cache, or development dependencies.
- [ ] CycloneDX/SPDX SBOM, dependency audit, secret scan, IaC scan, and image vulnerability scan are attached; HIGH/CRITICAL exceptions have expiry and security approval.
- [ ] Image is pushed once, signed with the approved workload/KMS identity, provenance-attested, and promoted by digest rather than rebuilt between environments.
- [ ] Registry repository, OCI source label, version, revision, build time, signature, SBOM, and provenance resolve to the same release.

## 7. Deployment configuration

- [ ] Compose/Kubernetes manifests render and pass strict schema/IaC validation; placeholders and `.example` labels are replaced in overlays.
- [ ] Image is pinned by digest; pull policy, registry authentication, admission policy, and signature verification are effective.
- [ ] TLS gateway is the only ingress; Service remains ClusterIP/loopback; trusted edge namespace/source is narrowly selected.
- [ ] Default-deny network policy is active; the governed remote runtime permits DNS and HTTPS only to the labeled identity/JWKS gateway. Database egress exists only in separately reviewed connector overlays.
- [ ] Non-root UID/GID, read-only root, dropped capabilities, no-new-privileges, seccomp, no service-account token, resource limits, PID/file limits, and bounded temporary storage are enforced.
- [ ] Runtime ConfigMap and secret objects are external, access-controlled, non-empty, validated, and absent from Git/rendered evidence; staged signing/artifact files are UID 65532 mode `0400` in tmpfs and the server does not mount their projected source.
- [ ] One replica/Recreate is retained while SQLite/RWO stores are used; any scale-out architecture has separate concurrency, lease, and session evidence.
- [ ] Operator maker/checker runs on one trusted host under distinct, non-reused OS accounts; shared cross-host/container-UID control storage is blocked until a host- or IdP-bound identity is implemented.

## 8. Persistence, recovery, and keys

- [ ] Control, job, security, and encrypted artifact volumes use approved encrypted storage classes, quotas, retention, snapshot schedules, and deletion protection.
- [ ] Application-consistent backup captures SQLite main/WAL/SHM state and artifacts at one recovery point; file-copy-only backup is prohibited.
- [ ] Restore rehearsal verifies integrity, tenant bindings, replay state, historical keys, artifact decryption/hash, audit continuity, and a certified analysis digest.
- [ ] Measured RPO/RTO and restore owner meet policy; failed restore blocks release.
- [ ] Artifact/signing key rings include the active key and every retained historical key; rotation and revocation procedures are rehearsed.
- [ ] Every SQLite database is greenfield/component-registry initialized, or has an approved offline migration and rollback package; arbitrary pre-registry in-place upgrades are blocked.

## 9. Health, capacity, and failure behavior

- [ ] `/healthz` exposes liveness only; `/readyz` fails when mandatory auth/policy/key/control persistence is invalid and does not overclaim lazy source health.
- [ ] SIGTERM drains readiness/work, closes listeners/pools/stores, and exits inside 45 seconds; SIGKILL/restart leaves jobs safely retryable and audit evidence consistent.
- [ ] Worker hard deadlines, resource ceilings, lease heartbeats, cancellation, claim-scoped plan replay defense, and verified manifest recovery pass under crash/fault injection.
- [ ] Load tests cover expected and burst MCP sessions, database concurrency, worst permitted analysis, cancellation races, artifact size, disk pressure, and queue/lease recovery.
- [ ] IdP/JWKS, policy, KMS/key, audit, database, storage, DNS, network, and telemetry outages have verified fail-closed/degraded behavior.
- [ ] Capacity thresholds, rate limits, timeouts, alerts, dashboards/runbooks, and on-call ownership are approved.

## 10. Privacy, audit, and incident readiness

- [ ] Logs/metrics/traces contain no bearer tokens, keys, URLs with credentials, connection strings, raw rows, direct identifiers, full prompts, or unrestricted arguments.
- [ ] Required audit events cover identity, tenant, policy decision/version, mapping/snapshot/recipe, signed plan, execution limits/outcome, result digest/handle, and approval chain.
- [ ] Audit events are delivered to append-only/WORM storage under separate administration; fail-closed buffering behavior is tested.
- [ ] Data retention, deletion, residency, model-provider boundary, legal hold, and customer notification requirements are approved.
- [ ] Incident procedure can isolate one tenant/client, revoke credentials/keys, preserve evidence, identify affected handles/artifacts, and validate safe restoration.

## 11. Promotion and rollback

- [ ] Staging uses production-equivalent identity, policy, network, database-role, storage, and secret delivery controls with synthetic/canary data.
- [ ] Canary deployment passes health/readiness, authenticated capabilities, one certified analysis, cross-tenant denial, audit receipt, backup checkpoint, and client smokes.
- [ ] Promotion requires two-person approval for policy, mappings, borrowing-base rules, keys, and production deployment where separation of duties applies.
- [ ] Rollback digest/config/schema compatibility is proven; rollback does not discard audit, nonce, lease, mapping, or artifact evidence.
- [ ] Post-deploy observation window completes with no unexplained auth denies, policy errors, audit gaps, readiness flaps, timeouts, integrity failures, or cross-tenant canary alerts.

## Release sign-off

| Role | Name | Decision | Timestamp | Evidence link |
|---|---|---|---|---|
| Engineering owner |  |  |  |  |
| Domain/model-risk owner |  |  |  |  |
| Security owner |  |  |  |  |
| Data/platform owner |  |  |  |  |
| Operations/on-call owner |  |  |  |  |
