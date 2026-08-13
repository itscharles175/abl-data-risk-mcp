# Operations Guide

## Deployment status and safety boundary

The repository produces a hardened, non-root OCI image. Its default command is the local STDIO transport, which is suitable for an MCP host or sidecar and does not open a network listener.

The Compose and Kubernetes files are **deployment templates, not evidence of a live deployment**. They select `node /app/dist/remote-cli.js` and refuse startup unless OAuth configuration, policy, tenant-membership state, private key rings, and durable control storage are present. Do not replace that command with the unauthenticated loopback launcher in `dist/cli.js`; it deliberately rejects non-loopback binds and is not a production edge.

No Ingress, public load balancer, DNS record, certificate, identity-provider registration, database, or secret is created by these templates. Those are environment-owned controls and release gates.

## Runtime topology

Production traffic should follow this path:

1. A managed TLS gateway receives `https://<public-host>/mcp`, preserves the canonical host, and applies connection/rate limits.
2. The remote MCP process validates Host and Origin, then verifies the bearer token's issuer, signature, algorithm, expiry, audience, and resource.
3. The process resolves the principal's tenant membership from the fixed `oauth_tenant_memberships` table in the control database and evaluates server-owned policy.
4. Typed, bounded analysis workers read only certified encrypted snapshot artifacts and governed definitions. Live database extraction belongs to a separately authorized connector/ingestion topology.
5. Control, job, security, and artifact state is persisted on dedicated volumes. Secrets and raw bearer tokens are never written there or logged.

The Kubernetes Service is `ClusterIP`; there is intentionally no Ingress. The Compose port is bound to host loopback only so a same-host TLS gateway can proxy to it without making the clear-text listener public.

## Image lifecycle

The Dockerfile compiles with digest-pinned Node.js `24.13.1-bookworm-slim` and pnpm `11.16.0`, then copies only production dependencies and built artifacts into a digest-pinned distroless Node.js 24 Debian 13 runtime. The final image has no shell or package manager, runs as numeric non-root UID/GID `65532`, and leaves application files non-writable. Only `/var/lib/abl/control`, `/var/lib/abl/artifacts`, the explicitly mounted `/tmp`, and the in-memory secret-staging mount are writable at runtime.

Build and verify locally:

```sh
pnpm install --frozen-lockfile
pnpm run verify
pnpm run audit:prod
docker build --pull --build-arg VCS_REF="$(git rev-parse HEAD)" -t abl-mcp-server:local .
docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint /nodejs/bin/node abl-mcp-server:local /app/dist/cli.js --help
```

The image's default STDIO mode can be used locally with an explicit read-only config mount. Pass database credentials through the host's secret mechanism, not in the image or JSON configuration.

Every promoted image must be referenced by registry digest, accompanied by an SBOM, scanned, signed, and traceable to a reviewed commit. The owning repository must add its canonical OCI source label and replace the example image repository in the release build/overlay before promotion.

## Required remote configuration

The authenticated remote process uses the following contract. Empty, malformed, or inconsistent values must stop startup.

| Setting | Purpose |
|---|---|
| `ABL_AUTH_MODE=oauth` | Forces bearer-token resource-server mode. No production fallback is permitted. |
| `ABL_MCP_PUBLIC_URL` | Canonical HTTPS service URL used to derive/verify externally visible resource metadata. |
| `ABL_MCP_HOST=0.0.0.0`, `ABL_MCP_PORT=3333` | Container bind only; the Service or loopback proxy remains the exposure boundary. |
| `ABL_MCP_ALLOWED_HOSTS`, `ABL_MCP_ALLOWED_ORIGINS` | Explicit comma/JSON policy accepted by the remote entry point. Do not use wildcards. |
| `ABL_OAUTH_RESOURCE` | Exact protected-resource identifier expected in tokens and metadata. |
| `ABL_OAUTH_ISSUERS_JSON` | Bounded JSON array of trusted issuers, JWKS URIs, audiences, resources, and allowed asymmetric algorithms. |
| `ABL_OAUTH_MAX_TOKEN_LENGTH` | Maximum bearer-token bytes; the templates default to `16384`. Reduce where the issuer permits. |
| `ABL_OAUTH_SCOPES_SUPPORTED` | Explicit supported scope set. Keep catalog, analysis, administration, and approval scopes separate. |
| `ABL_OAUTH_RESOURCE_NAME`, `ABL_OAUTH_RESOURCE_DOCUMENTATION` | Required human-readable name and optional HTTPS documentation URL. |
| `ABL_MCP_CONFIG` | Read-only, non-secret source allowlist JSON. |
| `ABL_MCP_CONTROL_DB_PATH` | Durable mappings, snapshots, evidence, audit, and fixed OAuth tenant-membership table. |
| `ABL_MCP_JOB_DB_PATH` | Durable job/lease/idempotency state. |
| `ABL_MCP_SECURITY_DB_PATH` | Durable nonce/replay and security state. |
| `ABL_MCP_ARTIFACT_ROOT` | Durable encrypted artifact envelopes. |
| `ABL_MCP_ARTIFACT_KEYS_FILE` | Owner-only (`0400`) artifact encryption key ring supplied through private staging. |
| `ABL_MCP_SIGNING_KEYS_FILE` | Owner-only (`0400`) plan/handle signing key ring supplied through private staging. |
| `ABL_MCP_POLICY_FILE` | Read-only server-owned authorization policy. |
| `ABL_MCP_CODE_VERSION` | Immutable application/compiler version recorded in lineage. It must match the promoted image. |
| `ABL_MCP_WORKER_ID`, `ABL_MCP_WORKER_LEASE_SECONDS`, `ABL_MCP_WORKER_POLL_INTERVAL_MS` | Stable worker identity plus bounded lease and polling behavior. |
| `ABL_MCP_RATE_LIMIT_WINDOW_MS`, `ABL_MCP_RATE_LIMIT_MAX_REQUESTS` | Bounded per-principal/tenant request window consumed by the remote edge. |
| `ABL_MCP_MAX_CONCURRENT_REQUESTS`, `ABL_MCP_MAX_CONCURRENT_JOBS` | Hard in-process concurrency ceilings. |

The governed remote runtime validates the non-secret source configuration for syntax but does not instantiate live source adapters or require a portfolio database credential. Database extraction and snapshot certification belong to a separately authorized connector/ingestion deployment with its own read-only credential, egress, and release evidence. Keep the remote base's source list empty unless that separate topology is being deliberately composed and reviewed.

The checked-in `remote-cli` does not construct `portfolioSurveillanceWorkflow`; `abl_capabilities` and `abl_start_job` expose only snapshot stratification, vintage, AR borrowing-base, and monitoring. `buildRemoteServer` has a fail-closed optional seam for `portfolio_surveillance_v1`, but there is no safe environment toggle for it. The repository now has durable local snapshot/evidence and workflow-state stores, governed dataset bindings, effective source-policy selection, a repository-backed publication verifier, metadata-only preflight, post-policy materialization, a dedicated v4 lifecycle, and IDs-only modern capture/certification services, but none of the modern writer/workflow chain is injected into `remote-cli`. Do not compose the fifth operation until source/scope/control/runtime/methodology/dimension/FX authority is lifecycle-backed, artifact staging and historical replay are complete, production adapters are certified, and a verified composite status/result/cancel router is present.

Tenant membership uses the fixed `oauth_tenant_memberships` control-store table. Its table name is not configurable by an operator, client, model, or token. Populate memberships through the reviewed administrative workflow before admitting traffic; never infer a tenant from an MCP tool argument.

## Compose

`deploy/compose.yaml` is an operator-oriented single-node template. It uses named volumes, a read-only root filesystem, all-capability drop, no-new-privileges, PID/file-descriptor/memory/CPU limits, a loopback-only published port, and file-backed secrets. Before starting the remote module, the distroless Node entrypoint running as UID 65532 copies key/policy inputs into an owner-only `0400` tmpfs and points the runtime loader only at those private copies. The remote service is behind the explicit `remote` profile.

Create secret files outside the repository with mode `0600`, then export only their paths and the non-secret OAuth settings. The key and policy file formats are owned by the runtime parsers; use generated/validated files, not hand-written production keys.

```sh
export ABL_MCP_ARTIFACT_KEYS_FILE_SOURCE=/secure/abl/artifact-keys.json
export ABL_MCP_SIGNING_KEYS_FILE_SOURCE=/secure/abl/signing-keys.json
export ABL_MCP_POLICY_FILE_SOURCE=/secure/abl/policy.json
export ABL_MCP_CONFIG_FILE=/secure/abl/source-policy.json

export ABL_MCP_PUBLIC_URL=https://abl.example.com
export ABL_MCP_ALLOWED_HOSTS=abl.example.com
export ABL_MCP_ALLOWED_ORIGINS=https://approved-client.example.com
export ABL_OAUTH_RESOURCE=https://abl.example.com
export ABL_OAUTH_ISSUERS_JSON="$(</secure/abl/oauth-issuers.json)"
export ABL_OAUTH_SCOPES_SUPPORTED='abl:catalog abl:analyze abl:monitor'

docker compose -f deploy/compose.yaml --profile remote config --quiet
docker compose -f deploy/compose.yaml --profile remote up --build --detach
docker compose -f deploy/compose.yaml --profile remote ps
```

The bridge network does not provide destination-aware egress filtering. Use host firewall policy or an egress proxy to restrict the process to trusted JWKS and approved telemetry destinations. Connector/database egress is deliberately outside this governed remote deployment. Kubernetes with a policy-capable CNI is preferred for a multi-tenant production environment.

## Kubernetes

The base in `deploy/kubernetes` intentionally has one replica and `Recreate` strategy because the current durable stores are local SQLite files on `ReadWriteOnce` claims. Do not scale this base above one replica. Horizontal scaling requires external transactional control/job/security stores, object storage for artifacts, distributed lease tests, and a session-independent MCP transport.

Before rendering the base:

1. Review the source policy. The governed remote base intentionally contains no live sources; connector-specific source allowlists belong in a separate deployment.
2. Create an immutable `abl-mcp-runtime` ConfigMap containing the public URL, Host/Origin policy, `ABL_OAUTH_RESOURCE`, `ABL_OAUTH_ISSUERS_JSON`, scopes, required resource name, and optional HTTPS documentation URL.
3. Create `abl-mcp-runtime-secrets` from three non-empty files named `artifact-keys`, `signing-keys`, and `policy`. A restricted UID 65532 distroless Node init container copies them into an in-memory volume and applies mode `0400`; the server never mounts the projected source. Do not commit the resulting Secret manifest.
4. Replace the placeholder image with a signed registry digest and choose reviewed storage classes, sizes, encryption, snapshot, and retention policies.
5. Label only the trusted edge namespace `abl-mcp.example/access=true`. Route configured HTTPS JWKS endpoints through a dedicated identity gateway in a namespace labeled `abl-mcp.example/identity-egress=true` and pods labeled `abl-mcp.example/identity-gateway=true`.
6. Confirm the cluster's DNS labels match the supplied `k8s-app=kube-dns` selector. The base permits HTTPS only to that labeled identity gateway and intentionally blocks arbitrary internet and database egress. Standard NetworkPolicy cannot express FQDNs, so the gateway or a CNI FQDN policy must enforce the exact reviewed issuer/JWKS destinations.
7. Put a TLS gateway in front of the ClusterIP Service. Do not change the Service to `LoadBalancer` or `NodePort` as a shortcut.

One safe way to create the external objects from protected files is:

```sh
kubectl apply -f deploy/kubernetes/namespace.yaml

kubectl -n abl-mcp create configmap abl-mcp-runtime \
  --from-literal=ABL_MCP_PUBLIC_URL=https://abl.example.com \
  --from-literal=ABL_MCP_ALLOWED_HOSTS=abl.example.com \
  --from-literal=ABL_MCP_ALLOWED_ORIGINS=https://approved-client.example.com \
  --from-literal=ABL_OAUTH_RESOURCE=https://abl.example.com \
  --from-file=ABL_OAUTH_ISSUERS_JSON=/secure/abl/oauth-issuers.json \
  --from-literal=ABL_OAUTH_SCOPES_SUPPORTED='abl:catalog abl:analyze abl:monitor' \
  --from-literal=ABL_OAUTH_RESOURCE_NAME='ABL Data and Risk MCP'

kubectl -n abl-mcp create secret generic abl-mcp-runtime-secrets \
  --from-file=artifact-keys=/secure/abl/artifact-keys.json \
  --from-file=signing-keys=/secure/abl/signing-keys.json \
  --from-file=policy=/secure/abl/policy.json

kubectl kustomize deploy/kubernetes > /tmp/abl-mcp.rendered.yaml
```

Review the rendered manifest and environment-specific overlays before `kubectl apply`. The base alone is expected to remain unready without valid external configuration and egress.

## Health, readiness, and shutdown

- `/healthz` is unauthenticated liveness only. It should prove the event loop and HTTP listener are responsive without disclosing configuration or dependency detail.
- `/readyz` is the unauthenticated traffic gate. Release tests must prove that it is non-200 when OAuth metadata, policy, membership/control storage, keys, or mandatory persistence is unavailable, and 200 only after required startup checks succeed.
- These two minimal probe routes are mounted before Host/Origin and OAuth enforcement so kubelet and container probes work. `/mcp` remains Host/Origin-validated and authenticated; OAuth metadata is unauthenticated but Host/Origin-validated.
- This governed remote process opens no live source database connection, so readiness covers its OAuth/policy/key/control/worker dependencies only. Connector health is reported by the separately deployed ingestion topology.
- The container health script accepts only HTTP(S), refuses URL credentials and redirects, limits response size, and accepts JSON status `ok` or `ready`.
- Kubernetes sends `SIGTERM` and allows 45 seconds. The server stops readiness and new claims, closes MCP handlers/listeners, waits for bounded in-flight workers, then closes SQLite stores. Each claim uses a fresh replay-protected plan; after a forced kill, an expired fenced lease may be reclaimed up to the bounded attempt limit, and any already-persisted immutable manifest is verified and adopted without recomputation. Queue reaper and crash-recovery behavior are covered by tests.

## Persistence, backup, and recovery

The control directory contains three SQLite databases and their possible `-wal`/`-shm` companions. The artifact directory contains encrypted, write-once envelopes. A plain copy of only the main SQLite file while the process is running is not a valid backup.

The repository also provides attested SQLite components for immutable `DatasetSnapshotV2`, modern certification-evidence records, publication lineage, and the dedicated v4 workflow state. They enforce tenant identity, exact idempotency, correction-chain continuity, snapshot/evidence referential integrity, canonical JSON, append-only audit/state transitions, and no-update/no-delete triggers. These are durable local repository primitives, not active production dependencies: the checked-in remote process does not open or compose them. If an approved deployment later adopts them, place their databases and WAL/SHM companions inside the same application-consistent recovery boundary as the encrypted plan/result artifacts and job/security state.

Use CSI volume snapshots with application-consistent quiescing, or a tested SQLite online-backup/checkpoint workflow. Capture control, job, security, and artifact data at one documented recovery point and retain every encryption/signing key needed to read or verify retained records. Store key escrow separately from the volume snapshot.

At least quarterly, restore into an isolated namespace and prove:

- schema/version checks and integrity checks pass;
- active and historical mappings, evidence, audit events, jobs, nonces, and manifests remain tenant-bound;
- sampled artifact hashes and authenticated decryption verify;
- expired/replayed handles remain unusable;
- a known certified analysis reproduces its recorded digest;
- measured RPO/RTO meet the approved objective.

Never run two pods against the same SQLite files through a shared filesystem. After an unclean stop, inspect the pod event, storage health, SQLite integrity, outstanding leases, and audit continuity before restoring readiness.

The component schema registry is a greenfield baseline. Store startup attests the canonical registry plus every registered component table, index, and trigger, including object type, owner table, case-insensitive identity, and canonical DDL. Unexpected attached objects, missing receipts, name collisions, tampering, partial initialization, and unsupported newer versions fail closed. Do not point this release at an arbitrary database created before component-version receipts existed. Such a database requires an offline, backed-up, explicitly reviewed migration; only the fully attested legacy monitoring-alert form covered by the migration tests is adopted automatically.

The privileged operator CLI currently binds identity to the numeric OS account on one trusted host. Maker and checker accounts must be distinct and non-reused, and their control storage must not be shared across hosts or container UID namespaces. Request files cannot supply `actor`, `proposedBy`, or another identity override. The additive `definition-v2-*` commands persist in the shared control database but remain outside MCP and the remote runtime; get/list/effective-selection/audit responses expose lifecycle metadata, semantic diff paths, impact previews, and integrity hashes only, never definition documents or transition evidence. A cross-host operator topology requires a host- or IdP-bound trusted service identity before release.

## Secrets and key rotation

Secrets must come from the platform secret manager or CSI driver, not Git, image layers, ConfigMaps, command-line arguments, or MCP inputs. Restrict secret read access to the workload identity and security administrators. Signing and artifact key files must be absolute regular files owned/readable by the runtime UID with no group/world bits; the supplied distroless Node entrypoint stages them as UID 65532 mode `0400` in tmpfs. Disable service-account token mounting unless an environment-specific secret driver requires it.

Rotate artifact and signing keys by adding a new active key while retaining prior verification/decryption keys for the full artifact/handle retention period. Deploy readers before writers, verify old and new fixtures, then change the active key. Removing an old key is a separate retention/legal decision and requires restore evidence.

In connector deployments, rotate database credentials with a read-only replacement role/credential, confirm `NOSUPERUSER`, `NOBYPASSRLS`, non-owner status and SELECT-only grants, update the connector secret, restart gracefully, and inspect database audit logs. Tokens and database URLs must never appear in application logs or health responses.

## Observability and incident response

Ship stdout/stderr through the platform log collector and add request/trace correlation at the TLS edge. Do not log bearer tokens, secret file contents, connection strings, full prompts, raw rows, or unrestricted tool arguments. Alert on sustained readiness failure, authentication-deny spikes, policy errors, replay detections, job lease exhaustion, analysis timeouts, database saturation, volume pressure, artifact integrity failures, and audit gaps.

For a suspected data-boundary incident:

1. Remove the Service from the gateway or revoke the affected issuer/client while preserving volumes and logs.
2. Revoke/rotate bearer clients, database credentials, and signing keys according to scope; do not destroy old verification evidence.
3. Snapshot immutable evidence and database audit identifiers without copying raw portfolio data into the ticket.
4. Determine tenant, principal, tools, dataset/snapshot, policy/mapping versions, result handles, and exact time window.
5. Restore service only after cross-tenant canaries, replay tests, policy tests, and audit continuity pass.

## Local release evidence and known gaps

This repository intentionally contains no GitHub Actions workflow, and GitHub Actions is disabled in the repository settings. Operators run the locked installation, type checks, tests, build, production dependency audit, Compose rendering, Kustomize rendering, strict Kubernetes schema checks, Dockerfile checks, IaC scan, non-root/read-only container smoke, CycloneDX SBOM generation, image vulnerability scan, and repository secret scan from a trusted local or explicitly approved build environment. Scanner images and tool versions remain pinned by digest or version where the documented commands specify them.

Manual verification does not publish, sign, or deploy an image because no registry, signing identity, cluster, or environment has been authorized in this repository. Any future delivery system must add keyless or KMS-backed signing, provenance attestation, registry retention, environment approvals, digest promotion, canary verification, and rollback evidence before this can be called deployed; it must not use GitHub Actions unless the repository owner explicitly changes this policy.
