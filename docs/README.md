# Documentation

This index separates architectural intent, runnable operator procedures, and status evidence. Read claims with their stated boundary: local deterministic coverage is not live-environment certification.

## Start here

| Document | Use it for |
|---|---|
| [Architecture](./ARCHITECTURE.md) | Trust boundaries, runtime components, data flow, and deployment topology |
| [Security](./SECURITY.md) | Threat model, authorization boundaries, data handling, and known assumptions |
| [Operations](./OPERATIONS.md) | Runtime configuration, container/Kubernetes templates, backup, recovery, and incident procedures |
| [Operator verification](./OPERATOR_VERIFICATION.md) | Exact local and opt-in external verification commands and evidence semantics |
| [Release checklist](./RELEASE_CHECKLIST.md) | Human sign-off and promotion gates for a specific immutable commit |

## Product and delivery status

| Document | Use it for |
|---|---|
| [Product blueprint](./PRODUCT_BLUEPRINT.md) | Target product behavior and governed user journeys |
| [Roadmap](./ROADMAP.md) | Sequenced follow-on capabilities; it is not a current-capability claim |
| [Upgrade implementation status](./UPGRADE_IMPLEMENTATION.md) | Code/conformance status versus environment gates by release area |
| [Upgrade checkpoint](./UPGRADE_CHECKPOINT.md) | Current handoff, verified stopping point, and next implementation slices |
| [Synthetic ABS/auto acceptance](./SYNTHETIC_ABS_AUTO_ACCEPTANCE.md) | Synthetic fixture scope and executable acceptance evidence |

## Workspace applications

- [BFF](../apps/bff/README.md) — browser authentication/session boundary and optional pilot job port.
- [Console](../apps/console/README.md) — React review and administration interface.
- [Shared contracts](../apps/contracts/README.md) — browser-safe request/response schemas shared by the BFF and console.

## Evidence policy

This repository intentionally contains no GitHub Actions workflows. Trusted operators run verification and release commands in approved environments, retain the generated evidence, and record any external gate that was not run. `local_pass_external_not_run` is local conformance evidence only; it is not production approval.
