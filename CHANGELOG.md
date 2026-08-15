# Changelog

This file records notable repository-level changes. The project has not declared a production release or semantic-version stability beyond the explicitly supported package subpaths.

## Unreleased

### Added

- A locally composed, production-disabled single-facility V2 surveillance pilot spanning governed capture, certification, publication, durable V4 execution, correction handling, and result recovery.
- A durable composite opaque-handle router for legacy jobs and the V4 surveillance lane.
- Optional BFF and console surfaces for IDs-only pilot job start, status, result, and cancellation.
- Supported package subpaths for contracts, repositories, and pilot composition services.
- Synthetic ABS/auto acceptance fixtures and executable vertical acceptance coverage.

### Changed

- Public-facing product identity is Aegis Ledger; existing package names, executable names, environment-variable prefixes, and protocol identifiers remain stable for compatibility.
- Repository verification and release evidence remain operator-run; GitHub Actions workflows are intentionally absent.

### Security

- The pilot remains aggregate-only, tenant/facility fenced, principal-bound, purpose-bound, and disabled for production/remote advertisement by default.

## 0.1.0 — development baseline

- Initial governed ABL and loan-tape analytics MCP implementation.
