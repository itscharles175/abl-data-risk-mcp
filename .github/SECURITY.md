# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through [GitHub Security Advisories](https://github.com/itscharles175/abl-data-risk-mcp/security/advisories/new). Do not include customer loan data, credentials, access tokens, database URLs, or production configuration.

Include the affected commit or version, the trust boundary involved, a minimal reproduction using synthetic data, the expected impact, and any suggested containment. Please avoid public disclosure until the issue has been triaged and a coordinated resolution is available.

## Scope

High-priority reports include cross-tenant disclosure, authorization or policy bypass, signed-plan or handle forgery, source mutation, secret exposure, SQL escape, suppression bypass, audit tampering, and deterministic-analysis integrity failures.

The repository's detailed security architecture and explicit operational assumptions are documented in [docs/SECURITY.md](../docs/SECURITY.md).
