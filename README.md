# ABL Data & Risk MCP

A model-agnostic, read-only MCP server for governed asset-based lending (ABL) and loan-tape analytics.

The product thesis is deliberately narrower and safer than “chat with SQL”:

> The model expresses intent, proposes mappings, and explains results. Deterministic code maps fields, compiles governed queries, calculates portfolio facts, reconciles totals, and preserves lineage.

This repository is a working greenfield vertical slice. It currently provides:

- one server factory that supports legacy 2025-era and modern 2026-era MCP clients;
- STDIO for Codex, Claude Desktop, Claude Code, and other local MCP hosts;
- Streamable HTTP on a loopback-only development launcher;
- allowlisted PostgreSQL and SQLite source adapters;
- a 67-field canonical loan-tape and ABL dictionary;
- explainable, deterministic field-mapping suggestions and readiness validation;
- aggregate-only stratification tables for one explicit snapshot date;
- sparse loan vintage analysis from repeated snapshots;
- structured tool results plus JSON text fallbacks for client portability;
- no generic SQL tool, raw-row preview, source writes, or model-side calculations.

The larger product direction—including borrowing-base reperformance, automation, monitoring, and the production trust model—is captured in [Product Blueprint](./docs/PRODUCT_BLUEPRINT.md), [Architecture](./docs/ARCHITECTURE.md), [Security](./docs/SECURITY.md), and [Roadmap](./docs/ROADMAP.md).

## Why this shape

Loan and collateral data is semantically dangerous even when SQL is syntactically correct. A field called `balance` may mean original principal, current principal, gross receivables, eligible receivables, lender share, or borrower-reported capacity. A vintage curve is not defensible without a fixed cohort, repeated observations or events, an explicit denominator, and treatment for unseasoned periods. A borrowing base is a legal-policy waterfall whose rule ordering matters.

The MCP therefore exposes domain operations, not unrestricted execution:

1. inspect an operator-approved source;
2. map it to governed canonical fields;
3. validate grain, type, and profile coverage;
4. run a versioned analysis recipe;
5. return bounded aggregates, reconciliation, warnings, and lineage.

## Current MCP tools

| Tool | Purpose |
|---|---|
| `abl_capabilities` | Report protocol, transport, source, and safety capabilities. |
| `abl_list_sources` | List configured source IDs and allowlists without credentials. |
| `abl_list_tables` | List allowlisted tables/views for one source. |
| `abl_describe_table` | Return names, types, nullability, and restriction flags—never comments or values. |
| `abl_list_dictionary` | Read/filter the canonical lending dictionary. |
| `abl_suggest_mapping` | Rank mapping candidates with explicit evidence and type checks. |
| `abl_validate_mapping` | Validate mapping uniqueness, types, and profile readiness. |
| `abl_run_stratification` | Build a reconciled strat table for one explicit as-of date. |
| `abl_run_vintage` | Build cohort/month observations from longitudinal snapshots. |

The canonical dictionary and methodology are also exposed as optional MCP resources. Tools remain the portable source of truth because client support for resources and prompts varies.

## Quick start

Requirements: Node.js 22.13+ and pnpm.

```sh
pnpm install
pnpm run verify
pnpm run audit:prod
pnpm build
```

Copy [config/example.json](./config/example.json) and change only non-secret source policy. Database URLs must live in the environment variable named by `connectionEnv`; they must never be written into config or passed as tool arguments.

Start the local STDIO server:

```sh
ABL_MCP_CONFIG=/absolute/path/to/config.json node dist/cli.js serve stdio
```

Start the loopback-only Streamable HTTP server:

```sh
node dist/cli.js serve http --config /absolute/path/to/config.json --port 3333
```

The bundled HTTP launcher refuses non-loopback binds. A remote deployment must mount `createAblHttpHandler` behind an OAuth/OIDC resource-server gateway that validates issuer, audience, subject, tenant, scopes, Host, and Origin before MCP dispatch.

## Codex configuration

Project-scoped `.codex/config.toml`:

```toml
[mcp_servers.abl]
command = "node"
args = [
  "/absolute/path/to/SQLProject/dist/cli.js",
  "serve",
  "stdio",
  "--config",
  "/absolute/path/to/SQLProject/config/local.json"
]
default_tools_approval_mode = "writes"
tool_timeout_sec = 60
```

Codex supports STDIO and Streamable HTTP. See the current [OpenAI Codex MCP documentation](https://developers.openai.com/codex/extend/mcp).

## Claude configuration

Project `.mcp.json` for a local server:

```json
{
  "mcpServers": {
    "abl": {
      "type": "stdio",
      "command": "node",
      "args": [
        "/absolute/path/to/SQLProject/dist/cli.js",
        "serve",
        "stdio",
        "--config",
        "/absolute/path/to/SQLProject/config/local.json"
      ]
    }
  }
}
```

Claude Code also supports remote Streamable HTTP. See the current [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).

## Source configuration

Sources are operator-controlled and closed-world:

```json
{
  "sources": [
    {
      "id": "portfolio",
      "dialect": "postgres",
      "connectionEnv": "ABL_PORTFOLIO_DATABASE_URL",
      "allowedSchemas": ["analytics"],
      "allowedTables": ["analytics.loan_tape"],
      "restrictedColumns": ["customer_legal_name"],
      "statementTimeoutMs": 15000,
      "maxResultRows": 500
    }
  ],
  "analysis": {
    "maxGroups": 200,
    "maxVintagePoints": 5000,
    "minimumCohortSize": 10
  }
}
```

The runtime resolves every requested table against this allowlist. Analysis SQL is generated only from exact catalog matches and canonical mappings. PostgreSQL analysis runs inside a read-only transaction with statement and lock timeouts. SQLite is useful for local development and golden tests; its dynamic numeric representation is not a substitute for a production exact-decimal warehouse.

## Analysis semantics

Stratifications:

- require one explicit `as_of_date`;
- always include null values as `Unknown/Unmapped`;
- require explicit buckets for numeric dimensions;
- reject dictionary fields classified as restricted from dimensions and weighted outputs;
- return count, balance, balance share, and up to five weighted averages;
- reconcile bucket count/balance to the selected population;
- suppress small and complementary cells using the server threshold.

Vintages:

- require longitudinal snapshots or event history;
- fix cohort membership from origination date;
- deduplicate to the latest observation per loan/month-on-book;
- use original cohort balance as the loss and remaining-balance denominator;
- omit unseasoned cohort/month cells so callers render them as `null`, never zero;
- disclose whether cumulative net loss and delinquency inputs are mapped;
- suppress small cohorts.

Current live-table fingerprints identify the mapping and compiled query, but do not make a result audit-reproducible. Production runs need an immutable snapshot/content hash and versioned mapping, recipe, policy, FX, and compiler metadata.

## Verification

```sh
pnpm run verify
```

The suite covers the dictionary and mapper, a real read-only SQLite fixture, stratification/vintage golden results, output-schema validation, JSON text fallbacks, and both MCP protocol eras over HTTP and a spawned STDIO process. Separate manual smokes with Codex CLI `0.147.0-alpha.6.5` successfully called `abl_capabilities` over both STDIO and loopback Streamable HTTP; real Claude Code remains a release gate.

`pnpm run audit:prod` checks the locked production dependency graph. The workspace pins a patched Hono Node adapter because the MCP Node package's declared transitive range otherwise resolves to a version affected by GHSA-frvp-7c67-39w9.

## Current limits

- PostgreSQL is implemented but not yet certified against a live integration environment in this repository.
- CSV, XLSX, Parquet, Snowflake, BigQuery, SQL Server, and MySQL are roadmap adapters, not current claims.
- There is no mapping persistence/approval workflow yet; mappings are passed explicitly into an analysis call.
- There is no arbitrary SQL, raw-row export, scheduler, alert dispatcher, or source-system write path.
- Borrowing-base calculation is designed but not yet implemented in code.
- The local HTTP launcher is for development, not an internet-facing production service.

These constraints are intentional. The next useful milestone is a snapshot-backed pilot with persisted mapping versions, data-quality/reconciliation manifests, saved strat recipes, and one real portfolio—not a broader ungoverned query surface.
