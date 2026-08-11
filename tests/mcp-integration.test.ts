import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createMcpHandler } from "@modelcontextprotocol/server";

import { SourceRegistry } from "../src/infrastructure/sql/registry.js";
import { buildServer } from "../src/server.js";
import { createSqliteFixture, type SqliteFixture } from "./helpers/sqlite-fixture.js";

let fixture: SqliteFixture;
let registry: SourceRegistry;
let handler: ReturnType<typeof createMcpHandler>;

before(() => {
  fixture = createSqliteFixture();
  registry = new SourceRegistry(fixture.config);
  handler = createMcpHandler(() => buildServer({ config: fixture.config, registry }));
});

after(async () => {
  await handler.close();
  await registry.close();
  fixture.cleanup();
});

for (const [label, mode] of [
  ["legacy 2025", "legacy"],
  ["modern 2026", { pin: "2026-07-28" }]
] as const) {
  test(`HTTP handler serves ${label} clients with structured and text results`, async () => {
    const client = new Client(
      { name: "abl-mcp-test", version: "1.0.0" },
      { versionNegotiation: { mode } }
    );
    const transport = new StreamableHTTPClientTransport(new URL("http://test.local/mcp"), {
      fetch: (url, init) => handler.fetch(new Request(url, init))
    });

    await client.connect(transport);
    try {
      const tools = await client.listTools();
      assert.ok(tools.tools.some((tool) => tool.name === "abl_run_stratification"));
      const result = await client.callTool({
        name: "abl_run_stratification",
        arguments: {
          source_id: "fixture",
          table: { schema: "main", table: "loan_tape" },
          as_of_date: "2025-03-31",
          mappings: fixture.mappings,
          dimension: "risk_rating",
          weighted_average_fields: ["interest_rate"]
        }
      });
      assert.equal(result.isError, undefined);
      assert.equal((result.structuredContent as { totals?: { balance?: string } } | undefined)?.totals?.balance, "410");
      assert.equal(result.content[0]?.type, "text");
      assert.match(result.content[0]?.type === "text" ? result.content[0].text : "", /"analysisType":"stratification"/);
    } finally {
      await client.close();
    }
  });
}
