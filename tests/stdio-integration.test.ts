import assert from "node:assert/strict";
import { resolve } from "node:path";
import { test } from "node:test";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

import { createSqliteFixture } from "./helpers/sqlite-fixture.js";

for (const [label, mode] of [
  ["legacy 2025", "legacy"],
  ["modern 2026", { pin: "2026-07-28" }]
] as const) {
  test(`stdio launcher serves ${label} clients without stdout noise`, async () => {
    const fixture = createSqliteFixture();
    const client = new Client(
      { name: "abl-mcp-stdio-test", version: "1.0.0" },
      { versionNegotiation: { mode } }
    );
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [
        "--import",
        "tsx",
        resolve("src/cli.ts"),
        "serve",
        "stdio",
        "--config",
        fixture.configPath
      ],
      cwd: process.cwd(),
      stderr: "pipe"
    });

    try {
      await client.connect(transport);
      const result = await client.callTool({ name: "abl_capabilities" });
      assert.equal((result.structuredContent as { version?: string } | undefined)?.version, "0.1.0");
    } finally {
      await client.close();
      fixture.cleanup();
    }
  });
}
