import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadConfig } from "../src/config.js";

test("configuration is closed-world and resolves relative SQLite paths from the config file", () => {
  const directory = mkdtempSync(join(tmpdir(), "abl-mcp-config-test-"));
  try {
    const validPath = join(directory, "valid.json");
    writeFileSync(
      validPath,
      JSON.stringify({
        sources: [
          {
            id: "fixture",
            dialect: "sqlite",
            path: "data.sqlite",
            allowedSchemas: ["main"],
            allowedTables: ["main.loan_tape"]
          }
        ]
      })
    );
    const config = loadConfig(validPath);
    const source = config.sources[0];
    assert.equal(source?.dialect, "sqlite");
    assert.equal(source?.dialect === "sqlite" ? source.path : "", join(directory, "data.sqlite"));

    const invalidPath = join(directory, "invalid.json");
    writeFileSync(
      invalidPath,
      JSON.stringify({
        sources: [],
        analysis: { minimumCohortSize: 10, maxGroups: 200, maxVintagePoints: 5000, minimumCohortSze: 1 }
      })
    );
    assert.throws(() => loadConfig(invalidPath), /Unrecognized key/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
