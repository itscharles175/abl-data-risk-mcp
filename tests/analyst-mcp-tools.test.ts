import assert from "node:assert/strict";
import { test } from "node:test";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { McpServer, createMcpHandler } from "@modelcontextprotocol/server";

import { registerGovernedAnalystTools, type GovernedAnalystWorkflowApi } from "../src/mcp/analyst-tools.js";

const obligations = [{
  minimumCohortSize: 10,
  maxResultRows: 1_000,
  maxResultBytes: 1_000_000,
  maxExecutionMs: 30_000,
  allowRawRows: false,
  allowExport: false,
  requireImmutableSnapshot: true,
  rowFilterRefs: ["tenant-boundary"],
  fieldMasks: {},
  auditTags: ["analyst-workflow"]
}] as const;

test("additive analyst MCP registry exposes all nine portable workflows with bounded inputs", async () => {
  const calls: string[] = [];
  const response = (name: string, value: Record<string, unknown> = {}) => {
    calls.push(name);
    return Promise.resolve({ value: { operation: name, ...value }, obligations });
  };
  const api: GovernedAnalystWorkflowApi = {
    listMetrics: (_p, input) => response("list_metrics", { limit: input.limit }),
    listJobs: () => response("list_jobs"),
    getJobEvents: () => response("get_job_events"),
    explainResult: () => response("explain_result"),
    createInvestigation: (_p, input) => response("create_investigation", { fields: input.requestedFields }),
    getInvestigationRows: (_p, input) => response("get_investigation_rows", { limit: input.limit }),
    closeInvestigation: () => response("close_investigation"),
    listReports: () => response("list_reports"),
    getReport: () => response("get_report")
  };
  const handler = createMcpHandler(() => {
    const server = new McpServer({ name: "analyst-tools-test", version: "1" });
    registerGovernedAnalystTools(server, {
      principal: {} as never,
      api,
      guarded: async (operation) => operation(),
      format: (result) => ({
        structuredContent: result.value,
        content: [{ type: "text" as const, text: `UNTRUSTED_DATA_JSON:${JSON.stringify(result.value)}` }]
      })
    });
    return server;
  });
  const client = new Client({ name: "test", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  const transport = new StreamableHTTPClientTransport(new URL("http://test.local/mcp"), {
    fetch: (url, init) => handler.fetch(new Request(url, init))
  });
  await client.connect(transport);
  try {
    const names = (await client.listTools()).tools.map((tool) => tool.name).sort();
    assert.deepEqual(names, [
      "abl_close_investigation", "abl_create_investigation", "abl_explain_result",
      "abl_get_investigation_rows", "abl_get_job_events", "abl_get_report",
      "abl_list_jobs", "abl_list_metrics", "abl_list_reports"
    ]);
    const created = await client.callTool({
      name: "abl_create_investigation",
      arguments: {
        reference: { kind: "result", id: "result-a" },
        requested_fields: ["loan_id", "current_balance"],
        filter: { type: "predicate", field: "current_balance", operator: "gt", value: "100" },
        purpose: "Resolve a material concentration exception",
        reason: "Reviewer requested a bounded contribution trace",
        row_budget: 100,
        idempotency_key: "create-a"
      }
    });
    assert.equal(created.isError, undefined);
    assert.deepEqual((created.structuredContent as any).fields, ["loan_id", "current_balance"]);
    await client.callTool({ name: "abl_list_metrics", arguments: { dataset_id: "portfolio-a", limit: 25 } });
    assert.deepEqual(calls, ["create_investigation", "list_metrics"]);
  } finally {
    await client.close();
    await handler.close();
  }
});
