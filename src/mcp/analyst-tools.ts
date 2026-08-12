import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

import type { PolicyObligations } from "../security/policy.js";
import type { VerifiedPrincipalContext } from "../security/identity.js";

const identifier = z.string().min(1).max(256).regex(/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/u);
const opaqueHandle = z.string().min(20).max(2_048);
const scalar = z.union([z.string().max(4_096), z.boolean(), z.null()]);
const filter: z.ZodType<unknown> = z.lazy(() => z.union([
  z.object({
    type: z.literal("predicate"),
    field: identifier,
    operator: z.enum(["eq", "ne", "gt", "gte", "lt", "lte"]),
    value: scalar
  }).strict(),
  z.object({ type: z.literal("predicate"), field: identifier, operator: z.literal("in"), value: z.array(scalar).min(1).max(100) }).strict(),
  z.object({ type: z.literal("predicate"), field: identifier, operator: z.literal("is_null") }).strict(),
  z.object({ type: z.literal("and"), filters: z.array(filter).min(1).max(10) }).strict(),
  z.object({ type: z.literal("or"), filters: z.array(filter).min(1).max(10) }).strict()
]));

export interface GovernedAnalystToolResponse {
  readonly value: Readonly<Record<string, unknown>>;
  readonly obligations: readonly PolicyObligations[];
  readonly rowCount?: number;
}

export interface GovernedAnalystWorkflowApi {
  listMetrics(principal: VerifiedPrincipalContext, input: { readonly datasetId: string; readonly cursor?: string; readonly limit: number }, signal: AbortSignal): Promise<GovernedAnalystToolResponse>;
  listJobs(principal: VerifiedPrincipalContext, input: { readonly datasetId?: string; readonly cursor?: string; readonly limit: number }, signal: AbortSignal): Promise<GovernedAnalystToolResponse>;
  getJobEvents(principal: VerifiedPrincipalContext, input: { readonly jobHandle: string; readonly cursor?: string; readonly limit: number }, signal: AbortSignal): Promise<GovernedAnalystToolResponse>;
  explainResult(principal: VerifiedPrincipalContext, input: { readonly resultHandle: string; readonly cellReference?: string }, signal: AbortSignal): Promise<GovernedAnalystToolResponse>;
  createInvestigation(principal: VerifiedPrincipalContext, input: {
    readonly reference: { readonly kind: "snapshot" | "result"; readonly id: string };
    readonly requestedFields: readonly string[];
    readonly filter?: unknown;
    readonly purpose: string;
    readonly reason: string;
    readonly rowBudget: number;
    readonly reviewerPrincipalId?: string;
    readonly idempotencyKey: string;
  }, signal: AbortSignal): Promise<GovernedAnalystToolResponse>;
  getInvestigationRows(principal: VerifiedPrincipalContext, input: { readonly investigationId: string; readonly cursor?: string; readonly limit: number; readonly idempotencyKey: string }, signal: AbortSignal): Promise<GovernedAnalystToolResponse>;
  closeInvestigation(principal: VerifiedPrincipalContext, input: { readonly investigationId: string; readonly reason: string; readonly idempotencyKey: string }, signal: AbortSignal): Promise<GovernedAnalystToolResponse>;
  listReports(principal: VerifiedPrincipalContext, input: { readonly datasetId?: string; readonly cursor?: string; readonly limit: number }, signal: AbortSignal): Promise<GovernedAnalystToolResponse>;
  getReport(principal: VerifiedPrincipalContext, input: { readonly reportId: string }, signal: AbortSignal): Promise<GovernedAnalystToolResponse>;
}

export interface RegisterGovernedAnalystToolsOptions {
  readonly principal: VerifiedPrincipalContext;
  readonly api: GovernedAnalystWorkflowApi;
  readonly guarded: <T>(operation: () => Promise<T>) => Promise<T | unknown>;
  readonly format: (response: GovernedAnalystToolResponse, committed: boolean) => unknown;
}

const readOnly = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;
const internalWrite = { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;

/** Registers the additive analyst workflow tools on an authenticated governed MCP server. */
export function registerGovernedAnalystTools(server: McpServer, options: RegisterGovernedAnalystToolsOptions): void {
  server.registerTool("abl_list_metrics", {
    title: "List governed metrics",
    description: "List authorized metric definitions and methodology versions for one concrete dataset.",
    inputSchema: z.object({ dataset_id: identifier, cursor: z.string().max(1_024).optional(), limit: z.number().int().min(1).max(200).default(50) }).strict(),
    annotations: readOnly
  }, async ({ dataset_id, cursor, limit }, context) => options.guarded(async () =>
    options.format(await options.api.listMetrics(options.principal, {
      datasetId: dataset_id, ...(cursor ? { cursor } : {}), limit
    }, context.mcpReq.signal), false)) as never);

  server.registerTool("abl_list_jobs", {
    title: "List governed jobs",
    description: "List only jobs whose concrete dataset remains authorized under current policy.",
    inputSchema: z.object({ dataset_id: identifier.optional(), cursor: z.string().max(1_024).optional(), limit: z.number().int().min(1).max(200).default(50) }).strict(),
    annotations: readOnly
  }, async ({ dataset_id, cursor, limit }, context) => options.guarded(async () =>
    options.format(await options.api.listJobs(options.principal, {
      ...(dataset_id ? { datasetId: dataset_id } : {}), ...(cursor ? { cursor } : {}), limit
    }, context.mcpReq.signal), false)) as never);

  server.registerTool("abl_get_job_events", {
    title: "Get job stage history",
    description: "Return bounded durable stage and progress events for a principal-bound governed job.",
    inputSchema: z.object({ job_handle: opaqueHandle, cursor: z.string().max(1_024).optional(), limit: z.number().int().min(1).max(500).default(100) }).strict(),
    annotations: readOnly
  }, async ({ job_handle, cursor, limit }, context) => options.guarded(async () =>
    options.format(await options.api.getJobEvents(options.principal, {
      jobHandle: job_handle, ...(cursor ? { cursor } : {}), limit
    }, context.mcpReq.signal), false)) as never);

  server.registerTool("abl_explain_result", {
    title: "Explain governed result lineage",
    description: "Explain a result or cell using certified population, methodology, suppression, and contribution lineage.",
    inputSchema: z.object({ result_handle: opaqueHandle, cell_reference: z.string().min(1).max(512).optional() }).strict(),
    annotations: readOnly
  }, async ({ result_handle, cell_reference }, context) => options.guarded(async () =>
    options.format(await options.api.explainResult(options.principal, {
      resultHandle: result_handle, ...(cell_reference ? { cellReference: cell_reference } : {})
    }, context.mcpReq.signal), false)) as never);

  server.registerTool("abl_create_investigation", {
    title: "Create governed record investigation",
    description: "Create a short-lived, purpose-bound masked drill-through against a certified result or snapshot.",
    inputSchema: z.object({
      reference: z.object({ kind: z.enum(["snapshot", "result"]), id: identifier }).strict(),
      requested_fields: z.array(identifier).min(1).max(20),
      filter: filter.optional(),
      purpose: z.string().min(1).max(256),
      reason: z.string().min(1).max(2_048),
      row_budget: z.number().int().min(1).max(1_000).default(1_000),
      reviewer_principal_id: identifier.optional(),
      idempotency_key: identifier
    }).strict(),
    annotations: internalWrite
  }, async (input, context) => options.guarded(async () =>
    options.format(await options.api.createInvestigation(options.principal, {
      reference: input.reference,
      requestedFields: input.requested_fields,
      ...(input.filter === undefined ? {} : { filter: input.filter }),
      purpose: input.purpose,
      reason: input.reason,
      rowBudget: input.row_budget,
      ...(input.reviewer_principal_id ? { reviewerPrincipalId: input.reviewer_principal_id } : {}),
      idempotencyKey: input.idempotency_key
    }, context.mcpReq.signal), true)) as never);

  server.registerTool("abl_get_investigation_rows", {
    title: "Read masked investigation rows",
    description: "Read at most 100 masked rows per page and debit the immutable disclosure ledger.",
    inputSchema: z.object({ investigation_id: identifier, cursor: z.string().max(2_048).optional(), limit: z.number().int().min(1).max(100).default(100), idempotency_key: identifier }).strict(),
    annotations: readOnly
  }, async ({ investigation_id, cursor, limit, idempotency_key }, context) => options.guarded(async () =>
    options.format(await options.api.getInvestigationRows(options.principal, {
      investigationId: investigation_id, ...(cursor ? { cursor } : {}), limit, idempotencyKey: idempotency_key
    }, context.mcpReq.signal), false)) as never);

  server.registerTool("abl_close_investigation", {
    title: "Close governed investigation",
    description: "Close a principal-bound investigation and prevent additional record disclosure.",
    inputSchema: z.object({ investigation_id: identifier, reason: z.string().min(1).max(2_048), idempotency_key: identifier }).strict(),
    annotations: internalWrite
  }, async ({ investigation_id, reason, idempotency_key }, context) => options.guarded(async () =>
    options.format(await options.api.closeInvestigation(options.principal, {
      investigationId: investigation_id, reason, idempotencyKey: idempotency_key
    }, context.mcpReq.signal), true)) as never);

  server.registerTool("abl_list_reports", {
    title: "List signed report packs",
    description: "List authorized immutable aggregate reports and their approval/distribution state.",
    inputSchema: z.object({ dataset_id: identifier.optional(), cursor: z.string().max(1_024).optional(), limit: z.number().int().min(1).max(200).default(50) }).strict(),
    annotations: readOnly
  }, async ({ dataset_id, cursor, limit }, context) => options.guarded(async () =>
    options.format(await options.api.listReports(options.principal, {
      ...(dataset_id ? { datasetId: dataset_id } : {}), ...(cursor ? { cursor } : {}), limit
    }, context.mcpReq.signal), false)) as never);

  server.registerTool("abl_get_report", {
    title: "Get signed report pack",
    description: "Return one authorized aggregate report with warnings, suppression, comparisons, and manifest links.",
    inputSchema: z.object({ report_id: identifier }).strict(),
    annotations: readOnly
  }, async ({ report_id }, context) => options.guarded(async () =>
    options.format(await options.api.getReport(options.principal, { reportId: report_id }, context.mcpReq.signal), false)) as never);
}
