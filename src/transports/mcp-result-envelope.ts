export const MCP_UNTRUSTED_DATA_PREFIX = "UNTRUSTED_DATA_JSON:";
export const MCP_SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo";

export interface McpServerIdentity {
  readonly name: string;
  readonly version: string;
}

export interface McpCompatibilitySuccessResult extends Readonly<Record<string, unknown>> {
  readonly content: { type: "text"; text: string }[];
  readonly structuredContent: Record<string, unknown>;
}

/**
 * Builds the portable tools/call success shape used by both protocol eras.
 * The text block intentionally duplicates structuredContent for older hosts.
 */
export function mcpCompatibilitySuccessResult(value: unknown): McpCompatibilitySuccessResult {
  const json = JSON.stringify(value);
  if (json === undefined) throw new TypeError("MCP tool result is not JSON serializable");
  const structuredContent = JSON.parse(json) as unknown;
  if (structuredContent === null || typeof structuredContent !== "object" || Array.isArray(structuredContent)) {
    throw new TypeError("MCP structured tool result must be an object");
  }
  return {
    content: [{ type: "text" as const, text: `${MCP_UNTRUSTED_DATA_PREFIX}${json}` }],
    structuredContent: structuredContent as Record<string, unknown>
  };
}

/** Models the pinned SDK's modern complete-result fields for byte accounting. */
export function modernMcpCompleteResult(
  result: Readonly<Record<string, unknown>>,
  server: McpServerIdentity
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    ...result,
    resultType: "complete",
    _meta: Object.freeze({
      [MCP_SERVER_INFO_META_KEY]: Object.freeze({ name: server.name, version: server.version })
    })
  });
}

/** Exact UTF-8 size of the modern tools/call success result, excluding JSON-RPC framing. */
export function modernMcpSuccessResultByteLength(value: unknown, server: McpServerIdentity): number {
  const compatible = mcpCompatibilitySuccessResult(value);
  return Buffer.byteLength(JSON.stringify(modernMcpCompleteResult(compatible, server)), "utf8");
}
