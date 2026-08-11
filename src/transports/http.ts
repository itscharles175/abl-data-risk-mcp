import { createMcpExpressApp } from "@modelcontextprotocol/express";
import { toNodeHandler } from "@modelcontextprotocol/node";
import { createMcpHandler } from "@modelcontextprotocol/server";

import type { ServerServices } from "../server.js";
import { buildServer } from "../server.js";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1"]);

export function createAblHttpHandler(services: ServerServices) {
  return createMcpHandler(() => buildServer(services));
}

export async function startLocalHttp(services: ServerServices, host: string, port: number) {
  if (!LOOPBACK_HOSTS.has(host)) {
    throw new Error(
      "The bundled HTTP launcher is local-only. Mount createAblHttpHandler behind an OAuth/OIDC resource-server gateway for non-loopback deployment."
    );
  }
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) throw new Error("HTTP port must be 1..65535");

  const handler = createAblHttpHandler(services);
  const nodeHandler = toNodeHandler(handler);
  const app = createMcpExpressApp({ host });

  app.get("/healthz", (_request, response) => {
    response.status(200).json({ status: "ok" });
  });
  app.all("/mcp", (request, response) => {
    void nodeHandler(request, response, request.body);
  });

  const listener = await new Promise<ReturnType<typeof app.listen>>((resolve, reject) => {
    const server = app.listen(port, host, () => resolve(server));
    server.once("error", reject);
  });

  return {
    close: async () => {
      await handler.close();
      await new Promise<void>((resolve, reject) => {
        listener.close((error) => (error ? reject(error) : resolve()));
      });
    }
  };
}
