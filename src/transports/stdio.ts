import { serveStdio } from "@modelcontextprotocol/server/stdio";

import type { ServerServices } from "../server.js";
import { buildServer, SERVER_NAME, SERVER_VERSION } from "../server.js";

export function startStdio(services: ServerServices) {
  const handle = serveStdio(() => buildServer(services), { legacy: "serve" });
  console.error(`${SERVER_NAME} ${SERVER_VERSION} listening on stdio`);
  return handle;
}
