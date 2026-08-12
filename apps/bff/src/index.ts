import { buildApp } from "./app.js";
import { loadBffConfiguration } from "./config.js";

const configuration = loadBffConfiguration();
const app = buildApp({ configuration });

const server = app.listen(configuration.port, "127.0.0.1", () => {
  console.log(`ABL platform BFF listening on http://127.0.0.1:${configuration.port}`);
  console.log(`Authentication mode: ${configuration.authMode}; data adapter: fixture`);
});

const shutdown = (): void => {
  server.close((error) => {
    if (error) {
      console.error("BFF shutdown failed", error);
      process.exitCode = 1;
    }
  });
};

process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
