#!/usr/bin/env node

import { loadConfig } from "./config.js";
import { SourceRegistry } from "./infrastructure/sql/registry.js";
import { startLocalHttp } from "./transports/http.js";
import { startStdio } from "./transports/stdio.js";

interface CliOptions {
  readonly transport: "stdio" | "http";
  readonly configPath?: string;
  readonly host: string;
  readonly port: number;
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const config = loadConfig(options.configPath);
  const registry = new SourceRegistry(config);
  const services = { config, registry };

  if (options.transport === "stdio") {
    const handle = startStdio(services);
    installShutdown(async () => {
      await handle.close();
      await registry.close();
    });
    return;
  }

  const http = await startLocalHttp(services, options.host, options.port);
  console.error(`abl-data listening at http://${formatHost(options.host)}:${options.port}/mcp`);
  installShutdown(async () => {
    await http.close();
    await registry.close();
  });
}

function parseArgs(args: readonly string[]): CliOptions {
  let transport: "stdio" | "http" = "stdio";
  let configPath: string | undefined;
  let host = process.env.ABL_MCP_HOST ?? "127.0.0.1";
  let port = parsePort(process.env.ABL_MCP_PORT ?? "3333");
  const positionals: string[] = [];

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (!argument) continue;
    if (argument === "--help" || argument === "-h") {
      printHelp();
      process.exit(0);
    }
    if (argument === "--config") {
      configPath = requiredValue(args, ++index, "--config");
      continue;
    }
    if (argument === "--host") {
      host = requiredValue(args, ++index, "--host");
      continue;
    }
    if (argument === "--port") {
      port = parsePort(requiredValue(args, ++index, "--port"));
      continue;
    }
    if (argument.startsWith("--")) throw new Error(`Unknown option: ${argument}`);
    positionals.push(argument);
  }

  if (positionals[0] && positionals[0] !== "serve") throw new Error(`Unknown command: ${positionals[0]}`);
  if (positionals[1]) {
    if (positionals[1] !== "stdio" && positionals[1] !== "http") {
      throw new Error(`Unknown transport: ${positionals[1]}`);
    }
    transport = positionals[1];
  }
  if (positionals.length > 2) throw new Error(`Unexpected argument: ${positionals[2]}`);

  return { transport, ...(configPath ? { configPath } : {}), host, port };
}

function requiredValue(args: readonly string[], index: number, option: string): string {
  const value = args[index];
  if (!value) throw new Error(`${option} requires a value`);
  return value;
}

function parsePort(value: string): number {
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) throw new Error(`Invalid port: ${value}`);
  return port;
}

function formatHost(host: string): string {
  return host.includes(":") ? `[${host}]` : host;
}

function installShutdown(close: () => Promise<void>): void {
  let closing = false;
  const shutdown = () => {
    if (closing) return;
    closing = true;
    void close()
      .catch(() => {
        process.exitCode = 1;
      })
      .finally(() => process.exit());
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

function printHelp(): void {
  process.stderr.write(`Usage: abl-mcp serve [stdio|http] [options]\n\n`);
  process.stderr.write(`Options:\n`);
  process.stderr.write(`  --config PATH   Non-secret source configuration JSON\n`);
  process.stderr.write(`  --host HOST     Local HTTP bind (default: 127.0.0.1)\n`);
  process.stderr.write(`  --port PORT     Local HTTP port (default: 3333)\n`);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "ABL MCP failed to start";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
