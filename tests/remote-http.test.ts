import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import { afterEach, test } from "node:test";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { McpServer, type McpRequestContext } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

import { createVerifiedPrincipalContext } from "../src/security/identity.js";
import { OAuthAuthenticationError, type JwtOAuthAuthenticator } from "../src/security/oauth.js";
import {
  startRemoteHttp,
  type RemoteHttpServerHandle
} from "../src/transports/remote-http.js";

const handles: RemoteHttpServerHandle[] = [];

afterEach(async () => {
  await Promise.all(handles.splice(0).map((handle) => handle.close()));
});

const principal = createVerifiedPrincipalContext({
  issuer: "https://issuer.example.com/",
  subject: "subject-1",
  principalId: "analyst-1",
  tenantId: "tenant-a",
  clientId: "test-client",
  audiences: ["abl-api"],
  resourceIndicators: ["https://mcp.example.test/mcp"],
  scopes: ["metadata:read"],
  credentialFingerprint: "a".repeat(64),
  verifiedAtEpochSeconds: 1_786_440_000,
  expiresAtEpochSeconds: 4_000_000_000
});

const authenticator: JwtOAuthAuthenticator = {
  async authenticateAuthorizationHeader(header) {
    if (header !== "Bearer valid-test-token") {
      throw new OAuthAuthenticationError("INVALID_TOKEN", "Access token is invalid", 401, "invalid_token");
    }
    return principal;
  }
};

function buildServer(context: McpRequestContext) {
  const server = new McpServer({ name: "remote-test", version: "1.0.0" });
  server.registerTool(
    "whoami",
    {
      outputSchema: z.object({ tenantId: z.string(), rawTokenRetained: z.boolean() }),
      annotations: { readOnlyHint: true }
    },
    async () => {
      const verified = context.authInfo?.extra?.verifiedPrincipal as { tenantId?: string } | undefined;
      const output = {
        tenantId: verified?.tenantId ?? "missing",
        rawTokenRetained: context.authInfo?.token === "valid-test-token"
      };
      return { structuredContent: output, content: [{ type: "text", text: JSON.stringify(output) }] };
    }
  );
  return server;
}

async function start(
  overrides: Readonly<{
    allowedHosts?: readonly string[];
    allowedOrigins?: readonly string[];
    authenticator?: JwtOAuthAuthenticator;
    rateLimitWindowMs?: number;
    maxRequestsPerWindow?: number;
  }> = {}
) {
  const port = await reservePort();
  const handle = await startRemoteHttp({
    host: "127.0.0.1",
    port,
    allowedHosts: overrides.allowedHosts ?? [`127.0.0.1:${port}`, "client.example:8443", "[2001:db8::1]:8443"],
    allowedOrigins: overrides.allowedOrigins ?? ["https://client.example"],
    resource: "https://mcp.example.com/mcp",
    authorizationServers: ["https://issuer.example.com/"],
    scopesSupported: ["metadata:read"],
    resourceName: "ABL MCP",
    authenticator: overrides.authenticator ?? authenticator,
    serverFactory: buildServer,
    readiness: () => true,
    ...(overrides.rateLimitWindowMs === undefined
      ? {}
      : { rateLimitWindowMs: overrides.rateLimitWindowMs }),
    ...(overrides.maxRequestsPerWindow === undefined
      ? {}
      : { maxRequestsPerWindow: overrides.maxRequestsPerWindow })
  });
  handles.push(handle);
  return handle;
}

test("health is probe-safe while MCP and metadata enforce Host", async () => {
  const handle = await start();
  const base = `http://127.0.0.1:${handle.port}`;
  assert.equal((await fetch(`${base}/healthz`, { headers: { Host: "pod-ip.invalid" } })).status, 200);
  const metadataPath = new URL(handle.resourceMetadataUrl).pathname;
  assert.equal(await rawStatus(`${base}${metadataPath}`, { Host: "evil.example" }), 403);
  const metadata = await fetch(`${base}${metadataPath}`);
  assert.equal(metadata.status, 200);
  assert.equal((await metadata.json() as { resource?: string }).resource, "https://mcp.example.com/mcp");
});

test("unauthenticated MCP calls receive a token-free RFC 9728 challenge", async () => {
  const handle = await start();
  const response = await fetch(`http://127.0.0.1:${handle.port}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} })
  });
  assert.equal(response.status, 401);
  assert.match(response.headers.get("www-authenticate") ?? "", /resource_metadata=/);
  assert.equal((await response.text()).includes("valid-test-token"), false);
});

test("Host and Origin policies accept canonical ports and IPv6 while rejecting malformed entries", async () => {
  const handle = await start();
  const base = `http://127.0.0.1:${handle.port}`;
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });

  const blocked = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      Host: `127.0.0.1:${handle.port}`,
      Origin: "https://evil.example",
      "Content-Type": "application/json"
    },
    body
  });
  assert.equal(blocked.status, 403);

  const challenged = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      Host: `127.0.0.1:${handle.port}`,
      Origin: "https://client.example",
      "Content-Type": "application/json"
    },
    body
  });
  assert.equal(challenged.status, 401);

  await assert.rejects(() => start({ allowedHosts: ["client.example/path"] }), /Allowed host is invalid/);
  await assert.rejects(() => start({ allowedHosts: ["*.example"] }), /Allowed host is invalid/);
  await assert.rejects(() => start({ allowedOrigins: ["http://client.example"] }), /Allowed origin is invalid/);
  await assert.rejects(
    () => start({ allowedOrigins: ["https://user:password@client.example"] }),
    /Allowed origin is invalid/
  );
});

test("rate limits use the configured window and stable principal binding across token refresh", async () => {
  const refreshedPrincipal = createVerifiedPrincipalContext({
    issuer: principal.issuer,
    subject: principal.subject,
    principalId: principal.principalId,
    tenantId: principal.tenantId,
    clientId: principal.clientId,
    audiences: principal.audiences,
    resourceIndicators: principal.resourceIndicators,
    scopes: principal.scopes,
    credentialFingerprint: "b".repeat(64),
    verifiedAtEpochSeconds: principal.verifiedAtEpochSeconds + 1,
    expiresAtEpochSeconds: principal.expiresAtEpochSeconds
  });
  const rotatingAuthenticator: JwtOAuthAuthenticator = {
    async authenticateAuthorizationHeader(header) {
      if (header === "Bearer first-test-token") return principal;
      if (header === "Bearer refreshed-test-token") return refreshedPrincipal;
      throw new OAuthAuthenticationError("INVALID_TOKEN", "Access token is invalid", 401, "invalid_token");
    }
  };
  const handle = await start({
    authenticator: rotatingAuthenticator,
    rateLimitWindowMs: 1_000,
    maxRequestsPerWindow: 1
  });
  const url = `http://127.0.0.1:${handle.port}/mcp`;
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping", params: {} });
  const request = (token: string) =>
    fetch(url, {
      method: "POST",
      headers: {
        Host: `127.0.0.1:${handle.port}`,
        Origin: "https://client.example",
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body
    });

  const windowRemainder = Date.now() % 1_000;
  if (windowRemainder > 500) {
    await new Promise<void>((resolveDelay) => setTimeout(resolveDelay, 1_020 - windowRemainder));
  }
  const first = await request("first-test-token");
  assert.notEqual(first.status, 429);
  const second = await request("refreshed-test-token");
  assert.equal(second.status, 429);
  assert.equal(second.headers.get("retry-after"), "1");
});

for (const [label, mode] of [
  ["legacy", "legacy"],
  ["modern", { pin: "2026-07-28" }]
] as const) {
  test(`authenticated ${label} client receives verified tenant context without bearer retention`, async () => {
    const handle = await start();
    const client = new Client(
      { name: "remote-http-test", version: "1.0.0" },
      { versionNegotiation: { mode } }
    );
    const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${handle.port}/mcp`), {
      requestInit: {
        headers: {
          Host: `127.0.0.1:${handle.port}`,
          Origin: "https://client.example",
          Authorization: "Bearer valid-test-token"
        }
      }
    });
    await client.connect(transport);
    try {
      const result = await client.callTool({ name: "whoami", arguments: {} });
      assert.deepEqual(result.structuredContent, { tenantId: "tenant-a", rawTokenRetained: false });
    } finally {
      await client.close();
    }
  });
}

async function rawStatus(url: string, headers: Readonly<Record<string, string>>): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const request = httpRequest(url, { headers }, (response) => {
      response.resume();
      response.once("end", () => resolve(response.statusCode ?? 0));
    });
    request.once("error", reject);
    request.end();
  });
}

async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  assert(address && typeof address === "object");
  const port = address.port;
  await new Promise<void>((resolveClose, rejectClose) => {
    server.close((error) => (error ? rejectClose(error) : resolveClose()));
  });
  return port;
}
