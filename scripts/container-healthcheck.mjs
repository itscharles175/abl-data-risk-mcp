#!/usr/bin/env node

const defaultPort = process.env.ABL_MCP_PORT ?? "3333";
const target = process.argv[2] ?? process.env.ABL_MCP_HEALTH_URL ?? `http://127.0.0.1:${defaultPort}/healthz`;

let url;
try {
  url = new URL(target);
} catch {
  fail("health URL is invalid");
}

if (url.protocol !== "http:" && url.protocol !== "https:") fail("health URL must use HTTP or HTTPS");
if (url.username || url.password) fail("health URL must not contain credentials");

try {
  const response = await fetch(url, {
    headers: { accept: "application/json" },
    redirect: "error",
    signal: AbortSignal.timeout(4_000)
  });
  if (!response.ok) fail(`health endpoint returned HTTP ${response.status}`);

  const declaredLength = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(declaredLength) && declaredLength > 65_536) fail("health response is too large");
  const body = await response.text();
  if (Buffer.byteLength(body, "utf8") > 65_536) fail("health response is too large");

  let document;
  try {
    document = JSON.parse(body);
  } catch {
    fail("health endpoint did not return JSON");
  }
  if (!document || typeof document !== "object" || !["ok", "ready"].includes(document.status)) {
    fail("health endpoint did not report an accepted status");
  }
} catch (error) {
  if (error instanceof Error && error.message.startsWith("container healthcheck:")) throw error;
  fail("health request failed");
}

function fail(message) {
  process.stderr.write(`container healthcheck: ${message}\n`);
  process.exit(1);
}
