import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createPkcePair,
  OidcLoginRateLimiter,
  OidcTransactionCapacityError,
  OidcTransactionStore,
} from "../src/oidc.js";

describe("OIDC primitives", () => {
  it("creates an RFC 7636 S256 PKCE pair", () => {
    const pair = createPkcePair();
    expect(pair.verifier.length).toBeGreaterThanOrEqual(43);
    expect(pair.challenge).toBe(
      createHash("sha256").update(pair.verifier).digest("base64url"),
    );
    expect(pair.challenge).not.toBe(pair.verifier);
  });

  it("consumes an OIDC transaction exactly once and validates state", () => {
    const store = new OidcTransactionStore(() => new Date("2026-08-12T12:00:00.000Z"));
    const first = store.create({
      state: "state-a",
      nonce: "nonce-a",
      verifier: "verifier-a",
      returnTo: "/#/overview",
      stepUp: false,
    });
    expect(store.consume(first.id, "wrong-state")).toBeUndefined();
    expect(store.consume(first.id, "state-a")).toBeUndefined();

    const second = store.create({
      state: "state-b",
      nonce: "nonce-b",
      verifier: "verifier-b",
      returnTo: "/#/overview",
      stepUp: true,
      sessionId: "session-a",
    });
    expect(store.consume(second.id, "state-b")).toMatchObject({ id: second.id, stepUp: true });
    expect(store.consume(second.id, "state-b")).toBeUndefined();
  });

  it("bounds outstanding transactions and sweeps expired entries", () => {
    let current = new Date("2026-08-12T12:00:00.000Z");
    const store = new OidcTransactionStore(() => current, 60_000, 1);
    const input = {
      state: "state-a",
      nonce: "nonce-a",
      verifier: "verifier-a",
      returnTo: "/#/overview",
      stepUp: false,
    } as const;
    store.create(input);
    expect(() => store.create({ ...input, state: "state-b" })).toThrow(OidcTransactionCapacityError);
    current = new Date("2026-08-12T12:01:00.000Z");
    expect(store.size).toBe(0);
    expect(store.create({ ...input, state: "state-c" }).state).toBe("state-c");
  });

  it("rate-limits per key with bounded state and resets after the window", () => {
    let current = new Date("2026-08-12T12:00:00.000Z");
    const limiter = new OidcLoginRateLimiter(2, 60_000, 1, () => current);
    expect(limiter.allow("login:127.0.0.1")).toBe(true);
    expect(limiter.allow("login:127.0.0.1")).toBe(true);
    expect(limiter.allow("login:127.0.0.1")).toBe(false);
    expect(limiter.allow("login:192.0.2.7")).toBe(false);
    expect(limiter.size).toBe(1);
    current = new Date("2026-08-12T12:01:00.000Z");
    expect(limiter.allow("login:192.0.2.7")).toBe(true);
  });
});
