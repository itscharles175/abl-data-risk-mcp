import { randomBytes } from "node:crypto";
import {
  permissionsForRoles,
  type SessionPrincipal,
  type SessionView,
} from "@abl/platform-contracts";

export const SESSION_COOKIE = "abl_platform_session";
export const OIDC_TRANSACTION_COOKIE = "abl_oidc_transaction";

export interface SessionRecord {
  readonly id: string;
  readonly principal: SessionPrincipal;
  readonly csrfToken: string;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly stepUpUntil?: Date;
}

export interface SessionStore {
  create(principal: SessionPrincipal): SessionRecord;
  get(id: string): SessionRecord | undefined;
  satisfyStepUp(id: string): SessionRecord | undefined;
  delete(id: string): void;
}

export class InMemorySessionStore implements SessionStore {
  readonly #records = new Map<string, SessionRecord>();

  public constructor(
    private readonly sessionTtlMs: number,
    private readonly stepUpTtlMs: number,
    private readonly now: () => Date = () => new Date(),
  ) {}

  public create(principal: SessionPrincipal): SessionRecord {
    const createdAt = this.now();
    const record: SessionRecord = {
      id: randomBytes(32).toString("base64url"),
      principal,
      csrfToken: randomBytes(32).toString("base64url"),
      createdAt,
      expiresAt: new Date(createdAt.getTime() + this.sessionTtlMs),
    };
    this.#records.set(record.id, record);
    return record;
  }

  public get(id: string): SessionRecord | undefined {
    const record = this.#records.get(id);
    if (!record) return undefined;
    if (record.expiresAt.getTime() <= this.now().getTime()) {
      this.#records.delete(id);
      return undefined;
    }
    return record;
  }

  public satisfyStepUp(id: string): SessionRecord | undefined {
    const current = this.get(id);
    if (!current) return undefined;
    const updated: SessionRecord = {
      ...current,
      stepUpUntil: new Date(this.now().getTime() + this.stepUpTtlMs),
    };
    this.#records.set(id, updated);
    return updated;
  }

  public delete(id: string): void {
    this.#records.delete(id);
  }
}

export function serializeCookie(
  name: string,
  value: string,
  options: { readonly maxAgeSeconds: number; readonly secure: boolean; readonly httpOnly?: boolean },
): string {
  const attributes = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    `Max-Age=${Math.max(0, Math.floor(options.maxAgeSeconds))}`,
    "SameSite=Lax",
  ];
  if (options.httpOnly ?? true) attributes.push("HttpOnly");
  if (options.secure) attributes.push("Secure");
  return attributes.join("; ");
}

export function clearCookie(name: string, secure: boolean): string {
  return serializeCookie(name, "", { maxAgeSeconds: 0, secure });
}

export function parseCookies(header: string | undefined): Readonly<Record<string, string>> {
  if (!header) return {};
  return Object.fromEntries(
    header.split(";").flatMap((part) => {
      const separator = part.indexOf("=");
      if (separator < 1) return [];
      const key = part.slice(0, separator).trim();
      const value = part.slice(separator + 1).trim();
      try {
        return [[key, decodeURIComponent(value)]];
      } catch {
        return [];
      }
    }),
  );
}

export function toSessionView(record: SessionRecord, now = new Date()): SessionView {
  const stepUpSatisfied = (record.stepUpUntil?.getTime() ?? 0) > now.getTime();
  return {
    principal: record.principal,
    permissions: permissionsForRoles(record.principal.roles),
    csrfToken: record.csrfToken,
    stepUp: {
      satisfied: stepUpSatisfied,
      ...(stepUpSatisfied && record.stepUpUntil
        ? { expiresAt: record.stepUpUntil.toISOString() }
        : {}),
    },
    expiresAt: record.expiresAt.toISOString(),
  };
}
