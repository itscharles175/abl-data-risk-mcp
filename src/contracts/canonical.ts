import { createHash } from "node:crypto";

import { z } from "zod";

export type CanonicalJsonValue =
  | null
  | boolean
  | number
  | string
  | readonly CanonicalJsonValue[]
  | { readonly [key: string]: CanonicalJsonValue };

export type Sha256Hash = `sha256:${string}`;

export type ContractValidationErrorCode =
  | "INVALID_CONTRACT"
  | "INVALID_IDENTIFIER"
  | "INVALID_HASH"
  | "INVALID_TIMESTAMP"
  | "NON_CANONICAL_VALUE"
  | "HASH_MISMATCH"
  | "INVARIANT_VIOLATION";

export class ContractValidationError extends Error {
  constructor(
    readonly code: ContractValidationErrorCode,
    message: string,
    readonly issues: readonly string[] = []
  ) {
    super(message);
    this.name = "ContractValidationError";
  }
}

export const IdentifierSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/, "must be a portable identifier");

export const Sha256HashSchema = z
  .string()
  .regex(/^sha256:[a-f0-9]{64}$/, "must be a lowercase sha256: content hash")
  .transform((value) => value as Sha256Hash);

export const IsoDateSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, "must use YYYY-MM-DD")
  .refine(isValidIsoDate, "must be a real calendar date");

export const IsoTimestampSchema = z
  .string()
  .max(64)
  .refine(isCanonicalIsoTimestamp, "must be a canonical UTC ISO-8601 timestamp");

/**
 * Serializes the deliberately small, cross-runtime JSON subset used for
 * fingerprints. Numbers are limited to safe integers; exact decimals belong
 * in strings. This prevents IEEE-754 and language-specific formatting drift.
 */
export function canonicalJson(value: unknown): string {
  return serializeCanonical(value, "$", new Set<object>());
}

export function canonicalHash(value: unknown): Sha256Hash {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

export function assertCanonicalHash(
  value: unknown,
  expectedHash: string,
  label = "contract"
): asserts expectedHash is Sha256Hash {
  const parsedHash = parseWithSchema(Sha256HashSchema, expectedHash, `${label} hash`);
  const actualHash = canonicalHash(value);
  if (actualHash !== parsedHash) {
    throw new ContractValidationError(
      "HASH_MISMATCH",
      `${label} hash did not match its canonical content`,
      [`expected ${parsedHash}`, `actual ${actualHash}`]
    );
  }
}

export function parseWithSchema<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((issue) => {
      const path = issue.path.length === 0 ? "$" : `$.${issue.path.join(".")}`;
      return `${path}: ${issue.message}`;
    });
    throw new ContractValidationError(
      "INVALID_CONTRACT",
      `${label} failed validation`,
      Object.freeze(issues)
    );
  }
  return deepFreeze(parsed.data);
}

export function assertIdentifier(value: string, label: string): void {
  const parsed = IdentifierSchema.safeParse(value);
  if (!parsed.success) {
    throw new ContractValidationError("INVALID_IDENTIFIER", `${label} must be a portable identifier`);
  }
}

export function assertTimestampOrder(
  earlier: string,
  later: string,
  earlierLabel: string,
  laterLabel: string
): void {
  const earlierTime = Date.parse(earlier);
  const laterTime = Date.parse(later);
  if (!Number.isFinite(earlierTime) || !Number.isFinite(laterTime)) {
    throw new ContractValidationError("INVALID_TIMESTAMP", "Timestamp ordering requires valid timestamps");
  }
  if (earlierTime > laterTime) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      `${earlierLabel} must not be after ${laterLabel}`
    );
  }
}

export function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value as Record<string, unknown>)) deepFreeze(nested);
  return Object.freeze(value);
}

function serializeCanonical(value: unknown, path: string, ancestors: Set<object>): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new ContractValidationError(
        "NON_CANONICAL_VALUE",
        `${path} must use a safe integer or encode an exact decimal as a string`
      );
    }
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (typeof value !== "object") {
    throw new ContractValidationError(
      "NON_CANONICAL_VALUE",
      `${path} contains a non-JSON value`
    );
  }
  if (ancestors.has(value)) {
    throw new ContractValidationError("NON_CANONICAL_VALUE", `${path} contains a cycle`);
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const entries: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!(index in value)) {
          throw new ContractValidationError("NON_CANONICAL_VALUE", `${path}[${index}] is sparse`);
        }
        entries.push(serializeCanonical(value[index], `${path}[${index}]`, ancestors));
      }
      return `[${entries.join(",")}]`;
    }

    const prototype = Object.getPrototypeOf(value) as object | null;
    if (prototype !== Object.prototype && prototype !== null) {
      throw new ContractValidationError(
        "NON_CANONICAL_VALUE",
        `${path} must be a plain JSON object`
      );
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new ContractValidationError("NON_CANONICAL_VALUE", `${path} contains symbol keys`);
    }
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort(compareCodePoints);
    return `{${keys
      .map(
        (key) =>
          `${JSON.stringify(key)}:${serializeCanonical(record[key], `${path}.${key}`, ancestors)}`
      )
      .join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

function compareCodePoints(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isValidIsoDate(value: string): boolean {
  const date = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function isCanonicalIsoTimestamp(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false;
  const timestamp = new Date(value);
  return !Number.isNaN(timestamp.getTime()) && timestamp.toISOString() === value;
}
