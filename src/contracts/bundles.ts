import { z } from "zod";

import {
  ContractValidationError,
  IdentifierSchema,
  IsoTimestampSchema,
  Sha256HashSchema,
  assertCanonicalHash,
  canonicalHash,
  deepFreeze,
  parseWithSchema,
  type CanonicalJsonValue,
  type Sha256Hash
} from "./canonical.js";

export const BundleKindSchema = z.enum([
  "dictionary",
  "field_policy",
  "mapping_compiler",
  "methodology"
]);

export const ImmutableBundleReferenceV1Schema = z
  .object({
    contractVersion: z.literal(1),
    bundleKind: BundleKindSchema,
    bundleId: IdentifierSchema,
    version: z.string().min(1).max(64),
    contentHash: Sha256HashSchema,
    artifactId: IdentifierSchema,
    mediaType: z.string().min(3).max(128).regex(/^[^\s/]+\/[^\s/]+$/),
    createdAt: IsoTimestampSchema
  })
  .strict();

export type ImmutableBundleReferenceV1 = Readonly<
  z.infer<typeof ImmutableBundleReferenceV1Schema>
>;

export const DictionaryBundleReferenceV1Schema = ImmutableBundleReferenceV1Schema.extend({
  bundleKind: z.literal("dictionary"),
  dictionaryVersion: z.string().min(1).max(64),
  dictionaryHash: Sha256HashSchema,
  fieldPolicyVersion: z.string().min(1).max(64),
  fieldPolicyHash: Sha256HashSchema
}).strict();

export type DictionaryBundleReferenceV1 = Readonly<
  z.infer<typeof DictionaryBundleReferenceV1Schema>
>;

const HistoricalRuntimeBundleBodyV1Schema = z
  .object({
    contractVersion: z.literal(1),
    runtimeBundleId: IdentifierSchema,
    runtimeVersion: z.string().min(1).max(64),
    dictionary: DictionaryBundleReferenceV1Schema,
    mappingCompiler: ImmutableBundleReferenceV1Schema.extend({
      bundleKind: z.literal("mapping_compiler")
    }).strict(),
    methodologies: z
      .array(
        ImmutableBundleReferenceV1Schema.extend({ bundleKind: z.literal("methodology") }).strict()
      )
      .max(128),
    assembledAt: IsoTimestampSchema
  })
  .strict()
  .superRefine((value, context) => {
    const identities = new Set<string>();
    for (const reference of [value.dictionary, value.mappingCompiler, ...value.methodologies]) {
      const identity = `${reference.bundleKind}:${reference.bundleId}:${reference.version}`;
      if (identities.has(identity)) {
        context.addIssue({
          code: "custom",
          path: ["methodologies"],
          message: `duplicate immutable bundle reference ${identity}`
        });
      }
      identities.add(identity);
    }
  });

export const HistoricalRuntimeBundleV1Schema = HistoricalRuntimeBundleBodyV1Schema.extend({
  runtimeBundleHash: Sha256HashSchema
}).strict();

export type HistoricalRuntimeBundleV1 = Readonly<
  z.infer<typeof HistoricalRuntimeBundleV1Schema>
>;

export type HistoricalRuntimeBundleV1Input = Readonly<
  z.input<typeof HistoricalRuntimeBundleBodyV1Schema>
>;

export interface ResolvedImmutableBundleV1 {
  readonly reference: ImmutableBundleReferenceV1;
  /** Parsed immutable JSON content. Implementations must verify the content hash before returning. */
  readonly content: CanonicalJsonValue;
}

export interface ResolvedDictionaryBundleV1 extends ResolvedImmutableBundleV1 {
  readonly reference: DictionaryBundleReferenceV1;
}

/** Content-addressed resolver used to replay results against their historical runtime. */
export interface HistoricalRuntimeResolver {
  resolveRuntimeBundle(reference: {
    readonly runtimeBundleId: string;
    readonly runtimeBundleHash: Sha256Hash;
  }): Promise<HistoricalRuntimeBundleV1>;
  resolveDictionary(reference: DictionaryBundleReferenceV1): Promise<ResolvedDictionaryBundleV1>;
  resolveBundle(reference: ImmutableBundleReferenceV1): Promise<ResolvedImmutableBundleV1>;
}

/** Deterministic content-addressed resolver for conformance tests and embedded deployments. */
export class InMemoryHistoricalRuntimeResolver implements HistoricalRuntimeResolver {
  readonly #runtimeBundles = new Map<string, HistoricalRuntimeBundleV1>();
  readonly #bundles = new Map<string, ResolvedImmutableBundleV1>();

  constructor(
    runtimeBundles: readonly HistoricalRuntimeBundleV1[],
    bundles: readonly ResolvedImmutableBundleV1[]
  ) {
    for (const bundle of bundles) {
      const reference = parseBundleReference(bundle.reference);
      assertResolvedBundle(reference, bundle);
      const key = bundleKey(reference);
      if (this.#bundles.has(key)) {
        throw new ContractValidationError("INVARIANT_VIOLATION", `Duplicate bundle ${key}`);
      }
      this.#bundles.set(key, deepFreeze({ reference, content: bundle.content }));
    }
    for (const runtimeBundle of runtimeBundles) {
      const parsed = parseHistoricalRuntimeBundleV1(runtimeBundle);
      const key = `${parsed.runtimeBundleId}:${parsed.runtimeBundleHash}`;
      if (this.#runtimeBundles.has(key)) {
        throw new ContractValidationError("INVARIANT_VIOLATION", `Duplicate runtime bundle ${key}`);
      }
      this.#runtimeBundles.set(key, parsed);
    }
  }

  async resolveRuntimeBundle(reference: {
    readonly runtimeBundleId: string;
    readonly runtimeBundleHash: Sha256Hash;
  }): Promise<HistoricalRuntimeBundleV1> {
    const resolved = this.#runtimeBundles.get(
      `${reference.runtimeBundleId}:${reference.runtimeBundleHash}`
    );
    if (!resolved) {
      throw new ContractValidationError("INVARIANT_VIOLATION", "Historical runtime bundle was not found");
    }
    return resolved;
  }

  async resolveDictionary(
    reference: DictionaryBundleReferenceV1
  ): Promise<ResolvedDictionaryBundleV1> {
    const parsedReference = parseWithSchema(
      DictionaryBundleReferenceV1Schema,
      reference,
      "DictionaryBundleReferenceV1"
    );
    const resolved = await this.resolveBundle(parsedReference);
    return deepFreeze({ reference: parsedReference, content: resolved.content });
  }

  async resolveBundle(reference: ImmutableBundleReferenceV1): Promise<ResolvedImmutableBundleV1> {
    const parsedReference = parseBundleReference(reference);
    const resolved = this.#bundles.get(bundleKey(parsedReference));
    if (!resolved) {
      throw new ContractValidationError("INVARIANT_VIOLATION", "Immutable historical bundle was not found");
    }
    assertResolvedBundle(parsedReference, resolved);
    return resolved;
  }
}

export function createHistoricalRuntimeBundleV1(
  input: HistoricalRuntimeBundleV1Input
): HistoricalRuntimeBundleV1 {
  const body = parseWithSchema(
    HistoricalRuntimeBundleBodyV1Schema,
    input,
    "HistoricalRuntimeBundleV1"
  );
  return parseHistoricalRuntimeBundleV1({ ...body, runtimeBundleHash: canonicalHash(body) });
}

export function parseHistoricalRuntimeBundleV1(value: unknown): HistoricalRuntimeBundleV1 {
  const parsed = parseWithSchema(
    HistoricalRuntimeBundleV1Schema,
    value,
    "HistoricalRuntimeBundleV1"
  );
  const { runtimeBundleHash, ...body } = parsed;
  assertCanonicalHash(body, runtimeBundleHash, "HistoricalRuntimeBundleV1");
  return parsed;
}

export function assertResolvedBundle(
  expected: ImmutableBundleReferenceV1,
  resolved: ResolvedImmutableBundleV1
): void {
  const actualReference = parseWithSchema(
    expected.bundleKind === "dictionary"
      ? DictionaryBundleReferenceV1Schema
      : ImmutableBundleReferenceV1Schema,
    resolved.reference,
    "resolved bundle reference"
  );
  if (
    actualReference.bundleKind !== expected.bundleKind ||
    actualReference.bundleId !== expected.bundleId ||
    actualReference.version !== expected.version ||
    actualReference.contentHash !== expected.contentHash ||
    actualReference.artifactId !== expected.artifactId
  ) {
    throw new ContractValidationError(
      "INVARIANT_VIOLATION",
      "Resolved bundle identity did not match the historical reference"
    );
  }
  const contentHash = canonicalHash(resolved.content);
  if (contentHash !== expected.contentHash) {
    throw new ContractValidationError(
      "HASH_MISMATCH",
      "Resolved immutable bundle content did not match its reference",
      [`expected ${expected.contentHash}`, `actual ${contentHash}`]
    );
  }
  deepFreeze(resolved.content);
}

function parseBundleReference(reference: ImmutableBundleReferenceV1): ImmutableBundleReferenceV1 {
  return parseWithSchema(
    reference.bundleKind === "dictionary"
      ? DictionaryBundleReferenceV1Schema
      : ImmutableBundleReferenceV1Schema,
    reference,
    "ImmutableBundleReferenceV1"
  );
}

function bundleKey(reference: ImmutableBundleReferenceV1): string {
  return `${reference.bundleKind}:${reference.bundleId}:${reference.version}:${reference.contentHash}:${reference.artifactId}`;
}
