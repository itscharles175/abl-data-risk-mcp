import {
  DictionaryBundleReferenceV1Schema,
  ImmutableBundleReferenceV1Schema,
  assertResolvedBundle,
  canonicalJson,
  deepFreeze,
  IdentifierSchema,
  IsoTimestampSchema,
  parseWithSchema,
  Sha256HashSchema,
  type DictionaryBundleReferenceV1,
  type HistoricalRuntimeBundleV1,
  type HistoricalRuntimeResolver,
  type ImmutableBundleReferenceV1,
  type ResolvedDictionaryBundleV1,
  type ResolvedImmutableBundleV1,
  type Sha256Hash
} from "../contracts/index.js";
import {
  SqliteHistoricalRuntimeAuthorityV1,
  type RuntimeActivationProofV1
} from "./historical-runtime-authority-v1.js";

/**
 * The immutable historical time at which a certification is allowed to use
 * executable runtime evidence. This value is supplied by the certification
 * attempt record, never by a runtime resolver clock.
 */
export interface CertificationRuntimeUseContextV1 {
  readonly tenantId: string;
  readonly certifiedAt: string;
}

export interface CertificationRuntimeResolutionV1 {
  readonly context: CertificationRuntimeUseContextV1;
  readonly runtime: HistoricalRuntimeBundleV1;
  readonly activation: RuntimeActivationProofV1;
  readonly dictionary: ResolvedDictionaryBundleV1;
  readonly mappingCompiler: ResolvedImmutableBundleV1;
  readonly methodologies: readonly ResolvedImmutableBundleV1[];
}

export type CertificationRuntimeAuthorityErrorCode =
  | "INVALID_INPUT"
  | "RUNTIME_NOT_RESOLVED";

export class CertificationRuntimeAuthorityError extends Error {
  constructor(readonly code: CertificationRuntimeAuthorityErrorCode, message: string) {
    super(message);
    this.name = "CertificationRuntimeAuthorityError";
  }
}

/**
 * A certification-scoped adapter over the durable historical runtime
 * authority. It has no clock and cannot select a mutable current runtime:
 * every activation check is made at the immutable certification timestamp.
 *
 * The adapter also implements HistoricalRuntimeResolver so it can be injected
 * into the existing certification service without broadening that service's
 * API. Bundle and dictionary loads are deliberately limited to exact
 * references contained in a runtime that this adapter has resolved.
 */
export class CertificationRuntimeAuthorityV1 implements HistoricalRuntimeResolver {
  readonly #authority: SqliteHistoricalRuntimeAuthorityV1;
  readonly #context: CertificationRuntimeUseContextV1;
  readonly #resolvedBundles = new Map<string, ResolvedImmutableBundleV1>();

  constructor(
    authority: SqliteHistoricalRuntimeAuthorityV1,
    contextValue: CertificationRuntimeUseContextV1
  ) {
    if (!(authority instanceof SqliteHistoricalRuntimeAuthorityV1)) {
      invalid("A durable historical runtime authority is required");
    }
    this.#authority = authority;
    this.#context = context(contextValue);
  }

  get context(): CertificationRuntimeUseContextV1 {
    return this.#context;
  }

  /** Resolve and freeze one exact runtime plus every component it references. */
  resolveActivatedRuntime(referenceValue: {
    readonly runtimeBundleId: string;
    readonly runtimeBundleHash: Sha256Hash;
  }): CertificationRuntimeResolutionV1 {
    const reference = runtimeReference(referenceValue);
    const activated = this.#authority.resolveActivatedRuntime(
      this.#context.tenantId,
      reference,
      this.#context.certifiedAt
    );
    const runtime = activated.runtime;
    const dictionary = this.#resolveExactDictionary(runtime.dictionary);
    const mappingCompiler = this.#resolveExactBundle(runtime.mappingCompiler);
    const methodologies = runtime.methodologies.map((methodology) => this.#resolveExactBundle(methodology));
    return deepFreeze({
      context: this.#context,
      runtime,
      activation: activated.activation,
      dictionary,
      mappingCompiler,
      methodologies
    });
  }

  async resolveRuntimeBundle(reference: {
    readonly runtimeBundleId: string;
    readonly runtimeBundleHash: Sha256Hash;
  }): Promise<HistoricalRuntimeBundleV1> {
    return this.resolveActivatedRuntime(reference).runtime;
  }

  async resolveDictionary(referenceValue: DictionaryBundleReferenceV1): Promise<ResolvedDictionaryBundleV1> {
    const reference = parseWithSchema(
      DictionaryBundleReferenceV1Schema,
      referenceValue,
      "DictionaryBundleReferenceV1"
    );
    const resolved = this.#resolvedBundles.get(bundleKey(reference));
    if (!resolved) unresolved("Dictionary reference is not bound to a resolved certification runtime");
    assertResolvedBundle(reference, resolved);
    return deepFreeze({ reference, content: resolved.content });
  }

  async resolveBundle(referenceValue: ImmutableBundleReferenceV1): Promise<ResolvedImmutableBundleV1> {
    const reference = parseWithSchema(
      ImmutableBundleReferenceV1Schema,
      referenceValue,
      "ImmutableBundleReferenceV1"
    );
    const resolved = this.#resolvedBundles.get(bundleKey(reference));
    if (!resolved) unresolved("Bundle reference is not bound to a resolved certification runtime");
    assertResolvedBundle(reference, resolved);
    return deepFreeze({ reference, content: resolved.content });
  }

  #resolveExactDictionary(reference: DictionaryBundleReferenceV1): ResolvedDictionaryBundleV1 {
    const resolved = this.#resolveExactBundle(reference);
    return deepFreeze({ reference, content: resolved.content });
  }

  #resolveExactBundle(reference: ImmutableBundleReferenceV1): ResolvedImmutableBundleV1 {
    const resolved = this.#authority.resolveBundleForTenant(this.#context.tenantId, reference);
    assertResolvedBundle(reference, resolved);
    const exact = deepFreeze({ reference, content: resolved.content });
    const key = bundleKey(reference);
    const existing = this.#resolvedBundles.get(key);
    if (existing && canonicalJson(existing) !== canonicalJson(exact)) {
      invalid("A certification runtime reference resolved to inconsistent evidence");
    }
    this.#resolvedBundles.set(key, exact);
    return exact;
  }
}

/**
 * Stateless production composition helper. Each certification gets an
 * isolated resolver pinned to its durable attempt timestamp, so component
 * caches can never leak across tenants or attempts.
 */
export class CertificationRuntimeAuthorityFactoryV1 {
  constructor(readonly authority: SqliteHistoricalRuntimeAuthorityV1) {
    if (!(authority instanceof SqliteHistoricalRuntimeAuthorityV1)) {
      invalid("A durable historical runtime authority is required");
    }
  }

  forCertification(contextValue: CertificationRuntimeUseContextV1): CertificationRuntimeAuthorityV1 {
    return new CertificationRuntimeAuthorityV1(this.authority, contextValue);
  }
}

function context(value: CertificationRuntimeUseContextV1): CertificationRuntimeUseContextV1 {
  return deepFreeze({
    tenantId: identifier(value?.tenantId, "tenantId"),
    certifiedAt: timestamp(value?.certifiedAt, "certifiedAt")
  });
}

function runtimeReference(value: {
  readonly runtimeBundleId: string;
  readonly runtimeBundleHash: Sha256Hash;
}): { readonly runtimeBundleId: string; readonly runtimeBundleHash: Sha256Hash } {
  return deepFreeze({
    runtimeBundleId: identifier(value?.runtimeBundleId, "runtimeBundleId"),
    runtimeBundleHash: hash(value?.runtimeBundleHash, "runtimeBundleHash")
  });
}

function bundleKey(reference: ImmutableBundleReferenceV1): string {
  return canonicalJson(reference);
}

function identifier(value: unknown, label: string): string {
  const parsed = IdentifierSchema.safeParse(value);
  if (!parsed.success) invalid(`${label} is invalid`);
  return parsed.data;
}

function timestamp(value: unknown, label: string): string {
  const parsed = IsoTimestampSchema.safeParse(value);
  if (!parsed.success) invalid(`${label} is invalid`);
  return parsed.data;
}

function hash(value: unknown, label: string): Sha256Hash {
  const parsed = Sha256HashSchema.safeParse(value);
  if (!parsed.success) invalid(`${label} is invalid`);
  return parsed.data;
}

function invalid(message: string): never {
  throw new CertificationRuntimeAuthorityError("INVALID_INPUT", message);
}

function unresolved(message: string): never {
  throw new CertificationRuntimeAuthorityError("RUNTIME_NOT_RESOLVED", message);
}
