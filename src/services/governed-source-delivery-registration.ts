import {
  IdentifierSchema,
  IsoTimestampSchema,
  GovernedSourceDeliveryLocatorV1Schema,
  parseGovernedDatasetScopeBindingV1,
  parseSourceContractV1,
  parseWithSchema,
  type GovernedDatasetScopeBindingV1,
  type GovernedSourceDeliveryLocatorV1,
  type GovernedSourceDeliveryMutationResultV1,
  type RegisterGovernedSourceDeliveryV1,
  type SourceContractV1,
  type TrustedSourceDeliveryActorV1
} from "../contracts/index.js";
import {
  GovernedDefinitionV2ResolverError,
  type GovernedDefinitionV2Resolver,
  type ResolvedGovernedDefinitionV2
} from "./governed-definition-v2-resolver.js";

import { z } from "zod";

const TrustedActorSchema = z
  .object({
    tenantId: IdentifierSchema,
    actorId: IdentifierSchema,
    authority: z.literal("platform_operator"),
    identitySource: z.literal("server_derived")
  })
  .strict();

const RegistrationRequestSchema = z
  .object({
    deliveryId: IdentifierSchema,
    sourceContractDefinitionVersionId: IdentifierSchema,
    datasetScopeBindingDefinitionVersionId: IdentifierSchema,
    idempotencyKey: IdentifierSchema
  })
  .strict();

const TrustedDeliveryMaterialSchema = z
  .object({
    locator: z.unknown(),
    sourceObservedAt: IsoTimestampSchema,
    receivedAt: IsoTimestampSchema
  })
  .strict();

export interface RegisterGovernedSourceDeliveryFromLifecycleV1 {
  readonly deliveryId: string;
  readonly sourceContractDefinitionVersionId: string;
  readonly datasetScopeBindingDefinitionVersionId: string;
  readonly idempotencyKey: string;
}

/**
 * Private source-adapter output. It intentionally contains no caller-provided
 * source, binding, locator, or timestamp fields.
 */
export interface TrustedSourceDeliveryMaterialResolverV1 {
  resolveForRegistration(input: {
    readonly tenantId: string;
    readonly deliveryId: string;
  }): Promise<{
    readonly locator: GovernedSourceDeliveryLocatorV1;
    readonly sourceObservedAt: string;
    readonly receivedAt: string;
  } | undefined>;
}

export type GovernedSourceDeliveryDefinitionResolverV1 = Pick<
  GovernedDefinitionV2Resolver,
  "resolveFrozen" | "resolveEffective"
>;

export interface GovernedSourceDeliveryCatalogV1 {
  register(
    actor: TrustedSourceDeliveryActorV1,
    input: RegisterGovernedSourceDeliveryV1
  ): GovernedSourceDeliveryMutationResultV1;
}

export type GovernedSourceDeliveryRegistrationErrorCode =
  | "INVALID_INPUT"
  | "NOT_FOUND"
  | "UNAPPROVED"
  | "INTEGRITY_FAILURE";

export class GovernedSourceDeliveryRegistrationError extends Error {
  constructor(readonly code: GovernedSourceDeliveryRegistrationErrorCode, message: string) {
    super(message);
    this.name = "GovernedSourceDeliveryRegistrationError";
  }
}

/**
 * The production admission boundary for new source deliveries. The caller
 * supplies only durable definition IDs and a delivery ID. Exact source/scope
 * documents are resolved from the v2 lifecycle and delivery metadata comes
 * only from a trusted source connector.
 */
export class GovernedSourceDeliveryRegistrationServiceV1 {
  constructor(
    private readonly dependencies: Readonly<{
      definitions: GovernedSourceDeliveryDefinitionResolverV1;
      deliveryMaterial: TrustedSourceDeliveryMaterialResolverV1;
      catalog: GovernedSourceDeliveryCatalogV1;
    }>
  ) {}

  async register(
    actorValue: TrustedSourceDeliveryActorV1,
    inputValue: RegisterGovernedSourceDeliveryFromLifecycleV1
  ): Promise<GovernedSourceDeliveryMutationResultV1> {
    const actor = trustedActor(actorValue);
    const input = registrationInput(inputValue);
    const material = await this.dependencies.deliveryMaterial.resolveForRegistration({
      tenantId: actor.tenantId,
      deliveryId: input.deliveryId
    });
    if (material === undefined) notFound("The requested source delivery was not found");
    const trustedMaterial = materialInput(material);

    const sourceFrozen = this.#resolveFrozen(
      actor.tenantId,
      input.sourceContractDefinitionVersionId,
      "source_contract"
    );
    const bindingFrozen = this.#resolveFrozen(
      actor.tenantId,
      input.datasetScopeBindingDefinitionVersionId,
      "dataset_scope_binding"
    );
    const source = executionSource(sourceFrozen);
    const binding = executionBinding(bindingFrozen);
    const asOfDate = trustedMaterial.sourceObservedAt.slice(0, 10);

    this.#assertEffective(actor.tenantId, sourceFrozen, asOfDate);
    this.#assertEffective(actor.tenantId, bindingFrozen, asOfDate);
    if (
      binding.tenantId !== actor.tenantId ||
      binding.sourceContract.sourceContractId !== source.sourceContractId ||
      binding.sourceContract.revision !== source.revision ||
      binding.sourceContract.sourceContractHash !== source.sourceContractHash
    ) {
      integrity("The governed dataset binding does not attest the exact governed source contract");
    }

    try {
      return this.dependencies.catalog.register(actor, {
        deliveryId: input.deliveryId,
        sourceContract: source,
        scopeBinding: binding,
        locator: trustedMaterial.locator,
        sourceObservedAt: trustedMaterial.sourceObservedAt,
        receivedAt: trustedMaterial.receivedAt,
        idempotencyKey: input.idempotencyKey
      });
    } catch (error) {
      // Preserve catalog-specific error semantics for callers that need to
      // distinguish duplicate delivery/idempotency behavior.
      throw error;
    }
  }

  #resolveFrozen(
    tenantId: string,
    definitionVersionId: string,
    kind: "source_contract" | "dataset_scope_binding"
  ): ResolvedGovernedDefinitionV2 {
    try {
      const resolved = this.dependencies.definitions.resolveFrozen({ tenantId, definitionVersionId });
      if (resolved.reference.kind !== kind) integrity("Governed definition kind did not match delivery registration");
      return resolved;
    } catch (error) {
      rethrowResolver(error);
    }
  }

  #assertEffective(
    tenantId: string,
    frozen: ResolvedGovernedDefinitionV2,
    asOfDate: string
  ): void {
    try {
      const effective = this.dependencies.definitions.resolveEffective({
        tenantId,
        kind: frozen.reference.kind,
        definitionKey: frozen.reference.definitionKey,
        asOfDate
      });
      if (
        effective.reference.definitionVersionId !== frozen.reference.definitionVersionId ||
        effective.reference.versionHash !== frozen.reference.versionHash ||
        effective.reference.documentHash !== frozen.reference.documentHash ||
        effective.reference.approvalEventHash !== frozen.reference.approvalEventHash
      ) {
        integrity("The requested governed definition is not the effective version at delivery observation time");
      }
    } catch (error) {
      rethrowResolver(error);
    }
  }
}

function registrationInput(
  value: RegisterGovernedSourceDeliveryFromLifecycleV1
): RegisterGovernedSourceDeliveryFromLifecycleV1 {
  try {
    return parseWithSchema(
      RegistrationRequestSchema,
      value,
      "RegisterGovernedSourceDeliveryFromLifecycleV1"
    );
  } catch {
    invalid("Delivery lifecycle registration input failed validation");
  }
}

function trustedActor(value: TrustedSourceDeliveryActorV1): TrustedSourceDeliveryActorV1 {
  try {
    return parseWithSchema(TrustedActorSchema, value, "TrustedSourceDeliveryActorV1");
  } catch {
    invalid("Server-derived platform operator is required for delivery registration");
  }
}

function materialInput(
  value: Awaited<ReturnType<TrustedSourceDeliveryMaterialResolverV1["resolveForRegistration"]>>
): Readonly<{
  locator: GovernedSourceDeliveryLocatorV1;
  sourceObservedAt: string;
  receivedAt: string;
}> {
  try {
    const parsed = parseWithSchema(TrustedDeliveryMaterialSchema, value, "TrustedSourceDeliveryMaterialV1");
    return {
      locator: parseWithSchema(
        GovernedSourceDeliveryLocatorV1Schema,
        parsed.locator,
        "GovernedSourceDeliveryLocatorV1"
      ),
      sourceObservedAt: parsed.sourceObservedAt,
      receivedAt: parsed.receivedAt
    };
  } catch {
    integrity("Trusted source delivery material failed validation");
  }
}

function executionSource(resolved: ResolvedGovernedDefinitionV2): SourceContractV1 {
  try {
    return parseSourceContractV1(resolved.executionDocument);
  } catch {
    integrity("Governed source-contract execution document failed validation");
  }
}

function executionBinding(resolved: ResolvedGovernedDefinitionV2): GovernedDatasetScopeBindingV1 {
  try {
    // The binding parser belongs here to guarantee the execution document is
    // re-hashed before its identity is used in an immutable delivery record.
    return parseGovernedDatasetScopeBindingV1(resolved.executionDocument);
  } catch {
    integrity("Governed dataset-scope binding execution document failed validation");
  }
}

function rethrowResolver(error: unknown): never {
  if (error instanceof GovernedDefinitionV2ResolverError) {
    throw new GovernedSourceDeliveryRegistrationError(error.code, error.message);
  }
  integrity("Governed definition resolution failed");
}

function invalid(message: string): never {
  throw new GovernedSourceDeliveryRegistrationError("INVALID_INPUT", message);
}

function notFound(message: string): never {
  throw new GovernedSourceDeliveryRegistrationError("NOT_FOUND", message);
}

function integrity(message: string): never {
  throw new GovernedSourceDeliveryRegistrationError("INTEGRITY_FAILURE", message);
}
