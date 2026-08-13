import {
  IdentifierSchema,
  IsoDateSchema,
  deepFreeze,
  parseGovernedDatasetScopeBindingV1,
  parseSourceContractV1,
  parseWithSchema,
  type GovernedDatasetScopeBindingV1,
  type SourceContractV1
} from "../contracts/index.js";
import {
  GovernedDefinitionV2ResolverError,
  type GovernedDefinitionExecutionApprovalV2,
  type GovernedDefinitionExecutionReferenceV2,
  type GovernedDefinitionV2Resolver,
  type ResolvedGovernedDefinitionV2
} from "./governed-definition-v2-resolver.js";

import { z } from "zod";

const ResolutionInputSchema = z
  .object({
    tenantId: IdentifierSchema,
    sourceContractDefinitionKey: IdentifierSchema,
    datasetScopeBindingDefinitionKey: IdentifierSchema,
    asOfDate: IsoDateSchema
  })
  .strict();

export interface ResolveEffectiveGovernedDeliveryDefinitionsV1 {
  readonly tenantId: string;
  readonly sourceContractDefinitionKey: string;
  readonly datasetScopeBindingDefinitionKey: string;
  readonly asOfDate: string;
}

/**
 * Immutable lifecycle evidence for one projected delivery definition. The
 * execution document is deliberately exposed separately so downstream capture
 * and registration code cannot substitute an equal-looking document for the
 * lifecycle-approved reference.
 */
export interface GovernedDeliveryDefinitionEvidenceV1 {
  readonly definition: GovernedDefinitionExecutionReferenceV2;
  readonly approval: GovernedDefinitionExecutionApprovalV2;
}

export interface EffectiveGovernedDeliveryDefinitionsV1 {
  readonly sourceContract: SourceContractV1;
  readonly scopeBinding: GovernedDatasetScopeBindingV1;
  readonly sourceContractEvidence: GovernedDeliveryDefinitionEvidenceV1;
  readonly scopeBindingEvidence: GovernedDeliveryDefinitionEvidenceV1;
}

export type GovernedDeliveryDefinitionAuthorityV1ErrorCode =
  | "INVALID_INPUT"
  | "NOT_FOUND"
  | "UNAPPROVED"
  | "INTEGRITY_FAILURE";

export class GovernedDeliveryDefinitionAuthorityV1Error extends Error {
  constructor(readonly code: GovernedDeliveryDefinitionAuthorityV1ErrorCode, message: string) {
    super(message);
    this.name = "GovernedDeliveryDefinitionAuthorityV1Error";
  }
}

/**
 * Resolves the active lifecycle pair needed to admit a source delivery. This
 * is intentionally a read-only adapter: it accepts definition *keys*, not
 * caller-supplied source or scope documents, and it does not broaden the
 * existing append-only delivery catalog's write surface.
 */
export class GovernedDeliveryDefinitionAuthorityV1 {
  constructor(
    private readonly definitions: Pick<GovernedDefinitionV2Resolver, "resolveEffective">
  ) {}

  resolveEffective(
    inputValue: ResolveEffectiveGovernedDeliveryDefinitionsV1
  ): EffectiveGovernedDeliveryDefinitionsV1 {
    const input = resolutionInput(inputValue);
    const sourceResolved = this.#resolve(
      input.tenantId,
      "source_contract",
      input.sourceContractDefinitionKey,
      input.asOfDate
    );
    const bindingResolved = this.#resolve(
      input.tenantId,
      "dataset_scope_binding",
      input.datasetScopeBindingDefinitionKey,
      input.asOfDate
    );
    const sourceContract = sourceDocument(sourceResolved);
    const scopeBinding = bindingDocument(bindingResolved);

    this.#assertSource(input, sourceResolved, sourceContract);
    this.#assertBinding(input, bindingResolved, scopeBinding);
    if (
      scopeBinding.sourceContract.sourceContractId !== sourceContract.sourceContractId ||
      scopeBinding.sourceContract.revision !== sourceContract.revision ||
      scopeBinding.sourceContract.sourceContractHash !== sourceContract.sourceContractHash
    ) {
      integrity("Dataset-scope binding does not attest the exact effective source contract");
    }

    return deepFreeze({
      sourceContract,
      scopeBinding,
      sourceContractEvidence: evidence(sourceResolved),
      scopeBindingEvidence: evidence(bindingResolved)
    });
  }

  #resolve(
    tenantId: string,
    kind: "source_contract" | "dataset_scope_binding",
    definitionKey: string,
    asOfDate: string
  ): ResolvedGovernedDefinitionV2 {
    try {
      const resolved = this.definitions.resolveEffective({ tenantId, kind, definitionKey, asOfDate });
      if (resolved.reference.kind !== kind || resolved.reference.definitionKey !== definitionKey) {
        integrity("Effective delivery definition resolution returned another kind or definition key");
      }
      if (
        resolved.approvalEvidence.status !== "approved" ||
        resolved.approvalEvidence.approvalEventHash !== resolved.reference.approvalEventHash ||
        resolved.approvalEvidence.proposedBy === resolved.approvalEvidence.approvedBy
      ) {
        integrity("Effective delivery definition lacks consistent maker/checker approval evidence");
      }
      return resolved;
    } catch (error) {
      rethrowResolver(error);
    }
  }

  #assertSource(
    input: ResolveEffectiveGovernedDeliveryDefinitionsV1,
    resolved: ResolvedGovernedDefinitionV2,
    source: SourceContractV1
  ): void {
    if (
      source.tenantId !== input.tenantId ||
      source.sourceKey !== input.sourceContractDefinitionKey ||
      source.status !== "approved" ||
      !effectiveAt(source.effectiveFrom, source.effectiveTo, input.asOfDate)
    ) {
      integrity("Effective source-contract document did not match its requested tenant, key, state, or date");
    }
    if (resolved.reference.kind !== "source_contract") {
      integrity("Source contract evidence carried another governed definition kind");
    }
  }

  #assertBinding(
    input: ResolveEffectiveGovernedDeliveryDefinitionsV1,
    resolved: ResolvedGovernedDefinitionV2,
    binding: GovernedDatasetScopeBindingV1
  ): void {
    if (
      binding.tenantId !== input.tenantId ||
      binding.bindingId !== input.datasetScopeBindingDefinitionKey ||
      !effectiveAt(binding.effectiveFrom, binding.effectiveTo, input.asOfDate)
    ) {
      integrity("Effective dataset-scope binding did not match its requested tenant, key, or date");
    }
    if (resolved.reference.kind !== "dataset_scope_binding") {
      integrity("Dataset-scope binding evidence carried another governed definition kind");
    }
  }
}

function resolutionInput(
  value: ResolveEffectiveGovernedDeliveryDefinitionsV1
): ResolveEffectiveGovernedDeliveryDefinitionsV1 {
  try {
    return parseWithSchema(
      ResolutionInputSchema,
      value,
      "ResolveEffectiveGovernedDeliveryDefinitionsV1"
    );
  } catch {
    invalid("Effective governed delivery-definition input failed validation");
  }
}

function sourceDocument(resolved: ResolvedGovernedDefinitionV2): SourceContractV1 {
  try {
    return parseSourceContractV1(resolved.executionDocument);
  } catch {
    integrity("Effective source-contract execution document failed verification");
  }
}

function bindingDocument(resolved: ResolvedGovernedDefinitionV2): GovernedDatasetScopeBindingV1 {
  try {
    return parseGovernedDatasetScopeBindingV1(resolved.executionDocument);
  } catch {
    integrity("Effective dataset-scope binding execution document failed verification");
  }
}

function evidence(resolved: ResolvedGovernedDefinitionV2): GovernedDeliveryDefinitionEvidenceV1 {
  return deepFreeze({
    definition: resolved.reference,
    approval: resolved.approvalEvidence
  });
}

function effectiveAt(effectiveFrom: string, effectiveTo: string | undefined, asOfDate: string): boolean {
  return effectiveFrom <= asOfDate && (effectiveTo === undefined || effectiveTo > asOfDate);
}

function rethrowResolver(error: unknown): never {
  if (error instanceof GovernedDeliveryDefinitionAuthorityV1Error) throw error;
  if (error instanceof GovernedDefinitionV2ResolverError) {
    throw new GovernedDeliveryDefinitionAuthorityV1Error(error.code, error.message);
  }
  integrity("Governed delivery definition resolution failed");
}

function invalid(message: string): never {
  throw new GovernedDeliveryDefinitionAuthorityV1Error("INVALID_INPUT", message);
}

function integrity(message: string): never {
  throw new GovernedDeliveryDefinitionAuthorityV1Error("INTEGRITY_FAILURE", message);
}
