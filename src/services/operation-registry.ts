import { canonicalHash } from "../contracts/canonical.js";

export type OperationKindV1 = "read" | "analysis" | "control_mutation";

export interface OperationExecutionContextV1 {
  readonly tenantId: string;
  readonly principalBinding: string;
  readonly purpose: string;
  readonly maximumResultRows: number;
  readonly maximumResultBytes: number;
  readonly maximumExecutionMs: number;
  readonly signal?: AbortSignal;
}

export interface OperationResultAccountingV1 {
  readonly rows: number;
  readonly bytes: number;
  readonly populationHashes: readonly string[];
  readonly disclosureFields: readonly string[];
}

export interface OperationDefinitionV1<Input, Output> {
  readonly schemaVersion: 1;
  readonly name: string;
  readonly kind: OperationKindV1;
  readonly inputSchemaHash: string;
  readonly outputSchemaHash: string;
  readonly disclosurePolicyId: string;
  readonly maximumReceiptBytes?: number;
  validateInput(value: unknown): Input;
  requiredDefinitions(input: Input): readonly { readonly kind: string; readonly id: string }[];
  requestedFields(input: Input): readonly string[];
  execute(input: Input, context: OperationExecutionContextV1): Promise<Output> | Output;
  accountResult(result: Output): OperationResultAccountingV1;
}

export interface OperationExecutionReceiptV1<Output> {
  readonly operation: string;
  readonly operationFingerprint: string;
  readonly output: Output;
  readonly accounting: OperationResultAccountingV1;
  readonly elapsedMs: number;
}

export class OperationRegistryError extends Error {
  constructor(readonly code: "INVALID_DEFINITION" | "DUPLICATE_OPERATION" | "NOT_FOUND" | "RESULT_LIMIT_EXCEEDED", message: string) {
    super(message);
    this.name = "OperationRegistryError";
  }
}

/** Composes schemas, definition requirements, fields, execution, accounting and disclosure policy in one immutable registry. */
export class OperationRegistryV1 {
  readonly #operations = new Map<string, OperationDefinitionV1<unknown, unknown>>();
  #sealed = false;

  register<Input, Output>(definition: OperationDefinitionV1<Input, Output>): this {
    if (this.#sealed) invalid("Operation registry is sealed");
    validateDefinition(definition);
    if (this.#operations.has(definition.name)) throw new OperationRegistryError("DUPLICATE_OPERATION", `Duplicate operation ${definition.name}`);
    this.#operations.set(definition.name, Object.freeze(definition) as OperationDefinitionV1<unknown, unknown>);
    return this;
  }

  seal(): this {
    if (this.#operations.size === 0) invalid("Operation registry cannot be empty");
    this.#sealed = true;
    return this;
  }

  list(): readonly { readonly name: string; readonly kind: OperationKindV1; readonly disclosurePolicyId: string }[] {
    return Object.freeze([...this.#operations.values()].map((operation) => ({
      name: operation.name,
      kind: operation.kind,
      disclosurePolicyId: operation.disclosurePolicyId
    })).sort((left, right) => left.name.localeCompare(right.name)));
  }

  describe(name: string, rawInput: unknown): {
    readonly requiredDefinitions: readonly { readonly kind: string; readonly id: string }[];
    readonly requestedFields: readonly string[];
    readonly operationFingerprint: string;
  } {
    const operation = this.#require(name);
    const input = operation.validateInput(rawInput);
    const requiredDefinitions = Object.freeze([...operation.requiredDefinitions(input)].sort(compareDefinition));
    const requestedFields = Object.freeze([...new Set(operation.requestedFields(input))].sort());
    return Object.freeze({
      requiredDefinitions,
      requestedFields,
      operationFingerprint: canonicalHash({
        name,
        input,
        inputSchemaHash: operation.inputSchemaHash,
        outputSchemaHash: operation.outputSchemaHash,
        disclosurePolicyId: operation.disclosurePolicyId,
        requiredDefinitions,
        requestedFields
      } as never)
    });
  }

  async execute<Output = unknown>(name: string, rawInput: unknown, context: OperationExecutionContextV1): Promise<OperationExecutionReceiptV1<Output>> {
    const operation = this.#require(name);
    validateContext(context);
    if (operation.kind === "control_mutation") {
      if (operation.maximumReceiptBytes === undefined || operation.maximumReceiptBytes > context.maximumResultBytes) {
        throw new OperationRegistryError("RESULT_LIMIT_EXCEEDED", "Mutation acknowledgement cannot fit the authorized result budget");
      }
    }
    context.signal?.throwIfAborted();
    const input = operation.validateInput(rawInput);
    const description = this.describe(name, rawInput);
    const startedAt = performance.now();
    const output = await operation.execute(input, context) as Output;
    context.signal?.throwIfAborted();
    const elapsedMs = performance.now() - startedAt;
    const accounting = operation.accountResult(output);
    validateAccounting(accounting);
    if (
      accounting.rows > context.maximumResultRows ||
      accounting.bytes > context.maximumResultBytes ||
      (operation.kind !== "control_mutation" && elapsedMs > context.maximumExecutionMs)
    ) {
      throw new OperationRegistryError("RESULT_LIMIT_EXCEEDED", "Operation result exceeded an authorized bound");
    }
    return Object.freeze({
      operation: name,
      operationFingerprint: description.operationFingerprint,
      output,
      accounting: Object.freeze(accounting),
      elapsedMs
    });
  }

  #require(name: string): OperationDefinitionV1<unknown, unknown> {
    if (!this.#sealed) invalid("Operation registry must be sealed before use");
    const operation = this.#operations.get(name);
    if (!operation) throw new OperationRegistryError("NOT_FOUND", "Operation was not found");
    return operation;
  }
}

function validateDefinition<Input, Output>(definition: OperationDefinitionV1<Input, Output>): void {
  if (definition.schemaVersion !== 1 || !/^[a-z][a-z0-9_.-]{0,127}$/u.test(definition.name)) invalid("Operation identity is invalid");
  if (!(["read", "analysis", "control_mutation"] as const).includes(definition.kind)) invalid("Operation kind is invalid");
  hash(definition.inputSchemaHash); hash(definition.outputSchemaHash);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/u.test(definition.disclosurePolicyId)) invalid("Disclosure policy id is invalid");
  if (definition.kind === "control_mutation" && (!Number.isSafeInteger(definition.maximumReceiptBytes) || definition.maximumReceiptBytes! < 64 || definition.maximumReceiptBytes! > 64_000)) invalid("Mutating operations require a bounded receipt size");
}

function validateContext(context: OperationExecutionContextV1): void {
  if (!context.tenantId || !context.principalBinding || !context.purpose) invalid("Operation context is incomplete");
  for (const value of [context.maximumResultRows, context.maximumResultBytes, context.maximumExecutionMs]) {
    if (!Number.isSafeInteger(value) || value < 1) invalid("Operation bounds must be positive integers");
  }
}

function validateAccounting(accounting: OperationResultAccountingV1): void {
  if (!Number.isSafeInteger(accounting.rows) || accounting.rows < 0 || !Number.isSafeInteger(accounting.bytes) || accounting.bytes < 0) invalid("Result accounting is invalid");
  for (const value of accounting.populationHashes) hash(value);
  if (accounting.disclosureFields.some((field) => !field || field.length > 256)) invalid("Disclosure field is invalid");
}

function hash(value: string): void {
  if (!/^(?:sha256:)?[0-9a-f]{64}$/u.test(value)) invalid("Schema/population hash is invalid");
}

function compareDefinition(left: { kind: string; id: string }, right: { kind: string; id: string }): number {
  return left.kind.localeCompare(right.kind) || left.id.localeCompare(right.id);
}

function invalid(message: string): never {
  throw new OperationRegistryError("INVALID_DEFINITION", message);
}
