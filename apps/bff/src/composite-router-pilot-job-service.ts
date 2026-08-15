import { z } from "zod";
import {
  BrowserSafePayloadSchema,
  PilotJobHandleSchema,
  PilotJobResultViewSchema,
  PilotJobScopeSchema,
  PilotJobStatusViewSchema,
  PilotStartedJobSchema,
  PlatformRoleSchema,
  hasPermission,
  type PilotJobResultView,
  type PilotJobScope,
  type PilotJobStatusView,
  type PilotStartedJob,
} from "@abl/platform-contracts";
import {
  PilotJobServiceError,
  type PilotJobActorContext,
  type PilotJobApi,
  type PilotJobServicePort,
  type PilotJobServiceResponse,
  type PilotPortfolioSurveillanceStartInput,
} from "./pilot-job-service.js";

type MaybePromise<T> = T | Promise<T>;

interface RouterResponse {
  readonly value: unknown;
  readonly obligations: readonly unknown[];
}

interface MutationRequestContext {
  readonly requestStartedAtMonotonicMs: number;
}

/**
 * Narrow structural projection of the root CompositeGovernedWorkflowRouter.
 *
 * The environment composition owns the concrete router and verified-identity
 * implementation. Keeping this projection in the BFF prevents the web package
 * from importing control-plane internals or constructing verified identities.
 */
export interface CompositeGovernedWorkflowRouterBridge<TPrincipal extends BoundRouterPrincipal> {
  readonly binding: PilotJobScope;
  startPortfolioSurveillanceAuthorized(
    principal: TPrincipal,
    input: PilotPortfolioSurveillanceStartInput,
    requestContext: MutationRequestContext,
  ): MaybePromise<RouterResponse>;
  getJobStatusAuthorized(
    principal: TPrincipal,
    jobHandle: string,
  ): MaybePromise<RouterResponse>;
  getJobResultAuthorized(
    principal: TPrincipal,
    jobHandle: string,
  ): MaybePromise<RouterResponse>;
  cancelJobAuthorized(
    principal: TPrincipal,
    jobHandle: string,
    requestContext: MutationRequestContext,
  ): MaybePromise<RouterResponse>;
}

export interface BoundRouterPrincipal {
  readonly tenantId: string;
  readonly principalId: string;
}

export type PilotVerifiedPrincipalFactory<TPrincipal extends BoundRouterPrincipal> = (
  context: Readonly<PilotJobActorContext>,
) => MaybePromise<TPrincipal>;

export interface CompositeRouterPilotJobApiOptions<TPrincipal extends BoundRouterPrincipal> {
  readonly bridge: CompositeGovernedWorkflowRouterBridge<TPrincipal>;
  readonly createVerifiedPrincipal: PilotVerifiedPrincipalFactory<TPrincipal>;
}

const ActorContextSchema = PilotJobScopeSchema.extend({
  principalId: z.string().min(1).max(256).regex(/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/u),
  roles: z.array(PlatformRoleSchema).min(1).max(32),
}).strict();

const PortableIdentifierSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u);

const RequestIdentifierSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/u);

const RouterStartInputSchema: z.ZodType<PilotPortfolioSurveillanceStartInput> = z
  .object({
    operation: z.literal("portfolio_surveillance_v1"),
    operationRequest: z.object({
      contractVersion: z.literal(1),
      operation: z.literal("portfolio_surveillance_v1"),
      sources: z.array(z.object({
        kind: z.literal("certification_manifest"),
        certificationManifestId: PortableIdentifierSchema,
      }).strict()).min(2).max(120),
      definitionVersionIds: z.array(PortableIdentifierSchema).min(2).max(256),
    }).strict(),
    idempotencyKey: RequestIdentifierSchema,
    purpose: RequestIdentifierSchema,
  })
  .strict()
  .superRefine((input, context) => {
    const manifests = input.operationRequest.sources.map(
      ({ certificationManifestId }) => certificationManifestId,
    );
    if (new Set(manifests).size !== manifests.length) {
      context.addIssue({
        code: "custom",
        path: ["operationRequest", "sources"],
        message: "Certification manifest ids must be unique",
      });
    }
    if (
      new Set(input.operationRequest.definitionVersionIds).size !==
      input.operationRequest.definitionVersionIds.length
    ) {
      context.addIssue({
        code: "custom",
        path: ["operationRequest", "definitionVersionIds"],
        message: "Definition version ids must be unique",
      });
    }
  });

/**
 * Creates the capability injected into buildApp. Scope comes only from the
 * environment-owned bridge; browser request bodies cannot select a tenant or
 * facility. The factory must mint a verified core principal from trusted BFF
 * session context and the adapter checks its binding before every router call.
 */
export function createCompositeRouterPilotJobApi<TPrincipal extends BoundRouterPrincipal>(
  options: CompositeRouterPilotJobApiOptions<TPrincipal>,
): PilotJobApi {
  const scope = Object.freeze(PilotJobScopeSchema.parse(options.bridge.binding));
  return Object.freeze({
    scope,
    service: new CompositeRouterPilotJobService(scope, options),
  });
}

class CompositeRouterPilotJobService<TPrincipal extends BoundRouterPrincipal>
  implements PilotJobServicePort {
  readonly #scope: Readonly<PilotJobScope>;
  readonly #bridge: CompositeGovernedWorkflowRouterBridge<TPrincipal>;
  readonly #createVerifiedPrincipal: PilotVerifiedPrincipalFactory<TPrincipal>;

  constructor(
    scope: Readonly<PilotJobScope>,
    options: CompositeRouterPilotJobApiOptions<TPrincipal>,
  ) {
    this.#scope = scope;
    this.#bridge = options.bridge;
    this.#createVerifiedPrincipal = options.createVerifiedPrincipal;
  }

  async startPortfolioSurveillance(
    context: PilotJobActorContext,
    input: PilotPortfolioSurveillanceStartInput,
  ): Promise<PilotJobServiceResponse<PilotStartedJob>> {
    return this.#invoke(
      context,
      PilotStartedJobSchema,
      (principal) => this.#bridge.startPortfolioSurveillanceAuthorized(
        principal,
        parseStartInput(input),
        trustedMutationContext(),
      ),
    );
  }

  async getJobStatus(
    context: PilotJobActorContext,
    jobHandle: string,
  ): Promise<PilotJobServiceResponse<PilotJobStatusView>> {
    return this.#invoke(
      context,
      PilotJobStatusViewSchema,
      (principal) => this.#bridge.getJobStatusAuthorized(principal, parseJobHandle(jobHandle)),
    );
  }

  async getJobResult(
    context: PilotJobActorContext,
    jobHandle: string,
  ): Promise<PilotJobServiceResponse<PilotJobResultView>> {
    return this.#invoke(
      context,
      PilotJobResultViewSchema,
      (principal) => this.#bridge.getJobResultAuthorized(principal, parseJobHandle(jobHandle)),
    );
  }

  async cancelJob(
    context: PilotJobActorContext,
    jobHandle: string,
  ): Promise<PilotJobServiceResponse<PilotJobStatusView>> {
    return this.#invoke(
      context,
      PilotJobStatusViewSchema,
      (principal) => this.#bridge.cancelJobAuthorized(
        principal,
        parseJobHandle(jobHandle),
        trustedMutationContext(),
      ),
    );
  }

  async #invoke<T>(
    contextValue: PilotJobActorContext,
    schema: z.ZodType<T>,
    invoke: (principal: TPrincipal) => MaybePromise<RouterResponse>,
  ): Promise<PilotJobServiceResponse<T>> {
    try {
      const context = this.#authorizedContext(contextValue);
      const principal = await this.#createVerifiedPrincipal(context);
      if (
        !principal ||
        principal.tenantId !== this.#scope.tenantId ||
        principal.principalId !== context.principalId
      ) {
        throw contractFailure("Verified principal did not match the bound pilot context");
      }
      const response = await invoke(principal);
      const value = parseRouterResponse(response, schema);
      return Object.freeze({ value });
    } catch (error) {
      throw publicPilotError(error);
    }
  }

  #authorizedContext(value: PilotJobActorContext): Readonly<PilotJobActorContext> {
    const parsed = ActorContextSchema.safeParse(value);
    if (!parsed.success) {
      throw new PilotJobServiceError(403, "pilot_scope_denied", "Pilot scope was not authorized");
    }
    if (
      parsed.data.tenantId !== this.#scope.tenantId ||
      parsed.data.facilityId !== this.#scope.facilityId ||
      !hasPermission(parsed.data.roles, "job:operate")
    ) {
      throw new PilotJobServiceError(403, "pilot_scope_denied", "Pilot scope was not authorized");
    }
    return Object.freeze({
      tenantId: parsed.data.tenantId,
      facilityId: parsed.data.facilityId,
      principalId: parsed.data.principalId,
      roles: Object.freeze([...parsed.data.roles]),
    });
  }
}

function parseStartInput(value: PilotPortfolioSurveillanceStartInput): PilotPortfolioSurveillanceStartInput {
  const parsed = RouterStartInputSchema.safeParse(value);
  if (!parsed.success) {
    throw new PilotJobServiceError(400, "invalid_pilot_job", "Pilot job request is invalid");
  }
  return parsed.data;
}

function parseJobHandle(value: string): string {
  const parsed = PilotJobHandleSchema.safeParse(value);
  if (!parsed.success) {
    throw new PilotJobServiceError(400, "invalid_job_handle", "Job handle is invalid");
  }
  return parsed.data;
}

function trustedMutationContext(): MutationRequestContext {
  return Object.freeze({ requestStartedAtMonotonicMs: performance.now() });
}

function parseRouterResponse<T>(response: RouterResponse, schema: z.ZodType<T>): T {
  if (
    typeof response !== "object" ||
    response === null ||
    !Array.isArray(response.obligations)
  ) {
    throw contractFailure("Governed workflow returned a malformed response envelope");
  }
  const parsed = schema.safeParse(response.value);
  if (!parsed.success || !BrowserSafePayloadSchema.safeParse(parsed.data).success) {
    throw contractFailure("Governed workflow returned an invalid browser response");
  }
  return parsed.data;
}

function contractFailure(message: string): PilotJobServiceError {
  return new PilotJobServiceError(503, "workflow_contract_violation", message);
}

function publicPilotError(error: unknown): unknown {
  if (error instanceof PilotJobServiceError) return error;
  const identity = recognizedRouterError(error);
  if (!identity) return error;
  switch (identity.code) {
    case "INVALID_INPUT":
      return new PilotJobServiceError(400, "invalid_pilot_job", "Pilot job request is invalid");
    case "POLICY_DENIED":
    case "GLOBAL_POLICY_DENIED":
    case "SCOPE_DENIED":
      return new PilotJobServiceError(403, "permission_denied", "Pilot operation was denied");
    case "ROUTE_NOT_FOUND":
      return new PilotJobServiceError(404, "job_not_found", "Job was not found");
    case "IDEMPOTENCY_CONFLICT":
    case "ROUTE_CONFLICT":
      return new PilotJobServiceError(409, "idempotency_conflict", "Pilot job conflicts with existing evidence");
    case "RESULT_NOT_READY":
      return new PilotJobServiceError(409, "result_not_ready", "Job result is not ready");
    case "CANCELLED":
      return new PilotJobServiceError(410, "job_terminal", "Job is already terminal");
    case "RESULT_TOO_LARGE":
      return new PilotJobServiceError(429, "result_limit_exceeded", "Job result exceeds the disclosure limit");
    case "AUTHORIZATION_UNAVAILABLE":
    case "AUDIT_REQUIRED":
    case "INTEGRITY_FAILURE":
    case "EXECUTION_FAILED":
    case "EXECUTION_TIMEOUT":
      return new PilotJobServiceError(503, "governed_workflow_unavailable", "Governed workflow is unavailable");
    default:
      return error;
  }
}

function recognizedRouterError(
  value: unknown,
): { readonly name: string; readonly code: string } | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const candidate = value as { readonly name?: unknown; readonly code?: unknown };
  if (typeof candidate.name !== "string" || typeof candidate.code !== "string") return undefined;
  if (
    candidate.name !== "PortfolioSurveillanceWorkflowV4Error" &&
    candidate.name !== "JobHandleRouteCatalogError" &&
    candidate.name !== "SingleFacilityV2SurveillanceRuntimeError"
  ) return undefined;
  return { name: candidate.name, code: candidate.code };
}
