import type { JobHandleRouteCatalog } from "../repositories/sqlite-job-handle-route-catalog.js";
import {
  assertVerifiedPrincipalContext,
  principalBinding,
  type VerifiedPrincipalContext
} from "../security/identity.js";
import type { PolicyObligations } from "../security/policy.js";
import type {
  GovernedMutationRequestContext,
  StartGovernedJobInput
} from "./governed-workflow.js";
import type { StartPortfolioSurveillanceJobV4Input } from "./portfolio-surveillance-workflow-v4.js";

export interface RoutedGovernedWorkflowResponse {
  readonly value: unknown;
  readonly obligations: readonly PolicyObligations[];
}

export interface LegacyRoutedWorkflowApi {
  startAuthorized(
    principal: VerifiedPrincipalContext,
    input: StartGovernedJobInput,
    requestContext?: GovernedMutationRequestContext
  ): RoutedGovernedWorkflowResponse | Promise<RoutedGovernedWorkflowResponse>;
  getJobStatusAuthorized(
    principal: VerifiedPrincipalContext,
    jobHandle: string
  ): RoutedGovernedWorkflowResponse | Promise<RoutedGovernedWorkflowResponse>;
  getJobResultAuthorized(
    principal: VerifiedPrincipalContext,
    jobHandle: string
  ): RoutedGovernedWorkflowResponse | Promise<RoutedGovernedWorkflowResponse>;
  cancelJobAuthorized(
    principal: VerifiedPrincipalContext,
    jobHandle: string,
    requestContext?: GovernedMutationRequestContext
  ): RoutedGovernedWorkflowResponse | Promise<RoutedGovernedWorkflowResponse>;
}

export interface PortfolioSurveillanceRoutedWorkflowApi {
  startPortfolioSurveillanceAuthorized(
    principal: VerifiedPrincipalContext,
    input: StartPortfolioSurveillanceJobV4Input,
    requestContext?: GovernedMutationRequestContext
  ): RoutedGovernedWorkflowResponse | Promise<RoutedGovernedWorkflowResponse>;
  getPortfolioSurveillanceJobStatusAuthorized(
    principal: VerifiedPrincipalContext,
    jobHandle: string
  ): RoutedGovernedWorkflowResponse | Promise<RoutedGovernedWorkflowResponse>;
  getPortfolioSurveillanceJobResultAuthorized(
    principal: VerifiedPrincipalContext,
    jobHandle: string
  ): RoutedGovernedWorkflowResponse | Promise<RoutedGovernedWorkflowResponse>;
  cancelPortfolioSurveillanceJobAuthorized(
    principal: VerifiedPrincipalContext,
    jobHandle: string,
    requestContext?: GovernedMutationRequestContext
  ): RoutedGovernedWorkflowResponse | Promise<RoutedGovernedWorkflowResponse>;
}

export interface CompositeGovernedWorkflowApi extends LegacyRoutedWorkflowApi {
  startPortfolioSurveillanceAuthorized(
    principal: VerifiedPrincipalContext,
    input: StartPortfolioSurveillanceJobV4Input,
    requestContext?: GovernedMutationRequestContext
  ): RoutedGovernedWorkflowResponse | Promise<RoutedGovernedWorkflowResponse>;
}

export interface CompositeGovernedWorkflowRouterServices {
  readonly legacy: LegacyRoutedWorkflowApi;
  readonly portfolioSurveillanceV4: PortfolioSurveillanceRoutedWorkflowApi;
  readonly routes: JobHandleRouteCatalog;
}

/**
 * Routes opaque job handles to their issuing workflow without probing another
 * workflow on lookup failure. Both starts and all subsequent operations must
 * pass through the same instance backed by a durable route catalog.
 */
export class CompositeGovernedWorkflowRouter
  implements CompositeGovernedWorkflowApi
{
  readonly #services: CompositeGovernedWorkflowRouterServices;

  constructor(services: CompositeGovernedWorkflowRouterServices) {
    this.#services = services;
  }

  async startAuthorized(
    principal: VerifiedPrincipalContext,
    input: StartGovernedJobInput,
    requestContext?: GovernedMutationRequestContext
  ): Promise<RoutedGovernedWorkflowResponse> {
    assertVerifiedPrincipalContext(principal);
    const response = await this.#services.legacy.startAuthorized(principal, input, requestContext);
    this.#register(principal, response, "legacy_governed");
    return response;
  }

  async startPortfolioSurveillanceAuthorized(
    principal: VerifiedPrincipalContext,
    input: StartPortfolioSurveillanceJobV4Input,
    requestContext?: GovernedMutationRequestContext
  ): Promise<RoutedGovernedWorkflowResponse> {
    assertVerifiedPrincipalContext(principal);
    const response = await this.#services.portfolioSurveillanceV4.startPortfolioSurveillanceAuthorized(
      principal,
      input,
      requestContext
    );
    this.#register(principal, response, "portfolio_surveillance_v4");
    return response;
  }

  async getJobStatusAuthorized(
    principal: VerifiedPrincipalContext,
    jobHandle: string
  ): Promise<RoutedGovernedWorkflowResponse> {
    return await (this.#lane(principal, jobHandle) === "legacy_governed"
      ? this.#services.legacy.getJobStatusAuthorized(principal, jobHandle)
      : this.#services.portfolioSurveillanceV4.getPortfolioSurveillanceJobStatusAuthorized(
          principal,
          jobHandle
        ));
  }

  async getJobResultAuthorized(
    principal: VerifiedPrincipalContext,
    jobHandle: string
  ): Promise<RoutedGovernedWorkflowResponse> {
    return await (this.#lane(principal, jobHandle) === "legacy_governed"
      ? this.#services.legacy.getJobResultAuthorized(principal, jobHandle)
      : this.#services.portfolioSurveillanceV4.getPortfolioSurveillanceJobResultAuthorized(
          principal,
          jobHandle
        ));
  }

  async cancelJobAuthorized(
    principal: VerifiedPrincipalContext,
    jobHandle: string,
    requestContext?: GovernedMutationRequestContext
  ): Promise<RoutedGovernedWorkflowResponse> {
    return await (this.#lane(principal, jobHandle) === "legacy_governed"
      ? this.#services.legacy.cancelJobAuthorized(principal, jobHandle, requestContext)
      : this.#services.portfolioSurveillanceV4.cancelPortfolioSurveillanceJobAuthorized(
          principal,
          jobHandle,
          requestContext
        ));
  }

  #lane(principal: VerifiedPrincipalContext, jobHandle: string) {
    assertVerifiedPrincipalContext(principal);
    return this.#services.routes.resolve({
      tenantId: principal.tenantId,
      principalBinding: principalBinding(principal),
      jobHandle
    });
  }

  #register(
    principal: VerifiedPrincipalContext,
    response: RoutedGovernedWorkflowResponse,
    lane: "legacy_governed" | "portfolio_surveillance_v4"
  ): void {
    this.#services.routes.register({
      tenantId: principal.tenantId,
      principalBinding: principalBinding(principal),
      jobHandle: startedJobHandle(response),
      lane
    });
  }
}

function startedJobHandle(response: RoutedGovernedWorkflowResponse): string {
  const value = response.value;
  if (
    typeof value !== "object" ||
    value === null ||
    !("jobHandle" in value) ||
    typeof value.jobHandle !== "string"
  ) {
    throw new TypeError("Workflow start did not return an opaque job handle");
  }
  return value.jobHandle;
}
