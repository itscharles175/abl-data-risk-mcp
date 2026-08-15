import type {
  PilotJobResultView,
  PilotJobScope,
  PilotJobStatusView,
  PilotPortfolioSurveillanceStartRequest,
  PilotStartedJob,
  PlatformRole,
} from "@abl/platform-contracts";

export interface PilotJobActorContext extends PilotJobScope {
  readonly principalId: string;
  readonly roles: readonly PlatformRole[];
}

export interface PilotPortfolioSurveillanceOperationRequest {
  readonly contractVersion: 1;
  readonly operation: "portfolio_surveillance_v1";
  readonly sources: readonly {
    readonly kind: "certification_manifest";
    readonly certificationManifestId: string;
  }[];
  readonly definitionVersionIds: readonly string[];
}

export interface PilotPortfolioSurveillanceStartInput {
  readonly operation: "portfolio_surveillance_v1";
  readonly operationRequest: PilotPortfolioSurveillanceOperationRequest;
  readonly idempotencyKey: string;
  readonly purpose: string;
}

export interface PilotJobServiceResponse<T> {
  readonly value: T;
}

/**
 * Boundary implemented by an environment-backed workflow composition.
 *
 * The BFF supplies tenant, facility, and actor context from its trusted session
 * and deployment configuration. Implementations must re-authorize that context;
 * this port is not an authorization bypass.
 */
export interface PilotJobServicePort {
  startPortfolioSurveillance(
    context: PilotJobActorContext,
    input: PilotPortfolioSurveillanceStartInput,
  ): Promise<PilotJobServiceResponse<PilotStartedJob>>;
  getJobStatus(
    context: PilotJobActorContext,
    jobHandle: string,
  ): Promise<PilotJobServiceResponse<PilotJobStatusView>>;
  getJobResult(
    context: PilotJobActorContext,
    jobHandle: string,
  ): Promise<PilotJobServiceResponse<PilotJobResultView>>;
  cancelJob(
    context: PilotJobActorContext,
    jobHandle: string,
  ): Promise<PilotJobServiceResponse<PilotJobStatusView>>;
}

export interface PilotJobApi {
  readonly scope: PilotJobScope;
  readonly service: PilotJobServicePort;
}

export type PilotJobServiceErrorStatus = 400 | 403 | 404 | 409 | 410 | 429 | 503;

export class PilotJobServiceError extends Error {
  public constructor(
    readonly status: PilotJobServiceErrorStatus,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "PilotJobServiceError";
  }
}

export function toPilotStartInput(
  request: PilotPortfolioSurveillanceStartRequest,
): PilotPortfolioSurveillanceStartInput {
  return {
    operation: "portfolio_surveillance_v1",
    operationRequest: {
      contractVersion: 1,
      operation: "portfolio_surveillance_v1",
      sources: request.certificationManifestIds.map((certificationManifestId) => ({
        kind: "certification_manifest" as const,
        certificationManifestId,
      })),
      definitionVersionIds: request.definitionVersionIds,
    },
    idempotencyKey: request.idempotencyKey,
    purpose: request.purpose,
  };
}
