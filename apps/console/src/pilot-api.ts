import type {
  PilotCapabilityResponse,
  PilotJobResultResponse,
  PilotJobStatusResponse,
  PilotPortfolioSurveillanceStartRequest,
  PilotStartJobResponse,
} from "@abl/platform-contracts";

export class PilotApiError extends Error {
  public constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...init,
    headers: {
      accept: "application/json",
      ...(init?.body ? { "content-type": "application/json" } : {}),
      ...init?.headers,
    },
  });
  if (!response.ok) {
    const payload = (await response.json().catch(() => undefined)) as
      | { readonly error?: { readonly code?: string; readonly message?: string } }
      | undefined;
    throw new PilotApiError(
      response.status,
      payload?.error?.code ?? "pilot_request_failed",
      payload?.error?.message ?? `Pilot request failed (${response.status})`,
    );
  }
  return (await response.json()) as T;
}

export interface PilotWorkflowClient {
  capability(): Promise<PilotCapabilityResponse>;
  start(
    input: PilotPortfolioSurveillanceStartRequest,
    csrfToken: string,
  ): Promise<PilotStartJobResponse>;
  status(jobHandle: string): Promise<PilotJobStatusResponse>;
  result(jobHandle: string): Promise<PilotJobResultResponse>;
  cancel(jobHandle: string, csrfToken: string): Promise<PilotJobStatusResponse>;
}

export const pilotWorkflowClient: PilotWorkflowClient = {
  capability: () => request("/api/v1/pilot"),
  start: (input, csrfToken) =>
    request("/api/v1/pilot/jobs", {
      method: "POST",
      headers: { "x-csrf-token": csrfToken },
      body: JSON.stringify(input),
    }),
  status: (jobHandle) =>
    request(`/api/v1/pilot/jobs/${encodeURIComponent(jobHandle)}/status`),
  result: (jobHandle) =>
    request(`/api/v1/pilot/jobs/${encodeURIComponent(jobHandle)}/result`),
  cancel: (jobHandle, csrfToken) =>
    request(`/api/v1/pilot/jobs/${encodeURIComponent(jobHandle)}/cancel`, {
      method: "POST",
      headers: { "x-csrf-token": csrfToken },
      body: "{}",
    }),
};
