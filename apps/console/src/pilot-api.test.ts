import { afterEach, describe, expect, it, vi } from "vitest";
import { PilotApiError, pilotWorkflowClient } from "./pilot-api.js";

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

afterEach(() => vi.unstubAllGlobals());

describe("pilotWorkflowClient", () => {
  it("uses the IDs-only start contract and CSRF protection", async () => {
    let capturedInit: RequestInit | undefined;
    const fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      capturedInit = init;
      return response({
      scope: { tenantId: "tenant-demo", facilityId: "facility-demo" },
      job: {
        jobHandle: "pilot_job_handle_0123456789",
        status: "queued",
        operation: "portfolio_surveillance_v1",
      },
      }, 202);
    });
    vi.stubGlobal("fetch", fetch);

    await pilotWorkflowClient.start({
      certificationManifestIds: ["cert-1", "cert-2"],
      definitionVersionIds: ["definition-1", "definition-2"],
      idempotencyKey: "monthly-run-1",
      purpose: "monthly_surveillance",
    }, "csrf-token");

    expect(fetch).toHaveBeenCalledWith("/api/v1/pilot/jobs", expect.objectContaining({
      method: "POST",
      credentials: "same-origin",
      headers: expect.objectContaining({ "x-csrf-token": "csrf-token" }),
    }));
    expect(JSON.parse(String(capturedInit?.body))).toEqual({
      certificationManifestIds: ["cert-1", "cert-2"],
      definitionVersionIds: ["definition-1", "definition-2"],
      idempotencyKey: "monthly-run-1",
      purpose: "monthly_surveillance",
    });
  });

  it("preserves the server error code for unavailable capability discovery", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => response({
      error: {
        code: "pilot_api_unavailable",
        message: "The governed pilot job API is not configured",
      },
    }, 404)));

    await expect(pilotWorkflowClient.capability()).rejects.toMatchObject({
        status: 404,
        code: "pilot_api_unavailable",
      } satisfies Partial<PilotApiError>);
  });
});
