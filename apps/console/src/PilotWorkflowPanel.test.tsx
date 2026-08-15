import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type {
  PilotCapabilityResponse,
  PilotJobResultResponse,
  PilotJobStatusResponse,
  PilotStartJobResponse,
} from "@abl/platform-contracts";
import { PilotWorkflowPanel } from "./PilotWorkflowPanel.js";
import { PilotApiError, type PilotWorkflowClient } from "./pilot-api.js";

afterEach(cleanup);

const scope = { tenantId: "tenant-demo", facilityId: "facility-synthetic-auto-1" } as const;
const jobHandle = "pilot_job_handle_0123456789";

function client(): PilotWorkflowClient {
  return {
    capability: vi.fn(async (): Promise<PilotCapabilityResponse> => ({
      enabled: true,
      scope,
      operations: ["portfolio_surveillance_v1"],
    })),
    start: vi.fn(async (): Promise<PilotStartJobResponse> => ({
      scope,
      job: { jobHandle, status: "queued", operation: "portfolio_surveillance_v1" },
    })),
    status: vi.fn(async (): Promise<PilotJobStatusResponse> => ({
      scope,
      job: {
        operation: "portfolio_surveillance_v1",
        status: "succeeded",
        durableStatus: "completed",
        attemptCount: 1,
        maxAttempts: 3,
        cancellationRequested: false,
        createdAt: "2026-08-15T12:00:00.000Z",
        updatedAt: "2026-08-15T12:01:00.000Z",
        errorCode: null,
        resultAvailable: true,
      },
    })),
    result: vi.fn(async (): Promise<PilotJobResultResponse> => ({
      scope,
      result: {
        operation: "portfolio_surveillance_v1",
        manifestId: "manifest-1",
        artifactId: "artifact-1",
        resultHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        result: {},
      },
    })),
    cancel: vi.fn(async (): Promise<PilotJobStatusResponse> => ({
      scope,
      job: {
        operation: "portfolio_surveillance_v1",
        status: "cancelled",
        durableStatus: "cancelled",
        attemptCount: 1,
        maxAttempts: 3,
        cancellationRequested: true,
        createdAt: "2026-08-15T12:00:00.000Z",
        updatedAt: "2026-08-15T12:00:30.000Z",
        errorCode: null,
        resultAvailable: false,
      },
    })),
  };
}

describe("PilotWorkflowPanel", () => {
  it("uses the injected BFF for start, status, and signed result evidence", async () => {
    const api = client();
    render(<PilotWorkflowPanel csrfToken="csrf-token" client={api} />);

    fireEvent.click(screen.getByRole("button", { name: "Check pilot API" }));
    expect(await screen.findByText("facility-synthetic-auto-1")).toBeInTheDocument();
    expect(screen.getByText("Capture source evidence")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Start governed surveillance" }));
    expect(await screen.findByText(jobHandle)).toBeInTheDocument();
    expect(api.start).toHaveBeenCalledWith(
      expect.objectContaining({ purpose: "monthly_portfolio_surveillance" }),
      "csrf-token",
    );

    fireEvent.click(screen.getByRole("button", { name: "Refresh status" }));
    expect(await screen.findByText("succeeded")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "View result" }));
    expect(await screen.findByText("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Portfolio surveillance completed" })).toBeInTheDocument();
  });

  it("stays read-only when the governed pilot service is not composed", async () => {
    const api = client();
    api.capability = vi.fn(async () => {
      throw new PilotApiError(404, "pilot_api_unavailable", "not configured");
    });
    render(<PilotWorkflowPanel csrfToken="csrf-token" client={api} />);
    fireEvent.click(screen.getByRole("button", { name: "Check pilot API" }));
    expect(await screen.findByText("Pilot API not composed")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start governed surveillance" })).not.toBeInTheDocument();
  });
});
