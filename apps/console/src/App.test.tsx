import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App.js";

const session = {
  principal: {
    id: "demo-analyst",
    displayName: "Riley Analyst",
    email: "analyst@demo.invalid",
    roles: ["risk_analyst"],
  },
  permissions: ["portfolio:read", "analysis:run", "alert:review"],
  csrfToken: "csrf-token",
  stepUp: { satisfied: false },
  expiresAt: "2026-08-12T20:00:00.000Z",
};

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

describe("App", () => {
  it("renders an authenticated, role-filtered portfolio workspace", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/v1/meta")) return response({ product: "ABL Portfolio Risk Console", backendMode: "oidc", dataMode: "fixture", warning: "Fixture" });
      if (url.endsWith("/api/v1/session")) return response(session);
      if (url.endsWith("/api/v1/navigation")) return response({ items: [
        { id: "overview", label: "Overview", group: "Monitor", permission: "portfolio:read" },
        { id: "alerts", label: "Alerts", group: "Monitor", permission: "alert:review" },
      ] });
      if (url.endsWith("/api/v1/workbench/overview")) return response({
        section: "overview", title: "Portfolio command center", description: "Certified risk review.", sourceMode: "fixture", asOf: "2026-08-12T12:00:00.000Z",
        summary: [{ label: "Availability", value: "$96.4m", tone: "positive" }],
        columns: [{ key: "portfolio", label: "Portfolio" }],
        rows: [{ id: "p1", status: "healthy", values: { portfolio: "Northeast ABL" } }],
      });
      return response({ error: { message: "not found" } }, 404);
    }));

    render(<App />);
    expect(await screen.findByRole("heading", { name: "Portfolio command center" })).toBeInTheDocument();
    expect(screen.getByText("$96.4m")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Alerts" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Policies" })).not.toBeInTheDocument();
    expect(screen.getByText(/No live control plane/u)).toBeInTheDocument();
  });

  it("shows fixture personas when the session is unauthenticated", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/v1/meta")) return response({ product: "ABL Portfolio Risk Console", backendMode: "fixture", dataMode: "fixture", warning: "Fixture" });
      return response({ error: { message: "Sign in is required" } }, 401);
    }));

    render(<App />);
    expect(await screen.findByRole("heading", { name: "Choose a review persona" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Casey Steward/u })).toBeInTheDocument();
    expect(screen.getAllByRole("button")).toHaveLength(6);
    await waitFor(() => expect(screen.getByText(/Production mode removes this chooser/u)).toBeInTheDocument());
  });

  it("uses the real OIDC step-up route from the approval queue", async () => {
    window.history.replaceState(null, "", "/#/approvals");
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/v1/meta")) return response({ product: "ABL Portfolio Risk Console", backendMode: "oidc", dataMode: "fixture", warning: "Fixture" });
      if (url.endsWith("/api/v1/session")) return response({
        ...session,
        principal: { id: "oidc-reviewer", displayName: "OIDC Reviewer", email: "reviewer@example.test", roles: ["risk_reviewer"] },
        permissions: ["portfolio:read", "approval:review", "mapping:approve"],
      });
      if (url.endsWith("/api/v1/navigation")) return response({ items: [
        { id: "approvals", label: "Approval queue", group: "Governance", permission: "approval:review" },
      ] });
      if (url.endsWith("/api/v1/workbench/approvals")) return response({
        section: "approvals", title: "Approval queue", description: "Governed review queue.", sourceMode: "fixture", asOf: "2026-08-12T12:00:00.000Z",
        summary: [], columns: [], rows: [],
      });
      if (url.endsWith("/api/v1/approvals")) return response({ items: [] });
      return response({ error: { message: "not found" } }, 404);
    }));

    render(<App />);
    const link = await screen.findByRole("link", { name: "Step up to review" });
    expect(link).toHaveAttribute("href", "/api/auth/step-up?returnTo=%2F%23%2Fapprovals");
    expect(screen.queryByRole("button", { name: "Step up to review" })).not.toBeInTheDocument();
  });
});
