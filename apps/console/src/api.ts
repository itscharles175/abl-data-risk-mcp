import type {
  ApprovalDecision,
  ApprovalRecord,
  BackendMetadata,
  HighRiskActionRequest,
  NavigationItem,
  SectionId,
  SessionView,
  SourceContractDraft,
  SourceContractPreview,
  WorkbenchSectionPayload,
} from "@abl/platform-contracts";

export class ApiError extends Error {
  public constructor(
    public readonly status: number,
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
      | { readonly error?: { readonly message?: string } }
      | undefined;
    throw new ApiError(response.status, payload?.error?.message ?? `Request failed (${response.status})`);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

function writeHeaders(csrfToken: string): HeadersInit {
  return { "x-csrf-token": csrfToken };
}

export const platformApi = {
  metadata: (): Promise<BackendMetadata> => request("/api/v1/meta"),
  session: (): Promise<SessionView> => request("/api/v1/session"),
  navigation: (): Promise<{ readonly items: readonly NavigationItem[] }> =>
    request("/api/v1/navigation"),
  section: (section: SectionId): Promise<WorkbenchSectionPayload> =>
    request(`/api/v1/workbench/${encodeURIComponent(section)}`),
  previewSourceContract: (
    draft: SourceContractDraft,
    csrfToken: string,
  ): Promise<SourceContractPreview> =>
    request("/api/v1/source-contracts/preview", {
      method: "POST",
      headers: writeHeaders(csrfToken),
      body: JSON.stringify(draft),
    }),
  fixtureLogin: (principalId: string): Promise<SessionView> =>
    request("/api/auth/fixture-login", {
      method: "POST",
      body: JSON.stringify({ principalId }),
    }),
  fixtureStepUp: (csrfToken: string): Promise<SessionView> =>
    request("/api/auth/fixture-step-up", {
      method: "POST",
      headers: writeHeaders(csrfToken),
      body: "{}",
    }),
  logout: (csrfToken: string): Promise<void> =>
    request("/api/auth/logout", {
      method: "POST",
      headers: writeHeaders(csrfToken),
      body: "{}",
    }),
  approvals: (): Promise<{ readonly items: readonly ApprovalRecord[] }> =>
    request("/api/v1/approvals"),
  createAction: (
    action: HighRiskActionRequest,
    csrfToken: string,
  ): Promise<ApprovalRecord> =>
    request("/api/v1/high-risk-actions", {
      method: "POST",
      headers: writeHeaders(csrfToken),
      body: JSON.stringify(action),
    }),
  decideApproval: (
    id: string,
    decision: ApprovalDecision,
    csrfToken: string,
  ): Promise<ApprovalRecord> =>
    request(`/api/v1/approvals/${encodeURIComponent(id)}/decision`, {
      method: "POST",
      headers: writeHeaders(csrfToken),
      body: JSON.stringify(decision),
    }),
};
