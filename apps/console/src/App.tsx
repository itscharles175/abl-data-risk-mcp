import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactElement } from "react";
import {
  HIGH_RISK_ACTION_KINDS,
  type ApprovalRecord,
  type BackendMetadata,
  type HighRiskActionKind,
  type NavigationItem,
  type SectionId,
  type SessionView,
  type SourceContractPreview,
  type WorkbenchSectionPayload,
} from "@abl/platform-contracts";
import { ApiError, platformApi } from "./api.js";

const DEMO_USERS = [
  { id: "demo-analyst", name: "Riley Analyst", role: "Risk analyst", note: "Portfolio and alert review" },
  { id: "demo-reviewer", name: "Morgan Reviewer", role: "Risk reviewer", note: "Reports and approvals" },
  { id: "demo-steward", name: "Casey Steward", role: "Data steward", note: "Onboarding and definitions" },
  { id: "demo-security", name: "Avery Security", role: "Security admin", note: "Access, policy, and keys" },
  { id: "demo-operator", name: "Jordan Operator", role: "Platform operator", note: "Jobs and deployments" },
  { id: "demo-auditor", name: "Taylor Auditor", role: "Auditor", note: "Evidence and report review" },
] as const;

const ACTION_FOR_SECTION: Partial<Record<SectionId, HighRiskActionKind>> = {
  "source-contracts": "source_contract_activation",
  mappings: "mapping_activation",
  definitions: "methodology_activation",
  memberships: "membership_change",
  policies: "policy_change",
  connectors: "connector_change",
  "key-rotations": "key_rotation",
  deployment: "deployment_change",
};

function stepUpHref(): string {
  return `/api/auth/step-up?returnTo=${encodeURIComponent(window.location.pathname + window.location.hash)}`;
}

function initialSection(): SectionId {
  const hash = window.location.hash.replace(/^#\/?/u, "");
  return hash ? (hash as SectionId) : "overview";
}

function LoadingScreen(): ReactElement {
  return (
    <main className="center-screen" aria-busy="true">
      <div className="loading-mark" aria-hidden="true" />
      <p>Opening the governed workspace…</p>
    </main>
  );
}

function SignIn({ metadata, onSignedIn }: { readonly metadata: BackendMetadata; readonly onSignedIn: (session: SessionView) => void }): ReactElement {
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState<string>();

  const signIn = async (principalId: string): Promise<void> => {
    setBusy(principalId);
    setError(undefined);
    try {
      onSignedIn(await platformApi.fixtureLogin(principalId));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Sign in failed");
    } finally {
      setBusy(undefined);
    }
  };

  return (
    <main className="login-shell">
      <section className="login-story" aria-labelledby="login-title">
        <div className="brand-lockup"><span className="brand-mark">A</span><span>ABL / RISK</span></div>
        <p className="eyebrow">Governed portfolio intelligence</p>
        <h1 id="login-title">Know the exposure.<br />Prove the answer.</h1>
        <p className="login-lede">A review and administration surface for certified loan data, deterministic analytics, and controlled risk decisions.</p>
        <div className="trust-row">
          <span>Tenant scoped</span><span>Deterministic</span><span>Auditable</span>
        </div>
      </section>
      <section className="login-panel" aria-labelledby="access-title">
        <p className="mode-pill">{metadata.backendMode === "oidc" ? "Enterprise OIDC" : "Fixture access"}</p>
        <h2 id="access-title">{metadata.backendMode === "oidc" ? "Sign in to your workspace" : "Choose a review persona"}</h2>
        <p className="muted">{metadata.backendMode === "oidc" ? "Your identity provider controls authentication and assigned roles." : "Each persona exercises a distinct least-privilege route policy."}</p>
        {error ? <p className="error-banner" role="alert">{error}</p> : null}
        {metadata.backendMode === "oidc" ? (
          <button className="primary-button oidc-button" type="button" onClick={() => window.location.assign("/api/auth/login")}>Continue with identity provider <span aria-hidden="true">→</span></button>
        ) : (
          <>
            <div className="persona-list">
              {DEMO_USERS.map((user) => (
                <button key={user.id} className="persona" type="button" onClick={() => void signIn(user.id)} disabled={Boolean(busy)}>
                  <span className="avatar" aria-hidden="true">{user.name.split(" ").map((part) => part[0]).join("")}</span>
                  <span><strong>{user.name}</strong><small>{user.role} · {user.note}</small></span>
                  <span aria-hidden="true">{busy === user.id ? "…" : "→"}</span>
                </button>
              ))}
            </div>
            <p className="fixture-disclosure">Demonstration identities and data only. Production mode removes this chooser and uses OIDC Authorization Code + PKCE.</p>
          </>
        )}
      </section>
    </main>
  );
}

function SectionView({ payload }: { readonly payload: WorkbenchSectionPayload }): ReactElement {
  return (
    <>
      <section className="summary-grid" aria-label={`${payload.title} summary`}>
        {payload.summary.map((item) => (
          <article className={`metric-card tone-${item.tone}`} key={item.label}>
            <span>{item.label}</span><strong>{item.value}</strong>
          </article>
        ))}
      </section>
      <section className="table-card">
        <div className="table-toolbar">
          <div><h2>Current review set</h2><p>{payload.rows.length} representative records</p></div>
          <button type="button" className="quiet-button">Filter</button>
        </div>
        <div className="table-scroll">
          <table>
            <caption className="sr-only">{payload.title} fixture records</caption>
            <thead><tr><th scope="col">State</th>{payload.columns.map((column) => <th scope="col" key={column.key}>{column.label}</th>)}</tr></thead>
            <tbody>
              {payload.rows.map((row) => (
                <tr key={row.id}>
                  <td><span className={`status-dot status-${row.status}`} /><span className="sr-only">{row.status}</span></td>
                  {payload.columns.map((column) => <td key={column.key}>{row.values[column.key] ?? "—"}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

function GovernedActionPanel({ backendMode, kind, session, onSessionChange }: { readonly backendMode: BackendMetadata["backendMode"]; readonly kind: HighRiskActionKind; readonly session: SessionView; readonly onSessionChange: (session: SessionView) => void }): ReactElement {
  const [targetId, setTargetId] = useState("");
  const [rollbackTargetId, setRollbackTargetId] = useState("");
  const [reason, setReason] = useState("");
  const [secretRef, setSecretRef] = useState("");
  const [message, setMessage] = useState<string>();
  const [busy, setBusy] = useState(false);
  const needsSecretRef = kind === "key_rotation" || kind === "connector_change";

  const stepUp = async (): Promise<void> => {
    setBusy(true);
    setMessage(undefined);
    try {
      if (backendMode === "fixture") {
        onSessionChange(await platformApi.fixtureStepUp(session.csrfToken));
      } else {
        window.location.assign(stepUpHref());
      }
    } catch (cause) {
      setMessage(cause instanceof Error ? cause.message : "Step-up failed");
    } finally {
      setBusy(false);
    }
  };

  const submit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    setBusy(true);
    setMessage(undefined);
    try {
      const created = await platformApi.createAction({
        kind,
        targetId,
        reason,
        rollbackTargetId,
        semanticDiff: { requestedFrom: "console", fixture: true },
        ...(secretRef ? { secretRef } : {}),
      }, session.csrfToken);
      setMessage(`Proposal ${created.id.slice(0, 8)} entered the checker queue.`);
      setTargetId(""); setRollbackTargetId(""); setReason(""); setSecretRef("");
    } catch (cause) {
      setMessage(cause instanceof Error ? cause.message : "Proposal failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="action-card" aria-labelledby="governed-change-title">
      <div><p className="eyebrow">Maker / checker</p><h2 id="governed-change-title">Propose governed change</h2><p>No activation occurs here. A different, authorized principal must review it.</p></div>
      {!session.stepUp.satisfied ? (
        backendMode === "oidc" ? (
          <a className="primary-button" href={stepUpHref()}>Verify identity to continue</a>
        ) : (
          <button className="primary-button" type="button" disabled={busy} onClick={() => void stepUp()}>Verify identity to continue</button>
        )
      ) : (
        <form className="action-form" onSubmit={(event) => void submit(event)}>
          <label>Target ID<input required maxLength={160} value={targetId} onChange={(event) => setTargetId(event.target.value)} /></label>
          <label>Rollback target<input required maxLength={160} value={rollbackTargetId} onChange={(event) => setRollbackTargetId(event.target.value)} /></label>
          {needsSecretRef ? <label>Opaque secret reference<input required placeholder="secretref://vault/path#version" value={secretRef} onChange={(event) => setSecretRef(event.target.value)} /></label> : null}
          <label className="wide">Reason<textarea required minLength={12} maxLength={1_000} value={reason} onChange={(event) => setReason(event.target.value)} /></label>
          <button className="primary-button" disabled={busy} type="submit">Send for independent review</button>
        </form>
      )}
      {message ? <p className="inline-message" role="status">{message}</p> : null}
    </section>
  );
}

function SourceOnboardingPanel({ session }: { readonly session: SessionView }): ReactElement {
  const [name, setName] = useState("Primary loan tape");
  const [deliveryMode, setDeliveryMode] = useState<"postgresql" | "xlsx" | "parquet" | "s3">("postgresql");
  const [sourceLocator, setSourceLocator] = useState("risk_read.loan_tape");
  const [secretRef, setSecretRef] = useState("secretref://vault/postgres/risk-reader#v2");
  const [watermarkField, setWatermarkField] = useState("as_of_date");
  const [preview, setPreview] = useState<SourceContractPreview>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const connected = deliveryMode === "postgresql" || deliveryMode === "s3";

  const submit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    setBusy(true); setError(undefined); setPreview(undefined);
    try {
      setPreview(await platformApi.previewSourceContract({
        name,
        deliveryMode,
        sourceLocator,
        watermarkField,
        notes: "Created through the fixture onboarding workflow.",
        ...(connected ? { secretRef } : {}),
      }, session.csrfToken));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Preview failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="onboarding-card" aria-labelledby="source-onboarding-title">
      <div className="onboarding-heading"><div><p className="eyebrow">Guided onboarding</p><h2 id="source-onboarding-title">Profile a new source contract</h2><p>Enter metadata and an opaque credential reference. Previewing never activates a contract or writes to the source.</p></div><span className="mode-pill">Fixture preview</span></div>
      <form className="action-form" onSubmit={(event) => void submit(event)}>
        <label>Contract name<input required minLength={3} value={name} onChange={(event) => setName(event.target.value)} /></label>
        <label>Delivery mode<select value={deliveryMode} onChange={(event) => setDeliveryMode(event.target.value as typeof deliveryMode)}><option value="postgresql">PostgreSQL</option><option value="xlsx">XLSX</option><option value="parquet">Parquet</option><option value="s3">S3 object delivery</option></select></label>
        <label>Source locator<input required value={sourceLocator} onChange={(event) => setSourceLocator(event.target.value)} /></label>
        <label>Watermark field<input required pattern="[A-Za-z_][A-Za-z0-9_]{0,62}" value={watermarkField} onChange={(event) => setWatermarkField(event.target.value)} /></label>
        {connected ? <label className="wide">Opaque secret reference<input required pattern="secretref://.*" value={secretRef} onChange={(event) => setSecretRef(event.target.value)} /></label> : null}
        <button className="primary-button" disabled={busy} type="submit">{busy ? "Profiling…" : "Run fixture profile"}</button>
      </form>
      {error ? <p className="error-banner" role="alert">{error}</p> : null}
      {preview ? <div className="profile-result" role="status"><div><strong>Preview {preview.previewId}</strong><span>{preview.profile.length} fields sampled · activation still requires maker/checker approval</span></div><div className="profile-grid">{preview.profile.map((field) => <div key={field.field}><strong>{field.field}</strong><span>{field.inferredType}</span><small>{field.nullShare} null · {field.distinctCount} distinct</small></div>)}</div><ul>{preview.findings.map((finding) => <li key={finding.message}>{finding.message}</li>)}</ul></div> : null}
    </section>
  );
}

function ApprovalsPanel({ backendMode, session, onSessionChange }: { readonly backendMode: BackendMetadata["backendMode"]; readonly session: SessionView; readonly onSessionChange: (session: SessionView) => void }): ReactElement {
  const [records, setRecords] = useState<readonly ApprovalRecord[]>([]);
  const [error, setError] = useState<string>();

  const refresh = useCallback(async () => {
    try { setRecords((await platformApi.approvals()).items); setError(undefined); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not load approvals"); }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  const stepUp = async (): Promise<void> => {
    try {
      if (backendMode === "fixture") {
        onSessionChange(await platformApi.fixtureStepUp(session.csrfToken));
      } else {
        window.location.assign(stepUpHref());
      }
    }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Step-up failed"); }
  };

  const decide = async (record: ApprovalRecord, decision: "approved" | "rejected"): Promise<void> => {
    try {
      await platformApi.decideApproval(record.id, { decision, rationale: `${decision === "approved" ? "Approved" : "Rejected"} after independent fixture review.` }, session.csrfToken);
      await refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Decision failed"); }
  };

  return (
    <section className="approval-card" aria-labelledby="approval-queue-title">
      <div className="table-toolbar"><div><p className="eyebrow">Live session queue</p><h2 id="approval-queue-title">Operator-created proposals</h2></div>{!session.stepUp.satisfied ? (backendMode === "oidc" ? <a className="primary-button" href={stepUpHref()}>Step up to review</a> : <button type="button" className="primary-button" onClick={() => void stepUp()}>Step up to review</button>) : null}</div>
      {error ? <p className="error-banner" role="alert">{error}</p> : null}
      {records.length === 0 ? <div className="empty-state"><strong>No pending proposals in this process</strong><span>Create one from a governed administration screen, then sign in as a different checker.</span></div> : (
        <ul className="approval-list">{records.map((record) => <li key={record.id}><div><strong>{record.kind.replaceAll("_", " ")}</strong><span>{record.targetId} · Maker: {record.maker.displayName}</span><small>Rollback: {record.rollbackTargetId}</small></div><span className={`state-chip state-${record.status}`}>{record.status}</span>{record.status === "pending" && session.stepUp.satisfied ? <div className="decision-buttons"><button type="button" onClick={() => void decide(record, "rejected")}>Reject</button><button className="primary-button" type="button" onClick={() => void decide(record, "approved")}>Approve</button></div> : null}</li>)}</ul>
      )}
    </section>
  );
}

function Workspace({ backendMode, session, onSessionChange, onSignedOut }: { readonly backendMode: BackendMetadata["backendMode"]; readonly session: SessionView; readonly onSessionChange: (session: SessionView) => void; readonly onSignedOut: () => void }): ReactElement {
  const [navigation, setNavigation] = useState<readonly NavigationItem[]>([]);
  const [section, setSection] = useState<SectionId>(initialSection);
  const [payload, setPayload] = useState<WorkbenchSectionPayload>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    void platformApi.navigation().then(({ items }) => {
      setNavigation(items);
      if (!items.some((item) => item.id === section)) setSection(items[0]?.id ?? "overview");
    }).catch((cause: unknown) => setError(cause instanceof Error ? cause.message : "Navigation failed"));
  }, [section]);

  useEffect(() => {
    setPayload(undefined); setError(undefined);
    void platformApi.section(section).then(setPayload).catch((cause: unknown) => setError(cause instanceof Error ? cause.message : "Section failed"));
    window.history.replaceState(null, "", `#/${section}`);
  }, [section]);

  const groups = useMemo(() => ["Monitor", "Data trust", "Governance", "Operations"] as const, []);
  const signOut = async (): Promise<void> => {
    try { await platformApi.logout(session.csrfToken); } finally { onSignedOut(); }
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup"><span className="brand-mark">A</span><span>ABL / RISK</span></div>
        <nav aria-label="Primary navigation">{groups.map((group) => {
          const items = navigation.filter((item) => item.group === group);
          return items.length ? <section className="nav-group" key={group}><h2>{group}</h2>{items.map((item) => <button className={item.id === section ? "nav-item active" : "nav-item"} type="button" key={item.id} aria-current={item.id === section ? "page" : undefined} onClick={() => setSection(item.id)}><span className="nav-glyph" aria-hidden="true">{item.label.slice(0, 1)}</span>{item.label}</button>)}</section> : null;
        })}</nav>
        <div className="sidebar-foot"><span className="environment-dot" />Local fixture environment</div>
      </aside>
      <main className="workspace">
        <header className="topbar">
          <div><p className="eyebrow">Demo Bank · Portfolio surveillance</p><h1>{payload?.title ?? "Loading…"}</h1></div>
          <div className="user-menu"><span className="avatar">{session.principal.displayName.split(" ").map((part) => part[0]).join("")}</span><span><strong>{session.principal.displayName}</strong><small>{session.principal.roles.join(", ").replaceAll("_", " ")}</small></span><button type="button" onClick={() => void signOut()}>Sign out</button></div>
        </header>
        <div className="fixture-banner"><strong>Fixture data</strong><span>No live control plane or portfolio database is connected. Values are representative only.</span><span>As of {payload ? new Date(payload.asOf).toLocaleString() : "—"}</span></div>
        <div className="content">
          {payload ? <div className="page-intro"><p>{payload.description}</p><div className="header-actions"><button type="button" className="quiet-button">Save view</button><button type="button" className="primary-button">Review evidence</button></div></div> : null}
          {error ? <p className="error-banner" role="alert">{error}</p> : null}
          {payload ? <SectionView payload={payload} /> : !error ? <p aria-busy="true">Loading review data…</p> : null}
          {section === "source-contracts" ? <SourceOnboardingPanel session={session} /> : null}
          {ACTION_FOR_SECTION[section] ? <GovernedActionPanel backendMode={backendMode} kind={ACTION_FOR_SECTION[section]} session={session} onSessionChange={onSessionChange} /> : null}
          {section === "approvals" ? <ApprovalsPanel backendMode={backendMode} session={session} onSessionChange={onSessionChange} /> : null}
        </div>
      </main>
    </div>
  );
}

export function App(): ReactElement {
  const [metadata, setMetadata] = useState<BackendMetadata>();
  const [session, setSession] = useState<SessionView | null>();

  useEffect(() => {
    void platformApi.metadata().then(setMetadata);
    void platformApi.session().then(setSession).catch((cause: unknown) => {
      if (cause instanceof ApiError && cause.status === 401) setSession(null);
      else setSession(null);
    });
  }, []);

  if (session === undefined || metadata === undefined) return <LoadingScreen />;
  if (session === null) return <SignIn metadata={metadata} onSignedIn={setSession} />;
  return <Workspace backendMode={metadata.backendMode} session={session} onSessionChange={setSession} onSignedOut={() => setSession(null)} />;
}

export { ACTION_FOR_SECTION, DEMO_USERS, HIGH_RISK_ACTION_KINDS };
