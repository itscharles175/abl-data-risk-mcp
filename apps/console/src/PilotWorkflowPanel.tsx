import { useState, type FormEvent, type ReactElement } from "react";
import type {
  PilotJobResultView,
  PilotJobScope,
  PilotJobStatusView,
  PilotPortfolioSurveillanceStartRequest,
  PilotStartedJob,
} from "@abl/platform-contracts";
import {
  PilotApiError,
  pilotWorkflowClient,
  type PilotWorkflowClient,
} from "./pilot-api.js";

const PREREQUISITES = [
  {
    number: 1,
    label: "Capture source evidence",
    description: "Create the immutable DatasetSnapshotV2 receipt through the trusted operator capture path.",
    authority: "Operator prerequisite",
  },
  {
    number: 2,
    label: "Certify the snapshot",
    description: "Run Mapping V2, data-quality, and declared reconciliation controls to produce certified manifests.",
    authority: "Operator prerequisite",
  },
  {
    number: 3,
    label: "Resolve publication authority",
    description: "Server preflight must resolve an enabled V2-only publication link for the exact certified inputs.",
    authority: "Server enforced",
  },
] as const;

function lines(value: string): string[] {
  return value.split(/[,\n]/u).map((item) => item.trim()).filter(Boolean);
}

function statusTone(status: PilotJobStatusView["status"] | PilotStartedJob["status"]): string {
  if (status === "succeeded") return "complete";
  if (status === "failed" || status === "cancelled") return "blocked";
  return "running";
}

export function PilotWorkflowPanel({
  csrfToken,
  client = pilotWorkflowClient,
}: {
  readonly csrfToken: string;
  readonly client?: PilotWorkflowClient;
}): ReactElement {
  const [scope, setScope] = useState<PilotJobScope>();
  const [discovering, setDiscovering] = useState(false);
  const [unavailable, setUnavailable] = useState(false);
  const [certificationManifestIds, setCertificationManifestIds] = useState(
    "cert-manifest-synthetic-auto-2021-10\ncert-manifest-synthetic-auto-history",
  );
  const [definitionVersionIds, setDefinitionVersionIds] = useState(
    "metric-definitions-synthetic-auto-v1\ncohort-definitions-synthetic-auto-v1",
  );
  const [purpose, setPurpose] = useState("monthly_portfolio_surveillance");
  const [idempotencyKey, setIdempotencyKey] = useState("synthetic-auto-2021-10-surveillance-v1");
  const [started, setStarted] = useState<PilotStartedJob>();
  const [status, setStatus] = useState<PilotJobStatusView>();
  const [result, setResult] = useState<PilotJobResultView>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const discover = async (): Promise<void> => {
    setDiscovering(true); setUnavailable(false); setError(undefined);
    try {
      const response = await client.capability();
      setScope(response.scope);
    } catch (cause) {
      if (cause instanceof PilotApiError && cause.code === "pilot_api_unavailable") setUnavailable(true);
      else setError(cause instanceof Error ? cause.message : "Pilot API discovery failed.");
    } finally {
      setDiscovering(false);
    }
  };

  const start = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    setBusy(true); setError(undefined); setResult(undefined);
    try {
      const input: PilotPortfolioSurveillanceStartRequest = {
        certificationManifestIds: lines(certificationManifestIds),
        definitionVersionIds: lines(definitionVersionIds),
        idempotencyKey,
        purpose,
      };
      const response = await client.start(input, csrfToken);
      setScope(response.scope); setStarted(response.job); setStatus(undefined);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Surveillance job failed to start.");
    } finally {
      setBusy(false);
    }
  };

  const refresh = async (): Promise<void> => {
    if (!started) return;
    setBusy(true); setError(undefined);
    try {
      const response = await client.status(started.jobHandle);
      setScope(response.scope); setStatus(response.job);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Job status failed to load.");
    } finally {
      setBusy(false);
    }
  };

  const cancel = async (): Promise<void> => {
    if (!started) return;
    setBusy(true); setError(undefined);
    try {
      const response = await client.cancel(started.jobHandle, csrfToken);
      setScope(response.scope); setStatus(response.job);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Cancellation failed.");
    } finally {
      setBusy(false);
    }
  };

  const loadResult = async (): Promise<void> => {
    if (!started) return;
    setBusy(true); setError(undefined);
    try {
      const response = await client.result(started.jobHandle);
      setScope(response.scope); setResult(response.result);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Result evidence failed to load.");
    } finally {
      setBusy(false);
    }
  };

  const observedStatus = status?.status ?? started?.status;

  return (
    <section className="pilot-card" aria-labelledby="pilot-workflow-title" data-testid="pilot-workflow">
      <header className="pilot-header">
        <div>
          <p className="eyebrow">Governed pilot runtime</p>
          <h2 id="pilot-workflow-title">Single-facility surveillance run</h2>
          <p>Submit IDs-only certified authority, then track the opaque job handle through status, result, or cancellation.</p>
        </div>
        <span className="pilot-scope">Aggregate only</span>
      </header>

      {!scope && !unavailable ? (
        <div className="pilot-discovery">
          <div><strong>Connect the governed job service</strong><span>Capability discovery is explicit; this page does not assume a live control plane.</span></div>
          <button className="primary-button" type="button" disabled={discovering} onClick={() => void discover()}>{discovering ? "Checking…" : "Check pilot API"}</button>
        </div>
      ) : null}

      {unavailable ? (
        <div className="pilot-unavailable" role="status">
          <strong>Pilot API not composed</strong>
          <span>The console remains read-only until an authorized environment injects the governed pilot job service.</span>
        </div>
      ) : null}

      {scope ? (
        <>
          <dl className="pilot-identity">
            <div><dt>Tenant</dt><dd>{scope.tenantId}</dd></div>
            <div><dt>Facility</dt><dd>{scope.facilityId}</dd></div>
            <div><dt>Operation</dt><dd>portfolio_surveillance_v1</dd></div>
            <div><dt>Identity</dt><dd>Server derived</dd></div>
          </dl>

          <ol className="workflow-rail" aria-label="Governed workflow prerequisites">
            {PREREQUISITES.map((stage) => (
              <li className="workflow-stage workflow-prerequisite" key={stage.number}>
                <div className="stage-number" aria-hidden="true">{stage.number}</div>
                <div className="stage-copy">
                  <div className="stage-title-row"><h3>{stage.label}</h3><span className="state-chip">{stage.authority}</span></div>
                  <p>{stage.description}</p>
                </div>
              </li>
            ))}
            <li className={`workflow-stage workflow-${observedStatus ? statusTone(observedStatus) : "ready"}`}>
              <div className="stage-number" aria-hidden="true">4</div>
              <div className="stage-copy">
                <div className="stage-title-row">
                  <h3>Run portfolio surveillance</h3>
                  {observedStatus ? <span className={`state-chip state-${observedStatus}`}>{observedStatus}</span> : <span className="state-chip">Ready for certified IDs</span>}
                </div>
                <p>Start the durable workflow without sending tenant, facility, or actor identity from the browser.</p>
                {started ? <code className="opaque-handle">{started.jobHandle}</code> : null}
                {status ? <small>{status.durableStatus} · attempt {status.attemptCount} of {status.maxAttempts}{status.cancellationRequested ? " · cancellation requested" : ""}</small> : null}
              </div>
              {started ? (
                <div className="stage-actions">
                  <button className="quiet-button" type="button" disabled={busy} onClick={() => void refresh()}>Refresh status</button>
                  {observedStatus === "queued" || observedStatus === "running" ? <button className="danger-button" type="button" disabled={busy} onClick={() => void cancel()}>Cancel</button> : null}
                  {status?.resultAvailable ? <button className="primary-button" type="button" disabled={busy} onClick={() => void loadResult()}>View result</button> : null}
                </div>
              ) : null}
            </li>
          </ol>

          {!started ? (
            <form className="pilot-form" onSubmit={(event) => void start(event)}>
              <div className="pilot-form-heading"><div><p className="eyebrow">IDs-only request</p><h3>Certified surveillance inputs</h3></div><span>Two or more IDs per authority set</span></div>
              <label>Certification manifest IDs<textarea required value={certificationManifestIds} onChange={(event) => setCertificationManifestIds(event.target.value)} /></label>
              <label>Definition version IDs<textarea required value={definitionVersionIds} onChange={(event) => setDefinitionVersionIds(event.target.value)} /></label>
              <label>Purpose<input required pattern="[A-Za-z0-9][A-Za-z0-9._:@/-]*" value={purpose} onChange={(event) => setPurpose(event.target.value)} /></label>
              <label>Idempotency key<input required pattern="[A-Za-z0-9][A-Za-z0-9._:@/-]*" value={idempotencyKey} onChange={(event) => setIdempotencyKey(event.target.value)} /></label>
              <button className="primary-button" type="submit" disabled={busy}>Start governed surveillance</button>
            </form>
          ) : null}
        </>
      ) : null}

      {error ? <p className="error-banner" role="alert">{error}</p> : null}
      {result ? (
        <article className="result-evidence" aria-live="polite">
          <div className="result-heading"><div><p className="eyebrow">Signed result evidence</p><h3>Portfolio surveillance completed</h3></div><button type="button" aria-label="Close result" onClick={() => setResult(undefined)}>×</button></div>
          <code>{result.manifestId}</code>
          <div className="result-summary"><div><span>Artifact</span><strong>{result.artifactId}</strong></div><div><span>Result hash</span><strong>{result.resultHash}</strong></div><div><span>Operation</span><strong>{result.operation}</strong></div></div>
          <p>Full aggregate result evidence is available from the immutable signed artifact bound to this manifest.</p>
        </article>
      ) : null}
    </section>
  );
}
