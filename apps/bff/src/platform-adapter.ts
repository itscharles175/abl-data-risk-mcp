import { createHash } from "node:crypto";
import {
  SECTION_IDS,
  type SectionId,
  type SourceContractDraft,
  type SourceContractPreview,
  type WorkbenchSectionPayload,
} from "@abl/platform-contracts";

export interface RiskPlatformAdapter {
  readonly dataMode: "fixture" | "environment";
  getWorkbenchSection(section: SectionId): Promise<WorkbenchSectionPayload>;
  previewSourceContract(draft: SourceContractDraft): Promise<SourceContractPreview>;
}

type FixtureSpec = Omit<WorkbenchSectionPayload, "section" | "sourceMode" | "asOf">;

const AS_OF = "2026-08-12T12:00:00.000Z";

const FIXTURES: Readonly<Record<SectionId, FixtureSpec>> = {
  overview: {
    title: "Portfolio command center",
    description: "Certification health, availability, exceptions, and operational readiness.",
    summary: [
      { label: "Managed commitments", value: "$428.0m", tone: "neutral" },
      { label: "Current availability", value: "$96.4m", tone: "positive" },
      { label: "Open exceptions", value: "7", tone: "warning" },
      { label: "Certified through", value: "Jul 2026", tone: "neutral" },
    ],
    columns: [
      { key: "portfolio", label: "Portfolio" },
      { key: "balance", label: "Balance" },
      { key: "availability", label: "Availability" },
      { key: "attention", label: "Attention" },
    ],
    rows: [
      { id: "portfolio-northeast", status: "healthy", values: { portfolio: "Northeast ABL", balance: "$148.2m", availability: "$34.7m", attention: "1 review" } },
      { id: "portfolio-specialty", status: "attention", values: { portfolio: "Specialty Finance", balance: "$173.5m", availability: "$41.2m", attention: "4 reviews" } },
      { id: "portfolio-industrial", status: "healthy", values: { portfolio: "Industrial", balance: "$106.3m", availability: "$20.5m", attention: "2 reviews" } },
    ],
  },
  portfolios: {
    title: "Portfolios",
    description: "Governed portfolio inventory and latest certified observation.",
    summary: [{ label: "Active", value: "3", tone: "positive" }, { label: "Coverage", value: "100%", tone: "positive" }],
    columns: [{ key: "name", label: "Portfolio" }, { key: "owner", label: "Owner" }, { key: "snapshot", label: "Latest snapshot" }, { key: "coverage", label: "Coverage" }],
    rows: [
      { id: "p-001", status: "healthy", values: { name: "Northeast ABL", owner: "Credit Risk", snapshot: "2026-07-31", coverage: "100%" } },
      { id: "p-002", status: "attention", values: { name: "Specialty Finance", owner: "Portfolio Risk", snapshot: "2026-07-31", coverage: "98.7%" } },
    ],
  },
  facilities: {
    title: "Facilities",
    description: "Facility-level exposure, utilization, and review state.",
    summary: [{ label: "Facilities", value: "64", tone: "neutral" }, { label: "Watch list", value: "5", tone: "warning" }],
    columns: [{ key: "facility", label: "Facility" }, { key: "borrower", label: "Borrower" }, { key: "utilization", label: "Utilization" }, { key: "review", label: "Next review" }],
    rows: [
      { id: "f-1042", status: "healthy", values: { facility: "F-1042", borrower: "Northwind Components", utilization: "71.4%", review: "Aug 20" } },
      { id: "f-1178", status: "attention", values: { facility: "F-1178", borrower: "Apex Distribution", utilization: "92.8%", review: "Today" } },
    ],
  },
  "source-contracts": {
    title: "Source contracts",
    description: "Create governed delivery contracts without exposing credentials or editing JSON.",
    summary: [{ label: "Active contracts", value: "5", tone: "positive" }, { label: "Draft previews", value: "1", tone: "neutral" }],
    columns: [{ key: "contract", label: "Contract" }, { key: "delivery", label: "Delivery mode" }, { key: "locator", label: "Source locator" }, { key: "state", label: "State" }],
    rows: [
      { id: "contract-loan-v3", status: "approved", values: { contract: "Loan tape v3", delivery: "PostgreSQL", locator: "risk_read.loan_tape", state: "Active" } },
      { id: "contract-bbc-v2", status: "pending", values: { contract: "BBC collateral v2", delivery: "S3 · Parquet", locator: "s3://client-risk/bbc/", state: "Preview" } },
    ],
  },
  profiles: {
    title: "Schema profiles",
    description: "Type, null, uniqueness, distribution, category, unit, temporal, and drift evidence.",
    summary: [{ label: "Fields profiled", value: "86", tone: "neutral" }, { label: "Material drift", value: "2", tone: "warning" }],
    columns: [{ key: "field", label: "Field" }, { key: "type", label: "Inferred type" }, { key: "nullShare", label: "Null share" }, { key: "distinct", label: "Distinct" }, { key: "drift", label: "Drift" }],
    rows: [
      { id: "profile-balance", status: "healthy", values: { field: "current_balance", type: "decimal(20,2)", nullShare: "0.00%", distinct: "17,904", drift: "Stable" } },
      { id: "profile-grade", status: "attention", values: { field: "risk_grade", type: "category", nullShare: "0.18%", distinct: "14", drift: "2 new values" } },
    ],
  },
  snapshots: {
    title: "Dataset snapshots",
    description: "Immutable deliveries, hashes, watermarks, and correction lineage.",
    summary: [{ label: "Latest received", value: "12:04 UTC", tone: "neutral" }, { label: "Corrections", value: "1", tone: "warning" }],
    columns: [{ key: "snapshot", label: "Snapshot" }, { key: "contract", label: "Source contract" }, { key: "watermark", label: "Watermark" }, { key: "hash", label: "Content hash" }],
    rows: [
      { id: "snap-20260731-v2", status: "pending", values: { snapshot: "Jul 2026 correction", contract: "Loan tape v3", watermark: "2026-07-31", hash: "sha256:4c9a…21fd" } },
      { id: "snap-20260630", status: "approved", values: { snapshot: "Jun 2026", contract: "Loan tape v3", watermark: "2026-06-30", hash: "sha256:d83f…7780" } },
    ],
  },
  certifications: {
    title: "Certifications",
    description: "Population, data-quality, and reconciliation evidence before analysis.",
    summary: [{ label: "Certified", value: "11", tone: "positive" }, { label: "Blocked", value: "1", tone: "warning" }],
    columns: [{ key: "period", label: "Period" }, { key: "population", label: "Population" }, { key: "dq", label: "DQ" }, { key: "reconciliation", label: "Reconciliation" }],
    rows: [
      { id: "cert-202607", status: "pending", values: { period: "Jul 2026", population: "18,405 loans", dq: "2 material findings", reconciliation: "99.94%" } },
      { id: "cert-202606", status: "approved", values: { period: "Jun 2026", population: "18,122 loans", dq: "Passed", reconciliation: "100.00%" } },
    ],
  },
  "data-quality": {
    title: "Data quality",
    description: "Material findings measured by affected records, balance, and portfolio share.",
    summary: [{ label: "Critical", value: "0", tone: "positive" }, { label: "Material balance", value: "$2.1m", tone: "warning" }],
    columns: [{ key: "rule", label: "Rule" }, { key: "severity", label: "Severity" }, { key: "records", label: "Records" }, { key: "balance", label: "Affected balance" }, { key: "share", label: "Portfolio share" }],
    rows: [
      { id: "dq-144", status: "attention", values: { rule: "Maturity after origination", severity: "High", records: "14", balance: "$1.6m", share: "0.37%" } },
      { id: "dq-145", status: "attention", values: { rule: "Unknown risk grade", severity: "Medium", records: "33", balance: "$0.5m", share: "0.12%" } },
    ],
  },
  reconciliations: {
    title: "Reconciliations",
    description: "Segmented source-to-canonical control totals.",
    summary: [{ label: "Segments passed", value: "47 / 48", tone: "warning" }, { label: "Net variance", value: "$241k", tone: "warning" }],
    columns: [{ key: "segment", label: "Segment" }, { key: "source", label: "Source" }, { key: "canonical", label: "Canonical" }, { key: "variance", label: "Variance" }],
    rows: [
      { id: "rec-usd-ar", status: "healthy", values: { segment: "USD · AR", source: "$221.3m", canonical: "$221.3m", variance: "$0" } },
      { id: "rec-cad-inventory", status: "attention", values: { segment: "CAD · Inventory", source: "$18.7m", canonical: "$18.5m", variance: "$241k" } },
    ],
  },
  mappings: {
    title: "Mapping governance",
    description: "Reusable mapping specifications, applications, drift, and activation controls.",
    summary: [{ label: "Active specs", value: "4", tone: "positive" }, { label: "Drift reviews", value: "2", tone: "warning" }],
    columns: [{ key: "mapping", label: "Mapping" }, { key: "version", label: "Version" }, { key: "applications", label: "Applications" }, { key: "state", label: "State" }],
    rows: [
      { id: "map-loan-v3", status: "approved", values: { mapping: "Loan tape canonical", version: "v3", applications: "7 periods", state: "Active" } },
      { id: "map-bbc-v2", status: "pending", values: { mapping: "BBC collateral", version: "v2", applications: "Preview only", state: "Awaiting checker" } },
    ],
  },
  definitions: {
    title: "Governed definitions",
    description: "Methodologies, metrics, cohorts, bins, policies, and report definitions.",
    summary: [{ label: "Active", value: "38", tone: "positive" }, { label: "Draft", value: "6", tone: "neutral" }],
    columns: [{ key: "definition", label: "Definition" }, { key: "type", label: "Type" }, { key: "version", label: "Version" }, { key: "state", label: "State" }],
    rows: [
      { id: "def-roll-rate", status: "approved", values: { definition: "30→60 roll rate", type: "Metric", version: "v4", state: "Active" } },
      { id: "def-risk-bins", status: "pending", values: { definition: "Risk grade bands", type: "Bin", version: "v2", state: "Review" } },
    ],
  },
  jobs: {
    title: "Jobs",
    description: "Durable analytics stages, progress, cancellation, and replay state.",
    summary: [{ label: "Running", value: "2", tone: "neutral" }, { label: "SLA risks", value: "1", tone: "warning" }],
    columns: [{ key: "job", label: "Job" }, { key: "stage", label: "Stage" }, { key: "progress", label: "Progress" }, { key: "started", label: "Started" }],
    rows: [
      { id: "job-a12", status: "pending", values: { job: "Jul surveillance pack", stage: "Analyze", progress: "74%", started: "12:17 UTC" } },
      { id: "job-a11", status: "attention", values: { job: "BBC recomputation", stage: "Reconcile", progress: "41%", started: "11:58 UTC" } },
    ],
  },
  reports: {
    title: "Reports",
    description: "Signed aggregate report packs and immutable distribution manifests.",
    summary: [{ label: "Ready for review", value: "3", tone: "warning" }, { label: "Distributed", value: "24", tone: "positive" }],
    columns: [{ key: "report", label: "Report" }, { key: "period", label: "Period" }, { key: "signature", label: "Signature" }, { key: "state", label: "State" }],
    rows: [
      { id: "report-jul-watch", status: "pending", values: { report: "Monthly watch list", period: "Jul 2026", signature: "Pending", state: "Review" } },
      { id: "report-jun-risk", status: "approved", values: { report: "Portfolio risk pack", period: "Jun 2026", signature: "Verified", state: "Distributed" } },
    ],
  },
  alerts: {
    title: "Alerts",
    description: "Governed monitor breaches with cooldown and acknowledgement state.",
    summary: [{ label: "Open", value: "7", tone: "warning" }, { label: "Critical", value: "1", tone: "warning" }],
    columns: [{ key: "alert", label: "Alert" }, { key: "facility", label: "Facility" }, { key: "observed", label: "Observed" }, { key: "owner", label: "Owner" }],
    rows: [
      { id: "alert-util", status: "attention", values: { alert: "Utilization above 90%", facility: "F-1178", observed: "92.8%", owner: "S. Patel" } },
      { id: "alert-stale", status: "blocked", values: { alert: "BBC data stale", facility: "F-1281", observed: "9 days", owner: "J. Chen" } },
    ],
  },
  memberships: {
    title: "Memberships",
    description: "Tenant roles and scoped access requests; raw credentials are never displayed.",
    summary: [{ label: "Active members", value: "42", tone: "neutral" }, { label: "Pending changes", value: "2", tone: "warning" }],
    columns: [{ key: "principal", label: "Principal" }, { key: "tenant", label: "Tenant" }, { key: "roles", label: "Roles" }, { key: "state", label: "State" }],
    rows: [
      { id: "member-1", status: "healthy", values: { principal: "analyst@demo.invalid", tenant: "Demo Bank", roles: "Risk analyst", state: "Active" } },
      { id: "member-2", status: "pending", values: { principal: "reviewer@demo.invalid", tenant: "Demo Bank", roles: "Risk reviewer", state: "Change pending" } },
    ],
  },
  policies: {
    title: "Authorization policies",
    description: "Versioned purpose, field, masking, and action policies.",
    summary: [{ label: "Active policies", value: "12", tone: "positive" }, { label: "Draft changes", value: "1", tone: "neutral" }],
    columns: [{ key: "policy", label: "Policy" }, { key: "version", label: "Version" }, { key: "scope", label: "Scope" }, { key: "state", label: "State" }],
    rows: [
      { id: "policy-detail", status: "approved", values: { policy: "Drill-through disclosure", version: "v5", scope: "detail:read", state: "Active" } },
      { id: "policy-export", status: "pending", values: { policy: "Report distribution", version: "v3", scope: "report:approve", state: "Review" } },
    ],
  },
  connectors: {
    title: "Connectors",
    description: "Outbound-only client-VPC connectors and opaque credential references.",
    summary: [{ label: "Connected", value: "2", tone: "positive" }, { label: "Needs rotation", value: "1", tone: "warning" }],
    columns: [{ key: "connector", label: "Connector" }, { key: "region", label: "Region" }, { key: "credential", label: "Credential ref" }, { key: "heartbeat", label: "Heartbeat" }],
    rows: [
      { id: "conn-east", status: "healthy", values: { connector: "client-vpc-east", region: "us-east-1", credential: "secretref://vault/connectors/east#v8", heartbeat: "18s ago" } },
      { id: "conn-west", status: "attention", values: { connector: "client-vpc-west", region: "us-west-2", credential: "secretref://vault/connectors/west#v5", heartbeat: "4m ago" } },
    ],
  },
  "key-rotations": {
    title: "Key rotations",
    description: "Governed rotation requests containing references, never secret material.",
    summary: [{ label: "Due in 30 days", value: "3", tone: "warning" }, { label: "Overdue", value: "0", tone: "positive" }],
    columns: [{ key: "key", label: "Key use" }, { key: "reference", label: "Opaque reference" }, { key: "lastRotation", label: "Last rotation" }, { key: "due", label: "Due" }],
    rows: [
      { id: "key-sign", status: "healthy", values: { key: "Plan signing", reference: "secretref://kms/plan-signing#v4", lastRotation: "2026-07-01", due: "2026-10-01" } },
      { id: "key-connector", status: "attention", values: { key: "West connector", reference: "secretref://vault/connectors/west#v5", lastRotation: "2026-05-18", due: "2026-08-18" } },
    ],
  },
  deployment: {
    title: "Deployment configuration",
    description: "Non-secret runtime posture and independently deployable service inventory.",
    summary: [{ label: "Services healthy", value: "5 / 5", tone: "positive" }, { label: "Config drift", value: "0", tone: "positive" }],
    columns: [{ key: "service", label: "Service" }, { key: "release", label: "Release" }, { key: "replicas", label: "Replicas" }, { key: "state", label: "State" }],
    rows: [
      { id: "svc-mcp", status: "healthy", values: { service: "MCP API", release: "0.1.0-fixture", replicas: "2 desired", state: "Design fixture" } },
      { id: "svc-worker", status: "pending", values: { service: "Analytics worker", release: "0.1.0-fixture", replicas: "4 desired", state: "Design fixture" } },
    ],
  },
  audit: {
    title: "Audit trail",
    description: "Append-only actor, purpose, policy, and configuration evidence.",
    summary: [{ label: "Events today", value: "1,284", tone: "neutral" }, { label: "Delivery backlog", value: "0", tone: "positive" }],
    columns: [{ key: "time", label: "Time" }, { key: "actor", label: "Actor" }, { key: "event", label: "Event" }, { key: "evidence", label: "Evidence" }],
    rows: [
      { id: "audit-1", status: "healthy", values: { time: "12:32:18", actor: "steward@demo.invalid", event: "Mapping previewed", evidence: "audit:91be…7d2a" } },
      { id: "audit-2", status: "healthy", values: { time: "12:30:02", actor: "system", event: "Snapshot hashed", evidence: "audit:0fc1…3a18" } },
    ],
  },
  approvals: {
    title: "Approval queue",
    description: "High-risk proposals requiring step-up and a different checker.",
    summary: [{ label: "Pending", value: "3", tone: "warning" }, { label: "Oldest", value: "2h 14m", tone: "neutral" }],
    columns: [{ key: "change", label: "Change" }, { key: "maker", label: "Maker" }, { key: "rollback", label: "Rollback target" }, { key: "state", label: "State" }],
    rows: [
      { id: "approval-fixture-1", status: "pending", values: { change: "Activate loan mapping v4", maker: "Data Steward", rollback: "map-loan-v3", state: "Awaiting checker" } },
      { id: "approval-fixture-2", status: "pending", values: { change: "Rotate west connector", maker: "Security Admin", rollback: "key-version-5", state: "Awaiting checker" } },
    ],
  },
};

if (Object.keys(FIXTURES).length !== SECTION_IDS.length) {
  throw new Error("Fixture adapter must cover every console section");
}

export class FixtureRiskPlatformAdapter implements RiskPlatformAdapter {
  public readonly dataMode = "fixture" as const;
  public async getWorkbenchSection(section: SectionId): Promise<WorkbenchSectionPayload> {
    return {
      section,
      sourceMode: "fixture",
      asOf: AS_OF,
      ...FIXTURES[section],
    };
  }

  public async previewSourceContract(draft: SourceContractDraft): Promise<SourceContractPreview> {
    const previewId = createHash("sha256")
      .update(JSON.stringify(draft))
      .digest("hex")
      .slice(0, 20);
    return {
      previewId: `preview-${previewId}`,
      sourceContract: draft,
      fixture: true,
      profile: [
        { field: "loan_id", inferredType: "string", nullShare: "0.00%", distinctCount: "18,405", driftState: "stable" },
        { field: "as_of_date", inferredType: "date", nullShare: "0.00%", distinctCount: "1", driftState: "stable" },
        { field: "current_balance", inferredType: "decimal(20,2)", nullShare: "0.04%", distinctCount: "17,904", driftState: "attention" },
        { field: "risk_grade", inferredType: "category", nullShare: "0.18%", distinctCount: "14", driftState: "new" },
      ],
      findings: [
        { severity: "warning", message: "current_balance has 7 null values affecting $182k of reported balance." },
        { severity: "info", message: "Two previously unseen risk_grade values require a governed code-map decision." },
      ],
      nextStep: "propose_activation",
    };
  }
}
