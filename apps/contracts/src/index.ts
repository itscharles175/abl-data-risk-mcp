import { z } from "zod";

export const PLATFORM_ROLES = [
  "risk_analyst",
  "risk_reviewer",
  "data_steward",
  "security_admin",
  "platform_operator",
  "auditor",
] as const;

export const PlatformRoleSchema = z.enum(PLATFORM_ROLES);
export type PlatformRole = z.infer<typeof PlatformRoleSchema>;

export const PLATFORM_PERMISSIONS = [
  "portfolio:read",
  "analysis:run",
  "source:govern",
  "mapping:govern",
  "definition:govern",
  "job:operate",
  "report:review",
  "alert:review",
  "membership:govern",
  "policy:govern",
  "connector:govern",
  "key:rotate",
  "deployment:govern",
  "audit:read",
  "approval:review",
  "source:approve",
  "mapping:approve",
  "definition:approve",
  "membership:approve",
  "policy:approve",
  "connector:approve",
  "key:approve",
  "deployment:approve",
] as const;

export const PlatformPermissionSchema = z.enum(PLATFORM_PERMISSIONS);
export type PlatformPermission = z.infer<typeof PlatformPermissionSchema>;

export const ROLE_PERMISSIONS: Readonly<Record<PlatformRole, readonly PlatformPermission[]>> = {
  risk_analyst: ["portfolio:read", "analysis:run", "alert:review"],
  risk_reviewer: [
    "portfolio:read",
    "report:review",
    "alert:review",
    "approval:review",
    "source:approve",
    "mapping:approve",
    "definition:approve",
  ],
  data_steward: [
    "portfolio:read",
    "source:govern",
    "mapping:govern",
    "definition:govern",
    "approval:review",
    "source:approve",
    "mapping:approve",
    "definition:approve",
  ],
  security_admin: [
    "membership:govern",
    "policy:govern",
    "connector:govern",
    "key:rotate",
    "audit:read",
    "approval:review",
    "membership:approve",
    "policy:approve",
    "connector:approve",
    "key:approve",
  ],
  platform_operator: [
    "portfolio:read",
    "job:operate",
    "connector:govern",
    "deployment:govern",
    "approval:review",
    "connector:approve",
    "deployment:approve",
  ],
  auditor: ["portfolio:read", "audit:read", "report:review"],
};

export const SECTION_IDS = [
  "overview",
  "portfolios",
  "facilities",
  "source-contracts",
  "profiles",
  "snapshots",
  "certifications",
  "data-quality",
  "reconciliations",
  "mappings",
  "definitions",
  "jobs",
  "reports",
  "alerts",
  "memberships",
  "policies",
  "connectors",
  "key-rotations",
  "deployment",
  "audit",
  "approvals",
] as const;

export const SectionIdSchema = z.enum(SECTION_IDS);
export type SectionId = z.infer<typeof SectionIdSchema>;

export interface NavigationItem {
  readonly id: SectionId;
  readonly label: string;
  readonly group: "Monitor" | "Data trust" | "Governance" | "Operations";
  readonly permission: PlatformPermission;
}

export const NAVIGATION: readonly NavigationItem[] = [
  { id: "overview", label: "Overview", group: "Monitor", permission: "portfolio:read" },
  { id: "portfolios", label: "Portfolios", group: "Monitor", permission: "portfolio:read" },
  { id: "facilities", label: "Facilities", group: "Monitor", permission: "portfolio:read" },
  { id: "source-contracts", label: "Source contracts", group: "Data trust", permission: "source:govern" },
  { id: "profiles", label: "Schema profiles", group: "Data trust", permission: "source:govern" },
  { id: "snapshots", label: "Snapshots", group: "Data trust", permission: "source:govern" },
  { id: "certifications", label: "Certifications", group: "Data trust", permission: "source:govern" },
  { id: "data-quality", label: "Data quality", group: "Data trust", permission: "source:govern" },
  { id: "reconciliations", label: "Reconciliations", group: "Data trust", permission: "source:govern" },
  { id: "mappings", label: "Mappings", group: "Governance", permission: "mapping:govern" },
  { id: "definitions", label: "Definitions", group: "Governance", permission: "definition:govern" },
  { id: "jobs", label: "Jobs", group: "Operations", permission: "job:operate" },
  { id: "reports", label: "Reports", group: "Monitor", permission: "report:review" },
  { id: "alerts", label: "Alerts", group: "Monitor", permission: "alert:review" },
  { id: "memberships", label: "Memberships", group: "Governance", permission: "membership:govern" },
  { id: "policies", label: "Policies", group: "Governance", permission: "policy:govern" },
  { id: "connectors", label: "Connectors", group: "Operations", permission: "connector:govern" },
  { id: "key-rotations", label: "Key rotations", group: "Operations", permission: "key:rotate" },
  { id: "deployment", label: "Deployment", group: "Operations", permission: "deployment:govern" },
  { id: "audit", label: "Audit", group: "Governance", permission: "audit:read" },
  { id: "approvals", label: "Approval queue", group: "Governance", permission: "approval:review" },
] as const;

export const OpaqueSecretRefSchema = z
  .string()
  .min(12)
  .max(512)
  .regex(
    /^secretref:\/\/[a-z0-9][a-z0-9-]*(?:\/[A-Za-z0-9._~:@%+-]+)+(?:#[A-Za-z0-9._~:@%+-]+)?$/,
    "Expected an opaque secretref:// reference; raw secret material is forbidden",
  );
export type OpaqueSecretRef = z.infer<typeof OpaqueSecretRefSchema>;

const SENSITIVE_FIELD_FRAGMENTS = [
  "password",
  "passwd",
  "pwd",
  "secret",
  "credential",
  "apikey",
  "accesskey",
  "authtoken",
  "bearertoken",
  "refreshtoken",
  "privatekey",
  "connectionstring",
  "dsn",
] as const;

const RAW_SECRET_PATTERNS = [
  /-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----/iu,
  /\b(?:Bearer|Basic)\s+[A-Za-z0-9+/._~-]{12,}={0,2}\b/iu,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u,
  /\bsk-[A-Za-z0-9_-]{20,}\b/u,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u,
  /:\/\/[^\s/@:]+(?::[^\s/@]+)?@/u,
  /(?:^|[?&\s;,])(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\s*[=:]\s*[^\s&;,]+/iu,
] as const;

function isSensitiveFieldName(name: string): boolean {
  const normalized = name.replace(/[^A-Za-z0-9]/gu, "").toLowerCase();
  return SENSITIVE_FIELD_FRAGMENTS.some((fragment) => normalized.includes(fragment));
}

function forbiddenSecretPath(
  value: unknown,
  path: readonly (string | number)[] = [],
  key?: string,
  seen: WeakSet<object> = new WeakSet<object>(),
  depth = 0,
): readonly (string | number)[] | undefined {
  if (depth > 16) return path;
  if (key && isSensitiveFieldName(key)) {
    return typeof value === "string" && OpaqueSecretRefSchema.safeParse(value).success
      ? undefined
      : path;
  }
  if (typeof value === "string") {
    if (OpaqueSecretRefSchema.safeParse(value).success) return undefined;
    return RAW_SECRET_PATTERNS.some((pattern) => pattern.test(value)) ? path : undefined;
  }
  if (!value || typeof value !== "object") return undefined;
  if (seen.has(value)) return path;
  seen.add(value);
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const found = forbiddenSecretPath(value[index], [...path, index], undefined, seen, depth + 1);
      if (found) return found;
    }
    return undefined;
  }
  for (const [childKey, childValue] of Object.entries(value)) {
    const found = forbiddenSecretPath(childValue, [...path, childKey], childKey, seen, depth + 1);
    if (found) return found;
  }
  return undefined;
}

function rejectForbiddenSecretMaterial(
  value: unknown,
  context: z.RefinementCtx,
  basePath: readonly (string | number)[],
): void {
  const path = forbiddenSecretPath(value, basePath);
  if (!path) return;
  context.addIssue({
    code: "custom",
    path: [...path],
    message: "Raw credential material is forbidden; use an opaque secretref:// reference",
  });
}

export const HIGH_RISK_ACTION_KINDS = [
  "source_contract_activation",
  "mapping_activation",
  "methodology_activation",
  "membership_change",
  "policy_change",
  "connector_change",
  "key_rotation",
  "deployment_change",
] as const;

export const HighRiskActionKindSchema = z.enum(HIGH_RISK_ACTION_KINDS);
export type HighRiskActionKind = z.infer<typeof HighRiskActionKindSchema>;

export const DELIVERY_MODES = ["postgresql", "xlsx", "parquet", "s3"] as const;
export const DeliveryModeSchema = z.enum(DELIVERY_MODES);
export type DeliveryMode = z.infer<typeof DeliveryModeSchema>;

export const SourceContractDraftSchema = z
  .object({
    name: z.string().min(3).max(120),
    deliveryMode: DeliveryModeSchema,
    sourceLocator: z.string().min(3).max(512),
    secretRef: OpaqueSecretRefSchema.optional(),
    watermarkField: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,62}$/u).optional(),
    notes: z.string().max(1_000).default(""),
  })
  .strict()
  .superRefine((draft, context) => {
    if ((draft.deliveryMode === "postgresql" || draft.deliveryMode === "s3") && !draft.secretRef) {
      context.addIssue({
        code: "custom",
        path: ["secretRef"],
        message: "Connected sources require an opaque secret reference",
      });
    }
    rejectForbiddenSecretMaterial(draft.sourceLocator, context, ["sourceLocator"]);
    rejectForbiddenSecretMaterial(draft.notes, context, ["notes"]);
  });
export type SourceContractDraft = z.infer<typeof SourceContractDraftSchema>;

const PilotPortableIdentifierSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u);

const PilotRequestIdentifierSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/u);

export const PilotJobScopeSchema = z
  .object({
    tenantId: PilotPortableIdentifierSchema,
    facilityId: PilotPortableIdentifierSchema,
  })
  .strict();
export type PilotJobScope = z.infer<typeof PilotJobScopeSchema>;

export const PilotJobHandleSchema = z
  .string()
  .min(20)
  .max(1_024)
  .regex(/^[A-Za-z0-9._~-]+$/u);

export const PilotPortfolioSurveillanceStartRequestSchema = z
  .object({
    certificationManifestIds: z.array(PilotPortableIdentifierSchema).min(2).max(120),
    definitionVersionIds: z.array(PilotPortableIdentifierSchema).min(2).max(256),
    idempotencyKey: PilotRequestIdentifierSchema,
    purpose: PilotRequestIdentifierSchema,
  })
  .strict()
  .superRefine((request, context) => {
    if (new Set(request.certificationManifestIds).size !== request.certificationManifestIds.length) {
      context.addIssue({
        code: "custom",
        path: ["certificationManifestIds"],
        message: "Certification manifest ids must be unique",
      });
    }
    if (new Set(request.definitionVersionIds).size !== request.definitionVersionIds.length) {
      context.addIssue({
        code: "custom",
        path: ["definitionVersionIds"],
        message: "Definition version ids must be unique",
      });
    }
  });
export type PilotPortfolioSurveillanceStartRequest = z.infer<
  typeof PilotPortfolioSurveillanceStartRequestSchema
>;

export const PilotEmptyMutationSchema = z.object({}).strict();

export const PILOT_JOB_STATUSES = [
  "queued",
  "running",
  "succeeded",
  "failed",
  "cancelled",
] as const;
export type PilotJobStatus = (typeof PILOT_JOB_STATUSES)[number];

export interface PilotStartedJob {
  readonly jobHandle: string;
  readonly status: PilotJobStatus;
  readonly operation: "portfolio_surveillance_v1";
}

export interface PilotJobStatusView {
  readonly operation: "portfolio_surveillance_v1";
  readonly status: PilotJobStatus;
  readonly durableStatus: string;
  readonly attemptCount: number;
  readonly maxAttempts: number;
  readonly cancellationRequested: boolean;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly errorCode: string | null;
  readonly resultAvailable: boolean;
}

export const PilotStartedJobSchema: z.ZodType<PilotStartedJob> = z
  .object({
    jobHandle: PilotJobHandleSchema,
    status: z.enum(PILOT_JOB_STATUSES),
    operation: z.literal("portfolio_surveillance_v1"),
  })
  .strict();

export const PilotJobStatusViewSchema: z.ZodType<PilotJobStatusView> = z
  .object({
    operation: z.literal("portfolio_surveillance_v1"),
    status: z.enum(PILOT_JOB_STATUSES),
    durableStatus: z.enum([
      "submitted",
      "result_artifact_persisted",
      "manifest_artifact_persisted",
      "completion_prepared",
      "completed",
      "cancelled",
      "failed",
    ]),
    attemptCount: z.number().int().nonnegative(),
    maxAttempts: z.number().int().positive(),
    cancellationRequested: z.boolean(),
    createdAt: z.string().datetime(),
    updatedAt: z.string().datetime(),
    errorCode: z.string().min(1).max(256).nullable(),
    resultAvailable: z.boolean(),
  })
  .strict();

export interface PilotJobResultView {
  readonly operation: "portfolio_surveillance_v1";
  readonly manifestId: string;
  readonly artifactId: string;
  readonly resultHash: string;
  readonly result: unknown;
}

export const PilotJobResultViewSchema: z.ZodType<PilotJobResultView> = z
  .object({
    operation: z.literal("portfolio_surveillance_v1"),
    manifestId: PilotPortableIdentifierSchema,
    artifactId: PilotPortableIdentifierSchema,
    resultHash: z.string().regex(/^(?:sha256:)?[a-f0-9]{64}$/u),
    result: z.unknown(),
  })
  .strict();

export interface PilotCapabilityResponse {
  readonly enabled: true;
  readonly scope: PilotJobScope;
  readonly operations: readonly ["portfolio_surveillance_v1"];
}

export interface PilotStartJobResponse {
  readonly scope: PilotJobScope;
  readonly job: PilotStartedJob;
}

export interface PilotJobStatusResponse {
  readonly scope: PilotJobScope;
  readonly job: PilotJobStatusView;
}

export interface PilotJobResultResponse {
  readonly scope: PilotJobScope;
  readonly result: PilotJobResultView;
}

export interface SourceContractPreview {
  readonly previewId: string;
  readonly sourceContract: SourceContractDraft;
  readonly fixture: boolean;
  readonly profile: readonly {
    readonly field: string;
    readonly inferredType: string;
    readonly nullShare: string;
    readonly distinctCount: string;
    readonly driftState: "stable" | "new" | "attention";
  }[];
  readonly findings: readonly {
    readonly severity: "info" | "warning";
    readonly message: string;
  }[];
  readonly nextStep: "propose_activation";
}

export const HighRiskActionRequestSchema = z
  .object({
    kind: HighRiskActionKindSchema,
    targetId: z.string().min(1).max(160),
    reason: z.string().min(12).max(1_000),
    secretRef: OpaqueSecretRefSchema.optional(),
    semanticDiff: z.record(z.string(), z.unknown()).default({}),
    rollbackTargetId: z.string().min(1).max(160),
  })
  .strict()
  .superRefine((request, context) => {
    rejectForbiddenSecretMaterial(request.reason, context, ["reason"]);
    rejectForbiddenSecretMaterial(request.semanticDiff, context, ["semanticDiff"]);
  });
export type HighRiskActionRequest = z.infer<typeof HighRiskActionRequestSchema>;

export const ApprovalDecisionSchema = z
  .object({
    decision: z.enum(["approved", "rejected"]),
    rationale: z.string().min(12).max(1_000),
  })
  .strict();
export type ApprovalDecision = z.infer<typeof ApprovalDecisionSchema>;

export interface SessionPrincipal {
  readonly id: string;
  readonly displayName: string;
  readonly email: string;
  readonly roles: readonly PlatformRole[];
}

export interface SessionView {
  readonly principal: SessionPrincipal;
  readonly permissions: readonly PlatformPermission[];
  readonly csrfToken: string;
  readonly stepUp: {
    readonly satisfied: boolean;
    readonly expiresAt?: string;
  };
  readonly expiresAt: string;
}

export interface BackendMetadata {
  readonly product: "ABL Portfolio Risk Console";
  readonly backendMode: "fixture" | "oidc";
  readonly dataMode: "fixture" | "environment";
  readonly warning: string;
}

export interface WorkbenchColumn {
  readonly key: string;
  readonly label: string;
}

export interface WorkbenchRecord {
  readonly id: string;
  readonly status: "healthy" | "attention" | "blocked" | "pending" | "approved";
  readonly values: Readonly<Record<string, string>>;
}

export interface WorkbenchSectionPayload {
  readonly section: SectionId;
  readonly title: string;
  readonly description: string;
  readonly sourceMode: "fixture" | "environment";
  readonly asOf: string;
  readonly summary: readonly {
    readonly label: string;
    readonly value: string;
    readonly tone: "neutral" | "positive" | "warning";
  }[];
  readonly columns: readonly WorkbenchColumn[];
  readonly rows: readonly WorkbenchRecord[];
}

export const SourceContractPreviewSchema: z.ZodType<SourceContractPreview> = z
  .object({
    previewId: z.string().min(1).max(160),
    sourceContract: SourceContractDraftSchema,
    fixture: z.boolean(),
    profile: z.array(z.object({
      field: z.string().min(1).max(160),
      inferredType: z.string().min(1).max(160),
      nullShare: z.string().min(1).max(80),
      distinctCount: z.string().min(1).max(80),
      driftState: z.enum(["stable", "new", "attention"]),
    }).strict()).max(2_000),
    findings: z.array(z.object({
      severity: z.enum(["info", "warning"]),
      message: z.string().min(1).max(2_000),
    }).strict()).max(2_000),
    nextStep: z.literal("propose_activation"),
  })
  .strict();

export const WorkbenchSectionPayloadSchema: z.ZodType<WorkbenchSectionPayload> = z
  .object({
    section: SectionIdSchema,
    title: z.string().min(1).max(160),
    description: z.string().min(1).max(2_000),
    sourceMode: z.enum(["fixture", "environment"]),
    asOf: z.string().datetime(),
    summary: z.array(z.object({
      label: z.string().min(1).max(160),
      value: z.string().max(2_000),
      tone: z.enum(["neutral", "positive", "warning"]),
    }).strict()).max(256),
    columns: z.array(z.object({
      key: z.string().min(1).max(160),
      label: z.string().min(1).max(160),
    }).strict()).max(256),
    rows: z.array(z.object({
      id: z.string().min(1).max(256),
      status: z.enum(["healthy", "attention", "blocked", "pending", "approved"]),
      values: z.record(z.string().min(1).max(160), z.string().max(2_000)),
    }).strict()).max(10_000),
  })
  .strict();

export const BrowserSafePayloadSchema = z.unknown().superRefine((value, context) => {
  rejectForbiddenSecretMaterial(value, context, []);
});

export interface ApprovalRecord {
  readonly id: string;
  readonly kind: HighRiskActionKind;
  readonly targetId: string;
  readonly reason: string;
  readonly secretRef?: OpaqueSecretRef;
  readonly semanticDiff: Readonly<Record<string, unknown>>;
  readonly rollbackTargetId: string;
  readonly maker: SessionPrincipal;
  readonly checker?: SessionPrincipal;
  readonly status: "pending" | "approved" | "rejected";
  readonly createdAt: string;
  readonly decidedAt?: string;
  readonly rationale?: string;
}

export function permissionsForRoles(roles: readonly PlatformRole[]): readonly PlatformPermission[] {
  return [...new Set(roles.flatMap((role) => ROLE_PERMISSIONS[role]))].sort();
}

export function hasPermission(
  roles: readonly PlatformRole[],
  permission: PlatformPermission,
): boolean {
  return roles.some((role) => ROLE_PERMISSIONS[role].includes(permission));
}
