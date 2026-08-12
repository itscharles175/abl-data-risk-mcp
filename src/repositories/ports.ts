import type {
  InputPopulationV1,
  MappingApplicationV1,
  MappingSpecV2,
  SourceContractV1
} from "../contracts/index.js";
import type { DatasetSnapshotV2 } from "../contracts/dataset-snapshot-v2.js";
import type { CanonicalJsonValue, Sha256Hash } from "../contracts/canonical.js";

export interface RepositoryWriteContext {
  readonly tenantId: string;
  readonly actorId: string;
  readonly idempotencyKey: string;
  /** Required for updates to versioned state. Use zero only for the initial revision. */
  readonly expectedRevision?: number;
}

export interface RepositoryPageRequest {
  readonly limit?: number;
  /** Opaque repository-issued cursor; clients must not manufacture cursors. */
  readonly cursor?: string;
}

export interface RepositoryPage<T> {
  readonly items: readonly T[];
  readonly nextCursor: string | null;
}

export interface RepositoryPutResult<T> {
  readonly record: T;
  readonly replayed: boolean;
}

export type RepositoryErrorCode =
  | "INVALID_ARGUMENT"
  | "NOT_FOUND"
  | "ALREADY_EXISTS"
  | "IDEMPOTENCY_CONFLICT"
  | "CONCURRENCY_CONFLICT"
  | "INTEGRITY_FAILURE";

export class RepositoryError extends Error {
  constructor(readonly code: RepositoryErrorCode, message: string) {
    super(message);
    this.name = "RepositoryError";
  }
}

export interface TenantRecord {
  readonly tenantId: string;
}

export interface RevisionedTenantRecord extends TenantRecord {
  readonly revision: number;
}

/** Immutable resources. A duplicate identity is never overwritten. */
export interface ImmutableRepositoryPort<T extends TenantRecord> {
  put(record: T, context: RepositoryWriteContext): Promise<RepositoryPutResult<T>>;
  get(tenantId: string, recordId: string): Promise<T | undefined>;
  list(tenantId: string, page?: RepositoryPageRequest): Promise<RepositoryPage<T>>;
}

/** Current-state records whose complete revision history remains queryable. */
export interface VersionedRepositoryPort<T extends RevisionedTenantRecord> {
  put(record: T, context: RepositoryWriteContext): Promise<RepositoryPutResult<T>>;
  getCurrent(tenantId: string, recordId: string): Promise<T | undefined>;
  getRevision(tenantId: string, recordId: string, revision: number): Promise<T | undefined>;
  listCurrent(tenantId: string, page?: RepositoryPageRequest): Promise<RepositoryPage<T>>;
  listHistory(tenantId: string, recordId: string): Promise<readonly T[]>;
}

export interface ControlRepositoryPort {
  readonly sourceContracts: ImmutableRepositoryPort<SourceContractV1>;
  readonly datasetSnapshots: ImmutableRepositoryPort<DatasetSnapshotV2>;
  readonly mappingSpecs: ImmutableRepositoryPort<MappingSpecV2>;
  readonly mappingApplications: ImmutableRepositoryPort<MappingApplicationV1>;
  readonly inputPopulations: ImmutableRepositoryPort<InputPopulationV1>;
}

export type FoundationDefinitionKind =
  | "dictionary_bundle"
  | "mapping_compiler_bundle"
  | "methodology_bundle"
  | "data_quality_profile"
  | "authorization_policy"
  | "monitor_definition"
  | "metric_definition"
  | "cohort_definition"
  | "bin_definition"
  | "reconciliation_definition"
  | "entity_resolution_definition"
  | "report_definition";

export interface DefinitionRepositoryRecordV1 extends RevisionedTenantRecord {
  readonly contractVersion: 1;
  readonly definitionId: string;
  readonly definitionKey: string;
  readonly kind: FoundationDefinitionKind;
  readonly version: string;
  readonly status: "proposed" | "validated" | "approved" | "active" | "superseded" | "retired";
  readonly document: CanonicalJsonValue;
  readonly documentHash: Sha256Hash;
  readonly effectiveFrom: string;
  readonly effectiveTo?: string;
}

export interface DefinitionRepositoryPort {
  readonly records: VersionedRepositoryPort<DefinitionRepositoryRecordV1>;
}

export type FoundationRole =
  | "risk_analyst"
  | "risk_reviewer"
  | "data_steward"
  | "security_admin"
  | "platform_operator"
  | "auditor";

export interface MembershipRepositoryRecordV1 extends RevisionedTenantRecord {
  readonly contractVersion: 1;
  readonly membershipId: string;
  readonly issuer: string;
  readonly subject: string;
  readonly clientId: string;
  readonly principalId: string;
  readonly roles: readonly FoundationRole[];
  readonly status: "proposed" | "active" | "revoked";
  readonly notBefore?: string;
  readonly expiresAt?: string;
}

export interface MembershipRepositoryPort {
  readonly records: VersionedRepositoryPort<MembershipRepositoryRecordV1>;
}

export interface JobRepositoryRecordV1 extends RevisionedTenantRecord {
  readonly contractVersion: 1;
  readonly jobId: string;
  readonly jobKind: string;
  readonly status: "queued" | "running" | "succeeded" | "failed" | "cancelled";
  readonly request: CanonicalJsonValue;
  readonly requestHash: Sha256Hash;
  readonly requestedBy: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly resultArtifactId?: string;
  readonly errorCode?: string;
}

export interface JobRepositoryPort {
  readonly records: VersionedRepositoryPort<JobRepositoryRecordV1>;
}

export interface AlertRepositoryRecordV1 extends RevisionedTenantRecord {
  readonly contractVersion: 1;
  readonly alertId: string;
  readonly monitorId: string;
  readonly dedupeKey: Sha256Hash;
  readonly severity: "info" | "warning" | "error" | "critical";
  readonly status: "open" | "acknowledged" | "escalated" | "resolved" | "suppressed";
  readonly evidence: CanonicalJsonValue;
  readonly evidenceHash: Sha256Hash;
  readonly firstSeenAt: string;
  readonly lastSeenAt: string;
}

export interface AlertRepositoryPort {
  readonly records: VersionedRepositoryPort<AlertRepositoryRecordV1>;
}

export type SecurityRepositoryRecordV1 = ReplaySecurityRecordV1 | HandleSecurityRecordV1;

export interface ReplaySecurityRecordV1 extends RevisionedTenantRecord {
  readonly contractVersion: 1;
  readonly recordKind: "replay";
  readonly securityRecordId: string;
  readonly principalBindingHash: Sha256Hash;
  readonly nonceHash: Sha256Hash;
  readonly expiresAt: string;
  readonly state: "reserved" | "consumed";
}

export interface HandleSecurityRecordV1 extends RevisionedTenantRecord {
  readonly contractVersion: 1;
  readonly recordKind: "handle";
  readonly securityRecordId: string;
  readonly principalBindingHash: Sha256Hash;
  readonly purposeHash: Sha256Hash;
  readonly expiresAt: string;
  readonly state: "active" | "revoked" | "expired";
}

export interface SecurityRepositoryPort {
  readonly records: VersionedRepositoryPort<SecurityRepositoryRecordV1>;
}

export interface ArtifactMetadataV1 extends TenantRecord {
  readonly contractVersion: 1;
  readonly artifactId: string;
  readonly kind: string;
  readonly mediaType: string;
  readonly contentHash: Sha256Hash;
  readonly byteLength: number;
  readonly keyId: string;
  readonly uri: string;
  readonly createdAt: string;
}

export interface PutArtifactCommandV1 {
  readonly metadata: ArtifactMetadataV1;
  readonly bytes: Uint8Array;
}

export interface ArtifactRepositoryPort {
  put(
    command: PutArtifactCommandV1,
    context: RepositoryWriteContext
  ): Promise<RepositoryPutResult<ArtifactMetadataV1>>;
  getMetadata(tenantId: string, artifactId: string): Promise<ArtifactMetadataV1 | undefined>;
  read(tenantId: string, artifactId: string): Promise<Uint8Array | undefined>;
  list(tenantId: string, page?: RepositoryPageRequest): Promise<RepositoryPage<ArtifactMetadataV1>>;
}

export interface AppendAuditEventCommandV1 extends TenantRecord {
  readonly contractVersion: 1;
  readonly eventId: string;
  readonly eventType: string;
  readonly entityType: string;
  readonly entityId: string;
  readonly actorId: string;
  readonly details: CanonicalJsonValue;
  readonly occurredAt: string;
}

export interface AuditEventRecordV1 extends AppendAuditEventCommandV1 {
  readonly sequence: number;
  readonly eventHash: Sha256Hash;
  readonly previousEventHash: Sha256Hash | null;
}

export interface AuditRepositoryPort {
  append(
    command: AppendAuditEventCommandV1,
    context: RepositoryWriteContext
  ): Promise<RepositoryPutResult<AuditEventRecordV1>>;
  list(
    tenantId: string,
    afterSequence?: number,
    limit?: number
  ): Promise<readonly AuditEventRecordV1[]>;
}

export interface FoundationRepositoryPorts {
  readonly control: ControlRepositoryPort;
  readonly definitions: DefinitionRepositoryPort;
  readonly memberships: MembershipRepositoryPort;
  readonly jobs: JobRepositoryPort;
  readonly alerts: AlertRepositoryPort;
  readonly security: SecurityRepositoryPort;
  readonly artifacts: ArtifactRepositoryPort;
  readonly audit: AuditRepositoryPort;
}
