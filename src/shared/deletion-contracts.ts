export type ArtifactDeletionStatus =
  | "pending"
  | "approved"
  | "executing"
  | "completed"
  | "failed"
  | "cancelled";

export interface ArtifactDeletionRequestV1 {
  readonly contractVersion: 1;
  readonly tenantId: string;
  readonly requestId: string;
  readonly artifactId: string;
  readonly objectKey: string;
  readonly objectVersionId: string;
  readonly requestedBy: string;
  readonly reasonHash: string;
  readonly executeAfter: string;
  readonly status: ArtifactDeletionStatus;
  readonly approvedBy: string | null;
  readonly approvedAt: string | null;
  readonly executionId: string | null;
  readonly completedAt: string | null;
  readonly errorCode: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CreateArtifactDeletionRequest {
  readonly tenantId: string;
  readonly artifactId: string;
  readonly objectKey: string;
  readonly objectVersionId: string;
  readonly requestedBy: string;
  readonly reason: string;
  readonly executeAfter: string;
}

export interface ArtifactDeletionRequestStorePort {
  create(input: CreateArtifactDeletionRequest): Promise<ArtifactDeletionRequestV1>;
  get(tenantId: string, requestId: string): Promise<ArtifactDeletionRequestV1 | undefined>;
  approve(
    tenantId: string,
    requestId: string,
    approvedBy: string,
    approvedAt: string
  ): Promise<ArtifactDeletionRequestV1 | undefined>;
  markExecuting(
    tenantId: string,
    requestId: string,
    executionId: string,
    now: string
  ): Promise<ArtifactDeletionRequestV1 | undefined>;
  markCompleted(
    tenantId: string,
    requestId: string,
    executionId: string,
    now: string
  ): Promise<ArtifactDeletionRequestV1 | undefined>;
  markFailed(
    tenantId: string,
    requestId: string,
    executionId: string,
    errorCode: string,
    now: string
  ): Promise<ArtifactDeletionRequestV1 | undefined>;
}
