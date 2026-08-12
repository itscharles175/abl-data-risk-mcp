/**
 * Additive PostgreSQL schema for shared control-plane operations. Operators run
 * migrations in a trusted environment; application roles receive table-level
 * privileges separately. Every lookup key starts with tenant_id.
 */
export const SHARED_POSTGRES_SCHEMA_VERSION = 1 as const;

export const SHARED_POSTGRES_MIGRATION_V1 = String.raw`
CREATE TABLE IF NOT EXISTS abl_schema_migrations (
  component_name text NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (component_name, version)
);

CREATE TABLE IF NOT EXISTS abl_shared_leases (
  tenant_id text NOT NULL,
  resource_kind text NOT NULL,
  resource_id text NOT NULL,
  owner_id text NOT NULL,
  lease_id text NOT NULL,
  fence_token bigint NOT NULL CHECK (fence_token > 0),
  acquired_at timestamptz NOT NULL,
  lease_expires_at timestamptz NOT NULL,
  released_at timestamptz,
  PRIMARY KEY (tenant_id, resource_kind, resource_id),
  CHECK (lease_expires_at > acquired_at)
);
CREATE INDEX IF NOT EXISTS abl_shared_leases_expiry_idx
  ON abl_shared_leases (lease_expires_at);

CREATE TABLE IF NOT EXISTS abl_tenant_scheduler (
  tenant_id text PRIMARY KEY,
  weight integer NOT NULL DEFAULT 1 CHECK (weight BETWEEN 1 AND 100),
  virtual_finish numeric(30, 9) NOT NULL DEFAULT 0,
  last_dispatched_at timestamptz
);

CREATE TABLE IF NOT EXISTS abl_shared_work_items (
  tenant_id text NOT NULL,
  work_id text NOT NULL,
  queue_name text NOT NULL,
  idempotency_key text NOT NULL,
  request_hash char(64) NOT NULL,
  request_json jsonb NOT NULL,
  cost integer NOT NULL DEFAULT 1 CHECK (cost BETWEEN 1 AND 1000),
  priority integer NOT NULL DEFAULT 0 CHECK (priority BETWEEN -100 AND 100),
  status text NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  available_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  worker_id text,
  claim_id text,
  lease_fence_token bigint NOT NULL DEFAULT 0 CHECK (lease_fence_token >= 0),
  lease_expires_at timestamptz,
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 20),
  result_ref text,
  error_code text,
  PRIMARY KEY (tenant_id, work_id),
  UNIQUE (tenant_id, queue_name, idempotency_key)
);
CREATE INDEX IF NOT EXISTS abl_shared_work_claim_idx
  ON abl_shared_work_items (queue_name, status, available_at, tenant_id, priority DESC, created_at);

CREATE TABLE IF NOT EXISTS abl_transactional_outbox (
  tenant_id text NOT NULL,
  event_id text NOT NULL,
  aggregate_kind text NOT NULL,
  aggregate_id text NOT NULL,
  topic text NOT NULL,
  payload_hash char(64) NOT NULL,
  payload_json jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('pending', 'claimed', 'delivered', 'dead_letter')),
  available_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  claimed_by text,
  claim_id text,
  lease_fence_token bigint NOT NULL DEFAULT 0 CHECK (lease_fence_token >= 0),
  lease_expires_at timestamptz,
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 20),
  delivered_at timestamptz,
  receipt_hash char(64),
  error_code text,
  PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX IF NOT EXISTS abl_transactional_outbox_claim_idx
  ON abl_transactional_outbox (tenant_id, topic, status, available_at, created_at);

CREATE TABLE IF NOT EXISTS abl_replay_reservations (
  tenant_id text NOT NULL,
  principal_binding_hash char(64) NOT NULL,
  nonce_hash char(64) NOT NULL,
  reservation_id text NOT NULL,
  generation bigint NOT NULL CHECK (generation > 0),
  state text NOT NULL CHECK (state IN ('reserved', 'consumed')),
  reserved_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (tenant_id, principal_binding_hash, nonce_hash),
  CHECK (expires_at > reserved_at)
);
CREATE INDEX IF NOT EXISTS abl_replay_reservations_expiry_idx
  ON abl_replay_reservations (expires_at);

CREATE TABLE IF NOT EXISTS abl_artifact_deletion_requests (
  tenant_id text NOT NULL,
  request_id text NOT NULL,
  artifact_id text NOT NULL,
  object_key text NOT NULL,
  object_version_id text NOT NULL,
  requested_by text NOT NULL,
  reason_hash char(64) NOT NULL,
  execute_after timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('pending', 'approved', 'executing', 'completed', 'failed', 'cancelled')),
  approved_by text,
  approved_at timestamptz,
  execution_id text,
  completed_at timestamptz,
  error_code text,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, request_id),
  UNIQUE (tenant_id, artifact_id, object_version_id, request_id),
  CHECK (approved_by IS NULL OR approved_by <> requested_by)
);
CREATE INDEX IF NOT EXISTS abl_artifact_deletion_ready_idx
  ON abl_artifact_deletion_requests (tenant_id, status, execute_after);

INSERT INTO abl_schema_migrations (component_name, version)
VALUES ('abl.shared-operations', 1)
ON CONFLICT (component_name, version) DO NOTHING;
`;

export const SHARED_POSTGRES_MIGRATIONS = Object.freeze([
  Object.freeze({ version: SHARED_POSTGRES_SCHEMA_VERSION, sql: SHARED_POSTGRES_MIGRATION_V1 })
]);
