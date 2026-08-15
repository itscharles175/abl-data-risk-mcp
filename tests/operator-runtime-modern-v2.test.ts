import assert from "node:assert/strict";
import { test } from "node:test";

import type { OperatorPrincipal } from "../src/operator/control-plane.js";
import {
  bindOperatorModernSnapshotRuntime,
  OperatorRuntimeError
} from "../src/operator/runtime.js";
import type { ModernSnapshotRuntimeV1 } from "../src/services/modern-snapshot-runtime-v1.js";

const LOCAL_PRINCIPAL: OperatorPrincipal = {
  principalId: `local-os:${"a".repeat(64)}`,
  authenticationMethod: "local_os_account",
  authorizationScope: "global_admin"
};

test("modern operator binding derives one immutable tenant from the trusted runtime", () => {
  const modern = runtime("tenant-a");
  const bound = bindOperatorModernSnapshotRuntime(LOCAL_PRINCIPAL, modern);

  assert.deepEqual(bound.principal, { ...LOCAL_PRINCIPAL, tenantId: "tenant-a" });
  assert.equal(bound.capture, modern.capture);
  assert.equal(bound.certification, modern.certification);
  assert.equal(Object.isFrozen(bound), true);
  assert.equal(Object.isFrozen(bound.principal), true);
});

test("modern operator binding rejects cross-tenant and malformed trusted compositions", () => {
  assert.throws(
    () =>
      bindOperatorModernSnapshotRuntime(
        { ...LOCAL_PRINCIPAL, tenantId: "tenant-a" },
        runtime("tenant-b")
      ),
    invalidConfiguration
  );
  assert.throws(
    () => bindOperatorModernSnapshotRuntime(LOCAL_PRINCIPAL, runtime("tenant a")),
    invalidConfiguration
  );
  assert.throws(
    () =>
      bindOperatorModernSnapshotRuntime(LOCAL_PRINCIPAL, {
        tenantId: "tenant-a",
        capture: {} as ModernSnapshotRuntimeV1["capture"],
        certification: runtime("tenant-a").certification
      }),
    invalidConfiguration
  );
});

test("omitting modern ports preserves the legacy global-admin principal exactly", () => {
  const legacy = bindOperatorModernSnapshotRuntime(LOCAL_PRINCIPAL);
  assert.equal(legacy.principal, LOCAL_PRINCIPAL);
  assert.equal(legacy.capture, undefined);
  assert.equal(legacy.certification, undefined);
});

function runtime(tenantId: string): ModernSnapshotRuntimeV1 {
  return {
    tenantId,
    capture: {
      capture: async () => assert.fail("capture should not run")
    } as unknown as ModernSnapshotRuntimeV1["capture"],
    certification: {
      certify: async () => assert.fail("certification should not run")
    } as unknown as ModernSnapshotRuntimeV1["certification"]
  };
}

function invalidConfiguration(error: unknown): boolean {
  return (
    error instanceof OperatorRuntimeError && error.code === "INVALID_OPERATOR_CONFIGURATION"
  );
}
