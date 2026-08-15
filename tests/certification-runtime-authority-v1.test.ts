import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, test } from "node:test";

import { canonicalHash, type DictionaryBundleReferenceV1, type ImmutableBundleReferenceV1 } from "../src/contracts/index.js";
import { ArtifactStore } from "../src/control/artifacts.js";
import {
  CertificationRuntimeAuthorityError,
  CertificationRuntimeAuthorityV1
} from "../src/control/certification-runtime-authority-v1.js";
import {
  HistoricalRuntimeAuthorityError,
  SqliteHistoricalRuntimeAuthorityV1,
  type TrustedRuntimeAuthorityActorV1
} from "../src/control/historical-runtime-authority-v1.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("certification runtime authority freezes exact activated runtime and component evidence", async () => {
  const fixture = authorityFixture();
  const evidence = registerEvidence(fixture.authority);
  const activation = fixture.authority.activateRuntime(CHECKER, {
    runtimeBundleId: evidence.runtime.runtimeBundleId,
    runtimeBundleHash: evidence.runtime.runtimeBundleHash,
    idempotencyKey: "runtime-activate"
  }).value;
  const authority = new CertificationRuntimeAuthorityV1(fixture.authority, {
    tenantId: "tenant-a",
    certifiedAt: "2026-08-13T12:00:00.000Z"
  });

  const resolution = authority.resolveActivatedRuntime({
    runtimeBundleId: evidence.runtime.runtimeBundleId,
    runtimeBundleHash: evidence.runtime.runtimeBundleHash
  });
  assert.deepEqual(resolution.context, authority.context);
  assert.deepEqual(resolution.runtime, evidence.runtime);
  assert.deepEqual(resolution.activation, activation);
  assert.deepEqual(resolution.dictionary, {
    reference: evidence.dictionary,
    content: {
      dictionary: { fields: ["loan_id", "balance"] },
      fieldPolicy: { nulls: "preserve" }
    }
  });
  assert.deepEqual(resolution.mappingCompiler, {
    reference: evidence.compiler,
    content: { compiler: "mapping-v2", revision: 1 }
  });
  assert.deepEqual(resolution.methodologies, [{
    reference: evidence.methodology,
    content: { name: "Synthetic auto certification", sections: ["loan_tape"] }
  }]);

  // This is directly substitutable for the certification service's historical resolver port.
  assert.deepEqual(
    await authority.resolveRuntimeBundle({
      runtimeBundleId: evidence.runtime.runtimeBundleId,
      runtimeBundleHash: evidence.runtime.runtimeBundleHash
    }),
    evidence.runtime
  );
  assert.deepEqual(await authority.resolveDictionary(evidence.dictionary), resolution.dictionary);
  assert.deepEqual(await authority.resolveBundle(evidence.compiler), resolution.mappingCompiler);
  assert.deepEqual(await authority.resolveBundle(evidence.methodology), resolution.methodologies[0]);
});

test("certification runtime authority rejects a runtime activated after its immutable certification time", () => {
  const fixture = authorityFixture();
  const evidence = registerEvidence(fixture.authority);
  fixture.authority.activateRuntime(CHECKER, {
    runtimeBundleId: evidence.runtime.runtimeBundleId,
    runtimeBundleHash: evidence.runtime.runtimeBundleHash,
    idempotencyKey: "runtime-activate"
  });
  const authority = new CertificationRuntimeAuthorityV1(fixture.authority, {
    tenantId: "tenant-a",
    certifiedAt: "2026-08-13T11:59:59.999Z"
  });

  assert.throws(
    () => authority.resolveActivatedRuntime({
      runtimeBundleId: evidence.runtime.runtimeBundleId,
      runtimeBundleHash: evidence.runtime.runtimeBundleHash
    }),
    (error: unknown) => historicalError(error, "INACTIVE")
  );
});

test("certification runtime authority fences tenants and only exposes exact references from a resolved runtime", async () => {
  const fixture = authorityFixture();
  const evidence = registerEvidence(fixture.authority);
  fixture.authority.activateRuntime(CHECKER, {
    runtimeBundleId: evidence.runtime.runtimeBundleId,
    runtimeBundleHash: evidence.runtime.runtimeBundleHash,
    idempotencyKey: "runtime-activate"
  });
  const tenantA = new CertificationRuntimeAuthorityV1(fixture.authority, {
    tenantId: "tenant-a",
    certifiedAt: "2026-08-13T12:00:00.000Z"
  });
  const tenantB = new CertificationRuntimeAuthorityV1(fixture.authority, {
    tenantId: "tenant-b",
    certifiedAt: "2026-08-13T12:00:00.000Z"
  });

  await assert.rejects(
    tenantA.resolveDictionary(evidence.dictionary),
    (error: unknown) => adapterError(error, "RUNTIME_NOT_RESOLVED")
  );
  assert.throws(
    () => tenantB.resolveActivatedRuntime({
      runtimeBundleId: evidence.runtime.runtimeBundleId,
      runtimeBundleHash: evidence.runtime.runtimeBundleHash
    }),
    (error: unknown) => historicalError(error, "NOT_FOUND")
  );

  tenantA.resolveActivatedRuntime({
    runtimeBundleId: evidence.runtime.runtimeBundleId,
    runtimeBundleHash: evidence.runtime.runtimeBundleHash
  });
  const substituted = {
    ...evidence.compiler,
    artifactId: "substituted-artifact"
  };
  await assert.rejects(
    tenantA.resolveBundle(substituted),
    (error: unknown) => adapterError(error, "RUNTIME_NOT_RESOLVED")
  );
});

test("certification runtime authority fails closed when immutable runtime bundle metadata is tampered", () => {
  const fixture = authorityFixture();
  const evidence = registerEvidence(fixture.authority);
  fixture.authority.activateRuntime(CHECKER, {
    runtimeBundleId: evidence.runtime.runtimeBundleId,
    runtimeBundleHash: evidence.runtime.runtimeBundleHash,
    idempotencyKey: "runtime-activate"
  });
  const authority = new CertificationRuntimeAuthorityV1(fixture.authority, {
    tenantId: "tenant-a",
    certifiedAt: "2026-08-13T12:00:00.000Z"
  });

  const database = new DatabaseSync(fixture.databasePath);
  database.exec("DROP TRIGGER historical_runtime_bundles_v1_no_update");
  database.prepare(
    "UPDATE historical_runtime_bundles_v1 SET artifact_id = 'substituted-artifact' WHERE tenant_id = 'tenant-a' AND bundle_kind = 'mapping_compiler'"
  ).run();
  database.close();

  assert.throws(
    () => authority.resolveActivatedRuntime({
      runtimeBundleId: evidence.runtime.runtimeBundleId,
      runtimeBundleHash: evidence.runtime.runtimeBundleHash
    }),
    (error: unknown) => historicalError(error, "INTEGRITY_FAILURE")
  );
});

function authorityFixture() {
  const directory = mkdtempSync(join(tmpdir(), "certification-runtime-authority-"));
  directories.push(directory);
  const databasePath = join(directory, "authority.sqlite");
  const artifacts = new ArtifactStore(join(directory, "artifacts"), {
    activeKeyId: "test-key",
    keys: { "test-key": Buffer.alloc(32, 13) }
  });
  let event = 0;
  const authority = new SqliteHistoricalRuntimeAuthorityV1(databasePath, artifacts, {
    clock: () => new Date("2026-08-13T12:00:00.000Z"),
    eventId: () => `event-${++event}`
  });
  return { authority, databasePath };
}

function registerEvidence(authority: SqliteHistoricalRuntimeAuthorityV1) {
  const dictionaryContent = {
    dictionary: { fields: ["loan_id", "balance"] },
    fieldPolicy: { nulls: "preserve" }
  };
  const dictionary = authority.registerBundle(MAKER, {
    bundleKind: "dictionary",
    bundleId: "dictionary-core",
    version: "1.0.0",
    mediaType: "application/json",
    createdAt: "2026-08-13T09:00:00.000Z",
    dictionaryVersion: "1.0.0",
    dictionaryHash: canonicalHash(dictionaryContent.dictionary),
    fieldPolicyVersion: "1.0.0",
    fieldPolicyHash: canonicalHash(dictionaryContent.fieldPolicy),
    content: dictionaryContent,
    idempotencyKey: "dictionary-register"
  }).value;
  assert.equal(dictionary.bundleKind, "dictionary");
  if (dictionary.bundleKind !== "dictionary") throw new Error("expected dictionary reference");
  const compiler = authority.registerBundle(MAKER, {
    bundleKind: "mapping_compiler",
    bundleId: "mapping-v2",
    version: "1.0.0",
    mediaType: "application/json",
    createdAt: "2026-08-13T09:10:00.000Z",
    content: { compiler: "mapping-v2", revision: 1 },
    idempotencyKey: "compiler-register"
  }).value;
  assert.equal(compiler.bundleKind, "mapping_compiler");
  if (compiler.bundleKind !== "mapping_compiler") throw new Error("expected compiler reference");
  const methodology = authority.registerBundle(MAKER, {
    bundleKind: "methodology",
    bundleId: "certification-methodology",
    version: "1.0.0",
    mediaType: "application/json",
    createdAt: "2026-08-13T09:20:00.000Z",
    content: { name: "Synthetic auto certification", sections: ["loan_tape"] },
    idempotencyKey: "methodology-register"
  }).value;
  assert.equal(methodology.bundleKind, "methodology");
  if (methodology.bundleKind !== "methodology") throw new Error("expected methodology reference");
  const runtime = authority.registerRuntime(MAKER, {
    runtimeBundleId: "runtime-synthetic-auto-v1",
    runtimeVersion: "1.0.0",
    dictionary,
    mappingCompiler: compiler,
    methodologies: [methodology],
    assembledAt: "2026-08-13T10:00:00.000Z",
    idempotencyKey: "runtime-register"
  }).value;
  return {
    dictionary: dictionary as DictionaryBundleReferenceV1,
    compiler: compiler as ImmutableBundleReferenceV1,
    methodology: methodology as ImmutableBundleReferenceV1,
    runtime
  };
}

const MAKER: TrustedRuntimeAuthorityActorV1 = {
  tenantId: "tenant-a",
  actorId: "runtime-maker",
  authority: "platform_operator",
  identitySource: "server_derived"
};

const CHECKER: TrustedRuntimeAuthorityActorV1 = {
  tenantId: "tenant-a",
  actorId: "runtime-checker",
  authority: "platform_operator",
  identitySource: "server_derived"
};

function historicalError(error: unknown, code: HistoricalRuntimeAuthorityError["code"]): boolean {
  return error instanceof HistoricalRuntimeAuthorityError && error.code === code;
}

function adapterError(error: unknown, code: CertificationRuntimeAuthorityError["code"]): boolean {
  return error instanceof CertificationRuntimeAuthorityError && error.code === code;
}
