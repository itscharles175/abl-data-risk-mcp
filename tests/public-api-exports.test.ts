import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  CertifiedSnapshotEvidenceRecordV2Schema,
  DatasetSnapshotV2Schema,
  FieldPackV1Schema,
  GovernedCertifiedSnapshotPublicationLinkV2Schema,
} from "../src/contracts/index.js";
import {
  SQLITE_MODERN_SNAPSHOT_EXTRACTION_RECEIPTS_V1_SCHEMA_VERSION,
  SqliteCertifiedSnapshotEvidenceV2Repository,
  SqliteJobHandleRouteCatalog,
  SqliteModernSnapshotExtractionReceiptRepositoryV1,
  SqlitePortfolioSurveillanceV4StateStore,
} from "../src/repositories/index.js";
import type {
  GovernedJobLane,
  JobHandleRouteCatalog,
  SqliteModernSnapshotExtractionReceiptRepositoryV1Options,
} from "../src/repositories/index.js";
import {
  CompositeGovernedWorkflowRouter,
  DataQualityDefinitionV1Schema,
  GovernedModernExtractionAuthorityV1,
  GovernedCertifiedSnapshotPublicationV2Service,
  ModernSnapshotCaptureServiceV1,
  ModernSnapshotCertificationService,
  PortfolioSurveillanceWorkflowV4,
  RepositoryBackedSurveillanceSourcePublicationAuthorityV2,
  SINGLE_FACILITY_V2_SURVEILLANCE_EXPOSURE,
  SingleFacilityV2SurveillanceRuntimeError,
  V2OnlySurveillancePublicationReadAdapter,
  composeProductionDisabledSingleFacilityV2SurveillanceRuntime,
  composeModernSnapshotRuntimeV1,
} from "../src/services/index.js";
import type {
  CompositeGovernedWorkflowApi,
  CompositeGovernedWorkflowRouterServices,
  GovernedModernExtractionAuthorityV1Config,
  GovernedModernExtractionPlanV1,
  LegacyRoutedWorkflowApi,
  PortfolioSurveillanceRoutedWorkflowApi,
  RoutedGovernedWorkflowResponse,
  SingleFacilityV2SurveillanceRuntime,
  SingleFacilityV2SurveillanceRuntimeDependencies,
} from "../src/services/index.js";

const acceptRouteCatalog = (_catalog: JobHandleRouteCatalog): void => undefined;
const acceptRouterServices = (_services: CompositeGovernedWorkflowRouterServices): void => undefined;
const acceptCompositeApi = (_api: CompositeGovernedWorkflowApi): void => undefined;
const acceptLegacyApi = (_api: LegacyRoutedWorkflowApi): void => undefined;
const acceptPortfolioApi = (_api: PortfolioSurveillanceRoutedWorkflowApi): void => undefined;
const acceptRoutedResponse = (_response: RoutedGovernedWorkflowResponse): void => undefined;
const acceptReceiptOptions = (
  _options: SqliteModernSnapshotExtractionReceiptRepositoryV1Options,
): void => undefined;
const acceptExtractionConfig = (_config: GovernedModernExtractionAuthorityV1Config): void => undefined;
const acceptExtractionPlan = (_plan: GovernedModernExtractionPlanV1): void => undefined;
const acceptRuntime = (_runtime: SingleFacilityV2SurveillanceRuntime): void => undefined;
const acceptRuntimeDependencies = (
  _dependencies: SingleFacilityV2SurveillanceRuntimeDependencies,
): void => undefined;

test("pilot contracts and repositories are available from their public barrels", () => {
  assert.equal(typeof DatasetSnapshotV2Schema.parse, "function");
  assert.equal(typeof FieldPackV1Schema.parse, "function");
  assert.equal(typeof CertifiedSnapshotEvidenceRecordV2Schema.parse, "function");
  assert.equal(typeof GovernedCertifiedSnapshotPublicationLinkV2Schema.parse, "function");
  assert.equal(typeof SqliteCertifiedSnapshotEvidenceV2Repository, "function");
  assert.equal(typeof SqliteJobHandleRouteCatalog, "function");
  assert.equal(typeof SqliteModernSnapshotExtractionReceiptRepositoryV1, "function");
  assert.equal(typeof SqlitePortfolioSurveillanceV4StateStore, "function");
  assert.equal(SQLITE_MODERN_SNAPSHOT_EXTRACTION_RECEIPTS_V1_SCHEMA_VERSION, 2);
  const lane: GovernedJobLane = "portfolio_surveillance_v4";
  assert.equal(lane, "portfolio_surveillance_v4");
  assert.equal(typeof acceptRouteCatalog, "function");
  assert.equal(typeof acceptReceiptOptions, "function");
});

test("pilot application services are available from the supported service barrel", () => {
  assert.equal(typeof CompositeGovernedWorkflowRouter, "function");
  assert.equal(typeof GovernedModernExtractionAuthorityV1, "function");
  assert.equal(typeof ModernSnapshotCaptureServiceV1, "function");
  assert.equal(typeof ModernSnapshotCertificationService, "function");
  assert.equal(typeof composeModernSnapshotRuntimeV1, "function");
  assert.equal(typeof GovernedCertifiedSnapshotPublicationV2Service, "function");
  assert.equal(typeof RepositoryBackedSurveillanceSourcePublicationAuthorityV2, "function");
  assert.equal(typeof V2OnlySurveillancePublicationReadAdapter, "function");
  assert.equal(typeof PortfolioSurveillanceWorkflowV4, "function");
  assert.equal(typeof DataQualityDefinitionV1Schema.parse, "function");
  assert.equal(typeof composeProductionDisabledSingleFacilityV2SurveillanceRuntime, "function");
  assert.equal(typeof SingleFacilityV2SurveillanceRuntimeError, "function");
  assert.equal(SINGLE_FACILITY_V2_SURVEILLANCE_EXPOSURE.productionEnabled, false);
  assert.equal(SINGLE_FACILITY_V2_SURVEILLANCE_EXPOSURE.remoteAdvertised, false);
  assert.equal(typeof acceptRouterServices, "function");
  assert.equal(typeof acceptCompositeApi, "function");
  assert.equal(typeof acceptLegacyApi, "function");
  assert.equal(typeof acceptPortfolioApi, "function");
  assert.equal(typeof acceptRoutedResponse, "function");
  assert.equal(typeof acceptExtractionConfig, "function");
  assert.equal(typeof acceptExtractionPlan, "function");
  assert.equal(typeof acceptRuntime, "function");
  assert.equal(typeof acceptRuntimeDependencies, "function");
});

test("package exports resolve to emitted public barrels", async () => {
  const packageJson = JSON.parse(
    await readFile(new URL("../package.json", import.meta.url), "utf8"),
  ) as {
    readonly exports?: Readonly<Record<string, { readonly types: string; readonly default: string }>>;
  };

  assert.deepEqual(packageJson.exports, {
    "./contracts": {
      types: "./dist/contracts/index.d.ts",
      default: "./dist/contracts/index.js",
    },
    "./repositories": {
      types: "./dist/repositories/index.d.ts",
      default: "./dist/repositories/index.js",
    },
    "./services": {
      types: "./dist/services/index.d.ts",
      default: "./dist/services/index.js",
    },
  });
});
