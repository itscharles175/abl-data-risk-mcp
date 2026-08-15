/**
 * Supported composition surface for the governed single-facility pilot.
 *
 * Keep transport, remote-server, and UI concerns out of this barrel. The
 * exports below are the application services and ports required to compose
 * capture, certification, publication, and portfolio surveillance.
 */
export * from "./active-mapping-execution-authority-v1.js";
export * from "./artifact-backed-modern-source-evidence-v1.js";
export * from "./composite-governed-workflow-router.js";
export * from "./governed-certified-snapshot-publication-v2.js";
export * from "./governed-definition-v2-resolver.js";
export * from "./governed-delivery-definition-authority-v1.js";
export * from "./governed-fx-rate-capture-v1.js";
export {
  GovernedModernExtractionAuthorityV1,
  GovernedModernExtractionError,
  type GovernedModernExtractionAuthorityV1Config,
  type GovernedModernExtractionErrorCode,
  type GovernedModernExtractionPlanV1,
  type GovernedObjectParquetExtractionPlanV1,
  type GovernedObjectXlsxExtractionPlanV1,
  type GovernedPostgresqlExtractionPlanV1,
} from "./governed-modern-extraction-authority-v1.js";
export * from "./governed-operation-v4.js";
export * from "./governed-source-delivery-registration.js";
export * from "./historical-mapping-execution-authority-v1.js";
export * from "./mapping-v2-executor.js";
export * from "./modern-snapshot-capture.js";
export * from "./modern-snapshot-certification.js";
export {
  DataQualityDefinitionV1Schema,
  DataQualityRuleV2Schema,
  EffectiveWindowV1Schema,
  ReconciliationControlV1Schema,
  ReconciliationDefinitionV1Schema,
  RuntimeActivationV1Schema,
  SegmentedControlTotalV2Schema,
} from "./modern-snapshot-certification-types-v1.js";
export * from "./modern-snapshot-runtime-v1.js";
export * from "./operation-registry-v2.js";
export * from "./operations/portfolio-surveillance-v1.js";
export * from "./portfolio-surveillance-workflow-v4.js";
export * from "./postgres-snapshot-source.js";
export {
  SINGLE_FACILITY_V2_SURVEILLANCE_EXPOSURE,
  SingleFacilityV2SurveillanceRuntimeError,
  composeProductionDisabledSingleFacilityV2SurveillanceRuntime,
  type SingleFacilityV2PublicationAuthorities,
  type SingleFacilityV2SurveillanceDefinitionPorts,
  type SingleFacilityV2SurveillanceRuntime,
  type SingleFacilityV2SurveillanceRuntimeBinding,
  type SingleFacilityV2SurveillanceRuntimeDependencies,
  type SingleFacilityV2SurveillanceRuntimeErrorCode,
} from "./single-facility-v2-surveillance-runtime.js";
export * from "./sql-snapshot-extraction.js";
export * from "./surveillance-access-preflight.js";
export * from "./surveillance-materializer.js";
export * from "./surveillance-preflight-persistence.js";
export * from "./surveillance-production-authority-v2.js";
export * from "./surveillance-publication-v2-read-adapter.js";
