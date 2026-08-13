import { parentPort, workerData } from "node:worker_threads";

import {
  executePortfolioSurveillanceOperationV1,
  PortfolioSurveillanceOperationError,
  type PortfolioSurveillanceExecutionPlanV1
} from "./operations/portfolio-surveillance-v1.js";

export type PortfolioSurveillanceWorkerFailureCodeV4 =
  | "INVALID_PLAN"
  | "DISCLOSURE_POLICY_VIOLATION"
  | "EXECUTION_FAILED";

export type PortfolioSurveillanceWorkerMessageV4 =
  | Readonly<{
      ok: true;
      result: ReturnType<typeof executePortfolioSurveillanceOperationV1>;
    }>
  | Readonly<{
      ok: false;
      code: PortfolioSurveillanceWorkerFailureCodeV4;
    }>;

if (!parentPort) throw new Error("Portfolio-surveillance worker requires a parent port");

try {
  const result = executePortfolioSurveillanceOperationV1(
    workerData as PortfolioSurveillanceExecutionPlanV1
  );
  parentPort.postMessage({ ok: true, result } satisfies PortfolioSurveillanceWorkerMessageV4);
} catch (error) {
  const code: PortfolioSurveillanceWorkerFailureCodeV4 =
    error instanceof PortfolioSurveillanceOperationError
      ? error.code === "DISCLOSURE_POLICY_VIOLATION"
        ? "DISCLOSURE_POLICY_VIOLATION"
        : error.code === "PLAN_INTEGRITY_FAILURE" || error.code === "INVALID_REQUEST"
          ? "INVALID_PLAN"
          : "EXECUTION_FAILED"
      : "EXECUTION_FAILED";
  parentPort.postMessage({ ok: false, code } satisfies PortfolioSurveillanceWorkerMessageV4);
}
