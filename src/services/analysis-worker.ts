import { parentPort, workerData } from "node:worker_threads";

import * as z from "zod/v4";

import {
  executeGovernedAnalysis,
  GovernedWorkflowError,
  type GovernedAnalysisExecutionPayload
} from "./governed-workflow.js";

if (!parentPort) throw new Error("Analysis worker requires a parent port");

try {
  const result = executeGovernedAnalysis(workerData as GovernedAnalysisExecutionPayload);
  parentPort.postMessage({ ok: true, result });
} catch (error) {
  const code =
    (error instanceof GovernedWorkflowError && error.code === "INVALID_INPUT") || error instanceof z.ZodError
      ? "INVALID_INPUT"
      : "EXECUTION_FAILED";
  parentPort.postMessage({ ok: false, code });
}
