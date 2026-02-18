/**
 * @title  Threat Sentinel — CRE Workflow
 * @notice Monitors DeFi protocols for exploit patterns using a cron trigger,
 *         heuristic pre-filter, LLM analysis via runInNodeMode, and on-chain
 *         report submission through the EVM client.
 *
 * Architecture follows the @chainlink/cre-sdk pattern:
 *   main() → Runner.newRunner() → initWorkflow() → handler(trigger, callback)
 */

import {
  Runner,
  CronCapability,
  HTTPClient,
  EVMClient,
  handler,
  type Runtime,
  type NodeRuntime,
  type CronPayload,
} from "@chainlink/cre-sdk";
import { z } from "zod";

// Import logic and types
import { TelemetryFrame, ThreatAssessment } from "./logic/types";
import {
  HeuristicAnalyzer,
  runSentinelPipeline,
  HEURISTIC_GATE_THRESHOLD,
  SYSTEM_PROMPT,
} from "./logic/threat-logic";

// Re-export logic and types for convenience
export * from "./logic/types";
export * from "./logic/threat-logic";

// ═══════════════════════════════════════════════════════════════════════════
// CRE Workflow Entry Points
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Zod config schema validated by Runner at startup.
 */
export const sentinelConfigSchema = z.object({
  schedule: z.string().describe("Cron schedule for periodic sentinel sweeps"),
  chainSelector: z.string().describe("EVM chain selector for EVMClient"),
  telemetryApiUrl: z.string().describe("Endpoint serving TelemetryFrame JSON"),
  llmApiUrl: z.string().describe("Endpoint for LLM risk analysis"),
  sentinelContractAddress: z
    .string()
    .describe("SentinelActions contract address"),
  agentId: z.string().describe("Unique agent identifier"),
  targetProtocol: z.string().describe("Protocol address to monitor"),
});

export type SentinelConfig = z.infer<typeof sentinelConfigSchema>;

/**
 * CRE callback: fired on every cron tick.
 */
export const onCronTrigger = (
  runtime: Runtime<SentinelConfig>,
  _payload: CronPayload,
): string => {
  const config = runtime.config;
  runtime.log("Sentinel sweep triggered");

  // 1. Fetch telemetry
  const httpClient = new HTTPClient();
  const telemetryResponse = httpClient
    .fetch(runtime, {
      url: config.telemetryApiUrl,
      method: "GET",
    })
    .result();

  const telemetry: TelemetryFrame = JSON.parse(telemetryResponse.body);

  // 2. Heuristic pre-filter
  const heuristic = new HeuristicAnalyzer();
  const { baseRiskScore } = heuristic.score(telemetry);

  if (baseRiskScore < HEURISTIC_GATE_THRESHOLD) {
    runtime.log(
      `Heuristic score ${baseRiskScore.toFixed(3)} below gate — skipping LLM`,
    );
    return "skipped";
  }

  runtime.log(
    `Heuristic score ${baseRiskScore.toFixed(3)} above gate — invoking LLM`,
  );

  // 3. LLM analysis via runInNodeMode
  const fetchLLMAssessment = (
    nodeRuntime: NodeRuntime<SentinelConfig>,
  ): string => {
    const nodeHttp = new HTTPClient();
    const apiKey = runtime.getSecret("LLM_API_KEY").result();
    const response = nodeHttp
      .fetch(nodeRuntime, {
        url: config.llmApiUrl,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          system: SYSTEM_PROMPT,
          telemetry,
        }),
      })
      .result();
    return response.body;
  };

  const llmResultRaw = runtime
    .runInNodeMode(fetchLLMAssessment, {
      aggregate: (results: string[]) => {
        const assessments: ThreatAssessment[] = results.map((r) =>
          JSON.parse(r),
        );
        const scores = assessments
          .map((a) => a.overallRiskScore)
          .sort((a, b) => a - b);
        const medianIdx = Math.floor(scores.length / 2);
        const medianScore = scores[medianIdx];

        const closest = assessments.reduce((prev, curr) =>
          Math.abs(curr.overallRiskScore - medianScore) <
          Math.abs(prev.overallRiskScore - medianScore)
            ? curr
            : prev,
        );
        return JSON.stringify(closest);
      },
    })()
    .result();

  const assessment: ThreatAssessment = JSON.parse(llmResultRaw);

  // 4. Deterministic escalation pipeline
  const report = runSentinelPipeline(
    config.agentId,
    config.targetProtocol,
    telemetry,
    assessment,
  );

  if (!report) {
    runtime.log("No actionable threat — pipeline returned null");
    return "no_threat";
  }

  runtime.log(
    `Threat detected: action=${report.action} severity=${report.severity} confidence=${report.confidenceScore}`,
  );

  // 5. Submit signed report on-chain
  const evmClient = new EVMClient(config.chainSelector);
  evmClient
    .writeReport(runtime, {
      report: runtime.report(report).result(),
    })
    .result();

  runtime.log(`Report submitted on-chain: ${report.reportId}`);
  return "reported";
};

/**
 * CRE workflow initializer.
 */
export const initWorkflow = (config: SentinelConfig) => {
  const cron = new CronCapability();
  return [handler(cron.trigger({ schedule: config.schedule }), onCronTrigger)];
};

/**
 * CRE entry point.
 */
export async function main() {
  const runner = await Runner.newRunner<SentinelConfig>({
    configSchema: sentinelConfigSchema,
  });
  await runner.run(initWorkflow);
}
