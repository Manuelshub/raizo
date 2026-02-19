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
  handler,
  type Runtime,
  type NodeRuntime,
  type HTTPSendRequester,
  consensusMedianAggregation,
  consensusIdenticalAggregation,
  prepareReportRequest,
  ok,
  text,
} from "@chainlink/cre-sdk";
import { cre } from "@chainlink/cre-sdk";
import { z } from "zod";

// ABI encoding
import { encodeFunctionData } from "viem";
import { sentinelActionsAbi } from "./abis";

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
  _payload: any,
): string => {
  const config = runtime.config;
  runtime.log("Sentinel sweep triggered");

  try {
    // 1. Fetch telemetry
    const httpCapability = new cre.capabilities.HTTPClient();

    const fetchTelemetry = (sendRequester: HTTPSendRequester, cfg: SentinelConfig) => {
      const response = sendRequester.sendRequest({
        url: cfg.telemetryApiUrl,
        method: "GET",
      }).result();

      if (!ok(response)) {
        throw new Error(`Telemetry fetch failed: ${response.statusCode}`);
      }

      return text(response);
    };

    const telemetryBody = httpCapability
      .sendRequest(runtime, fetchTelemetry, consensusIdenticalAggregation())(config)
      .result();

    const telemetry: TelemetryFrame = JSON.parse(telemetryBody);

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

    // 3. LLM analysis via runInNodeMode (Confidential Compute)
    // Note: Using consensusIdenticalAggregation - all nodes must return identical assessments
    // In production, consider implementing multi-stage consensus if nodes return different scores
    const fetchLLMAssessment = (nodeRuntime: NodeRuntime<SentinelConfig>): string => {
      const nodeHttpCapability = new cre.capabilities.HTTPClient();

      const nodeFetch = (sendRequester: HTTPSendRequester) => {
        const response = sendRequester.sendRequest({
          url: config.llmApiUrl,
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            // Note: Secrets should be configured in CRE CLI config, not fetched at runtime
          },
          body: JSON.stringify({
            system: SYSTEM_PROMPT,
            // BigInt fields must be serialized as strings for JSON
            telemetry: JSON.parse(JSON.stringify(telemetry, (_, v) =>
              typeof v === 'bigint' ? v.toString() : v
            )),
          }),
        }).result();

        if (!ok(response)) {
          throw new Error(`LLM request failed: ${response.statusCode}`);
        }

        return text(response);
      };

      // Each node fetches independently
      return nodeFetch(nodeRuntime as any);
    };

    const llmResultRaw = runtime
      .runInNodeMode(fetchLLMAssessment, consensusIdenticalAggregation())()
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

    // 5. Submit threat report on-chain via SentinelActions.executeAction()
    const writeData = encodeFunctionData({
      abi: sentinelActionsAbi,
      functionName: "executeAction",
      args: [
        {
          reportId: report.reportId as `0x${string}`,
          agentId: report.agentId as `0x${string}`,
          exists: true,
          targetProtocol: report.targetProtocol as `0x${string}`,
          action: report.action,
          severity: report.severity,
          confidenceScore: report.confidenceScore,
          evidenceHash: Buffer.from(report.evidenceHash) as unknown as `0x${string}`,
          timestamp: BigInt(report.timestamp),
          donSignatures: "0x" as `0x${string}`, // Populated by CRE DON consensus at runtime
        },
      ],
    });

    const reportRequest = prepareReportRequest(writeData);
    runtime.report(reportRequest).result();
    runtime.log(`Report submitted on-chain: ${report.reportId}`);
    return "reported";
  } catch (error) {
    runtime.log(`Error in threat detection workflow: ${error}`);
    return "error";
  }
};

/**
 * CRE workflow initializer.
 */
export const initWorkflow = (config: SentinelConfig) => {
  const cron = new cre.capabilities.CronCapability();
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
