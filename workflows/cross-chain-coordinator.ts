/**
 * @title  Cross-Chain Coordinator — CRE Workflow
 * @notice Reacts to ThreatReported events on-chain via EVM Log Trigger.
 *         Evaluates the decision matrix (AI_AGENTS.md §5) and propagates
 *         alerts to other chains via CCIP using EVMClient.
 *
 * Architecture follows @chainlink/cre-sdk pattern:
 *   main() → Runner.newRunner() → initWorkflow() → handler(evmLogTrigger, callback)
 */

import {
  Runner,
  EVMClient,
  HTTPClient,
  handler,
  type Runtime,
} from "@chainlink/cre-sdk";
import { z } from "zod";

// Import logic and types
import { ThreatEvent, ProtocolDeployment } from "./logic/types";
import {
  runCoordinatorPipeline,
  parseThreatReportedEvent,
} from "./logic/coordinator-logic";

// Re-export for convenience
export * from "./logic/types";
export * from "./logic/coordinator-logic";

// ═══════════════════════════════════════════════════════════════════════════
// CRE Workflow Entry Points
// ═══════════════════════════════════════════════════════════════════════════

export const coordinatorConfigSchema = z.object({
  chainSelector: z.string().describe("Source chain selector for EVMClient"),
  sentinelContractAddress: z
    .string()
    .describe("SentinelActions contract emitting ThreatReported events"),
  deploymentRegistryUrl: z
    .string()
    .describe("API endpoint returning ProtocolDeployment JSON"),
  monitoredChainSelectors: z
    .array(z.string())
    .describe("Chain selectors for all monitored chains"),
  monitoredChainIds: z
    .array(z.number())
    .describe("Numeric chain IDs for monitored chains"),
});

export type CoordinatorConfig = z.infer<typeof coordinatorConfigSchema>;

/**
 * CRE callback: fired when a ThreatReported event is emitted on-chain.
 */
export const onThreatReported = (
  runtime: Runtime<CoordinatorConfig>,
  eventData: any,
): string => {
  const config = runtime.config;
  runtime.log("ThreatReported event received");

  // 1. Parse event
  const event = parseThreatReportedEvent(eventData);
  runtime.log(`Processing report ${event.reportId} severity=${event.severity}`);

  // 2. Fetch deployment topology
  const httpClient = new HTTPClient();
  const deploymentResponse = httpClient
    .fetch(runtime, {
      url: `${config.deploymentRegistryUrl}?protocol=${event.targetProtocol}`,
      method: "GET",
    })
    .result();
  const deployment: ProtocolDeployment = JSON.parse(deploymentResponse.body);

  // 3. Run coordinator pipeline
  const messages = runCoordinatorPipeline(
    event,
    deployment,
    config.monitoredChainIds,
  );

  if (messages.length === 0) {
    runtime.log("Scope=LOCAL_ONLY — no cross-chain propagation needed");
    return "local_only";
  }

  runtime.log(`Propagating to ${messages.length} chains`);

  // 4. Dispatch via EVMClient on each target chain
  for (const msg of messages) {
    const targetChainSelector =
      config.monitoredChainSelectors[
        config.monitoredChainIds.indexOf(msg.destChain)
      ];
    if (!targetChainSelector) {
      runtime.log(`No selector for chain ${msg.destChain} — skipping`);
      continue;
    }

    const evmClient = new EVMClient(targetChainSelector);
    const signedReport = runtime.report(msg).result();
    evmClient.writeReport(runtime, { report: signedReport }).result();

    runtime.log(`Dispatched to chain ${msg.destChain}: ${msg.reportId}`);
  }

  return "propagated";
};

/**
 * CRE workflow initializer.
 */
export const coordinatorInitWorkflow = (config: CoordinatorConfig) => {
  const evmClient = new EVMClient(config.chainSelector);
  // Placeholder for EVMLogTrigger registration
  return [handler(evmClient as any, onThreatReported)];
};

/**
 * CRE entry point.
 */
export async function main() {
  const runner = await Runner.newRunner<CoordinatorConfig>({
    configSchema: coordinatorConfigSchema,
  });
  await runner.run(coordinatorInitWorkflow);
}
