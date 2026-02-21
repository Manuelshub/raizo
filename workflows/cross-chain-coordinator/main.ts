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
  handler,
  type Runtime,
  type HTTPSendRequester,
  type SecretsProvider,
  consensusMedianAggregation,
  consensusIdenticalAggregation,
  prepareReportRequest,
  ok,
  text,
} from "@chainlink/cre-sdk";
import { cre } from "@chainlink/cre-sdk";
import { z } from "zod";

// Import logic and types
import { ThreatEvent, ProtocolDeployment } from "../logic/types";
import {
  runCoordinatorPipeline,
  parseThreatReportedEvent,
} from "../logic/coordinator-logic";

// ABI encoding
import { encodeFunctionData } from "viem";
import { crossChainRelayAbi } from "../abis";

// Logic and types are available via ../logic/ imports directly
// (CRE WASM compiler only supports exporting main())

// ═══════════════════════════════════════════════════════════════════════════
// CRE Workflow Entry Points
// ═══════════════════════════════════════════════════════════════════════════

const coordinatorConfigSchema = z.object({
  schedule: z
    .string()
    .default("*/30 * * * * *")
    .describe("Cron schedule — temporary polling interval until EVM Log Trigger is available"),
  chainSelector: z.string().describe("Source chain selector for EVMClient"),
  agentId: z
    .string()
    .describe("CRE agent identifier (bytes32 hex) — required for on-chain registration per spec §6.1"),
  sentinelContractAddress: z
    .string()
    .describe("SentinelActions contract emitting ThreatReported events"),
  crossChainRelayAddress: z
    .string()
    .describe("CrossChainRelay contract address for CCIP messaging"),
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

type CoordinatorConfig = z.infer<typeof coordinatorConfigSchema>;

/**
 * CRE callback: fired when a ThreatReported event is emitted on-chain.
 */
const onThreatReported = (
  runtime: Runtime<CoordinatorConfig>,
  eventPayload: any,
): string => {
  const config = runtime.config;
  runtime.log("ThreatReported event received");

  try {
    // 1. Parse event from log payload
    const event = parseThreatReportedEvent(eventPayload.log);
    runtime.log(`Processing report ${event.reportId} severity=${event.severity}`);

    // 2. Fetch deployment topology
    const httpCapability = new cre.capabilities.HTTPClient();

    const fetchDeployment = (sendRequester: HTTPSendRequester, cfg: CoordinatorConfig) => {
      const response = sendRequester.sendRequest({
        url: `${cfg.deploymentRegistryUrl}?protocol=${event.targetProtocol}`,
        method: "GET",
      }).result();

      if (!ok(response)) {
        throw new Error(`Deployment fetch failed: ${response.statusCode}`);
      }

      return text(response);
    };

    const deploymentBody = httpCapability
      .sendRequest(runtime, fetchDeployment, consensusIdenticalAggregation())(config)
      .result();
    const deployment: ProtocolDeployment = JSON.parse(deploymentBody);

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

    // 4. Dispatch via CCIP through CrossChainRelay on source chain
    for (const msg of messages) {
      const targetChainSelector =
        config.monitoredChainSelectors[
        config.monitoredChainIds.indexOf(msg.destChain)
        ];
      if (!targetChainSelector) {
        runtime.log(`No selector for chain ${msg.destChain} — skipping`);
        continue;
      }

      // Encode cross-chain message for CCIP
      const destChainSelector = config.monitoredChainSelectors[
        config.monitoredChainIds.indexOf(msg.destChain)
      ];
      if (!destChainSelector) {
        runtime.log(`No chain selector for chain ${msg.destChain}, skipping`);
        continue;
      }

      const writeData = encodeFunctionData({
        abi: crossChainRelayAbi,
        functionName: "sendAlert",
        args: [
          BigInt(destChainSelector),
          msg.reportId as `0x${string}`,
          msg.action,
          msg.targetProtocol as `0x${string}`,
          "0x" as `0x${string}`, // Additional payload (empty for standard alerts)
        ],
      });

      runtime.report(prepareReportRequest(writeData)).result();
      runtime.log(`Dispatched to chain ${msg.destChain}: ${msg.reportId}`);
    }

    return "propagated";
  } catch (error) {
    runtime.log(`Error in coordinator workflow: ${error}`);
    return "error";
  }
};

/**
 * CRE workflow initializer.
 * TODO: Replace cron trigger with EVM log trigger once event listening pattern is documented
 */
const coordinatorInitWorkflow = (config: CoordinatorConfig, _secretsProvider: SecretsProvider) => {
  // NOTE: EVMLogTrigger is not yet available or documented in CRE SDK v1.1.0
  // Using cron as placeholder until event trigger pattern is clarified
  const cron = new cre.capabilities.CronCapability();

  // Poll interval sourced from config (temporary until EVM Log Trigger support)
  const trigger = cron.trigger({ schedule: config.schedule });

  return [handler(trigger, onThreatReported)];
};

/**
 * CRE entry point.
 */
export async function main() {
  const runner = await Runner.newRunner<CoordinatorConfig>({
    configParser: (raw: Uint8Array) =>
      coordinatorConfigSchema.parse(JSON.parse(new TextDecoder().decode(raw))),
  });
  await runner.run(coordinatorInitWorkflow);
}
