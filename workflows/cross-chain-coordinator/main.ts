import {
  CronCapability,
  EVMClient,
  handler,
  Runner,
  type Runtime,
  ConsensusAggregationByFields,
  identical,
  getNetwork,
  LAST_FINALIZED_BLOCK_NUMBER,
  encodeCallMsg,
  bytesToHex,
} from "@chainlink/cre-sdk";
import {
  keccak256,
  encodeFunctionData,
  decodeFunctionResult,
  stringToHex,
  zeroAddress,
} from "viem";

// ---------------------------------------------------------------------------
// Interfaces — aligned with AI_AGENTS.md §5
// ---------------------------------------------------------------------------

/** Protocol deployment info for the cross-chain decision matrix. */
interface ProtocolDeployment {
  protocolAddress: `0x${string}`;
  chainId: number;
  riskTier: number;
  isActive: boolean;
}

/** Decoded active action from SentinelActions. */
interface ActionEvent {
  reportId: `0x${string}`;
  protocol: `0x${string}`;
  action: number;
  severity: number;
  confidence: number;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type Config = {
  schedule: string;
  sentinelActionsAddress: `0x${string}`;
  crossChainRelayAddress: `0x${string}`;
  raizoCoreAddress: `0x${string}`;
  operatorAddress: `0x${string}`;
  chainName: string;
  chainId: number;
  isTestnet: boolean;
  targetChainSelectors: string[];
};

// ---------------------------------------------------------------------------
// On-chain ABIs
// ---------------------------------------------------------------------------

const RAIZO_CORE_ABI = [
  {
    inputs: [],
    name: "getAllProtocols",
    outputs: [
      {
        components: [
          { name: "protocolAddress", type: "address" },
          { name: "chainId", type: "uint16" },
          { name: "riskTier", type: "uint8" },
          { name: "isActive", type: "bool" },
          { name: "registeredAt", type: "uint256" },
        ],
        name: "protocols",
        type: "tuple[]",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
] as const;

const GET_ACTIVE_ACTIONS_ABI = [
  {
    inputs: [{ name: "protocol", type: "address" }],
    name: "getActiveActions",
    outputs: [
      {
        components: [
          { name: "reportId", type: "bytes32" },
          { name: "agentId", type: "bytes32" },
          { name: "exists", type: "bool" },
          { name: "targetProtocol", type: "address" },
          { name: "action", type: "uint8" },
          { name: "severity", type: "uint8" },
          { name: "confidenceScore", type: "uint16" },
          { name: "evidenceHash", type: "bytes" },
          { name: "timestamp", type: "uint256" },
          { name: "donSignatures", type: "bytes" },
        ],
        name: "",
        type: "tuple[]",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
] as const;

const ACTION_NAMES = ["PAUSE", "RATE_LIMIT", "DRAIN_BLOCK", "ALERT", "CUSTOM"];
const SEVERITY_NAMES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

// ---------------------------------------------------------------------------
// Cross-Chain Decision Matrix (AI_AGENTS.md §5.2)
// ---------------------------------------------------------------------------

/**
 * Determines which chains should receive the propagated alert.
 * Returns empty list if no cross-chain propagation is needed.
 */
const applyDecisionMatrix = (
  runtime: Runtime<Config>,
  event: ActionEvent,
  allProtocols: ProtocolDeployment[],
  localChainId: number,
  targetChainSelectors: string[],
): { targetSelectors: string[]; reason: string } => {
  // CRITICAL severity → propagate to ALL monitored chains
  if (event.severity >= 3) {
    runtime.log(
      `[DecisionMatrix] CRITICAL severity — propagating to ALL ${targetChainSelectors.length} chain(s)`,
    );
    return {
      targetSelectors: targetChainSelectors,
      reason: "CRITICAL severity — universal propagation",
    };
  }

  // Same protocol on other chains → propagate
  const otherChains = allProtocols.filter(
    (p) =>
      p.protocolAddress.toLowerCase() === event.protocol.toLowerCase() &&
      p.chainId !== localChainId &&
      p.isActive,
  );

  if (otherChains.length > 0) {
    runtime.log(
      `[DecisionMatrix] ${event.protocol} on ${otherChains.length} other chain(s) — propagating`,
    );
    return {
      targetSelectors: targetChainSelectors,
      reason: `Multi-chain deployment (${otherChains.length} chains)`,
    };
  }

  runtime.log(`[DecisionMatrix] ${event.protocol} local-only — no propagation`);
  return { targetSelectors: [], reason: "Local-only deployment" };
};

// ---------------------------------------------------------------------------
// Main workflow handler
// ---------------------------------------------------------------------------

const onCronTrigger = (runtime: Runtime<Config>) => {
  const {
    sentinelActionsAddress,
    raizoCoreAddress,
    chainName,
    chainId,
    isTestnet,
    targetChainSelectors,
  } = runtime.config;

  runtime.log("=== Raizo Cross-Chain Coordinator: Polling for active actions ===");

  const network = getNetwork({ chainFamily: "evm", chainSelectorName: chainName, isTestnet });
  if (!network) {
    throw new Error(`Unknown chain name: ${chainName}`);
  }

  const evmClient = new EVMClient(network.chainSelector.selector);

  // --- Step 1: Read registered protocols for decision matrix context ---
  let allProtocols: ProtocolDeployment[] = [];
  try {
    const reply = evmClient
      .callContract(runtime, {
        call: encodeCallMsg({
          from: zeroAddress,
          to: raizoCoreAddress,
          data: encodeFunctionData({ abi: RAIZO_CORE_ABI, functionName: "getAllProtocols" }),
        }),
        blockNumber: LAST_FINALIZED_BLOCK_NUMBER,
      })
      .result();

    const decoded = decodeFunctionResult({
      abi: RAIZO_CORE_ABI,
      functionName: "getAllProtocols",
      data: bytesToHex(reply.data) as `0x${string}`,
    }) as any[];

    allProtocols = decoded.map((p: any) => ({
      protocolAddress: p.protocolAddress as `0x${string}`,
      chainId: Number(p.chainId),
      riskTier: Number(p.riskTier),
      isActive: Boolean(p.isActive),
    }));

    runtime.log(`[RaizoCore] ${allProtocols.length} protocol(s) loaded`);
  } catch (e) {
    runtime.log(`[RaizoCore] getAllProtocols() failed: ${e}`);
  }

  // --- Step 2: Poll for active actions across all protocols ---
  const actionEvents: ActionEvent[] = [];

  for (const protocol of allProtocols) {
    if (!protocol.isActive) continue;

    try {
      const reply = evmClient
        .callContract(runtime, {
          call: encodeCallMsg({
            from: zeroAddress,
            to: sentinelActionsAddress,
            data: encodeFunctionData({
              abi: GET_ACTIVE_ACTIONS_ABI,
              functionName: "getActiveActions",
              args: [protocol.protocolAddress],
            }),
          }),
          blockNumber: LAST_FINALIZED_BLOCK_NUMBER,
        })
        .result();

      const decoded = decodeFunctionResult({
        abi: GET_ACTIVE_ACTIONS_ABI,
        functionName: "getActiveActions",
        data: bytesToHex(reply.data) as `0x${string}`,
      }) as any[];

      for (const report of decoded) {
        if (!report.exists) continue;
        actionEvents.push({
          reportId: report.reportId as `0x${string}`,
          protocol: report.targetProtocol as `0x${string}`,
          action: Number(report.action),
          severity: Number(report.severity),
          confidence: Number(report.confidenceScore),
        });
      }
    } catch (e) {
      runtime.log(
        `[EventPoll] getActiveActions() failed for ${protocol.protocolAddress}: ${e}`,
      );
    }
  }

  runtime.log(`[EventPoll] ${actionEvents.length} active action(s) found`);

  if (actionEvents.length === 0) {
    runtime.log("=== Raizo Cross-Chain Coordinator: No active events — done ===");
    return "No events";
  }

  // --- Step 3: Apply decision matrix and log propagation decisions ---
  // Note: Actual CCIP send requires a funded CrossChainRelay and configured
  // target chain selectors. For MVP, this workflow monitors and logs decisions.
  let wouldPropagateCount = 0;

  for (const event of actionEvents) {
    const { targetSelectors, reason } = applyDecisionMatrix(
      runtime,
      event,
      allProtocols,
      chainId,
      targetChainSelectors,
    );

    const actionName = ACTION_NAMES[event.action] || "UNKNOWN";
    const severityName = SEVERITY_NAMES[event.severity] || "UNKNOWN";

    if (targetSelectors.length === 0) {
      runtime.log(
        `[Propagation] ${event.reportId}: ${actionName}/${severityName} — skipped (${reason})`,
      );
      continue;
    }

    runtime.log(
      `[Propagation] ${event.reportId}: ${actionName}/${severityName} → ${targetSelectors.length} chain(s) (${reason})`,
    );
    wouldPropagateCount++;

    for (const dest of targetSelectors) {
      runtime.log(`  → chain=${dest} reportId=${event.reportId}`);
    }
  }

  runtime.log(
    `=== Raizo Cross-Chain Coordinator: ${wouldPropagateCount} alert(s) identified for propagation ===`,
  );
  return `Identified ${wouldPropagateCount} alerts for propagation`;
};

// ---------------------------------------------------------------------------
// Workflow initialization
// ---------------------------------------------------------------------------

const initWorkflow = (config: Config) => {
  const cron = new CronCapability();
  return [handler(cron.trigger({ schedule: config.schedule }), onCronTrigger)];
};

export async function main() {
  const runner = await Runner.newRunner<Config>();
  await runner.run(initWorkflow);
}
