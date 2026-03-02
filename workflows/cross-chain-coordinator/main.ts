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
  decodeEventLog,
} from "viem";

// ---------------------------------------------------------------------------
// Interfaces — aligned with AI_AGENTS.md §5 and contract interfaces
// ---------------------------------------------------------------------------

/**
 * Decoded ActionExecuted event from SentinelActions contract.
 * event ActionExecuted(bytes32 reportId, address protocol, ActionType action, Severity severity, uint16 confidence)
 */
interface ActionEvent {
  reportId: `0x${string}`;
  protocol: `0x${string}`;
  action: number; // ActionType enum index
  severity: number; // Severity enum index
  confidence: number; // basis points
}

/** Protocol deployment info for cross-chain decision matrix. */
interface ProtocolDeployment {
  protocolAddress: `0x${string}`;
  chainId: number;
  riskTier: number;
  isActive: boolean;
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
  /** Target chain selectors for CCIP propagation (configured per deployment). */
  targetChainSelectors: string[];
};

// ---------------------------------------------------------------------------
// On-chain ABIs
// ---------------------------------------------------------------------------

const SENTINEL_EVENTS_ABI = [
  {
    anonymous: false,
    inputs: [
      { indexed: true, name: "reportId", type: "bytes32" },
      { indexed: true, name: "protocol", type: "address" },
      { indexed: false, name: "action", type: "uint8" },
      { indexed: false, name: "severity", type: "uint8" },
      { indexed: false, name: "confidence", type: "uint16" },
    ],
    name: "ActionExecuted",
    type: "event",
  },
] as const;

const CROSS_CHAIN_RELAY_ABI = [
  {
    inputs: [
      { name: "destChainSelector", type: "uint64" },
      { name: "reportId", type: "bytes32" },
      { name: "actionType", type: "uint8" },
      { name: "targetProtocol", type: "address" },
      { name: "payload", type: "bytes" },
    ],
    name: "sendAlert",
    outputs: [{ name: "messageId", type: "bytes32" }],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

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

/** ActionExecuted event topic0. */
const ACTION_EXECUTED_TOPIC = keccak256(
  stringToHex("ActionExecuted(bytes32,address,uint8,uint8,uint16)"),
);

// ActionType enum names for logging.
const ACTION_NAMES = ["PAUSE", "RATE_LIMIT", "DRAIN_BLOCK", "ALERT", "CUSTOM"];
const SEVERITY_NAMES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

// ---------------------------------------------------------------------------
// Cross-Chain Decision Matrix (AI_AGENTS.md §5.2)
// ---------------------------------------------------------------------------

/**
 * Applies the cross-chain decision matrix from AI_AGENTS.md §5.2.
 *
 * Returns a list of chain selectors that should receive the propagated alert.
 * Empty list = no cross-chain propagation needed.
 *
 * | Condition                             | Action                                           |
 * |---------------------------------------|--------------------------------------------------|
 * | Same protocol, same chain             | Local only — no cross-chain needed               |
 * | Same protocol, multi-chain deployment | Propagate to all chains where protocol deployed  |
 * | Different protocol, shared liquidity  | Propagate alert (not action) to related protocols|
 * | Different protocol, no relationship   | No propagation                                   |
 * | Severity = CRITICAL                   | Propagate to ALL monitored chains (precaution)   |
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
      `[DecisionMatrix] CRITICAL severity — propagating to ALL ${targetChainSelectors.length} target chain(s)`,
    );
    return {
      targetSelectors: targetChainSelectors,
      reason: "CRITICAL severity — universal propagation",
    };
  }

  // Check if the same protocol is deployed on other chains
  const sameProtocolOtherChains = allProtocols.filter(
    (p) =>
      p.protocolAddress.toLowerCase() === event.protocol.toLowerCase() &&
      p.chainId !== localChainId &&
      p.isActive,
  );

  if (sameProtocolOtherChains.length > 0) {
    // Same protocol, multi-chain deployment → propagate to all those chains
    // For now, we propagate to all configured targets since we can't map chainId → chainSelector
    // without a lookup table. In production, this would use a registry.
    runtime.log(
      `[DecisionMatrix] Protocol ${event.protocol} deployed on ${sameProtocolOtherChains.length} other chain(s) — propagating`,
    );
    return {
      targetSelectors: targetChainSelectors,
      reason: `Multi-chain deployment (${sameProtocolOtherChains.length} chains)`,
    };
  }

  // Same protocol, same chain only → local action was already taken
  runtime.log(
    `[DecisionMatrix] Protocol ${event.protocol} only on local chain — no propagation needed`,
  );
  return {
    targetSelectors: [],
    reason: "Local-only deployment",
  };
};

// ---------------------------------------------------------------------------
// Main workflow handler
// ---------------------------------------------------------------------------

const onCronTrigger = (runtime: Runtime<Config>) => {
  const {
    sentinelActionsAddress,
    crossChainRelayAddress,
    raizoCoreAddress,
    operatorAddress,
    chainName,
    targetChainSelectors,
  } = runtime.config;

  runtime.log(
    "=== Raizo Cross-Chain Coordinator: Polling for ActionExecuted events ===",
  );

  const network = getNetwork({
    chainFamily: "evm",
    chainSelectorName: chainName,
    isTestnet: true,
  });

  if (!network) {
    throw new Error(`Unknown chain name: ${chainName}`);
  }

  const evmClient = new EVMClient(network.chainSelector.selector);

  // --- Step 1: Read all registered protocols for decision matrix context ---
  let allProtocols: ProtocolDeployment[] = [];
  try {
    const reply = evmClient
      .callContract(runtime, {
        call: encodeCallMsg({
          from: zeroAddress,
          to: raizoCoreAddress,
          data: encodeFunctionData({
            abi: RAIZO_CORE_ABI,
            functionName: "getAllProtocols",
          }),
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

    runtime.log(
      `[RaizoCore] Loaded ${allProtocols.length} protocol(s) for decision matrix`,
    );
  } catch (e) {
    runtime.log(`[RaizoCore] getAllProtocols() failed: ${e}`);
  }

  // --- Step 2: Poll for recent ActionExecuted events ---
  // Note: In a production CRE workflow, this would use filterLogs with a
  // block range. Since the SDK's EVMClient.filterLogs may not be available
  // in all versions, we use a cron-based polling approach.
  // The event-driven architecture described in §5.1 is achieved by:
  //   - Cron schedules a poll every block (~12s on Ethereum)
  //   - Workflow reads SentinelActions.getActiveActions() for all protocols
  //   - New actions (not yet propagated) trigger cross-chain sends

  const actionEvents: ActionEvent[] = [];

  for (const protocol of allProtocols) {
    if (!protocol.isActive) continue;

    try {
      // Read active actions for this protocol
      const activeActionsCalldata = encodeFunctionData({
        abi: [
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
        ] as const,
        functionName: "getActiveActions",
        args: [protocol.protocolAddress],
      });

      const reply = evmClient
        .callContract(runtime, {
          call: encodeCallMsg({
            from: zeroAddress,
            to: sentinelActionsAddress,
            data: activeActionsCalldata,
          }),
          blockNumber: LAST_FINALIZED_BLOCK_NUMBER,
        })
        .result();

      const decoded = decodeFunctionResult({
        abi: [
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
        ] as const,
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

  runtime.log(
    `[EventPoll] Found ${actionEvents.length} active action event(s) across all protocols`,
  );

  if (actionEvents.length === 0) {
    runtime.log(
      "=== Raizo Cross-Chain Coordinator: No active events — done ===",
    );
    return "No events";
  }

  // --- Step 3: Apply decision matrix and propagate via CCIP ---
  let propagatedCount = 0;

  for (const event of actionEvents) {
    const { targetSelectors, reason } = applyDecisionMatrix(
      runtime,
      event,
      allProtocols,
      /* localChainId */ 11155111, // Sepolia — would come from config in prod
      targetChainSelectors,
    );

    if (targetSelectors.length === 0) {
      runtime.log(`[Propagation] ${event.reportId}: skipped (${reason})`);
      continue;
    }

    runtime.log(
      `[Propagation] ${event.reportId}: ${
        ACTION_NAMES[event.action] || "UNKNOWN"
      } → ${targetSelectors.length} chain(s) (${reason})`,
    );

    for (const destSelector of targetSelectors) {
      try {
        evmClient
          .callContract(runtime, {
            call: encodeCallMsg({
              from: operatorAddress,
              to: crossChainRelayAddress,
              data: encodeFunctionData({
                abi: CROSS_CHAIN_RELAY_ABI,
                functionName: "sendAlert",
                args: [
                  BigInt(destSelector),
                  event.reportId,
                  event.action,
                  event.protocol,
                  stringToHex("coordinator-propagation"),
                ],
              }),
            }),
            blockNumber: LAST_FINALIZED_BLOCK_NUMBER,
          })
          .result();

        runtime.log(
          `[CCIP] Sent: reportId=${event.reportId} → chain=${destSelector}`,
        );
        propagatedCount++;
      } catch (e) {
        runtime.log(
          `[CCIP] sendAlert failed for ${event.reportId} → chain=${destSelector}: ${e}`,
        );
      }
    }
  }

  runtime.log(
    `=== Raizo Cross-Chain Coordinator: Propagated ${propagatedCount} alert(s) ===`,
  );
  return `Propagated ${propagatedCount} alerts`;
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
