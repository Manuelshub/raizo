import {
  CronCapability,
  HTTPClient,
  EVMClient,
  handler,
  Runner,
  type Runtime,
  type NodeRuntime,
  ConsensusAggregationByFields,
  median,
  identical,
  json,
  ok,
  bytesToHex,
  hexToBase64,
} from "@chainlink/cre-sdk";
import {
  keccak256,
  encodeAbiParameters,
  encodeFunctionData,
  decodeFunctionResult,
  stringToHex,
} from "viem";

// --- Interfaces ---

interface ThreatAssessment {
  overallRiskScore: number;
  threatDetected: boolean;
  recommendedAction: "NONE" | "ALERT" | "RATE_LIMIT" | "DRAIN_BLOCK" | "PAUSE";
  reasoning: string;
}

// --- Configuration ---

type Config = {
  schedule: string;
  raizoCoreAddress: `0x${string}`;
  sentinelActionsAddress: `0x${string}`;
  telemetryApiUrl: string;
  rpcUrl: string;
};

// JSON ABIs for stability in WASM
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
        name: "",
        type: "tuple[]",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
] as const;

const SENTINEL_ABI = [
  {
    inputs: [
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
        name: "report",
        type: "tuple",
      },
    ],
    name: "executeAction",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

const ACTION_MAP = {
  NONE: 0,
  PAUSE: 0,
  RATE_LIMIT: 1,
  DRAIN_BLOCK: 2,
  ALERT: 3,
};

const SEVERITY_MAP = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3,
};

const SEPOLIA_SELECTOR = 16015286601757825753n;

// --- Workflow Logic ---

const analyzeProtocol = (
  nodeRuntime: NodeRuntime<Config>,
  protocol: any,
): ThreatAssessment => {
  const { telemetryApiUrl } = nodeRuntime.config;
  const http = new HTTPClient();

  nodeRuntime.log(`Analyzing protocol: ${protocol.protocolAddress}`);

  const intelResponse = http
    .sendRequest(nodeRuntime, {
      url: `${telemetryApiUrl}?address=${protocol.protocolAddress}&chainId=${protocol.chainId}`,
      method: "GET",
    })
    .result();

  if (!ok(intelResponse)) {
    return {
      overallRiskScore: 0,
      threatDetected: false,
      recommendedAction: "NONE",
      reasoning: "Telemetry unreachable.",
    };
  }

  const intel = json(intelResponse) as any;
  let riskScore = 0.1;
  let action: ThreatAssessment["recommendedAction"] = "NONE";
  let reasoning = "Healthy.";

  if (intel.threatLevel === "high") {
    riskScore = 0.95;
    action = "PAUSE";
    reasoning = `High risk: ${intel.reason || "Detection triggered"}`;
  }

  return {
    overallRiskScore: riskScore,
    threatDetected: riskScore > 0.7,
    recommendedAction: action,
    reasoning,
  };
};

const onCronTrigger = (runtime: Runtime<Config>) => {
  const { raizoCoreAddress, sentinelActionsAddress } = runtime.config;
  const evm = new EVMClient(SEPOLIA_SELECTOR);

  runtime.log("Threat Sentinel Run Started");

  const protocolsReply = evm
    .callContract(runtime, {
      call: {
        to: raizoCoreAddress,
        data: encodeFunctionData({
          abi: RAIZO_CORE_ABI,
          functionName: "getAllProtocols",
        }),
      },
    })
    .result();

  if (protocolsReply.data.length === 0) {
    runtime.log("No protocols found or RaizoCore unreachable.");
    return "Done (No Data)";
  }

  const protocols = decodeFunctionResult({
    abi: RAIZO_CORE_ABI,
    functionName: "getAllProtocols",
    data: bytesToHex(protocolsReply.data) as `0x${string}`,
  }) as any[];

  for (const protocol of protocols) {
    if (!protocol.isActive) continue;

    const assessment = runtime
      .runInNodeMode(
        analyzeProtocol,
        ConsensusAggregationByFields<ThreatAssessment>({
          overallRiskScore: median,
          threatDetected: identical,
          recommendedAction: identical,
          reasoning: identical,
        }),
      )(protocol)
      .result();

    if (assessment.recommendedAction !== "NONE" && assessment.threatDetected) {
      const now = runtime.now().getTime();
      const reportId = keccak256(
        encodeAbiParameters(
          [{ type: "address" }, { type: "uint256" }],
          [protocol.protocolAddress as `0x${string}`, BigInt(now)],
        ),
      );

      const reportData = {
        reportId,
        agentId: keccak256(stringToHex("threat-sentinel-001")),
        exists: true,
        targetProtocol: protocol.protocolAddress,
        action:
          ACTION_MAP[assessment.recommendedAction as keyof typeof ACTION_MAP],
        severity:
          assessment.overallRiskScore > 0.9
            ? SEVERITY_MAP.CRITICAL
            : SEVERITY_MAP.HIGH,
        confidenceScore: Math.floor(assessment.overallRiskScore * 10000),
        evidenceHash: keccak256(stringToHex(assessment.reasoning)),
        timestamp: BigInt(Math.floor(now / 1000)),
        donSignatures: stringToHex("consensus-proof"),
      };

      evm
        .callContract(runtime, {
          call: {
            to: sentinelActionsAddress,
            data: encodeFunctionData({
              abi: SENTINEL_ABI,
              functionName: "executeAction",
              args: [reportData],
            }),
          },
        })
        .result();

      runtime.log(`Safeguard report submitted: ${reportId}`);
    }
  }

  return "Success";
};

const initWorkflow = (config: Config) => {
  const cron = new CronCapability();

  return [handler(cron.trigger({ schedule: config.schedule }), onCronTrigger)];
};

export async function main() {
  const runner = await Runner.newRunner<Config>();
  await runner.run(initWorkflow);
}
