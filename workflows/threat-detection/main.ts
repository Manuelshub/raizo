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

// --- Interfaces (from AI_AGENTS.md) ---

interface ExploitPattern {
  patternId: string;
  category:
    | "flash_loan"
    | "reentrancy"
    | "access_control"
    | "oracle_manipulation"
    | "logic_error"
    | "governance_attack";
  severity: "low" | "medium" | "high" | "critical";
  indicators: string[];
  confidence: number;
}

interface TelemetryFrame {
  chainId: number;
  blockNumber: number;
  protocolAddress: string;
  tvl: {
    current: string;
    delta24h: number;
  };
  transactionMetrics: {
    volumeUSD: string;
    failedTxRatio: number;
  };
  contractState: {
    paused: boolean;
    unusualApprovals: number;
  };
  threatIntel: {
    activeCVEs: string[];
    exploitPatterns: ExploitPattern[];
  };
  priceData: {
    tokenPrice: string;
    priceDeviation: number;
  };
}

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
  dexScreenerApiUrl: string;
  geminiApiUrl: string;
};

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

const SEPOLIA_SELECTOR = 16015286601757825753n;

// --- Telemetry Ingestion Helpers ---

// DexScreener API (free, no API key, 300 req/min)
// GET /token-pairs/v1/{chainId}/{tokenAddress}
// Returns: priceUsd, volume.h24, liquidity.usd, priceChange.h24, txns.h24
const fetchDexScreenerData = (
  nodeRuntime: NodeRuntime<Config>,
  protocolAddress: string,
): any => {
  const http = new HTTPClient();
  const response = http
    .sendRequest(nodeRuntime, {
      url: `${nodeRuntime.config.dexScreenerApiUrl}/token-pairs/v1/ethereum/${protocolAddress}`,
      method: "GET",
    })
    .result();

  if (!ok(response)) {
    return {
      priceUsd: "0",
      volume: { h24: 0 },
      liquidity: { usd: 0 },
      priceChange: { h24: 0 },
      txns: { h24: { buys: 0, sells: 0 } },
    };
  }

  try {
    const pairs = json(response) as any[];
    // Use the first (highest liquidity) pair
    return pairs[0] || {
      priceUsd: "0",
      volume: { h24: 0 },
      liquidity: { usd: 0 },
      priceChange: { h24: 0 },
      txns: { h24: { buys: 0, sells: 0 } },
    };
  } catch (e) {
    return {
      priceUsd: "0",
      volume: { h24: 0 },
      liquidity: { usd: 0 },
      priceChange: { h24: 0 },
      txns: { h24: { buys: 0, sells: 0 } },
    };
  }
};

// --- LLM (Gemini 2.0) Integration ---

const getGeminiAssessment = (
  nodeRuntime: NodeRuntime<Config>,
  frame: TelemetryFrame,
  apiKey: string,
): ThreatAssessment => {
  const http = new HTTPClient();

  const prompt = `
You are Raizo Sentinel, an autonomous DeFi security analyst. Analyze the following telemetry frame and output ONLY valid JSON.

Telemetry Frame:
${JSON.stringify(frame, null, 2)}

Rules:
1. Output ONLY valid JSON matching the ThreatAssessment schema.
2. If riskScore > 0.85, recommend "PAUSE".
3. If riskScore > 0.70, recommend "DRAIN_BLOCK".
4. If riskScore > 0.50, recommend "ALERT".
5. Otherwise, recommend "NONE".

Output Schema:
{
  "overallRiskScore": number (0.0 to 1.0),
  "threatDetected": boolean,
  "recommendedAction": "NONE" | "ALERT" | "RATE_LIMIT" | "DRAIN_BLOCK" | "PAUSE",
  "reasoning": "string"
}
`;

  const body = JSON.stringify({
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: { response_mime_type: "application/json" },
  });

  const response = http
    .sendRequest(nodeRuntime, {
      url: `${nodeRuntime.config.geminiApiUrl}?key=${apiKey}`,
      method: "POST",
      body: hexToBase64(stringToHex(body)),
    })
    .result();

  if (!ok(response)) {
    return {
      overallRiskScore: 0,
      threatDetected: false,
      recommendedAction: "NONE",
      reasoning: "Gemini API error",
    };
  }

  try {
    const result = json(response) as any;
    const text = result.candidates[0].content.parts[0].text;
    return JSON.parse(text) as ThreatAssessment;
  } catch (e) {
    return {
      overallRiskScore: 0,
      threatDetected: false,
      recommendedAction: "NONE",
      reasoning: "Failed to parse Gemini response",
    };
  }
};

// --- Workflow Logic ---

const analyzeProtocol = (
  nodeRuntime: NodeRuntime<Config>,
  protocol: any,
  apiKey: string,
): ThreatAssessment => {
  nodeRuntime.log(`Analyzing protocol: ${protocol.protocolAddress}`);

  // 1. Ingest High-Fidelity Telemetry from DexScreener (free, no API key)
  const dex = fetchDexScreenerData(nodeRuntime, protocol.protocolAddress);

  // Derive sell-pressure ratio as anomaly proxy
  const totalTxns = (dex.txns?.h24?.buys || 0) + (dex.txns?.h24?.sells || 0);
  const sellPressure = totalTxns > 0 ? (dex.txns?.h24?.sells || 0) / totalTxns : 0;

  const frame: TelemetryFrame = {
    chainId: protocol.chainId,
    blockNumber: 0,
    protocolAddress: protocol.protocolAddress,
    tvl: {
      current: String(dex.liquidity?.usd || 0),
      delta24h: dex.priceChange?.h24 || 0,
    },
    transactionMetrics: {
      volumeUSD: String(dex.volume?.h24 || 0),
      failedTxRatio: sellPressure,
    },
    contractState: { paused: false, unusualApprovals: 0 },
    threatIntel: {
      activeCVEs: [],
      exploitPatterns: [],
    },
    priceData: {
      tokenPrice: dex.priceUsd || "0",
      priceDeviation: dex.priceChange?.h24 || 0,
    },
  };

  // 2. AI Reasoning via Gemini 2.0
  return getGeminiAssessment(nodeRuntime, frame, apiKey);
};

const onCronTrigger = (runtime: Runtime<Config>) => {
  const { raizoCoreAddress, sentinelActionsAddress } = runtime.config;
  const evm = new EVMClient(SEPOLIA_SELECTOR);

  runtime.log("Raizo Workstream 9: Live Data Sentinel Started");

  // Fetch AI_API_KEY from secrets (env namespace)
  let apiKey: string;
  try {
    apiKey = runtime
      .getSecret({ id: "AI_API_KEY" })
      .result().value;
  } catch (e) {
    runtime.log(
      "Warning: AI_API_KEY secret not found, using simulation fallback",
    );
    apiKey = "AI_API_KEY_SIMULATION_FALLBACK"; // Should be passed via config in prod simulation
  }

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

  if (protocolsReply.data.length === 0) return "No protocols";

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
      )(protocol, apiKey)
      .result();

    if (assessment.recommendedAction !== "NONE" && assessment.threatDetected) {
      const reportData = {
        reportId: keccak256(
          stringToHex(protocol.protocolAddress + runtime.now().getTime()),
        ),
        agentId: keccak256(stringToHex("gemini-sentinel-001")),
        exists: true,
        targetProtocol: protocol.protocolAddress,
        action: 0,
        severity: 3,
        confidenceScore: 9500,
        evidenceHash: keccak256(stringToHex(assessment.reasoning)),
        timestamp: BigInt(Math.floor(runtime.now().getTime() / 1000)),
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

      runtime.log(
        `Safeguard report submitted via Gemini: ${assessment.recommendedAction}`,
      );
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
