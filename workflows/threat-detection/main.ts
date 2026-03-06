import {
  CronCapability,
  HTTPClient,
  EVMClient,
  handler,
  Runner,
  type Runtime,
  type NodeRuntime,
  ConsensusAggregationByFields,
  getNetwork,
  LAST_FINALIZED_BLOCK_NUMBER,
  median,
  identical,
  json,
  ok,
  bytesToHex,
  hexToBase64,
  encodeCallMsg,
} from "@chainlink/cre-sdk";
import {
  keccak256,
  encodeFunctionData,
  decodeFunctionResult,
  encodeAbiParameters,
  parseAbiParameters,
  stringToHex,
  zeroAddress,
} from "viem";
import { generatePaymentAuthorization, formatPaymentLog } from "../shared/x402";

// ---------------------------------------------------------------------------
// Interfaces — aligned with AI_AGENTS.md §3.2 (MVP subset)
// ---------------------------------------------------------------------------

/**
 * On-chain telemetry frame — MVP fields only.
 * Populated from Chain Reader (EVMClient.callContract).
 */
interface TelemetryFrame {
  chainId: number;
  protocolAddress: string;
  tvl: { current: string };
  contractState: { owner: string; paused: boolean };
  priceData: { tokenPrice: string; oracleLatency: number };
}

/**
 * LLM-generated assessment — aligned with AI_AGENTS.md §3.3.
 */
interface ThreatAssessment {
  overallRiskScore: number;
  threatDetected: boolean;
  threats: Array<{
    category: string;
    confidence: number;
    indicators: string[];
    estimatedImpactUSD: number;
  }>;
  recommendedAction: "NONE" | "ALERT" | "RATE_LIMIT" | "DRAIN_BLOCK" | "PAUSE";
  reasoning: string;
  evidenceCitations: string[];
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type Config = {
  schedule: string;
  raizoCoreAddress: `0x${string}`;
  sentinelActionsAddress: `0x${string}`;
  consumerAddress: `0x${string}`;
  operatorAddress: `0x${string}`;
  geminiApiUrl: string;
  chainName: string;
  isTestnet: boolean;
  gasLimit: string;
  priceFeedAddresses: Record<string, string>;
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

const PROTOCOL_READ_ABI = [
  {
    inputs: [],
    name: "totalSupply",
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "paused",
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "owner",
    outputs: [{ name: "", type: "address" }],
    stateMutability: "view",
    type: "function",
  },
] as const;

const AGGREGATOR_V3_ABI = [
  {
    inputs: [],
    name: "latestRoundData",
    outputs: [
      { name: "roundId", type: "uint80" },
      { name: "answer", type: "int256" },
      { name: "startedAt", type: "uint256" },
      { name: "updatedAt", type: "uint256" },
      { name: "answeredInRound", type: "uint80" },
    ],
    stateMutability: "view",
    type: "function",
  },
] as const;

// ---------------------------------------------------------------------------
// Action / Severity enums (must match ISentinelActions.sol)
// ---------------------------------------------------------------------------

const ACTION_TYPE_MAP: Record<string, number> = {
  PAUSE: 0,
  RATE_LIMIT: 1,
  DRAIN_BLOCK: 2,
  ALERT: 3,
  CUSTOM: 4,
};

const mapSeverity = (risk: number): number => {
  if (risk >= 0.95) return 3; // CRITICAL
  if (risk >= 0.85) return 2; // HIGH
  if (risk >= 0.7) return 1; // MEDIUM
  return 0; // LOW
};

// ---------------------------------------------------------------------------
// x402 Payment Submission Helper
// ---------------------------------------------------------------------------

const submitPaymentReport = (
  runtime: Runtime<Config>,
  evmClient: EVMClient,
  agentId: `0x${string}`,
  amount: bigint,
  label: string,
) => {
  const { consumerAddress, operatorAddress, gasLimit } = runtime.config;

  const payment = generatePaymentAuthorization(
    runtime,
    agentId,
    operatorAddress,
    amount,
  );

  // Encode AuthorizePayment for RaizoConsumer
  // (bytes32 agentId, address to, uint256 amount, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes signature)
  // Mock signature for demo simulation
  const mockSignature = stringToHex("x402-demo-signature") as `0x${string}`;

  const paymentData = encodeAbiParameters(
    parseAbiParameters(
      "bytes32 agentId, address to, uint256 amount, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes signature",
    ),
    [
      payment.agentId,
      payment.to,
      payment.amount,
      payment.validAfter,
      payment.validBefore,
      payment.nonce,
      mockSignature,
    ],
  );

  // Wrap with report type tag: (uint8 reportType=2, bytes data)
  const consumerPayload = encodeAbiParameters(
    parseAbiParameters("uint8 reportType, bytes data"),
    [2, paymentData],
  );

  runtime.log(`${formatPaymentLog(payment)} [${label}]`);

  const reportResponse = runtime
    .report({
      encodedPayload: hexToBase64(consumerPayload),
      encoderName: "evm",
      signingAlgo: "ecdsa",
      hashingAlgo: "keccak256",
    })
    .result();

  const writeResult = evmClient
    .writeReport(runtime, {
      receiver: consumerAddress,
      report: reportResponse,
      gasConfig: { gasLimit },
    })
    .result();

  const txHash = bytesToHex(writeResult.txHash || new Uint8Array(32));
  runtime.log(`[x402] Settlement TX: ${txHash}`);
};

// ---------------------------------------------------------------------------
// Tier 1: On-chain telemetry (Chain Reader via EVMClient)
// ---------------------------------------------------------------------------

const readOnChainTelemetry = (
  runtime: Runtime<Config>,
  evmClient: EVMClient,
  protocolAddress: `0x${string}`,
  chainId: number,
): TelemetryFrame => {
  // --- totalSupply (TVL proxy) ---
  let tvlCurrent = "0";
  try {
    const reply = evmClient
      .callContract(runtime, {
        call: encodeCallMsg({
          from: zeroAddress,
          to: protocolAddress,
          data: encodeFunctionData({
            abi: PROTOCOL_READ_ABI,
            functionName: "totalSupply",
          }),
        }),
        blockNumber: LAST_FINALIZED_BLOCK_NUMBER,
      })
      .result();
    tvlCurrent = String(
      decodeFunctionResult({
        abi: PROTOCOL_READ_ABI,
        functionName: "totalSupply",
        data: bytesToHex(reply.data) as `0x${string}`,
      }),
    );
  } catch (e) {
    runtime.log(
      `[ChainReader] totalSupply() failed for ${protocolAddress}: ${e}`,
    );
  }

  // --- paused() ---
  let paused = false;
  try {
    const reply = evmClient
      .callContract(runtime, {
        call: encodeCallMsg({
          from: zeroAddress,
          to: protocolAddress,
          data: encodeFunctionData({
            abi: PROTOCOL_READ_ABI,
            functionName: "paused",
          }),
        }),
        blockNumber: LAST_FINALIZED_BLOCK_NUMBER,
      })
      .result();
    paused = Boolean(
      decodeFunctionResult({
        abi: PROTOCOL_READ_ABI,
        functionName: "paused",
        data: bytesToHex(reply.data) as `0x${string}`,
      }),
    );
  } catch (_) {
    // paused() not available — expected for standard ERC-20 tokens
  }

  // --- owner() ---
  let owner = zeroAddress as string;
  try {
    const reply = evmClient
      .callContract(runtime, {
        call: encodeCallMsg({
          from: zeroAddress,
          to: protocolAddress,
          data: encodeFunctionData({
            abi: PROTOCOL_READ_ABI,
            functionName: "owner",
          }),
        }),
        blockNumber: LAST_FINALIZED_BLOCK_NUMBER,
      })
      .result();
    owner = String(
      decodeFunctionResult({
        abi: PROTOCOL_READ_ABI,
        functionName: "owner",
        data: bytesToHex(reply.data) as `0x${string}`,
      }),
    );
  } catch (_) {
    // owner() not available — expected for standard ERC-20 tokens
  }

  // --- Chainlink Price Feed ---
  let tokenPrice = "0";
  let oracleLatency = 0;
  const feedAddress = runtime.config.priceFeedAddresses?.[protocolAddress];
  if (feedAddress) {
    try {
      const reply = evmClient
        .callContract(runtime, {
          call: encodeCallMsg({
            from: zeroAddress,
            to: feedAddress as `0x${string}`,
            data: encodeFunctionData({
              abi: AGGREGATOR_V3_ABI,
              functionName: "latestRoundData",
            }),
          }),
          blockNumber: LAST_FINALIZED_BLOCK_NUMBER,
        })
        .result();
      const decoded = decodeFunctionResult({
        abi: AGGREGATOR_V3_ABI,
        functionName: "latestRoundData",
        data: bytesToHex(reply.data) as `0x${string}`,
      }) as readonly [bigint, bigint, bigint, bigint, bigint];
      const [, answer, , updatedAt] = decoded;
      tokenPrice = String(answer);
      oracleLatency =
        Math.floor(runtime.now().getTime() / 1000) - Number(updatedAt);
      runtime.log(
        `[PriceFeed] ${protocolAddress}: price=${tokenPrice}, latency=${oracleLatency}s`,
      );
    } catch (e) {
      runtime.log(
        `[PriceFeed] latestRoundData() failed for feed ${feedAddress}: ${e}`,
      );
    }
  }

  return {
    chainId,
    protocolAddress,
    tvl: { current: tvlCurrent },
    contractState: { owner, paused },
    priceData: { tokenPrice, oracleLatency },
  };
};

// ---------------------------------------------------------------------------
// LLM analysis (runInNodeMode — Confidential Compute)
// ---------------------------------------------------------------------------

/**
 * Enforces the action escalation matrix from AI_AGENTS.md §3.4.
 * Deterministic — overrides the LLM's suggested action.
 */
const enforceActionThresholds = (
  riskScore: number,
): ThreatAssessment["recommendedAction"] => {
  if (riskScore >= 0.95) return "PAUSE";
  if (riskScore >= 0.85) return "DRAIN_BLOCK";
  if (riskScore >= 0.7) return "RATE_LIMIT";
  if (riskScore >= 0.5) return "ALERT";
  return "NONE";
};

/**
 * Invokes Gemini for risk analysis. Runs inside DON node (Confidential Compute).
 * API key passed via x-goog-api-key header, not in URL.
 */
const analyzeProtocol = (
  nodeRuntime: NodeRuntime<Config>,
  frame: TelemetryFrame,
  apiKey: string,
): ThreatAssessment => {
  const http = new HTTPClient();

  const prompt = `You are Raizo Sentinel, an autonomous DeFi security analyst. Analyze on-chain telemetry and predict exploits.

RULES:
1. Output ONLY valid JSON matching the ThreatAssessment schema.
2. Do NOT hallucinate data — if uncertain, assign lower confidence scores.
3. A confidence score above 0.85 triggers protective action. Be conservative.
4. Always cite evidence from the telemetry frame.
5. Consider the exploit taxonomy: flash_loan, reentrancy, access_control, oracle_manipulation, logic_error, governance_attack.

Telemetry Frame:
${JSON.stringify(frame, null, 2)}

Output Schema:
{
  "overallRiskScore": number (0.0 to 1.0),
  "threatDetected": boolean,
  "threats": [{ "category": string, "confidence": number, "indicators": [string], "estimatedImpactUSD": number }],
  "recommendedAction": "NONE" | "ALERT" | "RATE_LIMIT" | "DRAIN_BLOCK" | "PAUSE",
  "reasoning": "Evidence-backed explanation string",
  "evidenceCitations": ["telemetryField.subField"]
}`;

  const body = JSON.stringify({
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: { response_mime_type: "application/json" },
  });

  nodeRuntime.log(
    `[Gemini] Sending threat assessment for ${frame.protocolAddress}`,
  );

  const response = http
    .sendRequest(nodeRuntime, {
      url: nodeRuntime.config.geminiApiUrl,
      method: "POST",
      headers: { "x-goog-api-key": apiKey, "Content-Type": "application/json" },
      body: hexToBase64(stringToHex(body)),
    })
    .result();

  if (!ok(response)) {
    nodeRuntime.log(
      `[Gemini] API failed (${response.statusCode}) — returning safe fallback`,
    );
    return {
      overallRiskScore: 0,
      threatDetected: false,
      threats: [],
      recommendedAction: "NONE",
      reasoning: "Gemini API unreachable — defaulting to safe state",
      evidenceCitations: [],
    };
  }

  try {
    const result = json(response) as any;
    const text = result.candidates[0].content.parts[0].text;
    const parsed = JSON.parse(text) as ThreatAssessment;

    // Clamp risk score to [0, 1]
    parsed.overallRiskScore = Math.max(
      0,
      Math.min(1, parsed.overallRiskScore || 0),
    );
    // Deterministic action override (AI_AGENTS.md §3.4)
    parsed.recommendedAction = enforceActionThresholds(parsed.overallRiskScore);

    nodeRuntime.log(
      `[Gemini] Result: risk=${parsed.overallRiskScore.toFixed(2)}, action=${
        parsed.recommendedAction
      }`,
    );
    return parsed;
  } catch (e) {
    nodeRuntime.log(`[Gemini] Parse error: ${e}`);
    return {
      overallRiskScore: 0,
      threatDetected: false,
      threats: [],
      recommendedAction: "NONE",
      reasoning: "Failed to parse Gemini response",
      evidenceCitations: [],
    };
  }
};

// ---------------------------------------------------------------------------
// Main workflow handler
// ---------------------------------------------------------------------------

const onCronTrigger = (runtime: Runtime<Config>) => {
  const { raizoCoreAddress, consumerAddress, chainName, isTestnet, gasLimit } =
    runtime.config;

  runtime.log("=== Raizo Threat Sentinel: Initiating scan ===");

  const network = getNetwork({
    chainFamily: "evm",
    chainSelectorName: chainName,
    isTestnet,
  });
  if (!network) {
    throw new Error(`Unknown chain name: ${chainName}`);
  }

  const evmClient = new EVMClient(network.chainSelector.selector);

  // Load API key from CRE secrets store
  let apiKey: string;
  try {
    apiKey = runtime.getSecret({ id: "API_KEY" }).result().value;
    runtime.log("[Secrets] API_KEY loaded");
  } catch (_) {
    runtime.log("[Secrets] API_KEY not found — using simulation fallback");
    apiKey = "SIMULATION_FALLBACK_KEY";
  }

  // --- Step 1: Read registered protocols from RaizoCore ---
  const protocolsReply = evmClient
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

  const protocols = decodeFunctionResult({
    abi: RAIZO_CORE_ABI,
    functionName: "getAllProtocols",
    data: bytesToHex(protocolsReply.data) as `0x${string}`,
  }) as any[];

  runtime.log(`[RaizoCore] ${protocols.length} protocol(s) registered`);

  // --- Step 2: Per-protocol analysis ---
  for (const protocol of protocols) {
    if (!protocol.isActive) continue;

    const protocolAddr = protocol.protocolAddress as `0x${string}`;
    runtime.log(`[Scan] Analyzing ${protocolAddr}`);

    // Tier 1: on-chain telemetry
    const frame = readOnChainTelemetry(
      runtime,
      evmClient,
      protocolAddr,
      protocol.chainId,
    );

    // --- Step 3: LLM analysis via runInNodeMode (DON consensus) ---
    // x402: Authorize and submit compute payment (5 Mock USDC)
    submitPaymentReport(
      runtime,
      evmClient,
      keccak256(stringToHex("raizo-threat-sentinel-v1")),
      5_000_000n,
      "AI Compute",
    );

    const assessment = runtime
      .runInNodeMode(
        analyzeProtocol,
        ConsensusAggregationByFields<ThreatAssessment>({
          overallRiskScore: median,
          threatDetected: identical,
          threats: identical,
          recommendedAction: identical,
          reasoning: identical,
          evidenceCitations: identical,
        }),
      )(frame, apiKey)
      .result();

    runtime.log(
      `[Assessment] ${protocolAddr}: risk=${assessment.overallRiskScore.toFixed(
        2,
      )}, action=${assessment.recommendedAction}, threats=${
        assessment.threats.length
      }`,
    );

    // --- Step 4: Write threat report on-chain via RaizoConsumer ---
    if (assessment.recommendedAction !== "NONE" && assessment.threatDetected) {
      const reportId = keccak256(
        stringToHex(protocolAddr + String(runtime.now().getTime())),
      );

      // Encode ThreatReport struct fields for RaizoConsumer
      const threatReportData = encodeAbiParameters(
        parseAbiParameters(
          "bytes32 reportId, bytes32 agentId, bool exists, address targetProtocol, uint8 action, uint8 severity, uint16 confidenceScore, bytes evidenceHash, uint256 timestamp, bytes donSignatures",
        ),
        [
          reportId,
          keccak256(stringToHex("raizo-threat-sentinel-v1")),
          true,
          protocolAddr,
          ACTION_TYPE_MAP[assessment.recommendedAction] ?? 0,
          mapSeverity(assessment.overallRiskScore),
          Math.round(assessment.overallRiskScore * 10000),
          keccak256(stringToHex(assessment.reasoning)) as `0x${string}`,
          BigInt(Math.floor(runtime.now().getTime() / 1000)),
          stringToHex("don-consensus") as `0x${string}`,
        ],
      );

      // Wrap with report type tag: (uint8 reportType=0, bytes data)
      const consumerPayload = encodeAbiParameters(
        parseAbiParameters("uint8 reportType, bytes data"),
        [0, threatReportData],
      );

      runtime.log(
        `[Action] Submitting report ${reportId}: ${assessment.recommendedAction}`,
      );

      // x402: Authorize and submit transaction subsidy (2 Mock USDC)
      submitPaymentReport(
        runtime,
        evmClient,
        keccak256(stringToHex("raizo-threat-sentinel-v1")),
        2_000_000n,
        "Gas Subsidy",
      );

      // Step 4a: Generate signed report via DON consensus
      const reportResponse = runtime
        .report({
          encodedPayload: hexToBase64(consumerPayload),
          encoderName: "evm",
          signingAlgo: "ecdsa",
          hashingAlgo: "keccak256",
        })
        .result();

      // Step 4b: Submit to RaizoConsumer via KeystoneForwarder
      const writeResult = evmClient
        .writeReport(runtime, {
          receiver: consumerAddress,
          report: reportResponse,
          gasConfig: { gasLimit },
        })
        .result();

      const txHash = bytesToHex(writeResult.txHash || new Uint8Array(32));
      runtime.log(`[Action] TX submitted: ${txHash}`);
    }
  }

  runtime.log("=== Raizo Threat Sentinel: Scan complete ===");
  return "Success";
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
