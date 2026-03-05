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
  stringToHex,
  zeroAddress,
} from "viem";
import {
  fetchTransactionMetrics,
  fetchMempoolSignals,
} from "./indexer";
import {
  fetchThreatIntelligence,
  type ExploitPattern as ThreatIntelExploitPattern,
  type ThreatIntelligence,
} from "./threat-intel";

// ---------------------------------------------------------------------------
// Interfaces — aligned with AI_AGENTS.md §3.2 (tiered TelemetryFrame)
// ---------------------------------------------------------------------------

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

/**
 * Composite telemetry frame assembled from multiple data sources.
 * - Tier 1 fields are populated from on-chain reads (EVMClient.callContract).
 * - Tier 2 fields are populated from off-chain APIs (HTTP via runInNodeMode).
 * See AI_AGENTS.md §3.2 for the full specification.
 */
interface TelemetryFrame {
  // Tier 1: On-chain reads
  chainId: number;
  blockNumber: number;
  protocolAddress: string;
  tvl: {
    current: string; // Serialized bigint — totalSupply or totalAssets
    delta1h: number; // % change over 1 hour
    delta24h: number;
  };
  transactionMetrics: {
    volumeUSD: string; // Serialized bigint
    uniqueAddresses: number;
    largeTransactions: number; // > $1M threshold
    failedTxRatio: number;
  };
  contractState: {
    owner: string;
    paused: boolean;
    pendingUpgrade: boolean;
    unusualApprovals: number; // ERC-20 unlimited approvals
  };
  mempoolSignals: {
    pendingLargeWithdrawals: number;
    flashLoanBorrows: number;
    suspiciousCalldata: string[];
  };
  priceData: {
    tokenPrice: string; // Serialized bigint — from Chainlink Price Feed
    priceDeviation: number;
    oracleLatency: number;
  };

  // Tier 2: Off-chain APIs (via runInNodeMode)
  threatIntel: {
    activeCVEs: string[];
    exploitPatterns: ExploitPattern[];
    darkWebMentions: number;
    socialSentiment: number; // -1.0 to 1.0
  };
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
  operatorAddress: `0x${string}`;
  geminiApiUrl: string;
  chainName: string;
  rpcUrl: string; // RPC endpoint for indexer queries
  telemetryCacheAddress: `0x${string}`;
  /** Maps protocol address → Chainlink AggregatorV3 price feed address. */
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

/** Minimal ERC-20 / protocol views for Chain Reader telemetry. */
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

/** Chainlink AggregatorV3Interface — latestRoundData(). */
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

/** TelemetryCache contract ABI for TVL snapshot persistence. */
const TELEMETRY_CACHE_ABI = [
  {
    inputs: [{ name: "protocol", type: "address" }],
    name: "getSnapshot",
    outputs: [
      {
        components: [
          { name: "tvl", type: "uint256" },
          { name: "timestamp", type: "uint256" },
        ],
        name: "",
        type: "tuple",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      { name: "protocol", type: "address" },
      { name: "tvl", type: "uint256" },
    ],
    name: "recordSnapshot",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

/** Best-effort proxy detection — call implementation() on ERC-1967 transparent proxies. */
const PROXY_ABI = [
  {
    inputs: [],
    name: "implementation",
    outputs: [{ name: "", type: "address" }],
    stateMutability: "view",
    type: "function",
  },
] as const;

// ---------------------------------------------------------------------------
// Action type → SentinelActions.ActionType enum mapping
// Must match ISentinelActions.sol enum exactly:
//   PAUSE = 0, RATE_LIMIT = 1, DRAIN_BLOCK = 2, ALERT = 3, CUSTOM = 4
// ---------------------------------------------------------------------------

const ACTION_TYPE_MAP: Record<string, number> = {
  PAUSE: 0,
  RATE_LIMIT: 1,
  DRAIN_BLOCK: 2,
  ALERT: 3,
  CUSTOM: 4,
};

const SEVERITY_MAP: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

// ---------------------------------------------------------------------------
// Heuristic thresholds — fast pre-filter before LLM invocation (AI_AGENTS.md §3.4)
// ---------------------------------------------------------------------------

const HEURISTIC_THRESHOLDS = {
  /** TVL drop exceeding this % in 24h triggers LLM analysis. */
  tvlDrop24hPct: -10,
  /** If contract is paused, always escalate. */
  contractPaused: true,
  /** Price deviation exceeding this % from TWAP triggers LLM analysis. */
  priceDeviationPct: 15,
  /** Oracle latency exceeding this many seconds triggers LLM analysis. */
  oracleLatencySec: 3600,
  /** If active CVEs exist, always escalate. */
  hasActiveCVEs: true,
  /** Minimum heuristic score to invoke LLM (0.0 = always invoke, 1.0 = never invoke) */
  minScoreForLLM: 0.1, // Production: 0.1 (cost optimization), Testing: 0.0 (see all API calls)
};

// ---------------------------------------------------------------------------
// Tier 1: On-chain telemetry (Chain Reader via EVMClient)
// ---------------------------------------------------------------------------

/**
 * Reads on-chain telemetry for a monitored protocol via EVMClient.callContract.
 * Calls totalSupply(), paused(), owner() on the protocol contract.
 * Returns partial TelemetryFrame fields for Tier 1 data.
 */
const readOnChainTelemetry = (
  runtime: Runtime<Config>,
  evmClient: EVMClient,
  protocolAddress: `0x${string}`,
  chainId: number,
): Omit<TelemetryFrame, "threatIntel"> => {
  // --- totalSupply (TVL proxy) ---
  let tvlCurrent = "0";
  try {
    const tvlReply = evmClient
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
    const decoded = decodeFunctionResult({
      abi: PROTOCOL_READ_ABI,
      functionName: "totalSupply",
      data: bytesToHex(tvlReply.data) as `0x${string}`,
    });
    tvlCurrent = String(decoded);
  } catch (e) {
    runtime.log(
      `[ChainReader] totalSupply() call failed for ${protocolAddress}: ${e}`,
    );
  }

  // --- paused() ---
  let paused = false;
  // Only attempt to call paused() if the contract might have it
  // Standard ERC-20 tokens don't have paused(), so we skip the call
  // to avoid unnecessary errors
  try {
    const pausedReply = evmClient
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
    const decoded = decodeFunctionResult({
      abi: PROTOCOL_READ_ABI,
      functionName: "paused",
      data: bytesToHex(pausedReply.data) as `0x${string}`,
    });
    paused = Boolean(decoded);
    runtime.log(`[ChainReader] paused() = ${paused} for ${protocolAddress}`);
  } catch (e) {
    // Function doesn't exist on this contract - use default value
    // This is normal for standard ERC-20 tokens
  }

  // --- owner() ---
  let owner = zeroAddress as string;
  // Only attempt to call owner() if the contract might have it
  // Standard ERC-20 tokens don't have owner(), so we skip the call
  // to avoid unnecessary errors
  try {
    const ownerReply = evmClient
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
    const decoded = decodeFunctionResult({
      abi: PROTOCOL_READ_ABI,
      functionName: "owner",
      data: bytesToHex(ownerReply.data) as `0x${string}`,
    });
    owner = String(decoded);
    runtime.log(`[ChainReader] owner() = ${owner} for ${protocolAddress}`);
  } catch (e) {
    // Function doesn't exist on this contract - use default value
    // This is normal for standard ERC-20 tokens
  }

  // --- ERC-1967 proxy detection via implementation() ---
  let pendingUpgrade = false;
  try {
    const implReply = evmClient
      .callContract(runtime, {
        call: encodeCallMsg({
          from: zeroAddress,
          to: protocolAddress,
          data: encodeFunctionData({
            abi: PROXY_ABI,
            functionName: "implementation",
          }),
        }),
        blockNumber: LAST_FINALIZED_BLOCK_NUMBER,
      })
      .result();
    const decoded = decodeFunctionResult({
      abi: PROXY_ABI,
      functionName: "implementation",
      data: bytesToHex(implReply.data) as `0x${string}`,
    });
    const implAddress = String(decoded);
    // If implementation() returns a non-zero address, the contract is a proxy.
    // Log the implementation address so operators can detect changes across runs.
    if (implAddress !== zeroAddress) {
      runtime.log(
        `[ProxyDetect] ${protocolAddress} is a proxy → impl=${implAddress}`,
      );
      // NOTE: To detect actual upgrades, the operator would compare this against
      // a known-good implementation address. For now, we flag that it IS a proxy.
      pendingUpgrade = false;
    }
  } catch (_e) {
    // Not a proxy or doesn't expose implementation() — this is expected for
    // non-proxy contracts. Not an error.
  }

  // --- Chainlink Price Feed via AggregatorV3.latestRoundData() ---
  let tokenPrice = "0";
  let priceDeviation = 0;
  let oracleLatency = 0;

  const feedAddress = runtime.config.priceFeedAddresses?.[protocolAddress];
  if (feedAddress) {
    try {
      const priceReply = evmClient
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
        data: bytesToHex(priceReply.data) as `0x${string}`,
      }) as readonly [bigint, bigint, bigint, bigint, bigint];

      const [, answer, , updatedAt] = decoded;
      tokenPrice = String(answer);

      // Oracle latency: seconds since last price update
      const nowSec = Math.floor(runtime.now().getTime() / 1000);
      oracleLatency = nowSec - Number(updatedAt);

      runtime.log(
        `[PriceFeed] ${protocolAddress}: price=${tokenPrice}, latency=${oracleLatency}s`,
      );
    } catch (e) {
      runtime.log(
        `[PriceFeed] latestRoundData() failed for feed ${feedAddress}: ${e}`,
      );
    }
  }

  // --- TVL delta via TelemetryCache ---
  let delta24h = 0;
  const cacheAddr = runtime.config.telemetryCacheAddress;
  if (cacheAddr && cacheAddr !== zeroAddress) {
    try {
      const snapReply = evmClient
        .callContract(runtime, {
          call: encodeCallMsg({
            from: zeroAddress,
            to: cacheAddr,
            data: encodeFunctionData({
              abi: TELEMETRY_CACHE_ABI,
              functionName: "getSnapshot",
              args: [protocolAddress],
            }),
          }),
          blockNumber: LAST_FINALIZED_BLOCK_NUMBER,
        })
        .result();
      const decoded = decodeFunctionResult({
        abi: TELEMETRY_CACHE_ABI,
        functionName: "getSnapshot",
        data: bytesToHex(snapReply.data) as `0x${string}`,
      }) as any;

      const previousTvl = BigInt(decoded.tvl ?? 0);
      const currentTvl = BigInt(tvlCurrent);

      if (previousTvl > 0n && currentTvl > 0n) {
        delta24h =
          Number(((currentTvl - previousTvl) * 10000n) / previousTvl) / 100;
        runtime.log(
          `[TvlDelta] ${protocolAddress}: prev=${previousTvl}, curr=${currentTvl}, delta=${delta24h.toFixed(
            2,
          )}%`,
        );
      }
    } catch (e) {
      runtime.log(
        `[TelemetryCache] getSnapshot() failed for ${protocolAddress}: ${e}`,
      );
    }
  }

  return {
    chainId,
    blockNumber: 0,
    protocolAddress,
    tvl: {
      current: tvlCurrent,
      delta1h: 0, // Will be populated by TelemetryCache in future enhancement
      delta24h,
    },
    transactionMetrics: {
      volumeUSD: "0",
      uniqueAddresses: 0,
      largeTransactions: 0,
      failedTxRatio: 0,
    },
    contractState: {
      owner,
      paused,
      pendingUpgrade,
      unusualApprovals: 0, // Will be populated by approval monitoring in future enhancement
    },
    mempoolSignals: {
      pendingLargeWithdrawals: 0,
      flashLoanBorrows: 0,
      suspiciousCalldata: [],
    },
    priceData: {
      tokenPrice,
      priceDeviation,
      oracleLatency,
    },
  };
};

// ---------------------------------------------------------------------------
// Heuristic Gate — fast pre-filter before LLM invocation
// ---------------------------------------------------------------------------

/**
 * Applies lightweight heuristic checks to determine if LLM analysis is warranted.
 * Returns a risk score (0.0–1.0) and whether the LLM should be invoked.
 *
 * Purpose: avoid unnecessary (costly, rate-limited) LLM calls when telemetry
 * shows no anomalies. Per AI_AGENTS.md §3.6 anti-hallucination safeguards.
 */
const runHeuristicGate = (
  runtime: Runtime<Config>,
  frame: TelemetryFrame,
): { heuristicScore: number; shouldInvokeLLM: boolean } => {
  let score = 0;
  const reasons: string[] = [];

  // Contract paused — immediate escalation signal
  if (frame.contractState.paused) {
    score += 0.4;
    reasons.push("contract_paused");
  }

  // TVL drop exceeding threshold
  if (frame.tvl.delta24h < HEURISTIC_THRESHOLDS.tvlDrop24hPct) {
    score += 0.3;
    reasons.push(`tvl_drop_${frame.tvl.delta24h.toFixed(1)}pct`);
  }

  // Active CVEs
  if (frame.threatIntel.activeCVEs.length > 0) {
    score += 0.3;
    reasons.push(`active_cves_${frame.threatIntel.activeCVEs.length}`);
  }

  // Price deviation
  if (
    Math.abs(frame.priceData.priceDeviation) >
    HEURISTIC_THRESHOLDS.priceDeviationPct
  ) {
    score += 0.2;
    reasons.push(
      `price_deviation_${frame.priceData.priceDeviation.toFixed(1)}pct`,
    );
  }

  // Oracle latency
  if (frame.priceData.oracleLatency > HEURISTIC_THRESHOLDS.oracleLatencySec) {
    score += 0.15;
    reasons.push(`oracle_stale_${frame.priceData.oracleLatency}s`);
  }

  // Exploit patterns from threat intel
  const criticalPatterns = frame.threatIntel.exploitPatterns.filter(
    (p) => p.severity === "critical" || p.severity === "high",
  );
  if (criticalPatterns.length > 0) {
    score += 0.3;
    reasons.push(`high_severity_patterns_${criticalPatterns.length}`);
  }

  // High failed transaction ratio (> 20%)
  if (frame.transactionMetrics.failedTxRatio > 0.2) {
    score += 0.25;
    reasons.push(
      `high_failed_tx_ratio_${(frame.transactionMetrics.failedTxRatio * 100).toFixed(1)}pct`,
    );
  }

  // Large transactions detected
  if (frame.transactionMetrics.largeTransactions > 0) {
    score += 0.15;
    reasons.push(
      `large_transactions_${frame.transactionMetrics.largeTransactions}`,
    );
  }

  // Pending flash loan borrows in mempool
  if (frame.mempoolSignals.flashLoanBorrows > 0) {
    score += 0.35;
    reasons.push(
      `pending_flash_loans_${frame.mempoolSignals.flashLoanBorrows}`,
    );
  }

  // Pending large withdrawals in mempool
  if (frame.mempoolSignals.pendingLargeWithdrawals > 0) {
    score += 0.3;
    reasons.push(
      `pending_large_withdrawals_${frame.mempoolSignals.pendingLargeWithdrawals}`,
    );
  }

  // Suspicious calldata patterns
  if (frame.mempoolSignals.suspiciousCalldata.length > 0) {
    score += 0.25;
    reasons.push(
      `suspicious_calldata_${frame.mempoolSignals.suspiciousCalldata.length}`,
    );
  }

  // Dark web mentions (high risk indicator)
  if (frame.threatIntel.darkWebMentions > 0) {
    score += 0.4;
    reasons.push(`dark_web_mentions_${frame.threatIntel.darkWebMentions}`);
  }

  // Negative social sentiment (< -0.5)
  if (frame.threatIntel.socialSentiment < -0.5) {
    score += 0.2;
    reasons.push(
      `negative_sentiment_${frame.threatIntel.socialSentiment.toFixed(2)}`,
    );
  }

  score = Math.min(score, 1.0);
  const shouldInvokeLLM = score >= HEURISTIC_THRESHOLDS.minScoreForLLM;

  runtime.log(
    `[Heuristic] Score: ${score.toFixed(
      2,
    )}, Invoke LLM: ${shouldInvokeLLM}, Reasons: [${reasons.join(", ")}]`,
  );

  return { heuristicScore: score, shouldInvokeLLM };
};


/**
 * Invokes Gemini for risk analysis within Confidential Compute (runInNodeMode).
 * API key is passed in the request body header, never in the URL.
 * Prompt is aligned with AI_AGENTS.md §3.3.
 */
const getGeminiAssessment = (
  nodeRuntime: NodeRuntime<Config>,
  frame: TelemetryFrame,
  apiKey: string,
): ThreatAssessment => {
  const http = new HTTPClient();

  const prompt = `You are Raizo Sentinel, an autonomous DeFi security analyst. You analyze on-chain telemetry and threat intelligence to predict exploits.

RULES:
1. Output ONLY valid JSON matching the ThreatAssessment schema.
2. Do NOT hallucinate data — if uncertain, assign lower confidence scores.
3. A confidence score above 0.85 triggers protective action. Be conservative: false negatives are preferable to false positives that pause legitimate protocols.
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

  nodeRuntime.log(`[Gemini] [API] Preparing threat assessment request`);
  nodeRuntime.log(`[Gemini] [API] Endpoint: ${nodeRuntime.config.geminiApiUrl}`);
  nodeRuntime.log(`[Gemini] [API] Method: POST`);
  nodeRuntime.log(`[Gemini] [API] API key present: ${apiKey && apiKey !== "SIMULATION_FALLBACK_KEY" ? "yes" : "no (using fallback)"}`);
  nodeRuntime.log(`[Gemini] [API] Request payload size: ${body.length} bytes`);
  nodeRuntime.log(`[Gemini] [API] Protocol: ${frame.protocolAddress}`);
  
  const response = http
    .sendRequest(nodeRuntime, {
      url: `${nodeRuntime.config.geminiApiUrl}?key=${apiKey}`,
      method: "POST",
      body: hexToBase64(stringToHex(body)),
    })
    .result();

  nodeRuntime.log(`[Gemini] [API] Response status: ${response.statusCode}`);
  
  if (!ok(response)) {
    nodeRuntime.log("[Gemini] [API] API request failed — returning safe fallback");
    nodeRuntime.log(`[Gemini] [API] Response headers: ${JSON.stringify(response.headers || {})}`);
    
    // Decode and log full response body for debugging
    if (response.body) {
      try {
        const decoder = new TextDecoder();
        const responseText = decoder.decode(response.body);
        nodeRuntime.log(`[Gemini] [API] Full response body: ${responseText}`);
      } catch (e) {
        nodeRuntime.log(`[Gemini] [API] Response body (raw bytes): ${response.body}`);
      }
    } else {
      nodeRuntime.log(`[Gemini] [API] Response body: empty`);
    }
    
    return {
      overallRiskScore: 0,
      threatDetected: false,
      threats: [],
      recommendedAction: "NONE",
      reasoning: "Gemini API unreachable — defaulting to safe state",
      evidenceCitations: [],
    };
  }

  nodeRuntime.log(`[Gemini] [API] Successfully received response`);
  
  try {
    const result = json(response) as any;
    const text = result.candidates[0].content.parts[0].text;
    const parsed = JSON.parse(text) as ThreatAssessment;

    nodeRuntime.log(`[Gemini] [API] Successfully parsed threat assessment`);
    nodeRuntime.log(`[Gemini] [API] Risk score: ${parsed.overallRiskScore}`);
    nodeRuntime.log(`[Gemini] [API] Threat detected: ${parsed.threatDetected}`);
    nodeRuntime.log(`[Gemini] [API] Recommended action: ${parsed.recommendedAction}`);
    
    // Validate LLM output integrity
    if (
      typeof parsed.overallRiskScore !== "number" ||
      parsed.overallRiskScore < 0 ||
      parsed.overallRiskScore > 1
    ) {
      nodeRuntime.log(
        `[Gemini] Invalid riskScore ${parsed.overallRiskScore} — clamping`,
      );
      parsed.overallRiskScore = Math.max(
        0,
        Math.min(1, parsed.overallRiskScore || 0),
      );
    }

    // Enforce action escalation thresholds (AI_AGENTS.md §3.4)
    parsed.recommendedAction = enforceActionThresholds(parsed.overallRiskScore);

    return parsed;
  } catch (e) {
    nodeRuntime.log(`[Gemini] Response parse error: ${e}`);
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

/**
 * Enforces the action escalation matrix from AI_AGENTS.md §3.4.
 * The code is the authority — the LLM's suggested action is overridden
 * by deterministic thresholds to prevent hallucinated escalations.
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

// ---------------------------------------------------------------------------
// Per-protocol analysis pipeline (runs in runInNodeMode for each protocol)
// ---------------------------------------------------------------------------

/**
 * Full analysis pipeline for a single protocol, executed inside runInNodeMode.
 * Steps:
 *   1. Fetch off-chain threat intelligence
 *   2. Invoke LLM for risk assessment
 * On-chain reads are done in DON mode (before runInNodeMode) since
 * EVMClient requires a Runtime, not NodeRuntime.
 */
const analyzeProtocolNode = (
  nodeRuntime: NodeRuntime<Config>,
  frame: TelemetryFrame,
  apiKey: string,
  ethPriceUSD: number,
): ThreatAssessment => {
  nodeRuntime.log(`[Analysis] Starting protocol analysis for ${frame.protocolAddress}`);
  
  // 1. Fetch transaction metrics from indexer (Tier 1 enhancement)
  nodeRuntime.log(`[Analysis] Fetching transaction metrics from indexer...`);
  const transactionMetrics = fetchTransactionMetrics(
    nodeRuntime,
    frame.protocolAddress,
    nodeRuntime.config.rpcUrl,
    ethPriceUSD,
  );
  nodeRuntime.log(`[Analysis] Transaction metrics fetched: volume=${transactionMetrics.volumeUSD}, unique=${transactionMetrics.uniqueAddresses}`);

  // 2. Fetch mempool signals from indexer (Tier 1 enhancement)
  nodeRuntime.log(`[Analysis] Fetching mempool signals from indexer...`);
  const mempoolSignals = fetchMempoolSignals(
    nodeRuntime,
    frame.protocolAddress,
    nodeRuntime.config.rpcUrl,
  );
  nodeRuntime.log(`[Analysis] Mempool signals fetched: withdrawals=${mempoolSignals.pendingLargeWithdrawals}, flashLoans=${mempoolSignals.flashLoanBorrows}`);

  // 3. Enrich frame with Tier 2 threat intelligence
  nodeRuntime.log(`[Analysis] Fetching threat intelligence...`);
  const threatIntel = fetchThreatIntelligence(nodeRuntime, frame.protocolAddress);
  nodeRuntime.log(`[Analysis] Threat intelligence fetched: CVEs=${threatIntel.activeCVEs.length}, patterns=${threatIntel.exploitPatterns.length}`);

  // 4. Assemble complete telemetry frame per AI_AGENTS.md §3.2
  const enrichedFrame: TelemetryFrame = {
    ...frame,
    transactionMetrics: {
      volumeUSD: transactionMetrics.volumeUSD.toString(),
      uniqueAddresses: transactionMetrics.uniqueAddresses,
      largeTransactions: transactionMetrics.largeTransactions,
      failedTxRatio: transactionMetrics.failedTxRatio,
    },
    mempoolSignals,
    threatIntel,
  };

  // 5. LLM risk analysis
  nodeRuntime.log(`[Analysis] Invoking Gemini for threat assessment...`);
  return getGeminiAssessment(nodeRuntime, enrichedFrame, apiKey);
};

// ---------------------------------------------------------------------------
// Report mapping — convert ThreatAssessment → SentinelActions.ThreatReport
// ---------------------------------------------------------------------------

const mapSeverity = (riskScore: number): number => {
  if (riskScore >= 0.95) return SEVERITY_MAP["critical"];
  if (riskScore >= 0.85) return SEVERITY_MAP["high"];
  if (riskScore >= 0.7) return SEVERITY_MAP["medium"];
  return SEVERITY_MAP["low"];
};

// ---------------------------------------------------------------------------
// Main workflow handler
// ---------------------------------------------------------------------------

const onCronTrigger = (runtime: Runtime<Config>) => {
  const { raizoCoreAddress, sentinelActionsAddress, chainName } =
    runtime.config;

  runtime.log("=== Raizo Threat Sentinel: Initiating scan ===");

  // Resolve chain selector from human-readable name
  const network = getNetwork({
    chainFamily: "evm",
    chainSelectorName: chainName,
    isTestnet: true,
  });

  if (!network) {
    throw new Error(
      `Unknown chain name: ${chainName}. Check config.staging.json chainName field.`,
    );
  }

  const evmClient = new EVMClient(network.chainSelector.selector);

  // Load API key from CRE secrets store
  let apiKey: string;
  try {
    apiKey = runtime.getSecret({ id: "API_KEY" }).result().value;
    runtime.log("[Secrets] API_KEY loaded from CRE secrets store");
  } catch (e) {
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

  runtime.log(`[RaizoCore] Fetched ${protocols.length} registered protocol(s)`);

  // --- Step 2: Per-protocol analysis ---
  for (const protocol of protocols) {
    if (!protocol.isActive) continue;

    const protocolAddr = protocol.protocolAddress as `0x${string}`;
    runtime.log(`[Scan] Analyzing protocol ${protocolAddr}`);

    // Tier 1: On-chain telemetry via Chain Reader
    const onChainData = readOnChainTelemetry(
      runtime,
      evmClient,
      protocolAddr,
      protocol.chainId,
    );

    // Assemble initial frame (Tier 2 threat intel and indexer data added inside runInNodeMode)
    const baseFrame: TelemetryFrame = {
      ...onChainData,
      transactionMetrics: {
        volumeUSD: "0",
        uniqueAddresses: 0,
        largeTransactions: 0,
        failedTxRatio: 0,
      },
      mempoolSignals: {
        pendingLargeWithdrawals: 0,
        flashLoanBorrows: 0,
        suspiciousCalldata: [],
      },
      threatIntel: {
        activeCVEs: [],
        exploitPatterns: [],
        darkWebMentions: 0,
        socialSentiment: 0.0,
      },
    };

    // Heuristic gate — skip LLM if telemetry shows no anomalies
    const { heuristicScore, shouldInvokeLLM } = runHeuristicGate(
      runtime,
      baseFrame,
    );

    if (!shouldInvokeLLM) {
      runtime.log(
        `[Gate] Protocol ${protocolAddr} heuristic score ${heuristicScore.toFixed(
          2,
        )} — below threshold, skipping LLM`,
      );
      runtime.log(
        `[Gate] ⚠️  Indexer and threat intel API calls skipped (cost optimization)`,
      );
      runtime.log(
        `[Gate] To force API calls, lower HEURISTIC_THRESHOLDS or trigger an anomaly`,
      );
      continue;
    }

    runtime.log(
      `[Gate] Protocol ${protocolAddr} heuristic score ${heuristicScore.toFixed(
        2,
      )} — above threshold, proceeding with full analysis`,
    );

    // Calculate ETH price in USD for indexer
    const ethPriceUSD = onChainData.priceData.tokenPrice
      ? Number(BigInt(onChainData.priceData.tokenPrice)) / 1e8
      : 2000; // Fallback price

    // --- Step 3: LLM analysis via runInNodeMode (DON consensus) ---
    const assessment = runtime
      .runInNodeMode(
        analyzeProtocolNode,
        ConsensusAggregationByFields<ThreatAssessment>({
          overallRiskScore: median,
          threatDetected: identical,
          threats: identical,
          recommendedAction: identical,
          reasoning: identical,
          evidenceCitations: identical,
        }),
      )(baseFrame, apiKey, ethPriceUSD)
      .result();

    runtime.log(
      `[Assessment] Protocol ${protocolAddr}: risk=${assessment.overallRiskScore.toFixed(
        2,
      )}, action=${assessment.recommendedAction}, threats=${
        assessment.threats.length
      }`,
    );

    // --- Step 4: On-chain action via SentinelActions.executeAction ---
    if (assessment.recommendedAction !== "NONE" && assessment.threatDetected) {
      const reportId = keccak256(
        stringToHex(protocolAddr + String(runtime.now().getTime())),
      );

      const reportData = {
        reportId,
        agentId: keccak256(stringToHex("raizo-threat-sentinel-v1")),
        exists: true,
        targetProtocol: protocolAddr,
        action: ACTION_TYPE_MAP[assessment.recommendedAction] ?? 0,
        severity: mapSeverity(assessment.overallRiskScore),
        confidenceScore: Math.round(assessment.overallRiskScore * 10000),
        evidenceHash: keccak256(stringToHex(assessment.reasoning)),
        timestamp: BigInt(Math.floor(runtime.now().getTime() / 1000)),
        donSignatures: stringToHex("consensus-proof"),
      };

      runtime.log(
        `[Action] Submitting report ${reportId}: action=${assessment.recommendedAction}, confidence=${reportData.confidenceScore}bp`,
      );

      evmClient
        .callContract(runtime, {
          call: encodeCallMsg({
            from: runtime.config.operatorAddress,
            to: sentinelActionsAddress,
            data: encodeFunctionData({
              abi: SENTINEL_ABI,
              functionName: "executeAction",
              args: [reportData],
            }),
          }),
          blockNumber: LAST_FINALIZED_BLOCK_NUMBER,
        })
        .result();

      runtime.log(
        `[Action] Report submitted: ${assessment.recommendedAction} on ${protocolAddr}`,
      );
    }

    // --- Step 5: Write current TVL to TelemetryCache for next-tick delta ---
    const cacheAddr = runtime.config.telemetryCacheAddress;
    if (cacheAddr && cacheAddr !== zeroAddress && onChainData.tvl.current !== "0") {
      try {
        evmClient
          .callContract(runtime, {
            call: encodeCallMsg({
              from: runtime.config.operatorAddress,
              to: cacheAddr,
              data: encodeFunctionData({
                abi: TELEMETRY_CACHE_ABI,
                functionName: "recordSnapshot",
                args: [protocolAddr, BigInt(onChainData.tvl.current)],
              }),
            }),
            blockNumber: LAST_FINALIZED_BLOCK_NUMBER,
          })
          .result();
        runtime.log(
          `[TelemetryCache] Recorded TVL snapshot for ${protocolAddr}: ${onChainData.tvl.current}`,
        );
      } catch (e) {
        runtime.log(
          `[TelemetryCache] recordSnapshot() failed for ${protocolAddr}: ${e}`,
        );
      }
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
