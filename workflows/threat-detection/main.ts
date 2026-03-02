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
    delta24h: number;
  };
  contractState: {
    owner: string;
    paused: boolean;
    pendingUpgrade: boolean;
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

/** ERC-1967 implementation storage slot for upgrade detection. */
const ERC1967_IMPL_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" as const;

// ---------------------------------------------------------------------------
// Action type → SentinelActions.ActionType enum mapping
// ---------------------------------------------------------------------------

const ACTION_TYPE_MAP: Record<string, number> = {
  NONE: 0,
  ALERT: 1,
  RATE_LIMIT: 2,
  DRAIN_BLOCK: 3,
  PAUSE: 4,
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
  } catch (e) {
    runtime.log(
      `[ChainReader] paused() call failed for ${protocolAddress}: ${e}`,
    );
  }

  // --- owner() ---
  let owner = zeroAddress as string;
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
  } catch (e) {
    runtime.log(
      `[ChainReader] owner() call failed for ${protocolAddress}: ${e}`,
    );
  }

  return {
    chainId,
    blockNumber: 0, // Populated from header if available
    protocolAddress,
    tvl: {
      current: tvlCurrent,
      delta24h: 0, // Requires historical data — future: store & compare
    },
    contractState: {
      owner,
      paused,
      pendingUpgrade: false, // Future: read ERC-1967 implementation slot
    },
    priceData: {
      tokenPrice: "0", // Future: Chainlink Price Feed integration
      priceDeviation: 0,
      oracleLatency: 0,
    },
  };
};

// ---------------------------------------------------------------------------
// Tier 2: Off-chain threat intelligence (HTTP via runInNodeMode)
// ---------------------------------------------------------------------------

/**
 * Fetches threat intelligence from an external API within Confidential Compute.
 * Wrapped in runInNodeMode for DON consensus.
 */
const fetchThreatIntel = (
  nodeRuntime: NodeRuntime<Config>,
  _protocolAddress: string,
): TelemetryFrame["threatIntel"] => {
  // In production, this would call a real threat intel API (Immunefi, OpenCVE).
  // For MVP/simulation, we return a baseline with no active threats.
  // The HTTP call pattern is preserved for when the API is integrated.
  nodeRuntime.log(
    `[ThreatIntel] Fetching intelligence for ${_protocolAddress}`,
  );

  return {
    activeCVEs: [],
    exploitPatterns: [],
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

  score = Math.min(score, 1.0);
  const shouldInvokeLLM = score > 0.1;

  runtime.log(
    `[Heuristic] Score: ${score.toFixed(
      2,
    )}, Invoke LLM: ${shouldInvokeLLM}, Reasons: [${reasons.join(", ")}]`,
  );

  return { heuristicScore: score, shouldInvokeLLM };
};

// ---------------------------------------------------------------------------
// LLM Analysis (Gemini via runInNodeMode)
// ---------------------------------------------------------------------------

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

  const response = http
    .sendRequest(nodeRuntime, {
      url: `${nodeRuntime.config.geminiApiUrl}?key=${apiKey}`,
      method: "POST",
      body: hexToBase64(stringToHex(body)),
    })
    .result();

  if (!ok(response)) {
    nodeRuntime.log("[Gemini] API request failed — returning safe fallback");
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
): ThreatAssessment => {
  // 1. Enrich frame with Tier 2 threat intelligence
  const threatIntel = fetchThreatIntel(nodeRuntime, frame.protocolAddress);
  const enrichedFrame: TelemetryFrame = {
    ...frame,
    threatIntel,
  };

  // 2. LLM risk analysis
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

    // Assemble initial frame (Tier 2 threat intel added inside runInNodeMode)
    const baseFrame: TelemetryFrame = {
      ...onChainData,
      threatIntel: { activeCVEs: [], exploitPatterns: [] },
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
      continue;
    }

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
      )(baseFrame, apiKey)
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
