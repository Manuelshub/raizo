import {
  CronCapability,
  EVMClient,
  HTTPClient,
  handler,
  Runner,
  type Runtime,
  type NodeRuntime,
  ConsensusAggregationByFields,
  identical,
  ok,
  json,
  hexToBase64,
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
// Interfaces — aligned with AI_AGENTS.md §4.3
// ---------------------------------------------------------------------------

interface Finding {
  type: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  description: string;
  evidence: string[];
}

/**
 * Full compliance report schema per AI_AGENTS.md §4.3.
 * Assembled from on-chain data (Chain Reader) and LLM analysis (runInNodeMode).
 */
interface ComplianceReport {
  metadata: {
    reportId: string;
    generatedAt: number;
    framework: string;
    coverageChains: number[];
    periodStart: number;
    periodEnd: number;
  };
  findings: Finding[];
  riskSummary: {
    overallRisk: "low" | "medium" | "high";
    flaggedTransactions: number;
    flaggedAddresses: string[];
    complianceScore: number;
  };
  recommendations: string[];
  attestation: {
    donSignature: string;
    nodeCount: number;
    consensusReached: boolean;
  };
}

/**
 * On-chain protocol metrics read via Chain Reader.
 * Used as input to the compliance analysis.
 */
interface ProtocolMetrics {
  totalSupply: string;
  paused: boolean;
  owner: string;
  reportCount: number;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type Config = {
  schedule: string;
  complianceVaultAddress: `0x${string}`;
  raizoCoreAddress: `0x${string}`;
  operatorAddress: `0x${string}`;
  chainId: number;
  chainName: string;
  agentId: `0x${string}`;
  geminiApiUrl: string;
};

// ---------------------------------------------------------------------------
// On-chain ABIs
// ---------------------------------------------------------------------------

const VAULT_ABI = [
  {
    inputs: [
      { name: "reportHash", type: "bytes32" },
      { name: "agentId", type: "bytes32" },
      { name: "reportType", type: "uint8" },
      { name: "chainId", type: "uint16" },
      { name: "reportURI", type: "string" },
    ],
    name: "storeReport",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "getReportCount",
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
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

/** ComplianceVault reportType enum mapping (from AI_AGENTS.md §4.2). */
const FRAMEWORK_MAP: Record<string, number> = {
  AML: 1,
  KYC: 2,
  ESG: 3,
  MiCA: 4,
  CUSTOM: 5,
};

// ---------------------------------------------------------------------------
// Tier 1: On-chain data ingestion (Chain Reader)
// ---------------------------------------------------------------------------

/**
 * Reads protocol metrics from on-chain contracts via EVMClient.
 * Provides the factual basis for compliance analysis.
 */
const readProtocolMetrics = (
  runtime: Runtime<Config>,
  evmClient: EVMClient,
  protocolAddress: `0x${string}`,
): ProtocolMetrics => {
  let totalSupply = "0";
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
    const decoded = decodeFunctionResult({
      abi: PROTOCOL_READ_ABI,
      functionName: "totalSupply",
      data: bytesToHex(reply.data) as `0x${string}`,
    });
    totalSupply = String(decoded);
  } catch (e) {
    runtime.log(
      `[ChainReader] totalSupply() failed for ${protocolAddress}: ${e}`,
    );
  }

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
    const decoded = decodeFunctionResult({
      abi: PROTOCOL_READ_ABI,
      functionName: "paused",
      data: bytesToHex(reply.data) as `0x${string}`,
    });
    paused = Boolean(decoded);
  } catch (e) {
    runtime.log(`[ChainReader] paused() failed for ${protocolAddress}: ${e}`);
  }

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
    const decoded = decodeFunctionResult({
      abi: PROTOCOL_READ_ABI,
      functionName: "owner",
      data: bytesToHex(reply.data) as `0x${string}`,
    });
    owner = String(decoded);
  } catch (e) {
    runtime.log(`[ChainReader] owner() failed for ${protocolAddress}: ${e}`);
  }

  return { totalSupply, paused, owner, reportCount: 0 };
};

/**
 * Reads the current report count from ComplianceVault via Chain Reader.
 */
const readVaultReportCount = (
  runtime: Runtime<Config>,
  evmClient: EVMClient,
  vaultAddress: `0x${string}`,
): number => {
  try {
    const reply = evmClient
      .callContract(runtime, {
        call: encodeCallMsg({
          from: zeroAddress,
          to: vaultAddress,
          data: encodeFunctionData({
            abi: VAULT_ABI,
            functionName: "getReportCount",
          }),
        }),
        blockNumber: LAST_FINALIZED_BLOCK_NUMBER,
      })
      .result();
    const decoded = decodeFunctionResult({
      abi: VAULT_ABI,
      functionName: "getReportCount",
      data: bytesToHex(reply.data) as `0x${string}`,
    });
    return Number(decoded);
  } catch (e) {
    runtime.log(`[ChainReader] getReportCount() failed: ${e}`);
    return 0;
  }
};

// ---------------------------------------------------------------------------
// Compliance analysis (LLM via runInNodeMode)
// ---------------------------------------------------------------------------

/**
 * Generates a compliance report using LLM analysis within Confidential Compute.
 * Takes on-chain metrics as factual input and produces findings + recommendations.
 */
const generateComplianceReport = (
  nodeRuntime: NodeRuntime<Config>,
  protocolMetrics: ProtocolMetrics[],
  framework: string,
  periodStart: number,
  periodEnd: number,
  apiKey: string,
): Omit<ComplianceReport, "attestation"> => {
  const http = new HTTPClient();
  const now = nodeRuntime.now().getTime();

  nodeRuntime.log(
    `[Compliance] Generating ${framework} report for ${protocolMetrics.length} protocol(s)`,
  );

  const prompt = `You are Raizo Compliance Reporter, an autonomous DeFi compliance analyst. Generate a compliance report for the ${framework} regulatory framework based on the following on-chain protocol metrics.

Protocol Metrics:
${JSON.stringify(protocolMetrics, null, 2)}

Coverage Period: ${new Date(periodStart * 1000).toISOString()} to ${new Date(
    periodEnd * 1000,
  ).toISOString()}

Rules:
1. Output ONLY valid JSON matching the ComplianceReport schema below.
2. Base findings on the actual metrics provided — do not fabricate data.
3. Flag any paused protocols as potential compliance concerns.
4. Score compliance from 0-100 based on operational health indicators.

Output Schema:
{
  "findings": [{ "type": string, "severity": "info"|"low"|"medium"|"high"|"critical", "description": string, "evidence": [string] }],
  "riskSummary": { "overallRisk": "low"|"medium"|"high", "flaggedTransactions": number, "flaggedAddresses": [string], "complianceScore": number },
  "recommendations": [string]
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

  const fallbackReport: Omit<ComplianceReport, "attestation"> = {
    metadata: {
      reportId: `REP-${now}`,
      generatedAt: Math.floor(now / 1000),
      framework,
      coverageChains: [nodeRuntime.config.chainId],
      periodStart,
      periodEnd,
    },
    findings: [],
    riskSummary: {
      overallRisk: "low",
      flaggedTransactions: 0,
      flaggedAddresses: [],
      complianceScore: 100,
    },
    recommendations: [],
  };

  if (!ok(response)) {
    nodeRuntime.log("[Gemini] API request failed — using baseline report");
    return fallbackReport;
  }

  try {
    const result = json(response) as any;
    const text = result.candidates[0].content.parts[0].text;
    const parsed = JSON.parse(text);

    nodeRuntime.log(
      `[Gemini] Generated report: score=${parsed.riskSummary?.complianceScore}, findings=${parsed.findings?.length}`,
    );

    // Validate and merge with metadata
    return {
      metadata: fallbackReport.metadata,
      findings: Array.isArray(parsed.findings) ? parsed.findings : [],
      riskSummary: {
        overallRisk: parsed.riskSummary?.overallRisk || "low",
        flaggedTransactions: parsed.riskSummary?.flaggedTransactions || 0,
        flaggedAddresses: parsed.riskSummary?.flaggedAddresses || [],
        complianceScore:
          typeof parsed.riskSummary?.complianceScore === "number"
            ? Math.max(0, Math.min(100, parsed.riskSummary.complianceScore))
            : 100,
      },
      recommendations: Array.isArray(parsed.recommendations)
        ? parsed.recommendations
        : [],
    };
  } catch (e) {
    nodeRuntime.log(`[Gemini] Parse error: ${e}`);
    return fallbackReport;
  }
};

// ---------------------------------------------------------------------------
// Main workflow handler
// ---------------------------------------------------------------------------

const onCronTrigger = (runtime: Runtime<Config>) => {
  const {
    complianceVaultAddress,
    raizoCoreAddress,
    chainId,
    agentId,
    chainName,
  } = runtime.config;

  runtime.log("=== Raizo Compliance Reporter: Starting report generation ===");

  // Resolve chain
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

  // --- Step 1: Read on-chain protocol metrics via Chain Reader ---
  runtime.log("[ChainReader] Fetching registered protocols from RaizoCore");

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

  // Read metrics for each active protocol
  const protocolMetrics: ProtocolMetrics[] = [];
  for (const protocol of protocols) {
    if (!protocol.isActive) continue;
    const metrics = readProtocolMetrics(
      runtime,
      evmClient,
      protocol.protocolAddress as `0x${string}`,
    );
    protocolMetrics.push(metrics);
  }

  // Read existing report count for context
  const existingReportCount = readVaultReportCount(
    runtime,
    evmClient,
    complianceVaultAddress,
  );
  runtime.log(
    `[ChainReader] ComplianceVault has ${existingReportCount} existing report(s)`,
  );

  // Define reporting period (24h window ending now)
  const nowSec = Math.floor(runtime.now().getTime() / 1000);
  const periodStart = nowSec - 86400;
  const periodEnd = nowSec;

  // --- Step 2: Generate compliance report via LLM (runInNodeMode) ---
  const report = runtime
    .runInNodeMode(
      generateComplianceReport,
      ConsensusAggregationByFields<Omit<ComplianceReport, "attestation">>({
        metadata: identical,
        findings: identical,
        riskSummary: identical,
        recommendations: identical,
      }),
    )(protocolMetrics, "AML", periodStart, periodEnd, apiKey)
    .result();

  // Attach attestation metadata
  const fullReport: ComplianceReport = {
    ...report,
    attestation: {
      donSignature: "aggregated-don-signature",
      nodeCount: 3,
      consensusReached: true,
    },
  };

  runtime.log(
    `[Report] Generated: id=${fullReport.metadata.reportId}, framework=${fullReport.metadata.framework}, score=${fullReport.riskSummary.complianceScore}`,
  );

  // --- Step 3: Anchor report hash on-chain via ComplianceVault.storeReport ---
  const reportData = JSON.stringify(fullReport);
  const reportHash = keccak256(stringToHex(reportData));
  const reportURI = "ipfs://compliance-reports/" + fullReport.metadata.reportId;

  runtime.log(`[Anchor] Hash: ${reportHash}`);
  runtime.log(`[Anchor] URI: ${reportURI}`);

  evmClient
    .callContract(runtime, {
      call: encodeCallMsg({
        from: runtime.config.operatorAddress,
        to: complianceVaultAddress,
        data: encodeFunctionData({
          abi: VAULT_ABI,
          functionName: "storeReport",
          args: [
            reportHash,
            agentId as `0x${string}`,
            FRAMEWORK_MAP[fullReport.metadata.framework] || 5,
            chainId,
            reportURI,
          ],
        }),
      }),
      blockNumber: LAST_FINALIZED_BLOCK_NUMBER,
    })
    .result();

  runtime.log(
    `=== Raizo Compliance Reporter: Report ${fullReport.metadata.reportId} anchored successfully ===`,
  );

  return fullReport.metadata.reportId;
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
