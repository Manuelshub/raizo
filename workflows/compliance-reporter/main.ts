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
  encodeAbiParameters,
  parseAbiParameters,
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
}

interface ProtocolMetrics {
  totalSupply: string;
  paused: boolean;
  owner: string;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type Config = {
  schedule: string;
  complianceVaultAddress: `0x${string}`;
  consumerAddress: `0x${string}`;
  raizoCoreAddress: `0x${string}`;
  operatorAddress: `0x${string}`;
  chainId: number;
  chainName: string;
  isTestnet: boolean;
  agentId: `0x${string}`;
  geminiApiUrl: string;
  gasLimit: string;
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

const VAULT_ABI = [
  {
    inputs: [],
    name: "getReportCount",
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
    type: "function",
  },
] as const;

/** ComplianceVault reportType enum (AI_AGENTS.md §4.2). */
const FRAMEWORK_MAP: Record<string, number> = {
  AML: 1,
  KYC: 2,
  ESG: 3,
  MiCA: 4,
  CUSTOM: 5,
};

// ---------------------------------------------------------------------------
// On-chain reads (Chain Reader)
// ---------------------------------------------------------------------------

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
    totalSupply = String(
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

  return { totalSupply, paused, owner };
};

// ---------------------------------------------------------------------------
// Compliance analysis (LLM via runInNodeMode)
// ---------------------------------------------------------------------------

const generateComplianceReport = (
  nodeRuntime: NodeRuntime<Config>,
  protocolMetrics: ProtocolMetrics[],
  framework: string,
  periodStart: number,
  periodEnd: number,
  apiKey: string,
): ComplianceReport => {
  const http = new HTTPClient();
  const now = nodeRuntime.now().getTime();

  const fallbackReport: ComplianceReport = {
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

  const prompt = `You are Raizo Compliance Reporter, an autonomous DeFi compliance analyst. Generate a compliance report for the ${framework} framework.

Protocol Metrics:
${JSON.stringify(protocolMetrics, null, 2)}

Coverage Period: ${new Date(periodStart * 1000).toISOString()} to ${new Date(
    periodEnd * 1000,
  ).toISOString()}

Rules:
1. Output ONLY valid JSON matching the schema below.
2. Base findings on actual metrics — do not fabricate data.
3. Flag paused protocols as potential compliance concerns.
4. Score compliance 0-100 based on operational health.

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

  nodeRuntime.log(`[Gemini] Generating ${framework} compliance report`);

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
      `[Gemini] API failed (${response.statusCode}) — using fallback`,
    );
    return fallbackReport;
  }

  try {
    const result = json(response) as any;
    if (!result.candidates?.[0]?.content?.parts?.[0]?.text) {
      nodeRuntime.log("[Gemini] Invalid response structure — using fallback");
      return fallbackReport;
    }

    const parsed = JSON.parse(result.candidates[0].content.parts[0].text);

    nodeRuntime.log(
      `[Gemini] Result: score=${
        parsed.riskSummary?.complianceScore
      }, findings=${parsed.findings?.length || 0}`,
    );

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
    consumerAddress,
    raizoCoreAddress,
    chainId,
    agentId,
    chainName,
    isTestnet,
    gasLimit,
  } = runtime.config;

  runtime.log("=== Raizo Compliance Reporter: Starting report generation ===");

  const network = getNetwork({
    chainFamily: "evm",
    chainSelectorName: chainName,
    isTestnet,
  });
  if (!network) {
    throw new Error(`Unknown chain name: ${chainName}`);
  }

  const evmClient = new EVMClient(network.chainSelector.selector);

  // Load API key
  let apiKey: string;
  try {
    apiKey = runtime.getSecret({ id: "API_KEY" }).result().value;
    runtime.log("[Secrets] API_KEY loaded");
  } catch (_) {
    runtime.log("[Secrets] API_KEY not found — using simulation fallback");
    apiKey = "SIMULATION_FALLBACK_KEY";
  }

  // --- Step 1: Read protocol metrics ---
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

  const protocolMetrics: ProtocolMetrics[] = [];
  for (const protocol of protocols) {
    if (!protocol.isActive) continue;
    protocolMetrics.push(
      readProtocolMetrics(
        runtime,
        evmClient,
        protocol.protocolAddress as `0x${string}`,
      ),
    );
  }

  // Reporting period: 24h window
  const nowSec = Math.floor(runtime.now().getTime() / 1000);
  const periodStart = nowSec - 86400;

  // --- Step 2: Generate compliance report via LLM ---
  const report = runtime
    .runInNodeMode(
      generateComplianceReport,
      ConsensusAggregationByFields<ComplianceReport>({
        metadata: identical,
        findings: identical,
        riskSummary: identical,
        recommendations: identical,
      }),
    )(protocolMetrics, "AML", periodStart, nowSec, apiKey)
    .result();

  runtime.log(
    `[Report] Generated: id=${report.metadata.reportId}, score=${report.riskSummary.complianceScore}`,
  );

  // --- Step 3: Anchor report hash on-chain via RaizoConsumer → ComplianceVault ---
  const reportData = JSON.stringify(report);
  const reportHash = keccak256(stringToHex(reportData));
  const reportURI = "ipfs://compliance-reports/" + report.metadata.reportId;

  // Encode ComplianceVault.storeReport params
  const complianceData = encodeAbiParameters(
    parseAbiParameters(
      "bytes32 reportHash, bytes32 agentId, uint8 reportType, uint32 chainId, string reportURI",
    ),
    [
      reportHash,
      agentId as `0x${string}`,
      FRAMEWORK_MAP[report.metadata.framework] || 5,
      chainId,
      reportURI,
    ],
  );

  // Wrap with report type tag: (uint8 reportType=1, bytes data)
  const consumerPayload = encodeAbiParameters(
    parseAbiParameters("uint8 reportType, bytes data"),
    [1, complianceData],
  );

  runtime.log(`[Anchor] Hash: ${reportHash}, URI: ${reportURI}`);

  // Generate signed report and write via consumer
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
  runtime.log(`[Anchor] TX submitted: ${txHash}`);

  runtime.log(
    `=== Raizo Compliance Reporter: Report ${report.metadata.reportId} complete ===`,
  );
  return report.metadata.reportId;
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
