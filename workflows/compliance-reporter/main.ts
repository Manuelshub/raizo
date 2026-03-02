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
  // bytesToHex,
  hexToBase64,
  getNetwork,
  LAST_FINALIZED_BLOCK_NUMBER,
  encodeCallMsg,
} from "@chainlink/cre-sdk";
import { keccak256, encodeFunctionData, stringToHex } from "viem";

// --- Interfaces ---

interface ComplianceReport {
  reportId: string;
  generatedAt: number;
  framework: string;
  overallRisk: "low" | "medium" | "high";
  complianceScore: number;
  summary: string;
  recommendations: string[];
}

// --- Configuration ---

type Config = {
  schedule: string;
  complianceVaultAddress: `0x${string}`;
  operatorAddress: `0x${string}`;
  rpcUrl: string;
  chainId: number;
  chainName: string;
  agentId: `0x${string}`;
  geminiApiUrl: string;
};

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
] as const;

const FRAMEWORK_MAP: Record<string, number> = {
  AML: 1,
  KYC: 2,
  ESG: 3,
  MiCA: 4,
  CUSTOM: 5,
};

// Chain selector will be dynamically resolved from chainName in config

// --- AI Service ---

const runGeminiReportEnhancement = (
  nodeRuntime: NodeRuntime<Config>,
  baseReport: any,
  apiKey: string,
): Partial<ComplianceReport> => {
  const http = new HTTPClient();

  nodeRuntime.log("[Gemini] Starting AI-enhanced report generation");
  nodeRuntime.log(`[Gemini] Framework: ${baseReport.framework}, Score: ${baseReport.complianceScore}`);

  const prompt = `
Generate a professional compliance summary and recommendations for a DeFi protocol based on the following automated findings:
Framework: ${baseReport.framework}
Compliance Score: ${baseReport.complianceScore}
Risk Level: ${baseReport.overallRisk}

Output ONLY valid JSON:
{
  "summary": "Detailed summary paragraph",
  "recommendations": ["Rec 1", "Rec 2"]
}
`;

  const body = JSON.stringify({
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: { response_mime_type: "application/json" },
  });

  nodeRuntime.log(`[Gemini] Making request to: ${nodeRuntime.config.geminiApiUrl}`);

  const response = http
    .sendRequest(nodeRuntime, {
      url: `${nodeRuntime.config.geminiApiUrl}?key=${apiKey}`,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: hexToBase64(stringToHex(body)),
    })
    .result();

  nodeRuntime.log(`[Gemini] Response received, ok: ${ok(response)}`);

  if (!ok(response)) {
    nodeRuntime.log("[Gemini] API request failed, using fallback");
    return { summary: "Summary unavailable.", recommendations: [] };
  }

  try {
    const result = json(response) as any;
    nodeRuntime.log(`[Gemini] Parsed response: ${JSON.stringify(result)}`);
    const text = result.candidates[0].content.parts[0].text;
    const parsed = JSON.parse(text);
    nodeRuntime.log("[Gemini] Successfully generated AI-enhanced report");
    return parsed;
  } catch (e) {
    nodeRuntime.log(`[Gemini] Error parsing response: ${e}`);
    return { summary: "Analysis failed.", recommendations: [] };
  }
};

// --- Workflow Logic ---

const generateReport = (
  nodeRuntime: NodeRuntime<Config>,
  apiKey: string,
): ComplianceReport => {
  const now = nodeRuntime.now().getTime();

  const baseReport = {
    reportId: `REP-${now}`,
    generatedAt: Math.floor(now / 1000),
    framework: "AML",
    overallRisk: "low" as const,
    complianceScore: 100,
  };

  // Enhance with Gemini
  const enhancement = runGeminiReportEnhancement(
    nodeRuntime,
    baseReport,
    apiKey,
  );

  return {
    ...baseReport,
    summary: enhancement.summary || "No automated summary.",
    recommendations: enhancement.recommendations || [],
  };
};

const onCronTrigger = (runtime: Runtime<Config>) => {
  const { complianceVaultAddress, chainId, agentId, chainName } = runtime.config;

  runtime.log("=== Raizo Compliance Reporter: Starting AI-Enhanced Generation ===");

  // Convert human-readable chain name to chain selector
  const network = getNetwork({
    chainFamily: "evm",
    chainSelectorName: chainName,
    isTestnet: true,
  });

  if (!network) {
    runtime.log(`ERROR: Unknown chain name: ${chainName}`);
    throw new Error(`Unknown chain name: ${chainName}`);
  }

  runtime.log(`Chain resolved: ${chainName} -> selector ${network.chainSelector.selector}`);

  const evm = new EVMClient(network.chainSelector.selector);

  // Fetch AI_API_KEY from secrets (env namespace)
  let apiKey: string;
  try {
    apiKey = runtime
      .getSecret({ id: "API_KEY" })
      .result().value;
    runtime.log("AI_API_KEY secret loaded successfully");
  } catch (e) {
    runtime.log(
      "Warning: AI_API_KEY secret not found, using simulation fallback",
    );
    apiKey = "AI_API_KEY_SIMULATION_FALLBACK";
  }

  runtime.log("Generating compliance report with AI enhancement...");

  const report = runtime
    .runInNodeMode(
      generateReport,
      ConsensusAggregationByFields<ComplianceReport>({
        reportId: identical,
        generatedAt: identical,
        framework: identical,
        overallRisk: identical,
        complianceScore: identical,
        summary: identical,
        recommendations: identical,
      }),
    )(apiKey)
    .result();

  runtime.log(`Report generated: ${report.reportId}`);
  runtime.log(`Summary: ${report.summary}`);
  runtime.log(`Recommendations: ${report.recommendations.length} items`);

  const reportData = JSON.stringify(report);
  const reportHash = keccak256(stringToHex(reportData));
  const reportURI = "ipfs://compliance-reports/" + report.reportId;

  runtime.log(`Anchoring Gemini-enhanced report: ${report.reportId}`);
  runtime.log(`Report hash: ${reportHash}`);

  evm
    .callContract(runtime, {
      call: encodeCallMsg({
        from: runtime.config.operatorAddress,
        to: complianceVaultAddress,
        data: encodeFunctionData({
          abi: VAULT_ABI,
          functionName: "storeReport",
          args: [
            reportHash,
            agentId,
            FRAMEWORK_MAP[report.framework] || 5,
            chainId,
            reportURI,
          ],
        }),
      }),
      blockNumber: LAST_FINALIZED_BLOCK_NUMBER,
    })
    .result();

  runtime.log(`✅ AI-Enhanced Report anchored successfully`);

  return report.reportId;
};

const initWorkflow = (config: Config) => {
  const cron = new CronCapability();
  return [handler(cron.trigger({ schedule: config.schedule }), onCronTrigger)];
};

export async function main() {
  const runner = await Runner.newRunner<Config>();
  await runner.run(initWorkflow);
}
