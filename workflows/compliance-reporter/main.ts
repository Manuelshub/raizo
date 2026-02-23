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
  bytesToHex,
  hexToBase64,
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
  rpcUrl: string;
  chainId: number;
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

const SEPOLIA_SELECTOR = 16015286601757825753n;

// --- AI Service ---

const runGeminiReportEnhancement = (
  nodeRuntime: NodeRuntime<Config>,
  baseReport: any,
  apiKey: string,
): Partial<ComplianceReport> => {
  const http = new HTTPClient();

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

  const response = http
    .sendRequest(nodeRuntime, {
      url: `${nodeRuntime.config.geminiApiUrl}?key=${apiKey}`,
      method: "POST",
      body: hexToBase64(stringToHex(body)),
    })
    .result();

  if (!ok(response)) {
    return { summary: "Summary unavailable.", recommendations: [] };
  }

  try {
    const result = json(response) as any;
    const text = result.candidates[0].content.parts[0].text;
    return JSON.parse(text);
  } catch (e) {
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
  const { complianceVaultAddress, chainId, agentId } = runtime.config;
  const evm = new EVMClient(SEPOLIA_SELECTOR);

  runtime.log("Raizo Compliance Reporter: Starting AI-Enhanced Generation");

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
    apiKey = "AI_API_KEY_SIMULATION_FALLBACK";
  }

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

  const reportData = JSON.stringify(report);
  const reportHash = keccak256(stringToHex(reportData));
  const reportURI = "ipfs://compliance-reports/" + report.reportId;

  runtime.log(`Anchoring Gemini-enhanced report: ${report.reportId}`);

  evm
    .callContract(runtime, {
      call: {
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
      },
    })
    .result();

  runtime.log(`AI-Enhanced Report anchored.`);

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
