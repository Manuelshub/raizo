import {
  CronCapability,
  EVMClient,
  handler,
  Runner,
  type Runtime,
  type NodeRuntime,
  ConsensusAggregationByFields,
  identical,
  bytesToHex,
} from "@chainlink/cre-sdk";
import { keccak256, encodeFunctionData, stringToHex } from "viem";

// --- Interfaces ---

interface ComplianceReport {
  reportId: string;
  generatedAt: number;
  framework: string;
  overallRisk: "low" | "medium" | "high";
  complianceScore: number;
}

// --- Configuration ---

type Config = {
  schedule: string;
  complianceVaultAddress: `0x${string}`;
  rpcUrl: string;
  chainId: number;
  agentId: `0x${string}`;
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

// --- Workflow Logic ---

const generateReport = (nodeRuntime: NodeRuntime<Config>): ComplianceReport => {
  const now = nodeRuntime.now().getTime();

  return {
    reportId: `REP-${now}`,
    generatedAt: Math.floor(now / 1000),
    framework: "AML",
    overallRisk: "low",
    complianceScore: 100,
  };
};

const onCronTrigger = (runtime: Runtime<Config>) => {
  const { complianceVaultAddress, chainId, agentId } = runtime.config;
  const evm = new EVMClient(SEPOLIA_SELECTOR);

  const report = runtime
    .runInNodeMode(
      generateReport,
      ConsensusAggregationByFields<ComplianceReport>({
        reportId: identical,
        generatedAt: identical,
        framework: identical,
        overallRisk: identical,
        complianceScore: identical,
      }),
    )()
    .result();

  const reportHash = keccak256(stringToHex("REPORT_DATA_" + report.reportId));
  const reportURI = "ipfs://compliance-reports/" + report.reportId;

  runtime.log(`Anchoring report hash: ${reportHash}`);

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

  runtime.log(`Report anchored.`);

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
