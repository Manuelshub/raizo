/**
 * @title  Compliance Reporter — CRE Workflow
 * @notice Automated Compliance Engine (ACE): evaluates regulatory rules against
 *         protocol metrics, generates compliance reports, and anchors them
 *         on-chain via signed CRE reports.
 *
 * Architecture follows @chainlink/cre-sdk pattern:
 *   main() → Runner.newRunner() → initWorkflow() → handler(trigger, callback)
 */

import {
  Runner,
  handler,
  type Runtime,
  type NodeRuntime,
  type HTTPSendRequester,
  consensusMedianAggregation,
  consensusIdenticalAggregation,
  prepareReportRequest,
  ok,
  text,
} from "@chainlink/cre-sdk";
import { cre } from "@chainlink/cre-sdk";
import { z } from "zod";

// ABI encoding
import { encodeFunctionData } from "viem";
import { complianceVaultAbi } from "./abis";

// Import logic and types
import { RegulatoryRule, ComplianceReport } from "./logic/types";
import { runCompliancePipeline } from "./logic/compliance-logic";

// Re-export for convenience
export * from "./logic/types";
export * from "./logic/compliance-logic";

// ═══════════════════════════════════════════════════════════════════════════
// CRE Workflow Entry Points
// ═══════════════════════════════════════════════════════════════════════════

export const complianceConfigSchema = z.object({
  schedule: z.string().describe("Cron schedule for periodic compliance checks"),
  chainSelector: z.string().describe("EVM chain selector"),
  chainId: z.number().describe("Numeric chain ID for report metadata"),
  agentId: z.string().describe("CRE agent identifier (bytes32 hex)"),
  metricsApiUrl: z.string().describe("Endpoint serving protocol metrics JSON"),
  sanctionsApiUrl: z.string().describe("Endpoint serving sanctions list"),
  rulesApiUrl: z.string().describe("Endpoint serving RegulatoryRule[] JSON"),
  complianceVaultAddress: z
    .string()
    .describe("ComplianceVault contract address"),
});

export type ComplianceConfig = z.infer<typeof complianceConfigSchema>;

/**
 * CRE callback: fired on every cron tick.
 */
export const onComplianceTrigger = (
  runtime: Runtime<ComplianceConfig>,
  _payload: any,
): string => {
  const config = runtime.config;
  runtime.log("Compliance check triggered");

  try {
    const httpCapability = new cre.capabilities.HTTPClient();

    // 1. Fetch rules
    const fetchRules = (sendRequester: HTTPSendRequester, cfg: ComplianceConfig) => {
      const response = sendRequester.sendRequest({
        url: cfg.rulesApiUrl,
        method: "GET",
      }).result();

      if (!ok(response)) {
        throw new Error(`Rules fetch failed: ${response.statusCode}`);
      }

      return text(response);
    };

    const rulesBody = httpCapability
      .sendRequest(runtime, fetchRules, consensusIdenticalAggregation())(config)
      .result();
    const rules: RegulatoryRule[] = JSON.parse(rulesBody);

    // 2. Fetch metrics
    const fetchMetrics = (sendRequester: HTTPSendRequester, cfg: ComplianceConfig) => {
      const response = sendRequester.sendRequest({
        url: cfg.metricsApiUrl,
        method: "GET",
      }).result();

      if (!ok(response)) {
        throw new Error(`Metrics fetch failed: ${response.statusCode}`);
      }

      return text(response);
    };

    const metricsBody = httpCapability
      .sendRequest(runtime, fetchMetrics, consensusIdenticalAggregation())(config)
      .result();
    const metrics: Record<string, any> = JSON.parse(metricsBody);

    // 3. Fetch sanctions list via runInNodeMode (Confidential Compute)
    // Note: Using consensusIdenticalAggregation - all nodes must return identical lists
    // In production, implement intersection logic if needed for multi-source sanctions
    const fetchSanctions = (nodeRuntime: NodeRuntime<ComplianceConfig>): string => {
      const nodeHttpCapability = new cre.capabilities.HTTPClient();

      const nodeFetch = (sendRequester: HTTPSendRequester) => {
        const response = sendRequester.sendRequest({
          url: config.sanctionsApiUrl,
          method: "GET",
        }).result();

        if (!ok(response)) {
          throw new Error(`Sanctions fetch failed: ${response.statusCode}`);
        }

        return text(response);
      };

      // Return sanctions list directly from this node
      return nodeFetch(nodeRuntime as any);
    };

    const sanctionsRaw = runtime
      .runInNodeMode(fetchSanctions, consensusIdenticalAggregation())()
      .result();

    const sanctionsList: string[] = JSON.parse(sanctionsRaw);

    // 4. Run compliance pipeline
    const report = runCompliancePipeline(
      config.chainId,
      rules,
      metrics,
      sanctionsList,
    );

    runtime.log(
      `Compliance report generated: score=${report.riskSummary.complianceScore} findings=${report.findings.length}`,
    );

    // 5. Anchor report hash on-chain via ComplianceVault.storeReport()
    if (report.findings.length > 0) {
      const writeData = encodeFunctionData({
        abi: complianceVaultAbi,
        functionName: "storeReport",
        args: [
          report.metadata.reportId as `0x${string}`,
          config.agentId as `0x${string}`,
          1, // reportType: 1 = AML (configurable per framework)
          config.chainId,
          `ipfs://raizo-report-${report.metadata.reportId}`, // URI (TEE-encrypted off-chain)
        ],
      });

      runtime.report(prepareReportRequest(writeData)).result();
      runtime.log(`Report hash anchored on-chain: ${report.metadata.reportId}`);
    }

    return report.riskSummary.complianceScore === 100 ? "compliant" : "flagged";
  } catch (error) {
    runtime.log(`Error in compliance workflow: ${error}`);
    return "error";
  }
};

/**
 * CRE workflow initializer.
 */
export const complianceInitWorkflow = (config: ComplianceConfig) => {
  const cron = new cre.capabilities.CronCapability();
  return [
    handler(cron.trigger({ schedule: config.schedule }), onComplianceTrigger),
  ];
};

/**
 * CRE entry point.
 */
export async function main() {
  const runner = await Runner.newRunner<ComplianceConfig>({
    configSchema: complianceConfigSchema,
  });
  await runner.run(complianceInitWorkflow);
}
