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
  CronCapability,
  HTTPClient,
  EVMClient,
  handler,
  type Runtime,
  type NodeRuntime,
  type CronPayload,
} from "@chainlink/cre-sdk";
import { z } from "zod";

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
  _payload: CronPayload,
): string => {
  const config = runtime.config;
  runtime.log("Compliance check triggered");

  const httpClient = new HTTPClient();

  // 1. Fetch rules
  const rulesResponse = httpClient
    .fetch(runtime, { url: config.rulesApiUrl, method: "GET" })
    .result();
  const rules: RegulatoryRule[] = JSON.parse(rulesResponse.body);

  // 2. Fetch metrics
  const metricsResponse = httpClient
    .fetch(runtime, { url: config.metricsApiUrl, method: "GET" })
    .result();
  const metrics: Record<string, any> = JSON.parse(metricsResponse.body);

  // 3. Fetch sanctions list via runInNodeMode
  const fetchSanctions = (
    nodeRuntime: NodeRuntime<ComplianceConfig>,
  ): string => {
    const nodeHttp = new HTTPClient();
    const response = nodeHttp
      .fetch(nodeRuntime, { url: config.sanctionsApiUrl, method: "GET" })
      .result();
    return response.body;
  };

  const sanctionsRaw = runtime
    .runInNodeMode(fetchSanctions, {
      aggregate: (results: string[]) => {
        const allLists: string[][] = results.map((r) => JSON.parse(r));
        if (allLists.length === 0) return "[]";
        const intersection = allLists[0].filter((addr) =>
          allLists.every((list) => list.includes(addr)),
        );
        return JSON.stringify(intersection);
      },
    })()
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

  // 5. Anchor report on-chain
  if (report.findings.length > 0) {
    const evmClient = new EVMClient(config.chainSelector);
    evmClient
      .writeReport(runtime, {
        report: runtime.report(report).result(),
      })
      .result();

    runtime.log(`Report anchored on-chain: ${report.metadata.reportId}`);
  }

  return report.riskSummary.complianceScore === 100 ? "compliant" : "flagged";
};

/**
 * CRE workflow initializer.
 */
export const complianceInitWorkflow = (config: ComplianceConfig) => {
  const cron = new CronCapability();
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
