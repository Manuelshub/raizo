import {
  RegulatoryRule,
  ComplianceReportFinding,
  ComplianceReport,
  ComplianceReportAttestation,
} from "./types";

export * from "./types";

export function evaluateRule(
  rule: RegulatoryRule,
  metrics: Record<string, any>,
  sanctionsList: string[],
): boolean {
  const value = metrics[rule.condition.metric];
  const threshold = rule.condition.threshold;

  switch (rule.condition.operator) {
    case "gt":
      return value > threshold;
    case "lt":
      return value < threshold;
    case "eq":
      return value === threshold;
    case "in":
      return (threshold as any[]).includes(value);
    case "matches":
      return sanctionsList.includes(value);
    default:
      return false;
  }
}

/** Maps rule frameworks to on-chain reportType enum values used by ComplianceVault */
export const FRAMEWORK_REPORT_TYPE: Record<string, number> = {
  AML: 1,
  KYC: 2,
  ESG: 3,
  MiCA: 4,
  SEC: 5,
};

/**
 * Derives the dominant framework from the fired rules' ruleIds.
 * Falls back to "AML" if no framework prefix is detectable.
 */
export function deriveFramework(findings: ComplianceReportFinding[], rules: RegulatoryRule[]): string {
  if (findings.length === 0) return "MiCA/AML";

  // Build a map of ruleId → framework from the full ruleset
  const ruleFrameworkMap = new Map<string, string>();
  for (const rule of rules) {
    ruleFrameworkMap.set(rule.ruleId, rule.framework);
  }

  // Count frameworks among fired findings
  const frameworkCounts = new Map<string, number>();
  for (const f of findings) {
    const fw = ruleFrameworkMap.get(f.ruleId) ?? "AML";
    frameworkCounts.set(fw, (frameworkCounts.get(fw) ?? 0) + 1);
  }

  // Return dominant framework, or combined string if multiple
  const sorted = [...frameworkCounts.entries()].sort((a, b) => b[1] - a[1]);
  if (sorted.length === 1) return sorted[0][0];
  return sorted.map(([fw]) => fw).join("/");
}

export function generateComplianceReport(
  chainId: number,
  findings: ComplianceReportFinding[],
  attestation?: ComplianceReportAttestation,
  rules?: RegulatoryRule[],
): ComplianceReport {
  const violationCount = findings.filter(
    (f) => f.severity === "violation",
  ).length;
  const warningCount = findings.filter((f) => f.severity === "warning").length;

  const score = Math.max(0, 100 - violationCount * 20 - warningCount * 5);

  // Derive framework from the rules that actually fired
  const framework = rules ? deriveFramework(findings, rules) : "MiCA/AML";

  const now = Math.floor(Date.now() / 1000);
  const reportIdInput = `compliance-${chainId}-${now}`;
  
  // Generate proper bytes32 hash using keccak256-like hashing
  // For deterministic ID generation, we create a padded hex string
  let reportId = "0x";
  const hexStr = Buffer.from(reportIdInput, "utf-8").toString("hex");
  // Pad or truncate to exactly 64 hex chars (32 bytes)
  reportId += hexStr.padEnd(64, "0").slice(0, 64);

  const report: ComplianceReport = {
    metadata: {
      reportId,
      generatedAt: now,
      framework,
      coverageChains: [chainId],
      periodStart: now - 86400,
      periodEnd: now,
    },
    findings,
    riskSummary: {
      overallRisk: score > 80 ? "low" : score > 50 ? "medium" : "high",
      flaggedTransactions: violationCount,
      flaggedAddresses: [],
      complianceScore: score,
    },
    recommendations:
      score < 100
        ? ["Review flagged transactions", "Update risk parameters"]
        : [],
  };

  if (attestation) {
    report.attestation = attestation;
  }

  return report;
}

export function runCompliancePipeline(
  chainId: number,
  rules: RegulatoryRule[],
  metrics: Record<string, any>,
  sanctionsList: string[],
): ComplianceReport {
  const findings: ComplianceReportFinding[] = [];
  const now = Math.floor(Date.now() / 1000);

  for (const rule of rules) {
    if (evaluateRule(rule, metrics, sanctionsList)) {
      findings.push({
        ruleId: rule.ruleId,
        severity: rule.action.severity,
        narrative: rule.action.narrative,
        detectedAt: now,
        evidence: metrics[rule.condition.metric],
      });
    }
  }

  return generateComplianceReport(chainId, findings, undefined, rules);
}
