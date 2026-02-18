import {
  RegulatoryRule,
  ComplianceReportFinding,
  ComplianceReport,
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

export function generateComplianceReport(
  chainId: number,
  findings: ComplianceReportFinding[],
): ComplianceReport {
  const violationCount = findings.filter(
    (f) => f.severity === "violation",
  ).length;
  const warningCount = findings.filter((f) => f.severity === "warning").length;

  const score = Math.max(0, 100 - violationCount * 20 - warningCount * 5);

  const now = Math.floor(Date.now() / 1000);
  const reportIdInput = `compliance-${chainId}-${now}`;
  let reportId = "0x";
  for (let i = 0; i < reportIdInput.length; i++) {
    reportId += reportIdInput.charCodeAt(i).toString(16).padStart(2, "0");
  }

  return {
    metadata: {
      reportId,
      generatedAt: now,
      framework: "MiCA/AML",
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

  return generateComplianceReport(chainId, findings);
}
