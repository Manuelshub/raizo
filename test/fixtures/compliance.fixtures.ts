/**
 * @file compliance.fixtures.ts
 * @notice Fixture factories for compliance test data
 */

import { ethers } from "hardhat";
import {
  RegulatoryRule,
  ComplianceReportFinding,
  ComplianceReport,
} from "../../workflows/logic/types";

/**
 * Build AML rule: flag large transactions
 */
export function buildAMLLargeTransactionRule(): RegulatoryRule {
  return {
    ruleId: "AML-001",
    framework: "AML",
    version: "1.0",
    effectiveDate: Math.floor(Date.now() / 1000) - 86400 * 30, // 30 days ago
    condition: {
      metric: "largeTransactionCount",
      operator: "gt",
      threshold: 10,
    },
    action: {
      type: "flag",
      severity: "warning",
      narrative:
        "Protocol processed >10 large transactions (>$1M) in reporting period.",
    },
    regulatoryReference: "FinCEN AML Rule §1010.330",
    jurisdiction: ["US", "EU"],
  };
}

/**
 * Build AML rule: sanctioned address detected
 */
export function buildAMLSanctionsRule(): RegulatoryRule {
  return {
    ruleId: "AML-002",
    framework: "AML",
    version: "1.0",
    effectiveDate: Math.floor(Date.now() / 1000) - 86400 * 30,
    condition: {
      metric: "sanctionedAddresses",
      operator: "matches",
      threshold: "SANCTIONS_LIST", // Special key for sanctions list
    },
    action: {
      type: "block",
      severity: "violation",
      narrative:
        "Transactions with OFAC-sanctioned addresses detected. Immediate review required.",
    },
    regulatoryReference: "OFAC Sanctions List (SDN)",
    jurisdiction: ["US"],
  };
}

/**
 * Build MiCA rule: TVL monitoring
 */
export function buildMiCATVLRule(): RegulatoryRule {
  return {
    ruleId: "MICA-001",
    framework: "MiCA",
    version: "2.0",
    effectiveDate: Math.floor(Date.now() / 1000) - 86400 * 60,
    condition: {
      metric: "tvlUSD",
      operator: "gt",
      threshold: 50_000_000, // $50M threshold for enhanced reporting
    },
    action: {
      type: "report",
      severity: "info",
      narrative:
        "Protocol TVL exceeds €50M threshold. Enhanced MiCA reporting required.",
    },
    regulatoryReference: "EU MiCA Regulation Article 47",
    jurisdiction: ["EU"],
  };
}

/**
 * Build SEC rule: unregistered securities
 */
export function buildSECTokenRule(): RegulatoryRule {
  return {
    ruleId: "SEC-001",
    framework: "SEC",
    version: "1.0",
    effectiveDate: Math.floor(Date.now() / 1000) - 86400 * 90,
    condition: {
      metric: "tokenType",
      operator: "in",
      threshold: ["governance", "revenue-share", "buyback"], // Security-like features
    },
    action: {
      type: "alert",
      severity: "warning",
      narrative:
        "Token exhibits security-like characteristics. SEC registration may be required.",
    },
    regulatoryReference: "SEC Howey Test Guidelines",
    jurisdiction: ["US"],
  };
}

/**
 * Build ESG rule: carbon footprint
 */
export function buildESGCarbonRule(): RegulatoryRule {
  return {
    ruleId: "ESG-001",
    framework: "ESG",
    version: "1.0",
    effectiveDate: Math.floor(Date.now() / 1000) - 86400 * 180,
    condition: {
      metric: "estimatedCarbonTonnes",
      operator: "gt",
      threshold: 1000, // >1000 tonnes CO2e per year
    },
    action: {
      type: "report",
      severity: "info",
      narrative:
        "Protocol estimated carbon footprint exceeds 1000t CO2e/year. ESG disclosure recommended.",
    },
    regulatoryReference: "EU Taxonomy Regulation (2020/852)",
    jurisdiction: ["EU"],
  };
}

/**
 * Build all standard rules
 */
export function buildStandardRules(): RegulatoryRule[] {
  return [
    buildAMLLargeTransactionRule(),
    buildAMLSanctionsRule(),
    buildMiCATVLRule(),
    buildSECTokenRule(),
    buildESGCarbonRule(),
  ];
}

/**
 * Build clean metrics (no violations)
 */
export function buildCleanMetrics(): Record<string, any> {
  return {
    largeTransactionCount: 5, // Below AML threshold
    sanctionedAddresses: [], // No sanctioned addresses
    tvlUSD: 25_000_000, // Below MiCA threshold
    tokenType: "utility", // Not a security
    estimatedCarbonTonnes: 500, // Below ESG threshold
    totalTransactions: 10_000,
    uniqueUsers: 5_000,
    dailyVolumeUSD: 2_000_000,
  };
}

/**
 * Build violating metrics (multiple rule triggers)
 */
export function buildViolatingMetrics(): Record<string, any> {
  return {
    largeTransactionCount: 25, // ✗ Violates AML-001
    sanctionedAddresses: [
      "0x1234567890123456789012345678901234567890", // ✗ Violates AML-002
      "0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
    ],
    tvlUSD: 75_000_000, // ✗ Triggers MiCA-001
    tokenType: "governance", // ✗ Triggers SEC-001
    estimatedCarbonTonnes: 2500, // ✗ Violates ESG-001
    totalTransactions: 50_000,
    uniqueUsers: 15_000,
    dailyVolumeUSD: 20_000_000,
  };
}

/**
 * Build sanctions list
 */
export function buildSanctionsList(): string[] {
  return [
    "0x1234567890123456789012345678901234567890", // North Korea
    "0xABCDEF1234567890ABCDEF1234567890ABCDEF12", // Iran
    "0x7890ABCDEF1234567890ABCDEF1234567890ABCD", // Russia
    "0x4567890ABCDEF1234567890ABCDEF1234567890", // Syria
  ];
}

/**
 * Build empty sanctions list (clean state)
 */
export function buildEmptySanctionsList(): string[] {
  return [];
}

/**
 * Build compliance report finding
 */
export function buildComplianceFinding(
  rule: RegulatoryRule,
  evidence: any,
): ComplianceReportFinding {
  return {
    ruleId: rule.ruleId,
    severity: rule.action.severity,
    narrative: rule.action.narrative,
    detectedAt: Math.floor(Date.now() / 1000),
    evidence,
  };
}

/**
 * Build clean compliance report (no findings)
 */
export function buildCleanComplianceReport(chainId: number = 1): ComplianceReport {
  const now = Math.floor(Date.now() / 1000);
  const reportIdInput = `compliance-${chainId}-${now}`;
  const reportId = ethers.id(reportIdInput);

  return {
    metadata: {
      reportId,
      generatedAt: now,
      framework: "MiCA/AML",
      coverageChains: [chainId],
      periodStart: now - 86400, // 24 hours ago
      periodEnd: now,
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
}

/**
 * Build compliance report with violations
 */
export function buildViolatingComplianceReport(
  chainId: number = 1,
): ComplianceReport {
  const now = Math.floor(Date.now() / 1000);
  const reportIdInput = `compliance-${chainId}-${now}`;
  const reportId = ethers.id(reportIdInput);

  const rules = buildStandardRules();
  const findings: ComplianceReportFinding[] = [
    buildComplianceFinding(rules[0], 25), // AML-001
    buildComplianceFinding(
      rules[1],
      "0x1234567890123456789012345678901234567890",
    ), // AML-002
    buildComplianceFinding(rules[2], 75_000_000), // MICA-001
  ];

  // Score calculation: 100 - (violations * 20) - (warnings * 5)
  const violations = findings.filter((f) => f.severity === "violation").length; // 1
  const warnings = findings.filter((f) => f.severity === "warning").length; // 1
  const score = 100 - violations * 20 - warnings * 5; // 75

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
      overallRisk: "medium",
      flaggedTransactions: violations,
      flaggedAddresses: [
        "0x1234567890123456789012345678901234567890",
        "0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
      ],
      complianceScore: score,
    },
    recommendations: [
      "Review flagged transactions",
      "Update risk parameters",
      "Implement sanctions screening",
    ],
  };
}

/**
 * Build high-risk compliance report (many violations)
 */
export function buildHighRiskComplianceReport(
  chainId: number = 1,
): ComplianceReport {
  const now = Math.floor(Date.now() / 1000);
  const reportIdInput = `compliance-${chainId}-${now}`;
  const reportId = ethers.id(reportIdInput);

  const rules = buildStandardRules();
  const findings: ComplianceReportFinding[] = [
    buildComplianceFinding(rules[0], 50), // AML-001
    buildComplianceFinding(
      rules[1],
      "Multiple sanctioned addresses",
    ), // AML-002
    buildComplianceFinding(rules[2], 150_000_000), // MICA-001
    buildComplianceFinding(rules[3], "revenue-share"), // SEC-001
    buildComplianceFinding(rules[4], 5000), // ESG-001
  ];

  const violations = findings.filter((f) => f.severity === "violation").length; // 1
  const warnings = findings.filter((f) => f.severity === "warning").length; // 2
  const score = Math.max(0, 100 - violations * 20 - warnings * 5); // 70

  return {
    metadata: {
      reportId,
      generatedAt: now,
      framework: "MiCA/AML/SEC/ESG",
      coverageChains: [chainId],
      periodStart: now - 86400 * 7, // 7 days
      periodEnd: now,
    },
    findings,
    riskSummary: {
      overallRisk: "high",
      flaggedTransactions: violations,
      flaggedAddresses: [
        "0x1234567890123456789012345678901234567890",
        "0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
        "0x7890ABCDEF1234567890ABCDEF1234567890ABCD",
      ],
      complianceScore: score,
    },
    recommendations: [
      "Immediate review of sanctioned addresses required",
      "Enhanced MiCA reporting mandatory",
      "Assess SEC registration requirements",
      "Implement carbon offset program",
      "Update compliance procedures",
    ],
  };
}

/**
 * Build ComplianceRecord for on-chain storage
 */
export interface ComplianceRecordFixture {
  reportHash: string;
  agentId: string;
  reportType: number; // 1=AML, 2=KYC, 3=ESG, 4=MiCA, 5=Custom
  chainId: number;
  reportURI: string;
}

export function buildComplianceRecord(
  report: ComplianceReport,
  agentId: string = ethers.id("raizo.compliance.v1"),
): ComplianceRecordFixture {
  // Hash the full report JSON
  const reportJSON = JSON.stringify(report);
  const reportHash = ethers.id(reportJSON);

  // Map framework to reportType enum
  const frameworkMap: Record<string, number> = {
    AML: 1,
    KYC: 2,
    ESG: 3,
    MiCA: 4,
    "MiCA/AML": 4, // Hybrid reports use primary framework
    "MiCA/AML/SEC/ESG": 5, // Custom multi-framework
  };

  const reportType = frameworkMap[report.metadata.framework] || 5;

  // Generate encrypted URI (simulated IPFS/Arweave + encryption)
  const reportURI = `ipfs://Qm${ethers.keccak256(ethers.toUtf8Bytes(reportJSON)).slice(2, 48)}`;

  return {
    reportHash,
    agentId,
    reportType,
    chainId: report.metadata.coverageChains[0],
    reportURI,
  };
}

/**
 * Build batch of compliance records
 */
export function buildComplianceRecordBatch(
  count: number = 3,
): ComplianceRecordFixture[] {
  const reports = [
    buildCleanComplianceReport(1),
    buildViolatingComplianceReport(10),
    buildHighRiskComplianceReport(8453), // Base
  ];

  return reports.slice(0, count).map((report) => buildComplianceRecord(report));
}
