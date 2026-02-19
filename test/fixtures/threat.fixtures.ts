/**
 * @file threat.fixtures.ts
 * @notice Fixture factories for ThreatAssessment and ThreatReport test data
 */

import { ethers } from "hardhat";
import {
  ThreatAssessment,
  RecommendedAction,
} from "../../workflows/logic/types";

/**
 * Clean assessment (no threat detected)
 */
export function buildCleanAssessment(): ThreatAssessment {
  return {
    overallRiskScore: 0.15,
    threatDetected: false,
    threats: [],
    recommendedAction: "NONE",
    reasoning:
      "No anomalous activity detected. Protocol metrics within normal parameters.",
    evidenceCitations: [],
  };
}

/**
 * Low-risk assessment (below action threshold)
 */
export function buildLowRiskAssessment(): ThreatAssessment {
  return {
    overallRiskScore: 0.42,
    threatDetected: true,
    threats: [
      {
        category: "flash_loan",
        confidence: 0.42,
        indicators: ["Single flash loan detected", "No TVL impact"],
        estimatedImpactUSD: 5000,
      },
    ],
    recommendedAction: "NONE",
    reasoning:
      "Minor flash loan activity detected but no evidence of exploit pattern.",
    evidenceCitations: ["mempoolSignals.flashLoanBorrows"],
  };
}

/**
 * ALERT-level assessment (0.5 ≤ score < 0.7)
 */
export function buildAlertAssessment(): ThreatAssessment {
  return {
    overallRiskScore: 0.62,
    threatDetected: true,
    threats: [
      {
        category: "oracle_manipulation",
        confidence: 0.62,
        indicators: [
          "Price deviation 8% from TWAP",
          "Oracle latency elevated",
        ],
        estimatedImpactUSD: 100_000,
      },
    ],
    recommendedAction: "ALERT",
    reasoning:
      "Moderate price deviation detected. Monitor for continued anomalies.",
    evidenceCitations: ["priceData.priceDeviation", "priceData.oracleLatency"],
  };
}

/**
 * RATE_LIMIT assessment (0.7 ≤ score < 0.85)
 */
export function buildRateLimitAssessment(): ThreatAssessment {
  return {
    overallRiskScore: 0.76,
    threatDetected: true,
    threats: [
      {
        category: "reentrancy",
        confidence: 0.76,
        indicators: [
          "Repeated withdraw calls detected",
          "Failed tx ratio elevated",
        ],
        estimatedImpactUSD: 250_000,
      },
    ],
    recommendedAction: "RATE_LIMIT",
    reasoning:
      "Potential reentrancy pattern observed. Recommend rate limiting withdrawals.",
    evidenceCitations: [
      "mempoolSignals.suspiciousCalldata",
      "transactionMetrics.failedTxRatio",
    ],
  };
}

/**
 * DRAIN_BLOCK assessment (0.85 ≤ score < 0.95)
 */
export function buildDrainBlockAssessment(): ThreatAssessment {
  return {
    overallRiskScore: 0.89,
    threatDetected: true,
    threats: [
      {
        category: "flash_loan",
        confidence: 0.89,
        indicators: [
          "Multiple flash loans in short timeframe",
          "TVL dropped 20% in 1 hour",
          "Large pending withdrawals",
        ],
        estimatedImpactUSD: 500_000,
      },
    ],
    recommendedAction: "DRAIN_BLOCK",
    reasoning:
      "High-confidence flash loan drain pattern. Block large withdrawals immediately.",
    evidenceCitations: [
      "mempoolSignals.flashLoanBorrows",
      "tvl.delta1h",
      "mempoolSignals.pendingLargeWithdrawals",
    ],
  };
}

/**
 * PAUSE assessment (score ≥ 0.95)
 */
export function buildPauseAssessment(): ThreatAssessment {
  return {
    overallRiskScore: 0.97,
    threatDetected: true,
    threats: [
      {
        category: "flash_loan",
        confidence: 0.97,
        indicators: [
          "Active CVE exploit in progress",
          "TVL dropped 35% in 1 hour",
          "Multiple coordinated flash loans",
          "Dark web chatter confirming attack",
        ],
        estimatedImpactUSD: 10_000_000,
      },
      {
        category: "reentrancy",
        confidence: 0.85,
        indicators: ["Reentrancy guard bypassed", "Recursive calls detected"],
        estimatedImpactUSD: 2_000_000,
      },
    ],
    recommendedAction: "PAUSE",
    reasoning:
      "CRITICAL: Multi-vector exploit in progress. Immediate full pause required.",
    evidenceCitations: [
      "threatIntel.activeCVEs",
      "tvl.delta1h",
      "mempoolSignals.flashLoanBorrows",
      "threatIntel.darkWebMentions",
      "mempoolSignals.suspiciousCalldata",
    ],
  };
}

/**
 * Governance attack assessment
 */
export function buildGovernanceAttackAssessment(): ThreatAssessment {
  return {
    overallRiskScore: 0.93,
    threatDetected: true,
    threats: [
      {
        category: "governance_attack",
        confidence: 0.93,
        indicators: [
          "Ownership transfer without timelock",
          "Pending malicious upgrade",
          "Unusual token approval spike",
        ],
        estimatedImpactUSD: 8_000_000,
      },
    ],
    recommendedAction: "PAUSE",
    reasoning:
      "Governance compromise detected. Malicious actor has admin access.",
    evidenceCitations: [
      "contractState.owner",
      "contractState.pendingUpgrade",
      "contractState.unusualApprovals",
    ],
  };
}

/**
 * Access control vulnerability assessment
 */
export function buildAccessControlAssessment(): ThreatAssessment {
  return {
    overallRiskScore: 0.91,
    threatDetected: true,
    threats: [
      {
        category: "access_control",
        confidence: 0.91,
        indicators: [
          "Unauthorized admin function calls",
          "Role escalation detected",
          "Privilege boundary violated",
        ],
        estimatedImpactUSD: 5_000_000,
      },
    ],
    recommendedAction: "DRAIN_BLOCK",
    reasoning:
      "Access control vulnerability exploited. Attacker has elevated privileges.",
    evidenceCitations: [
      "contractState.owner",
      "contractState.unusualApprovals",
      "threatIntel.exploitPatterns",
    ],
  };
}

/**
 * Oracle manipulation assessment
 */
export function buildOracleManipulationAssessment(): ThreatAssessment {
  return {
    overallRiskScore: 0.88,
    threatDetected: true,
    threats: [
      {
        category: "oracle_manipulation",
        confidence: 0.88,
        indicators: [
          "Price deviation 25% from TWAP",
          "Oracle latency >5 minutes",
          "Single large tx moving market",
        ],
        estimatedImpactUSD: 3_000_000,
      },
    ],
    recommendedAction: "DRAIN_BLOCK",
    reasoning:
      "Oracle manipulation attack in progress. Price feeds unreliable.",
    evidenceCitations: [
      "priceData.priceDeviation",
      "priceData.oracleLatency",
      "transactionMetrics.largeTransactions",
    ],
  };
}

/**
 * Build ThreatReport for on-chain submission
 */
export interface ThreatReportFixture {
  reportId: string;
  agentId: string;
  targetProtocol: string;
  action: number; // ActionType enum (0=PAUSE, 1=RATE_LIMIT, 2=DRAIN_BLOCK, 3=ALERT)
  severity: number; // Severity enum (0=LOW, 1=MEDIUM, 2=HIGH, 3=CRITICAL)
  confidenceScore: number; // Basis points (0-10000)
  evidenceHash: string;
  timestamp: number;
  donSignatures: string; // "0x" placeholder until CRE provides signatures
}

export function buildThreatReport(
  agentId: string = ethers.id("raizo.sentinel.v1"),
  targetProtocol: string = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  assessment: ThreatAssessment = buildPauseAssessment(),
  evidenceCitations: string[] = [],
): ThreatReportFixture {
  const timestamp = Math.floor(Date.now() / 1000);
  const reportIdInput = `${agentId}-${targetProtocol}-${timestamp}`;
  const reportId = ethers.id(reportIdInput);

  // Map recommendedAction to ActionType enum
  const actionMap: Record<RecommendedAction, number> = {
    PAUSE: 0,
    RATE_LIMIT: 1,
    DRAIN_BLOCK: 2,
    ALERT: 3,
    NONE: 3, // Map NONE to ALERT (no-op action)
  };

  // Map riskScore to Severity enum
  let severity: number;
  if (assessment.overallRiskScore >= 0.95) severity = 3; // CRITICAL
  else if (assessment.overallRiskScore >= 0.85) severity = 2; // HIGH
  else if (assessment.overallRiskScore >= 0.7) severity = 1; // MEDIUM
  else severity = 0; // LOW

  // Combine assessment citations with heuristic citations
  const allCitations = [
    ...assessment.evidenceCitations,
    ...evidenceCitations,
  ];
  const evidenceStr = `${assessment.reasoning} | Citations: ${allCitations.join(", ")}`;
  const evidenceHash = ethers.id(evidenceStr);

  return {
    reportId,
    agentId,
    targetProtocol,
    action: actionMap[assessment.recommendedAction],
    severity,
    confidenceScore: Math.floor(assessment.overallRiskScore * 10000), // Convert to basis points
    evidenceHash,
    timestamp,
    donSignatures: "0x", // ⚠️ Placeholder - CRE runtime must populate
  };
}

/**
 * Build multiple threat reports for batch testing
 */
export function buildThreatReportBatch(
  count: number = 5,
  agentId: string = ethers.id("raizo.sentinel.v1"),
): ThreatReportFixture[] {
  const assessments = [
    buildPauseAssessment(),
    buildDrainBlockAssessment(),
    buildRateLimitAssessment(),
    buildAlertAssessment(),
    buildGovernanceAttackAssessment(),
  ];

  return assessments.slice(0, count).map((assessment, idx) => {
    const targetProtocol = `0x${(idx + 1).toString(16).padStart(40, "0")}`;
    return buildThreatReport(agentId, targetProtocol, assessment);
  });
}

/**
 * Edge case: Minimum valid threat report
 */
export function buildMinimalThreatReport(): ThreatReportFixture {
  return {
    reportId: ethers.id("minimal-report"),
    agentId: ethers.id("raizo.sentinel.v1"),
    targetProtocol: "0x0000000000000000000000000000000000000001",
    action: 3, // ALERT (lowest impact)
    severity: 0, // LOW
    confidenceScore: 5000, // 50%
    evidenceHash: ethers.id("minimal evidence"),
    timestamp: Math.floor(Date.now() / 1000),
    donSignatures: "0x",
  };
}

/**
 * Edge case: Maximum severity threat report
 */
export function buildMaxSeverityThreatReport(): ThreatReportFixture {
  return {
    reportId: ethers.id("max-severity-report"),
    agentId: ethers.id("raizo.sentinel.v1"),
    targetProtocol: "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    action: 0, // PAUSE
    severity: 3, // CRITICAL
    confidenceScore: 10000, // 100%
    evidenceHash: ethers.id("CRITICAL: Protocol under active exploit"),
    timestamp: Math.floor(Date.now() / 1000),
    donSignatures: "0x",
  };
}
