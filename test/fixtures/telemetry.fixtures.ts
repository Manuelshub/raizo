/**
 * @file telemetry.fixtures.ts
 * @notice Fixture factories for TelemetryFrame test data
 */

import { TelemetryFrame, ExploitPattern } from "../../workflows/logic/types";

/**
 * Default clean telemetry frame with no anomalies
 */
export function buildCleanTelemetry(
  overrides: Partial<TelemetryFrame> = {},
): TelemetryFrame {
  return {
    chainId: 1,
    blockNumber: 20_000_000,
    tvl: {
      current: 50_000_000n, // $50M TVL
      delta1h: 0.5, // +0.5% (healthy growth)
      delta24h: 2.0, // +2% daily growth
    },
    transactionMetrics: {
      volumeUSD: 5_000_000n, // $5M daily volume
      uniqueAddresses: 1500,
      largeTransactions: 2, // Normal level
      failedTxRatio: 0.01, // 1% failure rate (acceptable)
    },
    contractState: {
      owner: "0x1234567890123456789012345678901234567890",
      paused: false,
      pendingUpgrade: false,
      unusualApprovals: 0,
    },
    mempoolSignals: {
      pendingLargeWithdrawals: 1,
      flashLoanBorrows: 0,
      suspiciousCalldata: [],
    },
    threatIntel: {
      activeCVEs: [],
      exploitPatterns: [],
      darkWebMentions: 0,
      socialSentiment: 0.6, // Slightly positive
    },
    priceData: {
      tokenPrice: 2_000n, // $2000 token price
      priceDeviation: 0.5, // 0.5% deviation from TWAP (normal)
      oracleLatency: 10, // 10 seconds (acceptable)
    },
    ...overrides,
  };
}

/**
 * High-risk telemetry: flash loan drain pattern
 */
export function buildFlashLoanDrainTelemetry(): TelemetryFrame {
  return buildCleanTelemetry({
    tvl: {
      current: 25_000_000n, // $25M (down 50% from $50M)
      delta1h: -35, // -35% in 1 hour (CRITICAL)
      delta24h: -50, // -50% in 24 hours
    },
    transactionMetrics: {
      volumeUSD: 30_000_000n, // $30M volume (6x normal - suspicious)
      uniqueAddresses: 50, // Fewer unique addresses despite high volume
      largeTransactions: 25, // 12.5x normal
      failedTxRatio: 0.15, // 15% failure rate (high)
    },
    mempoolSignals: {
      pendingLargeWithdrawals: 20,
      flashLoanBorrows: 8, // Multiple flash loans
      suspiciousCalldata: [
        "0xdeadbeef",
        "0xbaddcafe",
        "0x1337c0de",
        "0xfeedface",
      ],
    },
    threatIntel: {
      activeCVEs: ["CVE-2026-1337"],
      exploitPatterns: [
        {
          patternId: "FL-DRAIN-001",
          category: "flash_loan",
          severity: "critical",
          indicators: [
            "Multiple flash loans in single tx",
            "Reentrancy pattern detected",
            "TVL drop >30% in <1hr",
          ],
          confidence: 0.94,
        },
      ],
      darkWebMentions: 15,
      socialSentiment: -0.85, // Panic selling
    },
    priceData: {
      tokenPrice: 1_200n, // 40% price crash
      priceDeviation: 18.0, // 18% deviation (oracle manipulation?)
      oracleLatency: 120, // 2 minutes (stale oracle)
    },
  });
}

/**
 * Oracle manipulation pattern
 */
export function buildOracleManipulationTelemetry(): TelemetryFrame {
  return buildCleanTelemetry({
    tvl: {
      current: 48_000_000n,
      delta1h: -4, // Slight drop
      delta24h: -10,
    },
    priceData: {
      tokenPrice: 3_500n, // 75% price spike (from $2000)
      priceDeviation: 25.0, // 25% deviation from TWAP
      oracleLatency: 300, // 5 minutes (very stale)
    },
    threatIntel: {
      activeCVEs: [],
      exploitPatterns: [
        {
          patternId: "ORC-MANIP-001",
          category: "oracle_manipulation",
          severity: "high",
          indicators: [
            "Price deviation >20%",
            "Oracle latency >2min",
            "Single large tx moving price",
          ],
          confidence: 0.88,
        },
      ],
      darkWebMentions: 3,
      socialSentiment: -0.3,
    },
    transactionMetrics: {
      volumeUSD: 8_000_000n, // Elevated volume
      uniqueAddresses: 800,
      largeTransactions: 8,
      failedTxRatio: 0.08,
    },
  });
}

/**
 * Governance attack pattern
 */
export function buildGovernanceAttackTelemetry(): TelemetryFrame {
  return buildCleanTelemetry({
    contractState: {
      owner: "0x9999999999999999999999999999999999999999", // Ownership changed
      paused: false,
      pendingUpgrade: true, // Malicious upgrade pending
      unusualApprovals: 25, // Many unlimited token approvals
    },
    threatIntel: {
      activeCVEs: ["CVE-2026-GOV-001"],
      exploitPatterns: [
        {
          patternId: "GOV-ATK-001",
          category: "governance_attack",
          severity: "critical",
          indicators: [
            "Ownership transfer detected",
            "Pending upgrade not in governance queue",
            "Unusual token approval spike",
          ],
          confidence: 0.91,
        },
      ],
      darkWebMentions: 8,
      socialSentiment: -0.75,
    },
    tvl: {
      current: 45_000_000n,
      delta1h: -10, // Gradual drain starting
      delta24h: -15,
    },
  });
}

/**
 * Below-gate telemetry (heuristic score < threshold)
 */
export function buildBelowGateTelemetry(): TelemetryFrame {
  return buildCleanTelemetry({
    tvl: {
      current: 50_500_000n,
      delta1h: 1.0, // Healthy growth
      delta24h: 3.0,
    },
    transactionMetrics: {
      volumeUSD: 4_800_000n,
      uniqueAddresses: 1450,
      largeTransactions: 1,
      failedTxRatio: 0.005, // 0.5% - very low
    },
    priceData: {
      tokenPrice: 2_050n, // Slight price increase
      priceDeviation: 0.2, // Minimal deviation
      oracleLatency: 5,
    },
  });
}

/**
 * Reentrancy attack pattern
 */
export function buildReentrancyTelemetry(): TelemetryFrame {
  return buildCleanTelemetry({
    mempoolSignals: {
      pendingLargeWithdrawals: 30,
      flashLoanBorrows: 2,
      suspiciousCalldata: [
        "0xd0e30db0", // WETH deposit
        "0x2e1a7d4d", // WETH withdraw (repeated)
        "0x2e1a7d4d",
        "0x2e1a7d4d",
      ],
    },
    threatIntel: {
      activeCVEs: ["CVE-2026-REEN-001"],
      exploitPatterns: [
        {
          patternId: "REEN-001",
          category: "reentrancy",
          severity: "high",
          indicators: [
            "Repeated withdraw calls in single tx",
            "State-changing external call detected",
            "Check-effects-interactions violation",
          ],
          confidence: 0.87,
        },
      ],
      darkWebMentions: 5,
      socialSentiment: -0.5,
    },
    tvl: {
      current: 40_000_000n,
      delta1h: -20, // Rapid drain
      delta24h: -25,
    },
    transactionMetrics: {
      volumeUSD: 12_000_000n,
      uniqueAddresses: 200,
      largeTransactions: 15,
      failedTxRatio: 0.25, // 25% failure (exploit attempts failing)
    },
  });
}

/**
 * Access control vulnerability
 */
export function buildAccessControlTelemetry(): TelemetryFrame {
  return buildCleanTelemetry({
    contractState: {
      owner: "0xABCDEF1234567890ABCDEF1234567890ABCDEF12", // Unexpected owner
      paused: false,
      pendingUpgrade: true,
      unusualApprovals: 50, // Attacker granted many approvals
    },
    threatIntel: {
      activeCVEs: ["CVE-2026-ACCESS-001"],
      exploitPatterns: [
        {
          patternId: "ACCESS-001",
          category: "access_control",
          severity: "critical",
          indicators: [
            "Unauthorized admin function call",
            "Ownership transfer without timelock",
            "Role escalation detected",
          ],
          confidence: 0.93,
        },
      ],
      darkWebMentions: 12,
      socialSentiment: -0.9,
    },
    transactionMetrics: {
      volumeUSD: 20_000_000n,
      uniqueAddresses: 100,
      largeTransactions: 30,
      failedTxRatio: 0.05,
    },
  });
}

/**
 * Edge case: All zeros (worst case scenario)
 */
export function buildZeroTelemetry(): TelemetryFrame {
  return {
    chainId: 1,
    blockNumber: 20_000_000,
    tvl: {
      current: 0n, // Complete drain
      delta1h: -100,
      delta24h: -100,
    },
    transactionMetrics: {
      volumeUSD: 0n,
      uniqueAddresses: 0,
      largeTransactions: 0,
      failedTxRatio: 1.0, // All transactions failing
    },
    contractState: {
      owner: "0x0000000000000000000000000000000000000000",
      paused: true,
      pendingUpgrade: false,
      unusualApprovals: 0,
    },
    mempoolSignals: {
      pendingLargeWithdrawals: 0,
      flashLoanBorrows: 0,
      suspiciousCalldata: [],
    },
    threatIntel: {
      activeCVEs: [],
      exploitPatterns: [],
      darkWebMentions: 0,
      socialSentiment: -1.0,
    },
    priceData: {
      tokenPrice: 0n,
      priceDeviation: 100,
      oracleLatency: 1000,
    },
  };
}

/**
 * Edge case: Extreme values (fuzzing boundary)
 */
export function buildExtremeTelemetry(): TelemetryFrame {
  return {
    chainId: 1,
    blockNumber: 99_999_999,
    tvl: {
      current: 999_999_999_999n,
      delta1h: 999,
      delta24h: 999,
    },
    transactionMetrics: {
      volumeUSD: 999_999_999_999n,
      uniqueAddresses: 999_999,
      largeTransactions: 999,
      failedTxRatio: 0,
    },
    contractState: {
      owner: "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
      paused: false,
      pendingUpgrade: false,
      unusualApprovals: 999,
    },
    mempoolSignals: {
      pendingLargeWithdrawals: 999,
      flashLoanBorrows: 999,
      suspiciousCalldata: Array(100).fill("0xFFFFFFFF"),
    },
    threatIntel: {
      activeCVEs: Array(50).fill("CVE-2026-9999"),
      exploitPatterns: Array(20).fill({
        patternId: "EXTREME",
        category: "flash_loan",
        severity: "critical",
        indicators: ["everything"],
        confidence: 1.0,
      } as ExploitPattern),
      darkWebMentions: 999,
      socialSentiment: -1.0,
    },
    priceData: {
      tokenPrice: 999_999n,
      priceDeviation: 999,
      oracleLatency: 9999,
    },
  };
}
