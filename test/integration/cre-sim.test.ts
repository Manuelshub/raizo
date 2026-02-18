import { expect } from "chai";
import { ethers } from "hardhat";
import {
  TelemetryFrame,
  ThreatAssessment,
  HeuristicAnalyzer,
  escalateAction,
  runSentinelPipeline,
  buildThreatReport,
  HEURISTIC_GATE_THRESHOLD,
} from "../../workflows/logic/threat-logic";
import {
  evaluateScope,
  resolveTargetChains,
  buildPropagationMessages,
  runCoordinatorPipeline,
  ThreatEvent,
  ProtocolDeployment,
} from "../../workflows/logic/coordinator-logic";

// --- Test Fixtures ---

function buildTelemetry(
  overrides: Partial<TelemetryFrame> = {},
): TelemetryFrame {
  return {
    chainId: 1,
    blockNumber: 100000,
    tvl: { current: 10_000_000n, delta1h: 0, delta24h: 0 },
    transactionMetrics: {
      volumeUSD: 500_000n,
      uniqueAddresses: 100,
      largeTransactions: 0,
      failedTxRatio: 0.01,
    },
    contractState: {
      owner: "0x1234",
      paused: false,
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
      socialSentiment: 0.5,
    },
    priceData: {
      tokenPrice: 2_000n,
      priceDeviation: 0.1,
      oracleLatency: 1,
    },
    ...overrides,
  };
}

function buildHighRiskTelemetry(): TelemetryFrame {
  return buildTelemetry({
    tvl: { current: 5_000_000n, delta1h: -25, delta24h: -40 },
    mempoolSignals: {
      pendingLargeWithdrawals: 15,
      flashLoanBorrows: 4,
      suspiciousCalldata: ["0xdeadbeef", "0xbaddcafe"],
    },
    threatIntel: {
      activeCVEs: ["CVE-2026-0001"],
      exploitPatterns: [],
      darkWebMentions: 8,
      socialSentiment: -0.9,
    },
    priceData: {
      tokenPrice: 1_500n,
      priceDeviation: 12.0,
      oracleLatency: 5,
    },
    contractState: {
      owner: "0x1234",
      paused: false,
      pendingUpgrade: true,
      unusualApprovals: 7,
    },
  });
}

// ========================================================================
// 1. Heuristic Analyzer
// ========================================================================

describe("HeuristicAnalyzer", function () {
  let analyzer: HeuristicAnalyzer;

  beforeEach(function () {
    analyzer = new HeuristicAnalyzer();
  });

  it("should score clean telemetry near zero", function () {
    const telemetry = buildTelemetry();
    const { baseRiskScore } = analyzer.score(telemetry);

    expect(baseRiskScore).to.be.lt(HEURISTIC_GATE_THRESHOLD);
  });

  it("should score a flash-loan attack pattern above the gate threshold", function () {
    const telemetry = buildHighRiskTelemetry();
    const { baseRiskScore, citations } = analyzer.score(telemetry);

    expect(baseRiskScore).to.be.gte(HEURISTIC_GATE_THRESHOLD);
    expect(citations).to.include("mempoolSignals.flashLoanBorrows");
    expect(citations).to.include("tvl.delta1h");
  });

  it("should cite price deviation for oracle manipulation patterns", function () {
    const telemetry = buildTelemetry({
      priceData: { tokenPrice: 1000n, priceDeviation: 10.0, oracleLatency: 3 },
    });
    const { citations } = analyzer.score(telemetry);

    expect(citations).to.include("priceData.priceDeviation");
  });

  it("should remain bounded in [0, 1]", function () {
    const extreme = buildTelemetry({
      tvl: { current: 0n, delta1h: -100, delta24h: -100 },
      mempoolSignals: {
        pendingLargeWithdrawals: 100,
        flashLoanBorrows: 50,
        suspiciousCalldata: Array(50).fill("0x"),
      },
      priceData: { tokenPrice: 0n, priceDeviation: 100, oracleLatency: 100 },
      threatIntel: {
        activeCVEs: Array(20).fill("CVE-X"),
        exploitPatterns: [],
        darkWebMentions: 100,
        socialSentiment: -1.0,
      },
    });
    const { baseRiskScore } = analyzer.score(extreme);

    expect(baseRiskScore).to.be.gte(0);
    expect(baseRiskScore).to.be.lte(1);
  });
});

// ========================================================================
// 2. Action Escalation
// ========================================================================

describe("Action Escalation", function () {
  it("should map risk bands to correct actions", function () {
    expect(escalateAction(0.0)).to.equal("NONE");
    expect(escalateAction(0.3)).to.equal("NONE");
    expect(escalateAction(0.49)).to.equal("NONE");
    expect(escalateAction(0.5)).to.equal("ALERT");
    expect(escalateAction(0.69)).to.equal("ALERT");
    expect(escalateAction(0.7)).to.equal("RATE_LIMIT");
    expect(escalateAction(0.84)).to.equal("RATE_LIMIT");
    expect(escalateAction(0.85)).to.equal("DRAIN_BLOCK");
    expect(escalateAction(0.94)).to.equal("DRAIN_BLOCK");
    expect(escalateAction(0.95)).to.equal("PAUSE");
    expect(escalateAction(1.0)).to.equal("PAUSE");
  });

  it("should clamp out-of-range scores", function () {
    expect(escalateAction(-0.5)).to.equal("NONE");
    expect(escalateAction(1.5)).to.equal("PAUSE");
  });
});

// ========================================================================
// 3. Sentinel Pipeline (pure function tests)
// ========================================================================

describe("CRE Sentinel Pipeline", function () {
  const agentId = ethers.id("raizo.sentinel.v1");
  const targetProtocol = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";

  it("should generate a ThreatReport when overallRiskScore >= 0.85", function () {
    const mockAssessment: ThreatAssessment = {
      overallRiskScore: 0.95,
      threatDetected: true,
      threats: [
        {
          category: "flash_loan",
          confidence: 0.92,
          indicators: ["Large flash loans detected", "TVL dropping rapidly"],
          estimatedImpactUSD: 500000,
        },
      ],
      recommendedAction: "PAUSE",
      reasoning: "High-confidence detection of flash loan exploit pattern.",
      evidenceCitations: ["tvl.delta1h", "mempoolSignals.flashLoanBorrows"],
    };

    const report = runSentinelPipeline(
      agentId,
      targetProtocol,
      buildHighRiskTelemetry(),
      mockAssessment,
    );

    expect(report).to.not.be.null;
    expect(report!.agentId).to.equal(agentId);
    expect(report!.targetProtocol).to.equal(targetProtocol);
    expect(report!.action).to.equal(0); // PAUSE (escalation table: 0.95 → PAUSE)
    expect(report!.confidenceScore).to.equal(9500);
    expect(report!.reportId).to.be.a("string");
  });

  it("should NOT generate a report when risk is below threshold", function () {
    const mockAssessment: ThreatAssessment = {
      overallRiskScore: 0.4,
      threatDetected: false,
      threats: [],
      recommendedAction: "NONE",
      reasoning: "Normal protocol activity.",
      evidenceCitations: [],
    };

    const report = runSentinelPipeline(
      agentId,
      targetProtocol,
      buildHighRiskTelemetry(),
      mockAssessment,
    );

    expect(report).to.be.null;
  });

  it("should return null when heuristic score is below gate", function () {
    const report = runSentinelPipeline(
      agentId,
      targetProtocol,
      buildTelemetry(), // Clean telemetry
      null, // LLM not called
    );

    expect(report).to.be.null;
  });

  it("should override LLM action with deterministic escalation table", function () {
    // LLM says PAUSE but score is 0.72 → escalation table says RATE_LIMIT
    const mockAssessment: ThreatAssessment = {
      overallRiskScore: 0.72,
      threatDetected: true,
      threats: [
        {
          category: "reentrancy",
          confidence: 0.72,
          indicators: ["re-entrant call"],
          estimatedImpactUSD: 100000,
        },
      ],
      recommendedAction: "PAUSE", // LLM overestimates
      reasoning: "Possible reentrancy.",
      evidenceCitations: [],
    };

    const report = runSentinelPipeline(
      agentId,
      targetProtocol,
      buildHighRiskTelemetry(),
      mockAssessment,
    );

    expect(report).to.not.be.null;
    expect(report!.action).to.equal(1); // RATE_LIMIT (not PAUSE)
  });
});

// ========================================================================
// 4. Threat Report Builder
// ========================================================================

describe("Threat Report Builder", function () {
  it("should produce a well-formed report with merged citations", function () {
    const assessment: ThreatAssessment = {
      overallRiskScore: 0.9,
      threatDetected: true,
      threats: [
        {
          category: "oracle_manipulation",
          confidence: 0.9,
          indicators: ["price spike"],
          estimatedImpactUSD: 200000,
        },
      ],
      recommendedAction: "DRAIN_BLOCK",
      reasoning: "Oracle deviation.",
      evidenceCitations: ["priceData.priceDeviation"],
    };

    const report = buildThreatReport("agent-1", "0xProtocol", assessment, [
      "tvl.delta1h",
      "priceData.priceDeviation",
    ]);

    expect(report.agentId).to.equal("agent-1");
    expect(report.targetProtocol).to.equal("0xProtocol");
    expect(report.action).to.equal(2); // DRAIN_BLOCK
    expect(report.confidenceScore).to.equal(9000);
    expect(report.reportId).to.be.a("string");
    expect(report.timestamp).to.be.a("number");
    // evidenceHash contains deduplicated citations
    expect(report.evidenceHash).to.include("tvl.delta1h");
    expect(report.evidenceHash).to.include("priceData.priceDeviation");
  });
});

// ========================================================================
// 5. Cross-Chain Coordinator
// ========================================================================

describe("Cross-Chain Coordinator", function () {
  const agentId = ethers.id("raizo.coordinator.v1");
  const monitoredChains = [1, 8453, 42161]; // Ethereum, Base, Arbitrum

  function buildThreatEvent(overrides: Partial<ThreatEvent> = {}): ThreatEvent {
    return {
      reportId: ethers.id("report-1"),
      agentId,
      sourceChain: 1,
      targetProtocol: "0xProtocol",
      action: 0, // PAUSE
      severity: 2, // HIGH
      confidenceScore: 9200,
      evidenceHash: ethers.id("evidence"),
      timestamp: Math.floor(Date.now() / 1000),
      ...overrides,
    };
  }

  it("should propagate CRITICAL threats to all monitored chains", function () {
    const event = buildThreatEvent({ severity: 3 }); // CRITICAL
    const deployment: ProtocolDeployment = {
      protocol: "0xProtocol",
      chains: [1],
      relatedProtocols: [],
    };

    const messages = runCoordinatorPipeline(event, deployment, monitoredChains);

    // Should propagate to 2 chains (all except source)
    expect(messages.length).to.equal(2);
    expect(messages.map((m) => m.destChain)).to.not.include(1);
  });

  it("should scope LOCAL_ONLY for single-chain protocols without relationships", function () {
    const event = buildThreatEvent({ severity: 2 }); // HIGH but local
    const deployment: ProtocolDeployment = {
      protocol: "0xProtocol",
      chains: [1], // Single chain
      relatedProtocols: [],
    };

    const scope = evaluateScope(event, deployment);
    const messages = runCoordinatorPipeline(event, deployment, monitoredChains);

    expect(scope).to.equal("LOCAL_ONLY");
    expect(messages.length).to.equal(0);
  });

  it("should scope SAME_PROTOCOL for multi-chain deployments", function () {
    const event = buildThreatEvent({ severity: 2, sourceChain: 1 });
    const deployment: ProtocolDeployment = {
      protocol: "0xProtocol",
      chains: [1, 8453], // Deployed on Ethereum + Base
      relatedProtocols: [],
    };

    const scope = evaluateScope(event, deployment);
    const messages = runCoordinatorPipeline(event, deployment, monitoredChains);

    expect(scope).to.equal("SAME_PROTOCOL");
    expect(messages.length).to.be.gte(1);
    expect(messages.some((m) => m.destChain === 8453)).to.be.true;
  });

  it("should scope RELATED_ALERT and downgrade action to ALERT", function () {
    const event = buildThreatEvent({ severity: 2, action: 0 }); // PAUSE action
    const deployment: ProtocolDeployment = {
      protocol: "0xProtocol",
      chains: [1],
      relatedProtocols: ["0xRelated"],
    };

    const scope = evaluateScope(event, deployment);
    const messages = runCoordinatorPipeline(event, deployment, monitoredChains);

    expect(scope).to.equal("RELATED_ALERT");
    // All messages should have action=3 (ALERT), not the original PAUSE
    for (const msg of messages) {
      expect(msg.action).to.equal(3); // ALERT
    }
  });

  it("should resolve correct target chains excluding source", function () {
    const event = buildThreatEvent({ sourceChain: 8453 });

    const targets = resolveTargetChains(event, "ALL_CHAINS", monitoredChains);
    expect(targets).to.deep.equal([1, 42161]); // Exclude 8453
  });
});
