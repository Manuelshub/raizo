import { expect } from "chai";
import { ethers } from "hardhat";
import {
  ThreatSentinelWorkflow,
  TelemetryFrame,
  ThreatAssessment,
} from "../../workflows/threat-detection";

describe("CRE Simulation: Threat Sentinel Workflow", function () {
  let workflow: ThreatSentinelWorkflow;
  const agentId = ethers.id("raizo.sentinel.v1");
  const targetProtocol = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"; // Dummy protocol
  const chainId = 1;

  beforeEach(async function () {
    // Initialized in each test with specific capability mocks
  });

  it("should generate a ThreatReport when overallRiskScore >= 0.85", async function () {
    const mockTelemetry: TelemetryFrame = {
      chainId: chainId,
      blockNumber: 123456,
      tvl: { current: 1000000n, delta1h: -15, delta24h: -20 },
      transactionMetrics: {
        volumeUSD: 500000n,
        uniqueAddresses: 50,
        largeTransactions: 10,
        failedTxRatio: 0.1,
      },
      contractState: {
        owner: "0x123",
        paused: false,
        pendingUpgrade: true,
        unusualApprovals: 5,
      },
      mempoolSignals: {
        pendingLargeWithdrawals: 20,
        flashLoanBorrows: 2,
        suspiciousCalldata: ["0xdeadbeef"],
      },
      threatIntel: {
        activeCVEs: ["CVE-2026-0001"],
        exploitPatterns: [],
        darkWebMentions: 5,
        socialSentiment: -0.8,
      },
      priceData: {
        tokenPrice: 1000000n,
        priceDeviation: 5.5,
        oracleLatency: 2,
      },
    };

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

    workflow = new ThreatSentinelWorkflow(agentId, {
      ingestTelemetry: async () => mockTelemetry,
      analyzeRisk: async () => mockAssessment,
    });

    const report = await workflow.run(chainId, targetProtocol);

    expect(report).to.not.be.null;
    expect(report.agentId).to.equal(agentId);
    expect(report.targetProtocol).to.equal(targetProtocol);
    expect(report.action).to.equal(0); // PAUSE
    expect(report.confidenceScore).to.equal(9500);
    expect(report.donSignatures).to.equal("0x");
    expect(report.reportId).to.be.a("string");
  });

  it("should NOT generate a report when risk is below threshold", async function () {
    const mockAssessment: ThreatAssessment = {
      overallRiskScore: 0.4,
      threatDetected: false,
      threats: [],
      recommendedAction: "NONE",
      reasoning: "Normal protocol activity.",
      evidenceCitations: [],
    };

    workflow = new ThreatSentinelWorkflow(agentId, {
      analyzeRisk: async () => mockAssessment,
    });

    const report = await workflow.run(chainId, targetProtocol);
    expect(report).to.be.null;
  });
});
