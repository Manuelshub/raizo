import { expect } from "chai";
import { ethers } from "hardhat";
import { ComplianceVault } from "../../typechain-types";
import {
  RegulatoryRule,
  ComplianceReport,
  evaluateRule,
  generateComplianceReport,
  runCompliancePipeline,
} from "../../workflows/logic/compliance-logic";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

describe("Compliance Automation Integration", function () {
  let vault: ComplianceVault;
  let owner: HardhatEthersSigner;
  let agent: HardhatEthersSigner;
  const agentId = ethers.id("raizo.compliance.v1");
  const chainId = 1;

  beforeEach(async function () {
    [owner, agent] = await ethers.getSigners();

    const VaultFactory = await ethers.getContractFactory("ComplianceVault");
    vault = (await VaultFactory.deploy()) as unknown as ComplianceVault;

    const ANCHOR_ROLE = await vault.ANCHOR_ROLE();
    await vault.grantRole(ANCHOR_ROLE, agent.address);
  });

  it("should evaluate AML rules and anchor a violation report", async function () {
    const rules: RegulatoryRule[] = [
      {
        ruleId: "AML-001",
        framework: "AML",
        version: "1.0",
        effectiveDate: Math.floor(Date.now() / 1000),
        condition: {
          metric: "tx.valueUSD",
          operator: "gt",
          threshold: 10000,
        },
        action: {
          type: "report",
          severity: "violation",
          narrative: "High value transaction threshold exceeded.",
        },
        regulatoryReference: "FATF Rec 10",
        jurisdiction: ["Global"],
      },
    ];

    const mockMetrics = {
      "tx.valueUSD": 15000, // Violation!
      "address.riskScore": 0.1,
    };

    // 1. Run pipeline (pure function — no class needed)
    const report = runCompliancePipeline(chainId, rules, mockMetrics, []);

    expect(report.findings.length).to.equal(1);
    expect(report.findings[0].ruleId).to.equal("AML-001");
    expect(report.riskSummary.complianceScore).to.be.lt(100);

    // 2. Simulate Anchoring via Contract
    const reportHash = report.metadata.reportId;
    await expect(
      vault.connect(agent).storeReport(
        reportHash,
        agentId,
        1, // AML
        chainId,
        "ipfs://encrypted-report-blob",
      ),
    )
      .to.emit(vault, "ReportStored")
      .withArgs(reportHash, agentId, 1, chainId);

    // 3. Verify on-chain record
    const record = await vault.getReport(reportHash);
    expect(record.agentId).to.equal(agentId);
    expect(record.reportHash).to.equal(reportHash);
  });

  it("should produce a 100 score for clean metrics", function () {
    const rules: RegulatoryRule[] = [
      {
        ruleId: "AML-001",
        framework: "AML",
        version: "1.0",
        effectiveDate: Math.floor(Date.now() / 1000),
        condition: {
          metric: "tx.valueUSD",
          operator: "gt",
          threshold: 50000,
        },
        action: {
          type: "report",
          severity: "violation",
          narrative: "Threshold exceeded.",
        },
        regulatoryReference: "Ref",
        jurisdiction: ["Global"],
      },
    ];

    const mockMetrics = {
      "tx.valueUSD": 1000, // Clean
      "address.riskScore": 0.05,
    };

    const report = runCompliancePipeline(chainId, rules, mockMetrics, []);
    expect(report.findings.length).to.equal(0);
    expect(report.riskSummary.complianceScore).to.equal(100);
    expect(report.riskSummary.overallRisk).to.equal("low");
  });

  it("should correctly evaluate individual rules", function () {
    const rule: RegulatoryRule = {
      ruleId: "TEST-001",
      framework: "MiCA",
      version: "1.0",
      effectiveDate: 0,
      condition: { metric: "volume", operator: "gt", threshold: 100 },
      action: { type: "flag", severity: "warning", narrative: "High volume" },
      regulatoryReference: "MiCA Art 3",
      jurisdiction: ["EU"],
    };

    expect(evaluateRule(rule, { volume: 150 }, [])).to.be.true;
    expect(evaluateRule(rule, { volume: 50 }, [])).to.be.false;
  });

  it("should match sanctions list with 'matches' operator", function () {
    const rule: RegulatoryRule = {
      ruleId: "SANC-001",
      framework: "AML",
      version: "1.0",
      effectiveDate: 0,
      condition: { metric: "sender", operator: "matches", threshold: "" },
      action: {
        type: "block",
        severity: "violation",
        narrative: "Sanctioned address",
      },
      regulatoryReference: "OFAC SDN",
      jurisdiction: ["US"],
    };

    const sanctions = ["0xdead", "0xbeef"];
    expect(evaluateRule(rule, { sender: "0xdead" }, sanctions)).to.be.true;
    expect(evaluateRule(rule, { sender: "0xsafe" }, sanctions)).to.be.false;
  });
});
