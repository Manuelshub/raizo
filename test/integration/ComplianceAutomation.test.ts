import { expect } from "chai";
import { ethers } from "hardhat";
import { ComplianceVault } from "../../typechain-types";
import {
  ComplianceReporterWorkflow,
  RegulatoryRule,
  ComplianceReport,
} from "../../workflows/compliance-reporter";
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
          threshold: 10000, // Flag tx > $10k
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

    const workflow = new ComplianceReporterWorkflow(agentId, rules, {
      fetchProtocolMetrics: async () => mockMetrics,
      fetchSanctionsList: async () => [],
    });

    // 1. Run Workflow
    const report = await workflow.run(chainId, "0xProtocol");

    expect(report.findings.length).to.equal(1);
    expect(report.findings[0].ruleId).to.equal("AML-001");
    expect(report.riskSummary.complianceScore).to.be.lt(100);

    // 2. Simulate Anchoring via Contract
    // In production, the CRE would call a capability that sends the tx.
    // Here we simulate the final anchoring step.
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

  it("should produce a 100 score for clean metrics", async function () {
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

    const workflow = new ComplianceReporterWorkflow(agentId, rules, {
      fetchProtocolMetrics: async () => mockMetrics,
    });

    const report = await workflow.run(chainId, "0xProtocol");
    expect(report.findings.length).to.equal(0);
    expect(report.riskSummary.complianceScore).to.equal(100);
    expect(report.riskSummary.overallRisk).to.equal("low");
  });
});
