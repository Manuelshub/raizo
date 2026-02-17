import { expect } from "chai";
import { ethers } from "hardhat";
import { ComplianceVault } from "../../typechain-types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

describe("ComplianceVault (Audit Store)", function () {
  let vault: ComplianceVault;
  let owner: HardhatEthersSigner;
  let agent: HardhatEthersSigner;
  let unauthorized: HardhatEthersSigner;

  const AGENT_ID = ethers.id("agent.compliance.001");
  const REPORT_HASH = ethers.id("report.content.v1");
  const CHAIN_ID = 1; // Ethereum Mainnet
  const REPORT_URI = "ipfs://QmReport123";

  beforeEach(async function () {
    [owner, agent, unauthorized] = await ethers.getSigners();

    const VaultFactory = await ethers.getContractFactory("ComplianceVault");
    vault = (await VaultFactory.deploy()) as unknown as ComplianceVault;

    const ANCHOR_ROLE = await vault.ANCHOR_ROLE();
    await vault.grantRole(ANCHOR_ROLE, agent.address);
  });

  describe("Report Anchoring", function () {
    it("should allow an authorized agent to store a report", async function () {
      // Assume owner grants role to agent in actual implementation
      await expect(
        vault.connect(agent).storeReport(
          REPORT_HASH,
          AGENT_ID,
          4, // MiCA
          CHAIN_ID,
          REPORT_URI,
        ),
      )
        .to.emit(vault, "ReportStored")
        .withArgs(REPORT_HASH, AGENT_ID, 4, CHAIN_ID);

      const record = await vault.getReport(REPORT_HASH);
      expect(record.reportHash).to.equal(REPORT_HASH);
      expect(record.agentId).to.equal(AGENT_ID);
      expect(record.reportType).to.equal(4);
      expect(record.reportURI).to.equal(REPORT_URI);
    });

    it("should revert if anchoring a duplicate report hash", async function () {
      await vault
        .connect(agent)
        .storeReport(REPORT_HASH, AGENT_ID, 4, CHAIN_ID, REPORT_URI);

      await expect(
        vault
          .connect(agent)
          .storeReport(REPORT_HASH, AGENT_ID, 4, CHAIN_ID, REPORT_URI),
      )
        .to.be.revertedWithCustomError(vault, "ReportAlreadyExists")
        .withArgs(REPORT_HASH);
    });

    it("should revert if an unauthorized account tries to anchor", async function () {
      await expect(
        vault
          .connect(unauthorized)
          .storeReport(REPORT_HASH, AGENT_ID, 1, CHAIN_ID, REPORT_URI),
      )
        .to.be.revertedWithCustomError(vault, "UnauthorizedAnchor")
        .withArgs(unauthorized.address);
    });
  });

  describe("Retrieval & Auditing", function () {
    beforeEach(async function () {
      // Store a few reports for filtering tests
      await vault
        .connect(agent)
        .storeReport(ethers.id("h1"), AGENT_ID, 1, 1, "uri1"); // AML, Chain 1
      await vault
        .connect(agent)
        .storeReport(ethers.id("h2"), AGENT_ID, 4, 1, "uri2"); // MiCA, Chain 1
      await vault
        .connect(agent)
        .storeReport(ethers.id("h3"), AGENT_ID, 1, 10, "uri3"); // AML, Chain 10
    });

    it("should return the correct report count", async function () {
      expect(await vault.getReportCount()).to.equal(3);
    });

    it("should filter reports by type", async function () {
      const amlReports = await vault.getReportsByType(1);
      expect(amlReports.length).to.equal(2);
      expect(amlReports[0].reportType).to.equal(1);
      expect(amlReports[1].reportType).to.equal(1);
    });

    it("should filter reports by chain", async function () {
      const chain1Reports = await vault.getReportsByChain(1);
      expect(chain1Reports.length).to.equal(2);
      expect(chain1Reports[0].chainId).to.equal(1);
      expect(chain1Reports[1].chainId).to.equal(1);
    });

    it("should revert if retrieving a non-existent report", async function () {
      const fakeHash = ethers.id("fake");
      await expect(vault.getReport(fakeHash))
        .to.be.revertedWithCustomError(vault, "ReportNotFound")
        .withArgs(fakeHash);
    });
  });
});
