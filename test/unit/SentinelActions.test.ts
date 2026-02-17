import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { SentinelActions, RaizoCore } from "../../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("SentinelActions (Upgradeable)", function () {
  let sentinel: SentinelActions;
  let raizoCore: RaizoCore;
  let owner: SignerWithAddress;
  let emergency: SignerWithAddress;
  let agentWallet: SignerWithAddress;
  let node1: SignerWithAddress;
  let node2: SignerWithAddress;
  let node3: SignerWithAddress;
  let addr1: SignerWithAddress;

  const EMERGENCY_ROLE = ethers.keccak256(ethers.toUtf8Bytes("EMERGENCY_ROLE"));
  const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;

  const PROTOCOL_A = "0x0000000000000000000000000000000000000001";
  const CHAIN_ID = 1;
  const RISK_MEDIUM = 2;
  const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("threat-sentinel-v1"));
  const CONFIDENCE_HIGH = 9000; // 90%
  const CONFIDENCE_LOW = 7000; // 70%
  const BUDGET_USDC = ethers.parseUnits("100", 6);
  const ACTION_BUDGET = 10;

  const THRESHOLD_BPS = 8500;

  beforeEach(async function () {
    [owner, emergency, agentWallet, node1, node2, node3, addr1] =
      await ethers.getSigners();

    const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
    raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
      initializer: "initialize",
      kind: "uups",
    })) as unknown as RaizoCore;
    await raizoCore.waitForDeployment();

    const SentinelActionsFactory = await ethers.getContractFactory(
      "SentinelActions",
    );
    sentinel = (await upgrades.deployProxy(
      SentinelActionsFactory,
      [await raizoCore.getAddress()],
      {
        initializer: "initialize",
        kind: "uups",
      },
    )) as unknown as SentinelActions;
    await sentinel.waitForDeployment();

    const GOVERNANCE_ROLE = await raizoCore.GOVERNANCE_ROLE();
    await raizoCore.grantRole(GOVERNANCE_ROLE, owner.address);
    await sentinel.grantRole(EMERGENCY_ROLE, emergency.address);
    await raizoCore.registerProtocol(PROTOCOL_A, CHAIN_ID, RISK_MEDIUM);
    await raizoCore.registerAgent(AGENT_ID, agentWallet.address, BUDGET_USDC);
    await raizoCore.setConfidenceThreshold(THRESHOLD_BPS);
  });

  async function createReport(overrides = {}) {
    const report = {
      reportId: ethers.keccak256(ethers.toUtf8Bytes(Math.random().toString())),
      agentId: AGENT_ID,
      exists: false,
      targetProtocol: PROTOCOL_A,
      action: 0,
      severity: 3,
      confidenceScore: CONFIDENCE_HIGH,
      evidenceHash: ethers.toUtf8Bytes("evidence-cid"),
      timestamp: (await ethers.provider.getBlock("latest"))!.timestamp,
      donSignatures: "0x" as string,
      ...overrides,
    };

    const messageHash = ethers.solidityPackedKeccak256(
      [
        "bytes32",
        "bytes32",
        "bool",
        "address",
        "uint8",
        "uint8",
        "uint16",
        "uint256",
      ],
      [
        report.reportId,
        report.agentId,
        report.exists,
        report.targetProtocol,
        report.action,
        report.severity,
        report.confidenceScore,
        report.timestamp,
      ],
    );

    const sig1 = await node1.signMessage(ethers.getBytes(messageHash));
    const sig2 = await node2.signMessage(ethers.getBytes(messageHash));

    report.donSignatures = ethers.concat([sig1, sig2]);

    return report;
  }

  describe("Initialization", function () {
    it("should set correct raizoCore address", async function () {
      expect(await sentinel.raizoCore()).to.equal(await raizoCore.getAddress());
    });

    it("should grant admin role to owner", async function () {
      expect(await sentinel.hasRole(DEFAULT_ADMIN_ROLE, owner.address)).to.be
        .true;
    });
  });

  describe("executeAction", function () {
    it("should execute a valid PAUSE action (2 sigs)", async function () {
      const report = await createReport();
      await expect(sentinel.executeAction(report)).to.emit(
        sentinel,
        "ActionExecuted",
      );
      expect(await sentinel.isProtocolPaused(PROTOCOL_A)).to.be.true;
    });

    it("should revert if confidence score is below threshold", async function () {
      const report = await createReport({ confidenceScore: CONFIDENCE_LOW });
      await expect(sentinel.executeAction(report))
        .to.be.revertedWithCustomError(sentinel, "ConfidenceThresholdNotMet")
        .withArgs(CONFIDENCE_LOW, THRESHOLD_BPS);
    });

    it("should revert on duplicate report", async function () {
      const report = await createReport();
      await sentinel.executeAction(report);
      await expect(sentinel.executeAction(report))
        .to.be.revertedWithCustomError(sentinel, "DuplicateReport")
        .withArgs(report.reportId);
    });

    it("should revert if protocol is not active", async function () {
      const protocolB = "0x0000000000000000000000000000000000000002";
      const report = await createReport({ targetProtocol: protocolB });
      await expect(sentinel.executeAction(report))
        .to.be.revertedWithCustomError(sentinel, "ProtocolNotActive")
        .withArgs(protocolB);
    });

    it("should revert if agent is not active", async function () {
      const agentB = ethers.id("agent-b");
      const report = await createReport({ agentId: agentB });
      await expect(sentinel.executeAction(report))
        .to.be.revertedWithCustomError(sentinel, "AgentNotActive")
        .withArgs(agentB);
    });

    it("should enforce per-epoch budget", async function () {
      for (let i = 0; i < ACTION_BUDGET; i++) {
        const report = await createReport({
          reportId: ethers.id("budget-report-" + i),
        });
        await sentinel.executeAction(report);
      }
      const failReport = await createReport({
        reportId: ethers.id("failed-report"),
      });
      const epoch = Math.floor(
        (await ethers.provider.getBlock("latest"))!.timestamp / 86400,
      );
      await expect(sentinel.executeAction(failReport))
        .to.be.revertedWithCustomError(sentinel, "BudgetExceeded")
        .withArgs(AGENT_ID, epoch);
    });
  });

  describe("executeEmergencyPause", function () {
    it("should allow emergency role to pause", async function () {
      await sentinel.connect(emergency).executeEmergencyPause(PROTOCOL_A);
      expect(await sentinel.isProtocolPaused(PROTOCOL_A)).to.be.true;
    });

    it("should revert if already emergency paused", async function () {
      await sentinel.connect(emergency).executeEmergencyPause(PROTOCOL_A);
      await expect(
        sentinel.connect(emergency).executeEmergencyPause(PROTOCOL_A),
      )
        .to.be.revertedWithCustomError(sentinel, "EmergencyPauseAlreadyActive")
        .withArgs(PROTOCOL_A);
    });
  });

  describe("Hardening: Multi-Report Pausing", function () {
    it("should stay paused if at least one report is active", async function () {
      const report1 = await createReport({ reportId: ethers.id("report-1") });
      const report2 = await createReport({ reportId: ethers.id("report-2") });

      await sentinel.executeAction(report1);
      await sentinel.executeAction(report2);
      expect(await sentinel.isProtocolPaused(PROTOCOL_A)).to.be.true;

      // Lift first report
      await sentinel.liftAction(report1.reportId);
      expect(await sentinel.isProtocolPaused(PROTOCOL_A)).to.be.true;

      // Lift second report
      await sentinel.liftAction(report2.reportId);
      expect(await sentinel.isProtocolPaused(PROTOCOL_A)).to.be.false;
    });

    it("should correctly return all active reports", async function () {
      const report1 = await createReport({ reportId: ethers.id("report-1") });
      const report2 = await createReport({ reportId: ethers.id("report-2") });

      await sentinel.executeAction(report1);
      await sentinel.executeAction(report2);

      const active = await sentinel.getActiveActions(PROTOCOL_A);
      expect(active.length).to.equal(2);
      expect(active[0].reportId).to.equal(report1.reportId);
      expect(active[1].reportId).to.equal(report2.reportId);
    });
  });

  describe("UUPS Upgradability", function () {
    it("should allow owner to upgrade", async function () {
      const SentinelActionsV2 = await ethers.getContractFactory(
        "SentinelActions",
      );
      const v2 = await upgrades.upgradeProxy(
        await sentinel.getAddress(),
        SentinelActionsV2,
      );
      expect(await v2.getAddress()).to.equal(await sentinel.getAddress());
    });
  });
});
