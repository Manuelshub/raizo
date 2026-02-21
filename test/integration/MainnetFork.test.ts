/**
 * @file test/integration/MainnetFork.test.ts
 * @description Full-stack deployment integration tests.
 *
 * Spec References:
 *   - SMART_CONTRACTS.md §4: Deployment dependency matrix
 *   - ws8-implementation-guide.md: FORK-1→4
 *
 * Note: These tests run on the local hardhat network (not a real fork)
 * to verify end-to-end contract interaction through the deploy pipeline.
 *
 * Test Groups:
 *   FORK-1: Full deploy pipeline execution
 *   FORK-2: Post-deployment cross-contract calls
 *   FORK-3: End-to-end threat → action → compliance cycle
 *   FORK-4: Timelock integration with deployed contracts
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { deployAll, DeploymentResult } from "../../scripts/deploy";
import {
  RaizoCore,
  SentinelActions,
  PaymentEscrow,
  GovernanceGate,
  CrossChainRelay,
  ComplianceVault,
  TimelockUpgradeController,
} from "../../typechain-types";
import { ISentinelActions } from "../../typechain-types/contracts/core/interfaces/ISentinelActions";

describe("MainnetFork (FORK-1→4)", function () {
  let result: DeploymentResult;
  let deployer: SignerWithAddress;
  let node1: SignerWithAddress;
  let node2: SignerWithAddress;
  let agentWallet: SignerWithAddress;

  let raizoCore: RaizoCore;
  let sentinel: SentinelActions;
  let complianceVault: ComplianceVault;
  let governanceGate: GovernanceGate;
  let crossChainRelay: CrossChainRelay;
  let paymentEscrow: PaymentEscrow;
  let timelock: TimelockUpgradeController;

  const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("mainnet-test-agent"));
  const PROTOCOL_A = "0x0000000000000000000000000000000000000001";
  const CHAIN_ID = 1;
  const RISK_MEDIUM = 2;
  const BUDGET_USDC = ethers.parseUnits("100", 6);
  const THRESHOLD_BPS = 8500;
  const CONFIDENCE_HIGH = 9000;

  before(async function () {
    [deployer, node1, node2, agentWallet] = await ethers.getSigners();

    // Deploy entire Raizo stack through the deploy script
    result = await deployAll();

    // Attach typed interfaces to all contracts
    raizoCore = (await ethers.getContractAt(
      "RaizoCore",
      result.raizoCore,
    )) as unknown as RaizoCore;
    sentinel = (await ethers.getContractAt(
      "SentinelActions",
      result.sentinelActions,
    )) as unknown as SentinelActions;
    paymentEscrow = (await ethers.getContractAt(
      "PaymentEscrow",
      result.paymentEscrow,
    )) as unknown as PaymentEscrow;
    governanceGate = (await ethers.getContractAt(
      "GovernanceGate",
      result.governanceGate,
    )) as unknown as GovernanceGate;
    crossChainRelay = (await ethers.getContractAt(
      "CrossChainRelay",
      result.crossChainRelay,
    )) as unknown as CrossChainRelay;
    complianceVault = (await ethers.getContractAt(
      "ComplianceVault",
      result.complianceVault,
    )) as unknown as ComplianceVault;
    timelock = (await ethers.getContractAt(
      "TimelockUpgradeController",
      result.timelockController,
    )) as unknown as TimelockUpgradeController;
  });

  // ── FORK-1: Full deploy pipeline execution ────────────────────────────
  describe("FORK-1: Full deploy pipeline execution", function () {
    it("should deploy all 8 contracts to non-zero addresses", function () {
      expect(result.raizoCore).to.not.equal(ethers.ZeroAddress);
      expect(result.sentinelActions).to.not.equal(ethers.ZeroAddress);
      expect(result.paymentEscrow).to.not.equal(ethers.ZeroAddress);
      expect(result.governanceGate).to.not.equal(ethers.ZeroAddress);
      expect(result.crossChainRelay).to.not.equal(ethers.ZeroAddress);
      expect(result.complianceVault).to.not.equal(ethers.ZeroAddress);
      expect(result.timelockController).to.not.equal(ethers.ZeroAddress);
    });

    it("should deploy mock contracts on hardhat network", function () {
      expect(result.mockUSDC).to.not.be.undefined;
      expect(result.mockWorldID).to.not.be.undefined;
      expect(result.mockCCIPRouter).to.not.be.undefined;
    });
  });

  // ── FORK-2: Post-deployment cross-contract calls ──────────────────────
  describe("FORK-2: Post-deployment cross-contract calls", function () {
    it("should have SentinelActions wired to RaizoCore", async function () {
      const coreAddr = await sentinel.raizoCore();
      expect(coreAddr).to.equal(result.raizoCore);
    });

    it("should have CrossChainRelay wired to SentinelActions", async function () {
      const sentinelAddr = await crossChainRelay.sentinel();
      expect(sentinelAddr).to.equal(result.sentinelActions);
    });

    it("should have SentinelActions relay set to CrossChainRelay", async function () {
      const relayAddr = await sentinel.relay();
      expect(relayAddr).to.equal(result.crossChainRelay);
    });
  });

  // ── FORK-3: End-to-end threat → action → compliance cycle ────────────
  describe("FORK-3: End-to-end threat → action → compliance", function () {
    before(async function () {
      // Register protocol and agent through RaizoCore
      // deployer has DEFAULT_ADMIN_ROLE, which allows granting roles
      const GOVERNANCE_ROLE = await raizoCore.GOVERNANCE_ROLE();
      // Grant GOVERNANCE_ROLE to deployer for test setup
      await raizoCore.grantRole(GOVERNANCE_ROLE, deployer.address);
      await raizoCore.registerProtocol(PROTOCOL_A, CHAIN_ID, RISK_MEDIUM);
      await raizoCore.registerAgent(
        AGENT_ID,
        agentWallet.address,
        BUDGET_USDC,
      );
      await raizoCore.setConfidenceThreshold(THRESHOLD_BPS);
    });

    it("should execute a full threat-report → sentinel action → compliance record cycle", async function () {
      // 1. Build threat report
      const reportId = ethers.keccak256(ethers.toUtf8Bytes("fork-e2e-report"));
      const report: ISentinelActions.ThreatReportStruct = {
        reportId,
        agentId: AGENT_ID,
        exists: false,
        targetProtocol: PROTOCOL_A,
        action: 0, // PAUSE
        severity: 3, // CRITICAL
        confidenceScore: CONFIDENCE_HIGH,
        evidenceHash: ethers.toUtf8Bytes("e2e-evidence"),
        timestamp: (await ethers.provider.getBlock("latest"))!.timestamp,
        donSignatures: "0x",
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

      // 2. Execute action on SentinelActions
      await expect(sentinel.executeAction(report)).to.emit(
        sentinel,
        "ActionExecuted",
      );

      // 3. Verify protocol is paused
      expect(await sentinel.isProtocolPaused(PROTOCOL_A)).to.be.true;

      // 4. Store compliance record
      const ANCHOR_ROLE = ethers.keccak256(ethers.toUtf8Bytes("ANCHOR_ROLE"));
      const complianceHash = ethers.keccak256(
        ethers.toUtf8Bytes("fork-compliance-record"),
      );
      await complianceVault.storeReport(
        complianceHash,
        AGENT_ID,
        1, // reportType (1-5 valid)
        1, // chainId
        "ipfs://fork-e2e-compliance",
      );
    });
  });

  // ── FORK-4: Timelock integration with deployed contracts ──────────────
  describe("FORK-4: Timelock integration", function () {
    it("should have correct timelock roles for deployer", async function () {
      const PROPOSER_ROLE = ethers.keccak256(
        ethers.toUtf8Bytes("PROPOSER_ROLE"),
      );
      const EXECUTOR_ROLE = ethers.keccak256(
        ethers.toUtf8Bytes("EXECUTOR_ROLE"),
      );
      const CANCELLER_ROLE = ethers.keccak256(
        ethers.toUtf8Bytes("CANCELLER_ROLE"),
      );

      // On hardhat network, deployer is used for all roles
      expect(await timelock.hasRole(PROPOSER_ROLE, deployer.address)).to.be
        .true;
      expect(await timelock.hasRole(EXECUTOR_ROLE, deployer.address)).to.be
        .true;
      expect(await timelock.hasRole(CANCELLER_ROLE, deployer.address)).to.be
        .true;
    });

    it("should be able to propose an upgrade through the timelock", async function () {
      const tx = await timelock.proposeUpgrade(
        result.raizoCore,
        "0x0000000000000000000000000000000000000099",
      );
      const receipt = await tx.wait();
      const event = receipt?.logs.find((log) => {
        try {
          return (
            timelock.interface.parseLog(log as any)?.name === "UpgradeProposed"
          );
        } catch {
          return false;
        }
      });
      expect(event).to.not.be.undefined;
    });
  });
});
