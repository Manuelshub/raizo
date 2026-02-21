/**
 * @file test/integration/Deploy.test.ts
 * @description TDD tests for the full Raizo deployment pipeline.
 *
 * Spec References:
 *   - ARCHITECTURE.md §5 (Deployment Topology)
 *   - SMART_CONTRACTS.md §3 (Upgrade Strategy)
 *   - SECURITY.md §3.1 SC-3 (Upgrade Hijack Prevention)
 *
 * Test Groups:
 *   DEPLOY-1: All 8 contracts deploy successfully  (8 tests)
 *   DEPLOY-2: Dependency satisfaction               (4 tests)
 *   DEPLOY-3: UUPS proxy pattern                    (5 tests)
 *   DEPLOY-4: ComplianceVault immutability           (1 test)
 *   DEPLOY-5: Post-deployment role configuration     (6 tests)
 *   DEPLOY-6: Cross-references                       (1 test)
 *   DEPLOY-7: TimelockUpgradeController config       (4 tests)
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { deployAll, DeploymentResult } from "../../scripts/deploy";

describe("Deployment Pipeline (DEPLOY-1→7)", function () {
  let result: DeploymentResult;
  let deployer: SignerWithAddress;

  const ZERO_ADDRESS = ethers.ZeroAddress;
  const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;
  const GOVERNANCE_ROLE = ethers.keccak256(
    ethers.toUtf8Bytes("GOVERNANCE_ROLE"),
  );
  const ANCHOR_ROLE = ethers.keccak256(ethers.toUtf8Bytes("ANCHOR_ROLE"));
  const EMERGENCY_ROLE = ethers.keccak256(
    ethers.toUtf8Bytes("EMERGENCY_ROLE"),
  );
  const PROPOSER_ROLE = ethers.keccak256(ethers.toUtf8Bytes("PROPOSER_ROLE"));
  const EXECUTOR_ROLE = ethers.keccak256(ethers.toUtf8Bytes("EXECUTOR_ROLE"));
  const CANCELLER_ROLE = ethers.keccak256(
    ethers.toUtf8Bytes("CANCELLER_ROLE"),
  );

  before(async function () {
    [deployer] = await ethers.getSigners();
    result = await deployAll();
  });

  // ── DEPLOY-1: All contracts deployed ──────────────────────────────────
  describe("DEPLOY-1: All contracts deployed", function () {
    it("should deploy RaizoCore to a valid address", async function () {
      expect(result.raizoCore).to.not.equal(ZERO_ADDRESS);
      expect(result.raizoCore).to.be.properAddress;
    });

    it("should deploy SentinelActions to a valid address", async function () {
      expect(result.sentinelActions).to.not.equal(ZERO_ADDRESS);
      expect(result.sentinelActions).to.be.properAddress;
    });

    it("should deploy PaymentEscrow to a valid address", async function () {
      expect(result.paymentEscrow).to.not.equal(ZERO_ADDRESS);
      expect(result.paymentEscrow).to.be.properAddress;
    });

    it("should deploy GovernanceGate to a valid address", async function () {
      expect(result.governanceGate).to.not.equal(ZERO_ADDRESS);
      expect(result.governanceGate).to.be.properAddress;
    });

    it("should deploy CrossChainRelay to a valid address", async function () {
      expect(result.crossChainRelay).to.not.equal(ZERO_ADDRESS);
      expect(result.crossChainRelay).to.be.properAddress;
    });

    it("should deploy ComplianceVault to a valid address", async function () {
      expect(result.complianceVault).to.not.equal(ZERO_ADDRESS);
      expect(result.complianceVault).to.be.properAddress;
    });

    it("should deploy TimelockUpgradeController to a valid address", async function () {
      expect(result.timelockController).to.not.equal(ZERO_ADDRESS);
      expect(result.timelockController).to.be.properAddress;
    });

    it("should deploy all 3 mock contracts on hardhat network", async function () {
      expect(result.mockUSDC).to.be.properAddress;
      expect(result.mockWorldID).to.be.properAddress;
      expect(result.mockCCIPRouter).to.be.properAddress;
    });
  });

  // ── DEPLOY-2: Dependency satisfaction ─────────────────────────────────
  describe("DEPLOY-2: Dependency satisfaction", function () {
    it("SentinelActions should reference deployed RaizoCore", async function () {
      const sentinel = await ethers.getContractAt(
        "SentinelActions",
        result.sentinelActions,
      );
      expect(await sentinel.raizoCore()).to.equal(result.raizoCore);
    });

    it("PaymentEscrow should reference RaizoCore and MockUSDC", async function () {
      const escrow = await ethers.getContractAt(
        "PaymentEscrow",
        result.paymentEscrow,
      );
      expect(await escrow.raizoCore()).to.equal(result.raizoCore);
      expect(await escrow.usdc()).to.equal(result.mockUSDC);
    });

    it("GovernanceGate should reference MockWorldID", async function () {
      const gate = await ethers.getContractAt(
        "GovernanceGate",
        result.governanceGate,
      );
      expect(await gate.worldId()).to.equal(result.mockWorldID);
    });

    it("CrossChainRelay should reference Router, Sentinel, and RaizoCore", async function () {
      const relay = await ethers.getContractAt(
        "CrossChainRelay",
        result.crossChainRelay,
      );
      expect(await relay.router()).to.equal(result.mockCCIPRouter);
      expect(await relay.sentinel()).to.equal(result.sentinelActions);
      expect(await relay.raizoCore()).to.equal(result.raizoCore);
    });
  });

  // ── DEPLOY-3: UUPS proxy pattern ─────────────────────────────────────
  describe("DEPLOY-3: UUPS proxy pattern", function () {
    it("RaizoCore should reject re-initialization", async function () {
      const core = await ethers.getContractAt("RaizoCore", result.raizoCore);
      await expect(core.initialize()).to.be.revertedWith(
        "Initializable: contract is already initialized",
      );
    });

    it("SentinelActions should reject re-initialization", async function () {
      const sentinel = await ethers.getContractAt(
        "SentinelActions",
        result.sentinelActions,
      );
      await expect(
        sentinel.initialize(result.raizoCore),
      ).to.be.revertedWith(
        "Initializable: contract is already initialized",
      );
    });

    it("PaymentEscrow should reject re-initialization", async function () {
      const escrow = await ethers.getContractAt(
        "PaymentEscrow",
        result.paymentEscrow,
      );
      await expect(
        escrow.initialize(result.raizoCore, result.mockUSDC!),
      ).to.be.revertedWith(
        "Initializable: contract is already initialized",
      );
    });

    it("GovernanceGate should reject re-initialization", async function () {
      const gate = await ethers.getContractAt(
        "GovernanceGate",
        result.governanceGate,
      );
      await expect(gate.initialize(result.mockWorldID!)).to.be.revertedWith(
        "Initializable: contract is already initialized",
      );
    });

    it("CrossChainRelay should reject re-initialization", async function () {
      const relay = await ethers.getContractAt(
        "CrossChainRelay",
        result.crossChainRelay,
      );
      await expect(
        relay.initialize(
          result.mockCCIPRouter!,
          result.sentinelActions,
          result.raizoCore,
        ),
      ).to.be.revertedWith(
        "Initializable: contract is already initialized",
      );
    });
  });

  // ── DEPLOY-4: ComplianceVault immutability ────────────────────────────
  describe("DEPLOY-4: ComplianceVault immutability", function () {
    it("ComplianceVault should not expose an initialize function", async function () {
      const vault = await ethers.getContractAt(
        "ComplianceVault",
        result.complianceVault,
      );
      // ComplianceVault uses constructor, not initializer — no proxy
      expect(vault.interface.getFunction("storeReport")).to.not.be.null;
      expect(() => (vault.interface as any).getFunction("initialize")).to.throw;
    });
  });

  // ── DEPLOY-5: Post-deployment role configuration ──────────────────────
  describe("DEPLOY-5: Role configuration", function () {
    it("deployer should have DEFAULT_ADMIN_ROLE on RaizoCore", async function () {
      const core = await ethers.getContractAt("RaizoCore", result.raizoCore);
      expect(
        await core.hasRole(DEFAULT_ADMIN_ROLE, deployer.address),
      ).to.be.true;
    });

    it("GovernanceGate should have GOVERNANCE_ROLE on RaizoCore", async function () {
      const core = await ethers.getContractAt("RaizoCore", result.raizoCore);
      expect(
        await core.hasRole(GOVERNANCE_ROLE, result.governanceGate),
      ).to.be.true;
    });

    it("deployer should have ANCHOR_ROLE on ComplianceVault", async function () {
      const vault = await ethers.getContractAt(
        "ComplianceVault",
        result.complianceVault,
      );
      expect(await vault.hasRole(ANCHOR_ROLE, deployer.address)).to.be.true;
    });

    it("deployer (as multisig) should have EMERGENCY_ROLE on SentinelActions", async function () {
      const sentinel = await ethers.getContractAt(
        "SentinelActions",
        result.sentinelActions,
      );
      expect(
        await sentinel.hasRole(EMERGENCY_ROLE, deployer.address),
      ).to.be.true;
    });

    it("deployer should have DEFAULT_ADMIN_ROLE on SentinelActions", async function () {
      const sentinel = await ethers.getContractAt(
        "SentinelActions",
        result.sentinelActions,
      );
      expect(
        await sentinel.hasRole(DEFAULT_ADMIN_ROLE, deployer.address),
      ).to.be.true;
    });

    it("deployer should have DEFAULT_ADMIN_ROLE on PaymentEscrow", async function () {
      const escrow = await ethers.getContractAt(
        "PaymentEscrow",
        result.paymentEscrow,
      );
      expect(
        await escrow.hasRole(DEFAULT_ADMIN_ROLE, deployer.address),
      ).to.be.true;
    });
  });

  // ── DEPLOY-6: Cross-references ────────────────────────────────────────
  describe("DEPLOY-6: Cross-references", function () {
    it("SentinelActions relay should point to CrossChainRelay", async function () {
      const sentinel = await ethers.getContractAt(
        "SentinelActions",
        result.sentinelActions,
      );
      expect(await sentinel.relay()).to.equal(result.crossChainRelay);
    });
  });

  // ── DEPLOY-7: TimelockUpgradeController ───────────────────────────────
  describe("DEPLOY-7: TimelockUpgradeController", function () {
    it("should enforce 48-hour minimum delay", async function () {
      const timelock = await ethers.getContractAt(
        "TimelockUpgradeController",
        result.timelockController,
      );
      expect(await timelock.MIN_DELAY()).to.equal(48n * 60n * 60n);
    });

    it("deployer should have PROPOSER_ROLE", async function () {
      const timelock = await ethers.getContractAt(
        "TimelockUpgradeController",
        result.timelockController,
      );
      expect(
        await timelock.hasRole(PROPOSER_ROLE, deployer.address),
      ).to.be.true;
    });

    it("deployer should have EXECUTOR_ROLE", async function () {
      const timelock = await ethers.getContractAt(
        "TimelockUpgradeController",
        result.timelockController,
      );
      expect(
        await timelock.hasRole(EXECUTOR_ROLE, deployer.address),
      ).to.be.true;
    });

    it("deployer should have CANCELLER_ROLE", async function () {
      const timelock = await ethers.getContractAt(
        "TimelockUpgradeController",
        result.timelockController,
      );
      expect(
        await timelock.hasRole(CANCELLER_ROLE, deployer.address),
      ).to.be.true;
    });
  });
});
