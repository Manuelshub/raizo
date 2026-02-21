/**
 * @file test/integration/GasBudgets.test.ts
 * @description Gas profiling tests for core contract operations.
 *
 * Spec References:
 *   - SMART_CONTRACTS.md §6: Gas targets per operation
 *   - ws8-implementation-guide.md: CI hard-fail thresholds at ~2× spec target
 *
 * Aspirational targets from spec vs CI hard-fail thresholds:
 *   ┌─────────────────────┬──────────────┬─────────────────┐
 *   │ Operation           │ Spec Target  │ CI Hard-Fail    │
 *   ├─────────────────────┼──────────────┼─────────────────┤
 *   │ executeAction       │ <150k        │ <500k           │
 *   │ storeReport (vault) │ <80k         │ <400k           │
 *   │ vote                │ <250k        │ <300k           │
 *   │ sendAlert           │ <100k        │ <200k           │
 *   │ authorizePayment    │ <60k         │ <300k           │
 *   └─────────────────────┴──────────────┴─────────────────┘
 *
 * Test Groups:
 *   GAS-1: SentinelActions.executeAction gas measurement
 *   GAS-2: ComplianceVault.storeReport gas measurement
 *   GAS-3: GovernanceGate.vote gas measurement
 *   GAS-4: CrossChainRelay.sendAlert gas measurement
 *   GAS-5: PaymentEscrow.authorizePayment gas measurement
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import {
  RaizoCore,
  SentinelActions,
  PaymentEscrow,
  GovernanceGate,
  CrossChainRelay,
  ComplianceVault,
  MockUSDC,
  MockWorldID,
  MockCCIPRouter,
} from "../../typechain-types";
import { ISentinelActions } from "../../typechain-types/contracts/core/interfaces/ISentinelActions";

describe("GasBudgets (GAS-1→5)", function () {
  // ── Shared state ──
  let owner: SignerWithAddress;
  let agentWallet: SignerWithAddress;
  let node1: SignerWithAddress;
  let node2: SignerWithAddress;
  let voter: SignerWithAddress;

  let raizoCore: RaizoCore;
  let sentinel: SentinelActions;
  let paymentEscrow: PaymentEscrow;
  let governanceGate: GovernanceGate;
  let crossChainRelay: CrossChainRelay;
  let complianceVault: ComplianceVault;
  let mockUsdc: MockUSDC;
  let mockWorldId: MockWorldID;
  let mockRouter: MockCCIPRouter;

  const PROTOCOL_A = "0x0000000000000000000000000000000000000001";
  const CHAIN_ID = 1;
  const RISK_MEDIUM = 2;
  const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("threat-sentinel-v1"));
  const CONFIDENCE_HIGH = 9000;
  const BUDGET_USDC = ethers.parseUnits("1000", 6);
  const THRESHOLD_BPS = 8500;
  const ACTION_BUDGET = 10;

  /**
   * Helper: build a ThreatReport struct with 2 DON signatures.
   */
  async function createReport(overrides: Partial<ISentinelActions.ThreatReportStruct> = {}) {
    const report: ISentinelActions.ThreatReportStruct = {
      reportId: ethers.keccak256(ethers.toUtf8Bytes(Math.random().toString())),
      agentId: AGENT_ID,
      exists: false,
      targetProtocol: PROTOCOL_A,
      action: 0, // PAUSE
      severity: 3, // CRITICAL
      confidenceScore: CONFIDENCE_HIGH,
      evidenceHash: ethers.toUtf8Bytes("evidence-cid"),
      timestamp: (await ethers.provider.getBlock("latest"))!.timestamp,
      donSignatures: "0x",
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

  before(async function () {
    [owner, agentWallet, node1, node2, voter] = await ethers.getSigners();

    // ── Deploy mocks ──
    const MockUSDCFactory = await ethers.getContractFactory("MockUSDC");
    mockUsdc = (await MockUSDCFactory.deploy()) as unknown as MockUSDC;
    await mockUsdc.waitForDeployment();

    const MockWorldIDFactory = await ethers.getContractFactory("MockWorldID");
    mockWorldId =
      (await MockWorldIDFactory.deploy()) as unknown as MockWorldID;
    await mockWorldId.waitForDeployment();

    const MockRouterFactory =
      await ethers.getContractFactory("MockCCIPRouter");
    mockRouter =
      (await MockRouterFactory.deploy()) as unknown as MockCCIPRouter;
    await mockRouter.waitForDeployment();

    // ── Deploy RaizoCore ──
    const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
    raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
      initializer: "initialize",
      kind: "uups",
    })) as unknown as RaizoCore;
    await raizoCore.waitForDeployment();

    // ── Deploy SentinelActions ──
    const SentinelActionsFactory =
      await ethers.getContractFactory("SentinelActions");
    sentinel = (await upgrades.deployProxy(
      SentinelActionsFactory,
      [await raizoCore.getAddress()],
      { initializer: "initialize", kind: "uups" },
    )) as unknown as SentinelActions;
    await sentinel.waitForDeployment();

    // ── Deploy PaymentEscrow ──
    const PaymentEscrowFactory =
      await ethers.getContractFactory("PaymentEscrow");
    paymentEscrow = (await upgrades.deployProxy(
      PaymentEscrowFactory,
      [await raizoCore.getAddress(), await mockUsdc.getAddress()],
      { initializer: "initialize", kind: "uups" },
    )) as unknown as PaymentEscrow;
    await paymentEscrow.waitForDeployment();

    // ── Deploy GovernanceGate ──
    const GovernanceGateFactory =
      await ethers.getContractFactory("GovernanceGate");
    governanceGate = (await upgrades.deployProxy(
      GovernanceGateFactory,
      [await mockWorldId.getAddress()],
      { initializer: "initialize", kind: "uups" },
    )) as unknown as GovernanceGate;
    await governanceGate.waitForDeployment();

    // ── Deploy CrossChainRelay ──
    const CrossChainRelayFactory =
      await ethers.getContractFactory("CrossChainRelay");
    crossChainRelay = (await upgrades.deployProxy(
      CrossChainRelayFactory,
      [
        await mockRouter.getAddress(),
        await sentinel.getAddress(),
        await raizoCore.getAddress(),
      ],
      { initializer: "initialize", kind: "uups" },
    )) as unknown as CrossChainRelay;
    await crossChainRelay.waitForDeployment();

    // ── Deploy ComplianceVault ──
    const ComplianceVaultFactory =
      await ethers.getContractFactory("ComplianceVault");
    complianceVault =
      (await ComplianceVaultFactory.deploy()) as unknown as ComplianceVault;
    await complianceVault.waitForDeployment();

    // ── Post-deployment wiring ──
    const GOVERNANCE_ROLE = await raizoCore.GOVERNANCE_ROLE();
    const EMERGENCY_ROLE = ethers.keccak256(
      ethers.toUtf8Bytes("EMERGENCY_ROLE"),
    );
    const ANCHOR_ROLE = ethers.keccak256(ethers.toUtf8Bytes("ANCHOR_ROLE"));

    await raizoCore.grantRole(GOVERNANCE_ROLE, owner.address);
    await sentinel.grantRole(EMERGENCY_ROLE, owner.address);
    await complianceVault.grantRole(ANCHOR_ROLE, owner.address);

    // Register protocol and agent
    await raizoCore.registerProtocol(PROTOCOL_A, CHAIN_ID, RISK_MEDIUM);
    await raizoCore.registerAgent(
      AGENT_ID,
      agentWallet.address,
      BUDGET_USDC,
    );
    await raizoCore.setConfidenceThreshold(THRESHOLD_BPS);

    // Wire relay
    await sentinel.setRelay(await crossChainRelay.getAddress());
  });

  // ── GAS-1: SentinelActions.executeAction ──────────────────────────────
  describe("GAS-1: SentinelActions.executeAction", function () {
    it("should execute under 500k gas (CI hard-fail)", async function () {
      const report = await createReport();
      const tx = await sentinel.executeAction(report);
      const receipt = await tx.wait();
      const gasUsed = receipt!.gasUsed;

      console.log(`      ⛽ executeAction gas: ${gasUsed.toString()}`);
      expect(gasUsed).to.be.lte(500_000n);
    });
  });

  // ── GAS-2: ComplianceVault.storeReport ────────────────────────────────
  describe("GAS-2: ComplianceVault.storeReport", function () {
    it("should store under 400k gas (CI hard-fail)", async function () {
      const reportHash = ethers.keccak256(
        ethers.toUtf8Bytes("compliance-report-gas-test"),
      );
      const tx = await complianceVault.storeReport(
        reportHash,
        AGENT_ID,
        1, // reportType (1-5 are valid)
        1, // chainId
        "ipfs://gas-test-report",
      );
      const receipt = await tx.wait();
      const gasUsed = receipt!.gasUsed;

      console.log(`      ⛽ storeReport gas: ${gasUsed.toString()}`);
      expect(gasUsed).to.be.lte(400_000n);
    });
  });

  // ── GAS-3: GovernanceGate.vote ────────────────────────────────────────
  describe("GAS-3: GovernanceGate.vote", function () {
    it("should vote under 300k gas (CI hard-fail)", async function () {
      // First create a proposal to vote on
      const descHash = ethers.keccak256(ethers.toUtf8Bytes("gas-test-prop"));
      const proposeTx = await governanceGate.propose(
        descHash,
        1, // root
        1001, // nullifierHash (unique)
        [1, 2, 3, 4, 5, 6, 7, 8], // proof (MockWorldID passes all non-deadbeef)
      );
      const propReceipt = await proposeTx.wait();
      const propEvent = propReceipt?.logs.find((log) => {
        try {
          return (
            governanceGate.interface.parseLog(log as any)?.name ===
            "ProposalCreated"
          );
        } catch {
          return false;
        }
      });
      const proposalId =
        governanceGate.interface.parseLog(propEvent as any)?.args?.proposalId;

      // Now vote on it
      const tx = await governanceGate.vote(
        proposalId,
        true, // support
        2, // root
        2001, // different nullifierHash
        [1, 2, 3, 4, 5, 6, 7, 8], // proof
      );
      const receipt = await tx.wait();
      const gasUsed = receipt!.gasUsed;

      console.log(`      ⛽ vote gas: ${gasUsed.toString()}`);
      expect(gasUsed).to.be.lte(300_000n);
    });
  });

  // ── GAS-4: CrossChainRelay.sendAlert ──────────────────────────────────
  describe("GAS-4: CrossChainRelay.sendAlert", function () {
    it("should send alert under 200k gas (CI hard-fail)", async function () {
      const reportId = ethers.keccak256(ethers.toUtf8Bytes("gas-alert-test"));
      const tx = await crossChainRelay.sendAlert(
        1, // destChainSelector
        reportId,
        3, // ALERT actionType
        PROTOCOL_A,
        "0x", // payload
      );
      const receipt = await tx.wait();
      const gasUsed = receipt!.gasUsed;

      console.log(`      ⛽ sendAlert gas: ${gasUsed.toString()}`);
      expect(gasUsed).to.be.lte(200_000n);
    });
  });

  // ── GAS-5: PaymentEscrow.authorizePayment ─────────────────────────────
  describe("GAS-5: PaymentEscrow.authorizePayment", function () {
    it("should authorize under 300k gas (CI hard-fail)", async function () {
      // Fund agent wallet in escrow
      const depositAmount = ethers.parseUnits("500", 6);
      await mockUsdc.mint(owner.address, depositAmount);
      await mockUsdc.approve(
        await paymentEscrow.getAddress(),
        depositAmount,
      );
      await paymentEscrow.deposit(AGENT_ID, depositAmount);

      // Build EIP-712 typed data for authorizePayment
      const to = voter.address;
      const amount = ethers.parseUnits("10", 6);
      const validAfter = 0;
      const latestBlock = await ethers.provider.getBlock("latest");
      const validBefore = latestBlock!.timestamp + 86400;
      const nonce = ethers.keccak256(ethers.toUtf8Bytes("gas-test-nonce"));

      const domain = {
        name: "PaymentEscrow",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: await paymentEscrow.getAddress(),
      };

      const types = {
        AuthorizePayment: [
          { name: "agentId", type: "bytes32" },
          { name: "to", type: "address" },
          { name: "amount", type: "uint256" },
          { name: "validAfter", type: "uint256" },
          { name: "validBefore", type: "uint256" },
          { name: "nonce", type: "bytes32" },
        ],
      };

      const value = {
        agentId: AGENT_ID,
        to,
        amount,
        validAfter,
        validBefore,
        nonce,
      };

      const signature = await agentWallet.signTypedData(domain, types, value);

      const tx = await paymentEscrow.authorizePayment(
        AGENT_ID,
        to,
        amount,
        validAfter,
        validBefore,
        nonce,
        signature,
      );
      const receipt = await tx.wait();
      const gasUsed = receipt!.gasUsed;

      console.log(`      ⛽ authorizePayment gas: ${gasUsed.toString()}`);
      expect(gasUsed).to.be.lte(300_000n);
    });
  });
});
