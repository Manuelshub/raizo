/**
 * branch-coverage.test.ts
 *
 * Targeted tests to push branch coverage from 75% → ≥90%.
 * Each test is annotated with the contract, line, and branch it covers.
 * These tests exist ONLY to exercise uncovered conditional paths;
 * functional correctness is already validated in unit/ and fuzz/ suites.
 */
import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import {
  RaizoCore,
  SentinelActions,
  PaymentEscrow,
  GovernanceGate,
  CrossChainRelay,
  MockUSDC,
  MockWorldID,
  MockSentinelActions,
  MockCCIPRouter,
} from "../../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

/* ================================================================
 *  RaizoCore — Branch Coverage (56.25% → target ≥90%)
 * ================================================================ */
describe("RaizoCore Branch Coverage", function () {
  let raizo: RaizoCore;
  let owner: SignerWithAddress;
  let governance: SignerWithAddress;
  let addr1: SignerWithAddress;
  let addr2: SignerWithAddress;

  const GOVERNANCE_ROLE = ethers.keccak256(
    ethers.toUtf8Bytes("GOVERNANCE_ROLE"),
  );
  const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;

  const PROTOCOL_A = "0x0000000000000000000000000000000000000001";
  const PROTOCOL_B = "0x0000000000000000000000000000000000000002";
  const PROTOCOL_C = "0x0000000000000000000000000000000000000003";
  const CHAIN_ID = 1;
  const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("agent-1"));
  const BUDGET_USDC = ethers.parseUnits("1000", 6);

  beforeEach(async function () {
    [owner, governance, addr1, addr2] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("RaizoCore");
    raizo = (await upgrades.deployProxy(Factory, [], {
      initializer: "initialize",
      kind: "uups",
    })) as unknown as RaizoCore;
    await raizo.waitForDeployment();
    await raizo.grantRole(GOVERNANCE_ROLE, governance.address);
  });

  // --- registerProtocol revert paths (Lines 76-78) ---
  describe("registerProtocol guard branches", function () {
    it("reverts on zero address (L76 true branch)", async function () {
      await expect(
        raizo.registerProtocol(ethers.ZeroAddress, CHAIN_ID, 2),
      ).to.be.revertedWithCustomError(raizo, "ZeroAddress");
    });

    it("reverts on riskTier=0 (L77 true branch)", async function () {
      await expect(
        raizo.registerProtocol(PROTOCOL_A, CHAIN_ID, 0),
      ).to.be.revertedWithCustomError(raizo, "InvalidRiskTier");
    });

    it("reverts on riskTier>4 (L77 true branch, upper bound)", async function () {
      await expect(
        raizo.registerProtocol(PROTOCOL_A, CHAIN_ID, 5),
      ).to.be.revertedWithCustomError(raizo, "InvalidRiskTier");
    });

    it("reverts on duplicate registration (L78 true branch)", async function () {
      await raizo.registerProtocol(PROTOCOL_A, CHAIN_ID, 2);
      await expect(
        raizo.registerProtocol(PROTOCOL_A, CHAIN_ID, 3),
      ).to.be.revertedWithCustomError(raizo, "ProtocolAlreadyRegistered");
    });
  });

  // --- deregisterProtocol (Lines 98, 103) ---
  describe("deregisterProtocol guard & loop branches", function () {
    it("reverts on unregistered protocol (L98 true branch)", async function () {
      await expect(
        raizo.deregisterProtocol(PROTOCOL_A),
      ).to.be.revertedWithCustomError(raizo, "ProtocolNotRegistered");
    });

    it("loop iterates past non-matching entries (L103 false→true)", async function () {
      // Register A, B, C; deregister B → loop skips A before matching B
      await raizo.registerProtocol(PROTOCOL_A, CHAIN_ID, 1);
      await raizo.registerProtocol(PROTOCOL_B, CHAIN_ID, 2);
      await raizo.registerProtocol(PROTOCOL_C, CHAIN_ID, 3);

      await raizo.deregisterProtocol(PROTOCOL_B);
      expect((await raizo.getProtocol(PROTOCOL_B)).isActive).to.be.false;

      // Verify remaining protocols still active
      const all = await raizo.getAllProtocols();
      expect(all.length).to.equal(2);
    });

    it("deregister by governance works (L98 modifier branch)", async function () {
      await raizo.registerProtocol(PROTOCOL_A, CHAIN_ID, 2);
      await raizo.connect(governance).deregisterProtocol(PROTOCOL_A);
      expect((await raizo.getProtocol(PROTOCOL_A)).isActive).to.be.false;
    });

    it("non-admin/governance cannot deregister (modifier false branch)", async function () {
      await raizo.registerProtocol(PROTOCOL_A, CHAIN_ID, 2);
      await expect(
        raizo.connect(addr1).deregisterProtocol(PROTOCOL_A),
      ).to.be.revertedWithCustomError(raizo, "CallerNotAdminOrGovernance");
    });
  });

  // --- updateRiskTier (Lines 118-121 — completely untested) ---
  describe("updateRiskTier (all branches)", function () {
    beforeEach(async function () {
      await raizo.registerProtocol(PROTOCOL_A, CHAIN_ID, 2);
    });

    it("admin updates risk tier successfully (L118-121 happy path)", async function () {
      await expect(raizo.updateRiskTier(PROTOCOL_A, 4))
        .to.emit(raizo, "RiskTierUpdated")
        .withArgs(PROTOCOL_A, 2, 4);
      expect((await raizo.getProtocol(PROTOCOL_A)).riskTier).to.equal(4);
    });

    it("governance updates risk tier (L118 modifier branch)", async function () {
      await raizo.connect(governance).updateRiskTier(PROTOCOL_A, 1);
      expect((await raizo.getProtocol(PROTOCOL_A)).riskTier).to.equal(1);
    });

    it("unauthorized caller reverts (L118 modifier revert)", async function () {
      await expect(
        raizo.connect(addr1).updateRiskTier(PROTOCOL_A, 3),
      ).to.be.revertedWithCustomError(raizo, "CallerNotAdminOrGovernance");
    });

    it("unregistered protocol reverts (L119 true branch)", async function () {
      await expect(
        raizo.updateRiskTier(PROTOCOL_B, 2),
      ).to.be.revertedWithCustomError(raizo, "ProtocolNotRegistered");
    });

    it("newTier=0 reverts (L121 true branch, lower bound)", async function () {
      await expect(
        raizo.updateRiskTier(PROTOCOL_A, 0),
      ).to.be.revertedWithCustomError(raizo, "InvalidRiskTier");
    });

    it("newTier=5 reverts (L121 true branch, upper bound)", async function () {
      await expect(
        raizo.updateRiskTier(PROTOCOL_A, 5),
      ).to.be.revertedWithCustomError(raizo, "InvalidRiskTier");
    });
  });

  // --- registerAgent revert paths (Lines 165-166) ---
  describe("registerAgent guard branches", function () {
    it("reverts on zero-address wallet (L165 true branch)", async function () {
      await expect(
        raizo.registerAgent(AGENT_ID, ethers.ZeroAddress, BUDGET_USDC),
      ).to.be.revertedWithCustomError(raizo, "ZeroAddress");
    });

    it("reverts on duplicate agent (L166 true branch)", async function () {
      await raizo.registerAgent(AGENT_ID, addr1.address, BUDGET_USDC);
      await expect(
        raizo.registerAgent(AGENT_ID, addr2.address, BUDGET_USDC),
      ).to.be.revertedWithCustomError(raizo, "AgentAlreadyRegistered");
    });
  });

  // --- deregisterAgent (Lines 183-184 — completely untested) ---
  describe("deregisterAgent (all branches)", function () {
    it("admin deregisters active agent (L183-184 happy path)", async function () {
      await raizo.registerAgent(AGENT_ID, addr1.address, BUDGET_USDC);
      await expect(raizo.deregisterAgent(AGENT_ID))
        .to.emit(raizo, "AgentDeregistered")
        .withArgs(AGENT_ID);
      expect((await raizo.getAgent(AGENT_ID)).isActive).to.be.false;
    });

    it("reverts for non-existent agent (L183 true branch)", async function () {
      const fakeAgent = ethers.id("non-existent");
      await expect(
        raizo.deregisterAgent(fakeAgent),
      ).to.be.revertedWithCustomError(raizo, "AgentNotRegistered");
    });

    it("non-admin cannot deregister (L184 modifier revert)", async function () {
      await raizo.registerAgent(AGENT_ID, addr1.address, BUDGET_USDC);
      await expect(
        raizo.connect(addr1).deregisterAgent(AGENT_ID),
      ).to.be.revertedWith(/AccessControl: account .* is missing role/);
    });
  });

  // --- setConfidenceThreshold success path (L204) ---
  describe("setConfidenceThreshold branches", function () {
    it("governance sets valid threshold (L204 success path)", async function () {
      await expect(raizo.connect(governance).setConfidenceThreshold(9000))
        .to.emit(raizo, "ConfigUpdated")
        .withArgs("confidenceThreshold", 9000);
      expect(await raizo.getConfidenceThreshold()).to.equal(9000);
    });

    it("non-governance reverts (L204 modifier revert)", async function () {
      await expect(
        raizo.connect(addr1).setConfidenceThreshold(9000),
      ).to.be.revertedWith(/AccessControl: account .* is missing role/);
    });

    it("threshold=0 is valid (boundary)", async function () {
      await raizo.connect(governance).setConfidenceThreshold(0);
      expect(await raizo.getConfidenceThreshold()).to.equal(0);
    });

    it("threshold=10000 is valid (boundary)", async function () {
      await raizo.connect(governance).setConfidenceThreshold(10000);
      expect(await raizo.getConfidenceThreshold()).to.equal(10000);
    });
  });

  // --- setEpochDuration guards (L215) ---
  describe("setEpochDuration branches", function () {
    it("duration=0 reverts (L215 true branch)", async function () {
      await expect(
        raizo.setEpochDuration(0),
      ).to.be.revertedWithCustomError(raizo, "InvalidEpochDuration");
    });

    it("non-admin reverts (L215 modifier revert)", async function () {
      await expect(
        raizo.connect(addr1).setEpochDuration(3600),
      ).to.be.revertedWith(/AccessControl: account .* is missing role/);
    });
  });
});

/* ================================================================
 *  SentinelActions — Branch Coverage (80.56% → target ≥90%)
 * ================================================================ */
describe("SentinelActions Branch Coverage", function () {
  let sentinel: SentinelActions;
  let raizoCore: RaizoCore;
  let owner: SignerWithAddress;
  let emergency: SignerWithAddress;
  let agentWallet: SignerWithAddress;
  let node1: SignerWithAddress;
  let node2: SignerWithAddress;
  let addr1: SignerWithAddress;

  const EMERGENCY_ROLE = ethers.keccak256(ethers.toUtf8Bytes("EMERGENCY_ROLE"));
  const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;
  const PROTOCOL_A = "0x0000000000000000000000000000000000000001";
  const CHAIN_ID = 1;
  const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("threat-sentinel-v1"));
  const BUDGET_USDC = ethers.parseUnits("100", 6);

  beforeEach(async function () {
    [owner, emergency, agentWallet, node1, node2, addr1] =
      await ethers.getSigners();

    const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
    raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
      initializer: "initialize",
      kind: "uups",
    })) as unknown as RaizoCore;

    const SentinelFactory = await ethers.getContractFactory("SentinelActions");
    sentinel = (await upgrades.deployProxy(
      SentinelFactory,
      [await raizoCore.getAddress()],
      { initializer: "initialize", kind: "uups" },
    )) as unknown as SentinelActions;

    const GOVERNANCE_ROLE = await raizoCore.GOVERNANCE_ROLE();
    await raizoCore.grantRole(GOVERNANCE_ROLE, owner.address);
    await sentinel.grantRole(EMERGENCY_ROLE, emergency.address);
    await raizoCore.registerProtocol(PROTOCOL_A, CHAIN_ID, 2);
    await raizoCore.registerAgent(AGENT_ID, agentWallet.address, BUDGET_USDC);
    await raizoCore.connect(owner).setConfidenceThreshold(8500);
  });

  async function createReport(overrides: Record<string, unknown> = {}) {
    const report = {
      reportId: ethers.keccak256(ethers.toUtf8Bytes(Math.random().toString())),
      agentId: AGENT_ID,
      exists: false,
      targetProtocol: PROTOCOL_A,
      action: 0,
      severity: 3,
      confidenceScore: 9000,
      evidenceHash: ethers.toUtf8Bytes("ev"),
      timestamp: (await ethers.provider.getBlock("latest"))!.timestamp,
      donSignatures: "0x" as string,
      ...overrides,
    };
    const messageHash = ethers.solidityPackedKeccak256(
      ["bytes32", "bytes32", "bool", "address", "uint8", "uint8", "uint16", "uint256"],
      [report.reportId, report.agentId, report.exists, report.targetProtocol, report.action, report.severity, report.confidenceScore, report.timestamp],
    );
    const sig1 = await node1.signMessage(ethers.getBytes(messageHash));
    const sig2 = await node2.signMessage(ethers.getBytes(messageHash));
    report.donSignatures = ethers.concat([sig1, sig2]);
    return report;
  }

  // --- setRelay (L77 — never called) ---
  describe("setRelay branches", function () {
    it("admin sets relay address (L77 success path)", async function () {
      await sentinel.setRelay(addr1.address);
      // No public getter, but no revert means success
    });

    it("non-admin cannot set relay (L77 modifier revert)", async function () {
      await expect(
        sentinel.connect(addr1).setRelay(addr1.address),
      ).to.be.revertedWith(/AccessControl: account .* is missing role/);
    });
  });

  // --- executeEmergencyPause non-EMERGENCY caller (L184) ---
  describe("executeEmergencyPause ACL", function () {
    it("non-EMERGENCY_ROLE reverts (L184 false branch)", async function () {
      await expect(
        sentinel.connect(addr1).executeEmergencyPause(PROTOCOL_A),
      ).to.be.revertedWith(/AccessControl: account .* is missing role/);
    });
  });

  // --- liftAction branches (L204-214) ---
  describe("liftAction branches", function () {
    it("reverts for non-existent report (L205 true branch)", async function () {
      const fakeId = ethers.id("non-existent");
      await expect(
        sentinel.liftAction(fakeId),
      ).to.be.revertedWithCustomError(sentinel, "ReportNotFound");
    });

    it("reverts for already-lifted (inactive) report (L206 true branch)", async function () {
      const report = await createReport({ reportId: ethers.id("r1") });
      await sentinel.executeAction(report);
      await sentinel.liftAction(report.reportId);
      // Try lifting again → should revert
      await expect(
        sentinel.liftAction(report.reportId),
      ).to.be.revertedWithCustomError(sentinel, "ReportNotActive");
    });

    it("loop skips non-matching entries before finding target (L214 false→true)", async function () {
      // Execute 3 reports, then lift the SECOND one
      const r1 = await createReport({ reportId: ethers.id("r1") });
      const r2 = await createReport({ reportId: ethers.id("r2") });
      const r3 = await createReport({ reportId: ethers.id("r3") });

      await sentinel.executeAction(r1);
      await sentinel.executeAction(r2);
      await sentinel.executeAction(r3);

      // Lift r2 → loop must skip r1 at index 0 before matching r2
      await sentinel.liftAction(r2.reportId);

      const active = await sentinel.getActiveActions(PROTOCOL_A);
      expect(active.length).to.equal(2);
      // Remaining should be r1 and r3 (r3 swapped into r2's slot)
      const activeIds = active.map((a: any) => a.reportId);
      expect(activeIds).to.include(r1.reportId);
      expect(activeIds).to.include(r3.reportId);
    });
  });

  // --- double initialize (L64) ---
  describe("double initialize", function () {
    it("reverts on second initialize call (L64 true branch)", async function () {
      await expect(
        sentinel.initialize(await raizoCore.getAddress()),
      ).to.be.revertedWith("Initializable: contract is already initialized");
    });
  });
});

/* ================================================================
 *  PaymentEscrow — Branch Coverage (80.56% → target ≥90%)
 * ================================================================ */
describe("PaymentEscrow Branch Coverage", function () {
  let escrow: PaymentEscrow;
  let usdc: MockUSDC;
  let raizoCore: RaizoCore;
  let owner: SignerWithAddress;
  let agentWallet: SignerWithAddress;
  let provider: SignerWithAddress;
  let recipient: SignerWithAddress;
  let addr1: SignerWithAddress;

  const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("agent-001"));
  const DAILY_LIMIT = ethers.parseUnits("100", 6);
  const DEPOSIT_AMOUNT = ethers.parseUnits("500", 6);

  beforeEach(async function () {
    [owner, agentWallet, provider, recipient, addr1] =
      await ethers.getSigners();

    const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
    raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
      initializer: "initialize",
      kind: "uups",
    })) as unknown as RaizoCore;

    const MockUSDCFactory = await ethers.getContractFactory("MockUSDC");
    usdc = await MockUSDCFactory.deploy();

    await raizoCore.registerAgent(AGENT_ID, agentWallet.address, DAILY_LIMIT);

    const PaymentEscrowFactory = await ethers.getContractFactory("PaymentEscrow");
    escrow = (await upgrades.deployProxy(
      PaymentEscrowFactory,
      [await raizoCore.getAddress(), await usdc.getAddress()],
      { initializer: "initialize", kind: "uups" },
    )) as unknown as PaymentEscrow;

    await usdc.mint(provider.address, DEPOSIT_AMOUNT);
    await usdc.connect(provider).approve(await escrow.getAddress(), DEPOSIT_AMOUNT);
  });

  async function signPayment(
    agentId: string,
    to: string,
    amount: bigint,
    validAfter: number,
    validBefore: number,
    nonce: string,
    signer: SignerWithAddress = agentWallet,
  ) {
    return signer.signTypedData(
      {
        name: "PaymentEscrow",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: await escrow.getAddress(),
      },
      {
        AuthorizePayment: [
          { name: "agentId", type: "bytes32" },
          { name: "to", type: "address" },
          { name: "amount", type: "uint256" },
          { name: "validAfter", type: "uint256" },
          { name: "validBefore", type: "uint256" },
          { name: "nonce", type: "bytes32" },
        ],
      },
      { agentId, to, amount, validAfter, validBefore, nonce },
    );
  }

  // --- double initialize (L56) ---
  describe("double initialize", function () {
    it("reverts on second initialize call (L56 true branch)", async function () {
      await expect(
        escrow.initialize(await raizoCore.getAddress(), await usdc.getAddress()),
      ).to.be.revertedWith("Initializable: contract is already initialized");
    });
  });

  // --- withdraw overdraw (L106) ---
  describe("withdraw overdraw", function () {
    it("reverts when amount exceeds wallet balance (L106 true branch)", async function () {
      await escrow.connect(provider).deposit(AGENT_ID, DEPOSIT_AMOUNT);
      const overAmount = DEPOSIT_AMOUNT + 1n;
      await expect(
        escrow.withdraw(AGENT_ID, overAmount, owner.address),
      ).to.be.revertedWithCustomError(escrow, "InsufficientBalance");
    });
  });

  // --- getDailyRemaining (L199, L203 — never called) ---
  describe("getDailyRemaining branches", function () {
    beforeEach(async function () {
      await escrow.connect(provider).deposit(AGENT_ID, DEPOSIT_AMOUNT);
    });

    it("returns full budget before any spending (L199 true branch — reset path)", async function () {
      const remaining = await escrow.getDailyRemaining(AGENT_ID);
      expect(remaining).to.equal(DAILY_LIMIT);
    });

    it("returns reduced amount after spending (L199 false branch)", async function () {
      const amount = ethers.parseUnits("30", 6);
      const nonce = ethers.id("n-dr-1");
      const sig = await signPayment(AGENT_ID, recipient.address, amount, 0, 2000000000, nonce);
      await escrow.authorizePayment(AGENT_ID, recipient.address, amount, 0, 2000000000, nonce, sig);

      const remaining = await escrow.getDailyRemaining(AGENT_ID);
      expect(remaining).to.equal(DAILY_LIMIT - amount);
    });

    it("returns 0 when full budget is spent (L203 true branch)", async function () {
      const nonce = ethers.id("n-dr-2");
      const sig = await signPayment(AGENT_ID, recipient.address, DAILY_LIMIT, 0, 2000000000, nonce);
      await escrow.authorizePayment(AGENT_ID, recipient.address, DAILY_LIMIT, 0, 2000000000, nonce, sig);

      const remaining = await escrow.getDailyRemaining(AGENT_ID);
      expect(remaining).to.equal(0);
    });

    it("resets to full budget after 24h (L199 period reset path)", async function () {
      const nonce = ethers.id("n-dr-3");
      const sig = await signPayment(AGENT_ID, recipient.address, DAILY_LIMIT, 0, 2000000000, nonce);
      await escrow.authorizePayment(AGENT_ID, recipient.address, DAILY_LIMIT, 0, 2000000000, nonce, sig);

      // Advance 24h+1s
      await ethers.provider.send("evm_increaseTime", [86401]);
      await ethers.provider.send("evm_mine", []);

      const remaining = await escrow.getDailyRemaining(AGENT_ID);
      expect(remaining).to.equal(DAILY_LIMIT);
    });
  });

  // --- authorizePayment validAfter in future (L131 branch) ---
  describe("authorizePayment timing branches", function () {
    beforeEach(async function () {
      await escrow.connect(provider).deposit(AGENT_ID, DEPOSIT_AMOUNT);
    });

    it("reverts when validAfter is in the future (L131 validAfter branch)", async function () {
      const block = await ethers.provider.getBlock("latest");
      const futureAfter = block!.timestamp + 10000;
      const nonce = ethers.id("n-timing-1");
      const amount = ethers.parseUnits("10", 6);
      const sig = await signPayment(
        AGENT_ID, recipient.address, amount, futureAfter, futureAfter + 3600, nonce,
      );
      await expect(
        escrow.authorizePayment(AGENT_ID, recipient.address, amount, futureAfter, futureAfter + 3600, nonce, sig),
      ).to.be.revertedWithCustomError(escrow, "SignatureExpired");
    });
  });
});

/* ================================================================
 *  GovernanceGate — Branch Coverage (80% → target ≥90%)
 * ================================================================ */
describe("GovernanceGate Branch Coverage", function () {
  let govGate: GovernanceGate;
  let worldId: MockWorldID;
  let owner: SignerWithAddress;
  let proposer: SignerWithAddress;
  let voter: SignerWithAddress;
  let voter2: SignerWithAddress;

  const DESCRIPTION_HASH = ethers.id("Test Proposal");
  const ROOT = 12345;
  const PROOF: [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint] =
    [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];

  beforeEach(async function () {
    [owner, proposer, voter, voter2] = await ethers.getSigners();

    const MockWorldIDFactory = await ethers.getContractFactory("MockWorldID");
    worldId = await MockWorldIDFactory.deploy();

    const GovGateFactory = await ethers.getContractFactory("GovernanceGate");
    govGate = (await upgrades.deployProxy(
      GovGateFactory,
      [await worldId.getAddress()],
      { initializer: "initialize", kind: "uups" },
    )) as unknown as GovernanceGate;
  });

  // --- double initialize (L36) ---
  describe("double initialize", function () {
    it("reverts on second initialize call (L36 true branch)", async function () {
      await expect(
        govGate.initialize(await worldId.getAddress()),
      ).to.be.revertedWith("Initializable: contract is already initialized");
    });
  });

  // --- vote on already-executed proposal (L116 true branch) ---
  describe("vote on executed proposal", function () {
    it("reverts when voting on an already-executed proposal (L116 true branch)", async function () {
      // Create and pass a proposal
      await govGate.connect(proposer).propose(DESCRIPTION_HASH, ROOT, 1001, PROOF);
      await govGate.connect(voter).vote(0, true, ROOT, 2001, PROOF);

      // Mine blocks to end voting period
      for (let i = 0; i < 7201; i++) await ethers.provider.send("evm_mine", []);

      // Execute proposal
      await govGate.execute(0);

      // Try to vote on executed proposal
      await expect(
        govGate.connect(voter2).vote(0, true, ROOT, 3001, PROOF),
      ).to.be.revertedWithCustomError(govGate, "ProposalExpired");
    });
  });

  // --- execute while still active (L149) ---
  describe("execute timing branches", function () {
    it("reverts when executing while proposal is still active (L149 true branch)", async function () {
      await govGate.connect(proposer).propose(DESCRIPTION_HASH, ROOT, 4001, PROOF);
      await govGate.connect(voter).vote(0, true, ROOT, 5001, PROOF);

      // Do NOT mine blocks — proposal is still active
      await expect(govGate.execute(0)).to.be.revertedWithCustomError(
        govGate,
        "ProposalNotActive",
      );
    });

    it("reverts when executing an already-executed proposal (L150 true branch)", async function () {
      await govGate.connect(proposer).propose(DESCRIPTION_HASH, ROOT, 6001, PROOF);
      await govGate.connect(voter).vote(0, true, ROOT, 7001, PROOF);

      for (let i = 0; i < 7201; i++) await ethers.provider.send("evm_mine", []);

      await govGate.execute(0);

      // Second execution attempt
      await expect(govGate.execute(0)).to.be.revertedWithCustomError(
        govGate,
        "ProposalAlreadyExecuted",
      );
    });
  });
});

/* ================================================================
 *  CrossChainRelay — Branch Coverage (80% → target ≥90%)
 * ================================================================ */
describe("CrossChainRelay Branch Coverage", function () {
  let relay: CrossChainRelay;
  let sentinel: MockSentinelActions;
  let router: MockCCIPRouter;
  let raizoCore: RaizoCore;
  let owner: SignerWithAddress;
  let admin: SignerWithAddress;
  let other: SignerWithAddress;

  const SOURCE_CHAIN_SELECTOR = 12345n;
  const DEST_CHAIN_SELECTOR = 67890n;
  const REPORT_ID = ethers.id("threat.report.1");
  const AGENT_ID = ethers.id("agent.1");

  beforeEach(async function () {
    [owner, admin, other] = await ethers.getSigners();

    const MockSentinelFactory = await ethers.getContractFactory("MockSentinelActions");
    sentinel = await MockSentinelFactory.deploy();

    const MockRouterFactory = await ethers.getContractFactory("MockCCIPRouter");
    router = await MockRouterFactory.deploy();

    const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
    raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [])) as unknown as RaizoCore;

    const RelayFactory = await ethers.getContractFactory("CrossChainRelay");
    relay = (await upgrades.deployProxy(RelayFactory, [
      await router.getAddress(),
      await sentinel.getAddress(),
      await raizoCore.getAddress(),
    ])) as unknown as CrossChainRelay;

    await relay.grantRole(await relay.DEFAULT_ADMIN_ROLE(), admin.address);
  });

  // --- double initialize (L60) ---
  describe("double initialize", function () {
    it("reverts on second initialize call (L60 true branch)", async function () {
      await expect(
        relay.initialize(
          await router.getAddress(),
          await sentinel.getAddress(),
          await raizoCore.getAddress(),
        ),
      ).to.be.revertedWith("Initializable: contract is already initialized");
    });
  });

  // --- ccipReceive with invalid message type (L158) ---
  describe("ccipReceive invalid message type", function () {
    it("reverts on non-ACTION_EXECUTE message type (L158 true branch)", async function () {
      await relay.connect(admin).whitelistSourceChain(SOURCE_CHAIN_SELECTOR, true);
      await relay.connect(admin).whitelistSourceSender(SOURCE_CHAIN_SELECTOR, other.address, true);

      // The enum MessageType { ALERT_PROPAGATE=0, ACTION_EXECUTE=1, CONFIG_SYNC=2, ... }
      // Use 0 (ALERT_PROPAGATE) which is a valid enum value but not ACTION_EXECUTE
      const msgDataTuple = [
        0, // ALERT_PROPAGATE — valid enum but not ACTION_EXECUTE
        REPORT_ID,
        AGENT_ID,
        SOURCE_CHAIN_SELECTOR,
        DEST_CHAIN_SELECTOR,
        other.address,
        0, // PAUSE
        2, // HIGH
        9500,
        Math.floor(Date.now() / 1000),
        "0x",
        "0x",
      ];

      const payload = ethers.AbiCoder.defaultAbiCoder().encode(
        ["(uint8,bytes32,bytes32,uint64,uint64,address,uint8,uint8,uint16,uint256,bytes,bytes)"],
        [msgDataTuple],
      );

      const msg = {
        messageId: ethers.id("ccip.msg.invalid"),
        sourceChainSelector: SOURCE_CHAIN_SELECTOR,
        sender: ethers.AbiCoder.defaultAbiCoder().encode(["address"], [other.address]),
        data: payload,
        destTokenAmounts: [],
      };

      await expect(
        router.simulateReceive(await relay.getAddress(), msg),
      ).to.be.revertedWithCustomError(relay, "InvalidMessageType");
    });
  });

  // --- whitelistSourceSender non-admin (L225) ---
  describe("whitelistSourceSender ACL", function () {
    it("non-admin cannot whitelist sender (L225 true branch)", async function () {
      await expect(
        relay.connect(other).whitelistSourceSender(SOURCE_CHAIN_SELECTOR, other.address, true),
      ).to.be.revertedWithCustomError(relay, "AccessDenied");
    });
  });
});
