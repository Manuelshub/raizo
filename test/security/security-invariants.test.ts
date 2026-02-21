/**
 * @file security-invariants.test.ts
 * @notice Formal verification targets from SECURITY.md §8.
 *
 * Each test maps 1:1 to an invariant:
 *   INV-1  ComplianceVault  — report immutability
 *   INV-2  SentinelActions  — DON signature required
 *   INV-3  SentinelActions  — action budget cap
 *   INV-4  PaymentEscrow    — daily spending limit
 *   INV-5  PaymentEscrow    — nonce uniqueness
 *   INV-6  GovernanceGate   — nullifier uniqueness
 *   INV-7  CrossChainRelay  — reportId uniqueness
 *   INV-8  RaizoCore        — protocol registration ACL
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import {
    RaizoCore,
    SentinelActions,
    ComplianceVault,
    PaymentEscrow,
    GovernanceGate,
    CrossChainRelay,
    MockUSDC,
    MockWorldID,
    MockCCIPRouter,
    MockSentinelActions,
} from "../../typechain-types";

// ────────────────────────────────────────────────────────────────────────────
//  INV-1: ComplianceVault — report immutability
// ────────────────────────────────────────────────────────────────────────────

describe("INV-1: ComplianceVault — report immutability", function () {
    let vault: ComplianceVault;
    let owner: SignerWithAddress;
    let other: SignerWithAddress;

    const ANCHOR_ROLE = ethers.keccak256(ethers.toUtf8Bytes("ANCHOR_ROLE"));
    const REPORT_HASH = ethers.keccak256(ethers.toUtf8Bytes("report-001"));
    const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("agent-001"));

    beforeEach(async function () {
        [owner, other] = await ethers.getSigners();
        const Factory = await ethers.getContractFactory("ComplianceVault");
        vault = await Factory.deploy();
        await vault.waitForDeployment();
        await vault.grantRole(ANCHOR_ROLE, owner.address);
    });

    it("stored report cannot be overwritten by duplicate storeReport()", async function () {
        await vault.storeReport(REPORT_HASH, AGENT_ID, 1, 1, "ipfs://report-001");
        await expect(
            vault.storeReport(REPORT_HASH, AGENT_ID, 1, 1, "ipfs://different-uri"),
        ).to.be.revertedWithCustomError(vault, "ReportAlreadyExists");
    });

    it("no updateReport or deleteReport function exists on the contract", async function () {
        // Verify the contract ABI has no mutation methods beyond storeReport
        const iface = vault.interface;
        const mutatingFragments = iface.fragments
            .filter(
                (f) =>
                    f.type === "function" &&
                    "stateMutability" in f &&
                    (f.stateMutability === "nonpayable" || f.stateMutability === "payable"),
            )
            .map((f) => ("name" in f ? f.name : ""));

        expect(mutatingFragments).to.not.include("updateReport");
        expect(mutatingFragments).to.not.include("deleteReport");
        expect(mutatingFragments).to.not.include("removeReport");
    });

    it("report hash is retrievable and matches exactly after storage", async function () {
        await vault.storeReport(REPORT_HASH, AGENT_ID, 1, 1, "ipfs://report-001");
        const record = await vault.getReport(REPORT_HASH);
        expect(record.reportHash).to.equal(REPORT_HASH);
        expect(record.agentId).to.equal(AGENT_ID);
        expect(record.reportURI).to.equal("ipfs://report-001");
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  INV-2: SentinelActions — DON signature required
// ────────────────────────────────────────────────────────────────────────────

describe("INV-2: SentinelActions — DON signature required", function () {
    let sentinel: SentinelActions;
    let raizoCore: RaizoCore;
    let owner: SignerWithAddress;
    let agentWallet: SignerWithAddress;
    let node1: SignerWithAddress;
    let node2: SignerWithAddress;

    const PROTOCOL_A = "0x0000000000000000000000000000000000000001";
    const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("sentinel-v1"));
    const BUDGET = ethers.parseUnits("100", 6);

    beforeEach(async function () {
        [owner, agentWallet, node1, node2] = await ethers.getSigners();

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

        const GOV_ROLE = await raizoCore.GOVERNANCE_ROLE();
        await raizoCore.grantRole(GOV_ROLE, owner.address);
        await raizoCore.registerProtocol(PROTOCOL_A, 1, 2);
        await raizoCore.registerAgent(AGENT_ID, agentWallet.address, BUDGET);
    });

    it("reverts when donSignatures is empty (0 nodes)", async function () {
        const report = {
            reportId: ethers.keccak256(ethers.randomBytes(32)),
            agentId: AGENT_ID,
            exists: false,
            targetProtocol: PROTOCOL_A,
            action: 0,
            severity: 3,
            confidenceScore: 9000,
            evidenceHash: ethers.toUtf8Bytes("evidence"),
            timestamp: (await ethers.provider.getBlock("latest"))!.timestamp,
            donSignatures: "0x", // empty — no DON consensus
        };

        await expect(
            sentinel.executeAction(report),
        ).to.be.revertedWithCustomError(sentinel, "InvalidSignatures");
    });

    it("succeeds when valid DON signatures are provided", async function () {
        const report = {
            reportId: ethers.keccak256(ethers.randomBytes(32)),
            agentId: AGENT_ID,
            exists: false,
            targetProtocol: PROTOCOL_A,
            action: 0,
            severity: 3,
            confidenceScore: 9000,
            evidenceHash: ethers.toUtf8Bytes("evidence"),
            timestamp: (await ethers.provider.getBlock("latest"))!.timestamp,
            donSignatures: "0x" as string,
        };

        const messageHash = ethers.solidityPackedKeccak256(
            ["bytes32", "bytes32", "bool", "address", "uint8", "uint8", "uint16", "uint256"],
            [report.reportId, report.agentId, report.exists, report.targetProtocol, report.action, report.severity, report.confidenceScore, report.timestamp],
        );
        const sig1 = await node1.signMessage(ethers.getBytes(messageHash));
        const sig2 = await node2.signMessage(ethers.getBytes(messageHash));
        report.donSignatures = ethers.concat([sig1, sig2]);

        await expect(sentinel.executeAction(report)).to.emit(sentinel, "ActionExecuted");
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  INV-3: SentinelActions — action budget cap
// ────────────────────────────────────────────────────────────────────────────

describe("INV-3: SentinelActions — action budget cap", function () {
    let sentinel: SentinelActions;
    let raizoCore: RaizoCore;
    let owner: SignerWithAddress;
    let agentWallet: SignerWithAddress;
    let node1: SignerWithAddress;
    let node2: SignerWithAddress;

    const PROTOCOL_A = "0x0000000000000000000000000000000000000001";
    const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("budget-agent"));
    const BUDGET = ethers.parseUnits("100", 6);
    const ACTION_BUDGET = 10; // default from RaizoCore

    beforeEach(async function () {
        [owner, agentWallet, node1, node2] = await ethers.getSigners();

        const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
        raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
            initializer: "initialize", kind: "uups",
        })) as unknown as RaizoCore;

        const SentinelFactory = await ethers.getContractFactory("SentinelActions");
        sentinel = (await upgrades.deployProxy(
            SentinelFactory,
            [await raizoCore.getAddress()],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as SentinelActions;

        const GOV_ROLE = await raizoCore.GOVERNANCE_ROLE();
        await raizoCore.grantRole(GOV_ROLE, owner.address);
        await raizoCore.registerProtocol(PROTOCOL_A, 1, 2);
        await raizoCore.registerAgent(AGENT_ID, agentWallet.address, BUDGET);
    });

    async function signedReport(id: string) {
        const report = {
            reportId: ethers.id(id),
            agentId: AGENT_ID,
            exists: false,
            targetProtocol: PROTOCOL_A,
            action: 0,
            severity: 3,
            confidenceScore: 9000,
            evidenceHash: ethers.toUtf8Bytes("evidence"),
            timestamp: (await ethers.provider.getBlock("latest"))!.timestamp,
            donSignatures: "0x" as string,
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

    it("allows exactly actionBudgetPerEpoch actions, then reverts", async function () {
        // Exhaust the budget
        for (let i = 0; i < ACTION_BUDGET; i++) {
            const r = await signedReport(`budget-report-${i}`);
            await sentinel.executeAction(r);
        }

        // Budget + 1 must revert
        const overBudget = await signedReport("over-budget");
        await expect(
            sentinel.executeAction(overBudget),
        ).to.be.revertedWithCustomError(sentinel, "BudgetExceeded");
    });

    it("action count is tracked per-agent correctly", async function () {
        const r = await signedReport("count-check");
        await sentinel.executeAction(r);
        const count = await sentinel.getActionCount(AGENT_ID);
        expect(count).to.equal(1);
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  INV-4: PaymentEscrow — daily spending limit
// ────────────────────────────────────────────────────────────────────────────

describe("INV-4: PaymentEscrow — daily spending limit", function () {
    let escrow: PaymentEscrow;
    let usdc: MockUSDC;
    let raizoCore: RaizoCore;
    let owner: SignerWithAddress;
    let agentWallet: SignerWithAddress;
    let recipient: SignerWithAddress;
    let provider: SignerWithAddress;

    const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("daily-agent"));
    const DAILY_LIMIT = ethers.parseUnits("100", 6);
    const DEPOSIT = ethers.parseUnits("1000", 6);

    beforeEach(async function () {
        [owner, agentWallet, recipient, provider] = await ethers.getSigners();

        const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
        raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
            initializer: "initialize", kind: "uups",
        })) as unknown as RaizoCore;

        const MockFactory = await ethers.getContractFactory("MockUSDC");
        usdc = await MockFactory.deploy();

        await raizoCore.registerAgent(AGENT_ID, agentWallet.address, DAILY_LIMIT);

        const EscrowFactory = await ethers.getContractFactory("PaymentEscrow");
        escrow = (await upgrades.deployProxy(
            EscrowFactory,
            [await raizoCore.getAddress(), await usdc.getAddress()],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as PaymentEscrow;

        await usdc.mint(provider.address, DEPOSIT);
        await usdc.connect(provider).approve(await escrow.getAddress(), DEPOSIT);
        await escrow.connect(provider).deposit(AGENT_ID, DEPOSIT);
    });

    async function authorizePayment(amount: bigint, nonceSuffix: string) {
        const domain = {
            name: "PaymentEscrow",
            version: "1",
            chainId: (await ethers.provider.getNetwork()).chainId,
            verifyingContract: await escrow.getAddress(),
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
        const nonce = ethers.id(nonceSuffix);
        const value = {
            agentId: AGENT_ID,
            to: recipient.address,
            amount,
            validAfter: 0,
            validBefore: 2000000000,
            nonce,
        };
        const signature = await agentWallet.signTypedData(domain, types, value);
        return escrow.authorizePayment(
            AGENT_ID, recipient.address, amount, 0, 2000000000, nonce, signature,
        );
    }

    it("rejects payment that would exceed the daily limit", async function () {
        const over = DAILY_LIMIT + 1n;
        await expect(
            authorizePayment(over, "over-limit"),
        ).to.be.revertedWithCustomError(escrow, "DailyLimitExceeded");
    });

    it("rejects cumulative payments exceeding limit across multiple calls", async function () {
        await authorizePayment(DAILY_LIMIT, "first-spend");
        await expect(
            authorizePayment(1n, "second-spend"),
        ).to.be.revertedWithCustomError(escrow, "DailyLimitExceeded");
    });

    it("resets spending after 24-hour window rolls over", async function () {
        await authorizePayment(DAILY_LIMIT, "day1-spend");
        await ethers.provider.send("evm_increaseTime", [86401]);
        await ethers.provider.send("evm_mine", []);
        // After 24h reset, should succeed
        await expect(authorizePayment(1n, "day2-spend")).to.emit(escrow, "DailyLimitReset");
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  INV-5: PaymentEscrow — nonce uniqueness
// ────────────────────────────────────────────────────────────────────────────

describe("INV-5: PaymentEscrow — nonce uniqueness", function () {
    let escrow: PaymentEscrow;
    let usdc: MockUSDC;
    let raizoCore: RaizoCore;
    let owner: SignerWithAddress;
    let agentWallet: SignerWithAddress;
    let recipient: SignerWithAddress;
    let provider: SignerWithAddress;

    const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("nonce-agent"));
    const DAILY_LIMIT = ethers.parseUnits("500", 6);
    const DEPOSIT = ethers.parseUnits("1000", 6);
    const AMOUNT = ethers.parseUnits("10", 6);

    beforeEach(async function () {
        [owner, agentWallet, recipient, provider] = await ethers.getSigners();

        const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
        raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
            initializer: "initialize", kind: "uups",
        })) as unknown as RaizoCore;

        const MockFactory = await ethers.getContractFactory("MockUSDC");
        usdc = await MockFactory.deploy();

        await raizoCore.registerAgent(AGENT_ID, agentWallet.address, DAILY_LIMIT);

        const EscrowFactory = await ethers.getContractFactory("PaymentEscrow");
        escrow = (await upgrades.deployProxy(
            EscrowFactory,
            [await raizoCore.getAddress(), await usdc.getAddress()],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as PaymentEscrow;

        await usdc.mint(provider.address, DEPOSIT);
        await usdc.connect(provider).approve(await escrow.getAddress(), DEPOSIT);
        await escrow.connect(provider).deposit(AGENT_ID, DEPOSIT);
    });

    it("rejects replayed nonce even if all other params differ", async function () {
        const nonce = ethers.id("shared-nonce");
        const domain = {
            name: "PaymentEscrow",
            version: "1",
            chainId: (await ethers.provider.getNetwork()).chainId,
            verifyingContract: await escrow.getAddress(),
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

        const sig1 = await agentWallet.signTypedData(domain, types, {
            agentId: AGENT_ID, to: recipient.address, amount: AMOUNT,
            validAfter: 0, validBefore: 2000000000, nonce,
        });

        await escrow.authorizePayment(
            AGENT_ID, recipient.address, AMOUNT, 0, 2000000000, nonce, sig1,
        );

        // Same nonce, different amount → must still revert
        const sig2 = await agentWallet.signTypedData(domain, types, {
            agentId: AGENT_ID, to: recipient.address, amount: AMOUNT + 1n,
            validAfter: 0, validBefore: 2000000000, nonce,
        });

        await expect(
            escrow.authorizePayment(
                AGENT_ID, recipient.address, AMOUNT + 1n, 0, 2000000000, nonce, sig2,
            ),
        ).to.be.revertedWithCustomError(escrow, "NonceAlreadyUsed");
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  INV-6: GovernanceGate — nullifier uniqueness
// ────────────────────────────────────────────────────────────────────────────

describe("INV-6: GovernanceGate — nullifier uniqueness", function () {
    let gov: GovernanceGate;
    let owner: SignerWithAddress;
    let voter: SignerWithAddress;

    const PROOF: [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint] =
        [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];

    beforeEach(async function () {
        [owner, voter] = await ethers.getSigners();

        const MockFactory = await ethers.getContractFactory("MockWorldID");
        const worldId = await MockFactory.deploy();

        const GovFactory = await ethers.getContractFactory("GovernanceGate");
        gov = (await upgrades.deployProxy(
            GovFactory,
            [await worldId.getAddress()],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as GovernanceGate;
    });

    it("rejects vote with a previously-used nullifier", async function () {
        const nullifier = 99999;
        const proposalNullifier = 88888;

        // Create proposal
        await gov.connect(owner).propose(ethers.id("test-proposal"), 12345, proposalNullifier, PROOF);

        // First vote succeeds
        await gov.connect(voter).vote(0, true, 12345, nullifier, PROOF);

        // Second vote with same nullifier reverts
        await expect(
            gov.connect(voter).vote(0, false, 12345, nullifier, PROOF),
        ).to.be.revertedWithCustomError(gov, "DoubleVoting");
    });

    it("rejects proposal with a previously-used nullifier", async function () {
        const nullifier = 77777;
        await gov.connect(owner).propose(ethers.id("proposal-1"), 12345, nullifier, PROOF);

        await expect(
            gov.connect(owner).propose(ethers.id("proposal-2"), 12345, nullifier, PROOF),
        ).to.be.revertedWithCustomError(gov, "DoubleVoting");
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  INV-7: CrossChainRelay — reportId uniqueness
// ────────────────────────────────────────────────────────────────────────────

describe("INV-7: CrossChainRelay — reportId uniqueness", function () {
    let relay: CrossChainRelay;
    let router: MockCCIPRouter;
    let owner: SignerWithAddress;
    let admin: SignerWithAddress;
    let sender: SignerWithAddress;

    const SOURCE_CHAIN = 12345n;
    const DEST_CHAIN = 67890n;
    const REPORT_ID = ethers.id("threat.report.unique");
    const AGENT_ID = ethers.id("agent.unique");

    beforeEach(async function () {
        [owner, admin, sender] = await ethers.getSigners();

        const MockSentinelFactory = await ethers.getContractFactory("MockSentinelActions");
        const sentinel = await MockSentinelFactory.deploy();

        const MockRouterFactory = await ethers.getContractFactory("MockCCIPRouter");
        router = await MockRouterFactory.deploy();

        const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
        const raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [])) as unknown as RaizoCore;

        const RelayFactory = await ethers.getContractFactory("CrossChainRelay");
        relay = (await upgrades.deployProxy(RelayFactory, [
            await router.getAddress(),
            await sentinel.getAddress(),
            await raizoCore.getAddress(),
        ])) as unknown as CrossChainRelay;

        await relay.grantRole(await relay.DEFAULT_ADMIN_ROLE(), admin.address);
        await relay.connect(admin).whitelistSourceChain(SOURCE_CHAIN, true);
        await relay.connect(admin).whitelistSourceSender(SOURCE_CHAIN, sender.address, true);
    });

    function buildCCIPMessage(reportId: string) {
        const msgData = [
            1, reportId, AGENT_ID, SOURCE_CHAIN, DEST_CHAIN,
            sender.address, 0, 2, 9500,
            Math.floor(Date.now() / 1000), "0x", "0x",
        ];
        const payload = ethers.AbiCoder.defaultAbiCoder().encode(
            ["(uint8,bytes32,bytes32,uint64,uint64,address,uint8,uint8,uint16,uint256,bytes,bytes)"],
            [msgData],
        );
        return {
            messageId: ethers.id("ccip.msg." + reportId),
            sourceChainSelector: SOURCE_CHAIN,
            sender: ethers.AbiCoder.defaultAbiCoder().encode(["address"], [sender.address]),
            data: payload,
            destTokenAmounts: [],
        };
    }

    it("rejects duplicate cross-chain message with same reportId", async function () {
        const msg = buildCCIPMessage(REPORT_ID);

        // First delivery succeeds
        await expect(
            router.simulateReceive(await relay.getAddress(), msg),
        ).to.emit(relay, "AlertExecuted");

        // Replay must revert
        await expect(
            router.simulateReceive(await relay.getAddress(), msg),
        ).to.be.revertedWithCustomError(relay, "MessageAlreadyProcessed");
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  INV-8: RaizoCore — protocol registration ACL
// ────────────────────────────────────────────────────────────────────────────

describe("INV-8: RaizoCore — protocol registration ACL", function () {
    let raizoCore: RaizoCore;
    let owner: SignerWithAddress;
    let governance: SignerWithAddress;
    let attacker: SignerWithAddress;

    const PROTOCOL = "0x0000000000000000000000000000000000000042";

    beforeEach(async function () {
        [owner, governance, attacker] = await ethers.getSigners();

        const Factory = await ethers.getContractFactory("RaizoCore");
        raizoCore = (await upgrades.deployProxy(Factory, [], {
            initializer: "initialize", kind: "uups",
        })) as unknown as RaizoCore;

        const GOV_ROLE = await raizoCore.GOVERNANCE_ROLE();
        await raizoCore.grantRole(GOV_ROLE, governance.address);
    });

    it("OWNER can register a protocol", async function () {
        await expect(
            raizoCore.connect(owner).registerProtocol(PROTOCOL, 1, 2),
        ).to.emit(raizoCore, "ProtocolRegistered");
    });

    it("GOVERNANCE can register a protocol", async function () {
        await expect(
            raizoCore.connect(governance).registerProtocol(PROTOCOL, 1, 2),
        ).to.emit(raizoCore, "ProtocolRegistered");
    });

    it("random address CANNOT register a protocol", async function () {
        await expect(
            raizoCore.connect(attacker).registerProtocol(PROTOCOL, 1, 2),
        ).to.be.revertedWithCustomError(raizoCore, "CallerNotAdminOrGovernance");
    });

    it("OWNER can deregister a protocol", async function () {
        await raizoCore.connect(owner).registerProtocol(PROTOCOL, 1, 2);
        await expect(
            raizoCore.connect(owner).deregisterProtocol(PROTOCOL),
        ).to.emit(raizoCore, "ProtocolDeregistered");
    });

    it("random address CANNOT deregister a protocol", async function () {
        await raizoCore.connect(owner).registerProtocol(PROTOCOL, 1, 2);
        await expect(
            raizoCore.connect(attacker).deregisterProtocol(PROTOCOL),
        ).to.be.revertedWithCustomError(raizoCore, "CallerNotAdminOrGovernance");
    });
});
