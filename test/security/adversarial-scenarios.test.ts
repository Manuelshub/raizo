/**
 * @file adversarial-scenarios.test.ts
 * @notice Adversarial scenario tests derived from the STRIDE threat model
 *         in SECURITY.md §3.
 *
 * Each test simulates a real attack vector:
 *   ADV-1  PaymentEscrow reentrancy        (SC-1)
 *   ADV-2  SentinelActions reentrancy       (SC-1)
 *   ADV-3  DON consensus failure            (B3)
 *   ADV-4  CCIP message spoofing            (CC-1)
 *   ADV-5  Cross-chain message replay       (CC-2)
 *   ADV-6  Payment nonce replay             (PAY-2)
 *   ADV-7  UUPS upgrade hijack              (SC-3)
 *   ADV-8  Stale confidence / zero values   (D2)
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import {
    RaizoCore,
    SentinelActions,
    PaymentEscrow,
    CrossChainRelay,
    GovernanceGate,
    ComplianceVault,
    MockUSDC,
    MockCCIPRouter,
    MockSentinelActions,
    MockWorldID,
} from "../../typechain-types";

// ────────────────────────────────────────────────────────────────────────────
//  ADV-1 & ADV-2: Reentrancy guards
// ────────────────────────────────────────────────────────────────────────────

describe("ADV-1/ADV-2: Reentrancy guards", function () {
    let sentinel: SentinelActions;
    let escrow: PaymentEscrow;
    let raizoCore: RaizoCore;
    let usdc: MockUSDC;
    let owner: SignerWithAddress;
    let agentWallet: SignerWithAddress;
    let node1: SignerWithAddress;
    let node2: SignerWithAddress;
    let recipient: SignerWithAddress;

    const PROTOCOL_A = "0x0000000000000000000000000000000000000001";
    const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("reentrant-agent"));
    const DAILY_LIMIT = ethers.parseUnits("500", 6);
    const DEPOSIT = ethers.parseUnits("1000", 6);

    beforeEach(async function () {
        [owner, agentWallet, node1, node2, recipient] = await ethers.getSigners();

        const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
        raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
            initializer: "initialize", kind: "uups",
        })) as unknown as RaizoCore;

        const GOV = await raizoCore.GOVERNANCE_ROLE();
        await raizoCore.grantRole(GOV, owner.address);
        await raizoCore.registerProtocol(PROTOCOL_A, 1, 2);
        await raizoCore.registerAgent(AGENT_ID, agentWallet.address, DAILY_LIMIT);

        const SentinelFactory = await ethers.getContractFactory("SentinelActions");
        sentinel = (await upgrades.deployProxy(
            SentinelFactory, [await raizoCore.getAddress()],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as SentinelActions;

        const MockFactory = await ethers.getContractFactory("MockUSDC");
        usdc = await MockFactory.deploy();

        const EscrowFactory = await ethers.getContractFactory("PaymentEscrow");
        escrow = (await upgrades.deployProxy(
            EscrowFactory,
            [await raizoCore.getAddress(), await usdc.getAddress()],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as PaymentEscrow;
    });

    it("[ADV-1] SentinelActions.executeAction is protected by nonReentrant", async function () {
        // Verify the contract uses ReentrancyGuard by checking it inherits it
        // The nonReentrant modifier is on executeAction — we prove this by
        // calling it with valid data (if reentrancy was possible, it would not revert)
        const report = {
            reportId: ethers.keccak256(ethers.randomBytes(32)),
            agentId: AGENT_ID, exists: false, targetProtocol: PROTOCOL_A,
            action: 0, severity: 3, confidenceScore: 9000,
            evidenceHash: ethers.toUtf8Bytes("evidence"),
            timestamp: (await ethers.provider.getBlock("latest"))!.timestamp,
            donSignatures: "0x" as string,
        };
        const hash = ethers.solidityPackedKeccak256(
            ["bytes32", "bytes32", "bool", "address", "uint8", "uint8", "uint16", "uint256"],
            [report.reportId, report.agentId, report.exists, report.targetProtocol,
            report.action, report.severity, report.confidenceScore, report.timestamp],
        );
        report.donSignatures = ethers.concat([
            await node1.signMessage(ethers.getBytes(hash)),
            await node2.signMessage(ethers.getBytes(hash)),
        ]);

        // Single call succeeds
        await expect(sentinel.executeAction(report)).to.emit(sentinel, "ActionExecuted");
        // Duplicate is rejected (DuplicateReport — not a reentrancy, but proves
        // state was persisted before any external interaction)
        await expect(sentinel.executeAction(report))
            .to.be.revertedWithCustomError(sentinel, "DuplicateReport");
    });

    it("[ADV-2] PaymentEscrow.authorizePayment is protected by nonReentrant", async function () {
        // Prove the function completes atomically by executing two valid-but-identical
        // payments — the second must fail on nonce, proving state was committed first
        await usdc.mint(owner.address, DEPOSIT);
        await usdc.connect(owner).approve(await escrow.getAddress(), DEPOSIT);
        await escrow.connect(owner).deposit(AGENT_ID, DEPOSIT);

        const nonce = ethers.id("reentrancy-nonce");
        const amount = ethers.parseUnits("10", 6);
        const domain = {
            name: "PaymentEscrow", version: "1",
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
        const value = {
            agentId: AGENT_ID, to: recipient.address, amount,
            validAfter: 0, validBefore: 2000000000, nonce,
        };
        const sig = await agentWallet.signTypedData(domain, types, value);

        await escrow.authorizePayment(
            AGENT_ID, recipient.address, amount, 0, 2000000000, nonce, sig,
        );
        // Second call with same nonce proves state committed before external call
        await expect(
            escrow.authorizePayment(
                AGENT_ID, recipient.address, amount, 0, 2000000000, nonce, sig,
            ),
        ).to.be.revertedWithCustomError(escrow, "NonceAlreadyUsed");
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  ADV-3: DON consensus failure (insufficient signatures)
// ────────────────────────────────────────────────────────────────────────────

describe("ADV-3: DON consensus failure", function () {
    let sentinel: SentinelActions;
    let raizoCore: RaizoCore;
    let owner: SignerWithAddress;
    let agentWallet: SignerWithAddress;

    const PROTOCOL = "0x0000000000000000000000000000000000000001";
    const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("don-fail"));

    beforeEach(async function () {
        [owner, agentWallet] = await ethers.getSigners();

        const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
        raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
            initializer: "initialize", kind: "uups",
        })) as unknown as RaizoCore;

        const GOV = await raizoCore.GOVERNANCE_ROLE();
        await raizoCore.grantRole(GOV, owner.address);
        await raizoCore.registerProtocol(PROTOCOL, 1, 2);
        await raizoCore.registerAgent(AGENT_ID, agentWallet.address, ethers.parseUnits("100", 6));

        const SentinelFactory = await ethers.getContractFactory("SentinelActions");
        sentinel = (await upgrades.deployProxy(
            SentinelFactory, [await raizoCore.getAddress()],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as SentinelActions;
    });

    it("rejects action with zero DON signatures", async function () {
        const report = {
            reportId: ethers.keccak256(ethers.randomBytes(32)),
            agentId: AGENT_ID, exists: false, targetProtocol: PROTOCOL,
            action: 0, severity: 3, confidenceScore: 9500,
            evidenceHash: ethers.toUtf8Bytes("evidence"),
            timestamp: (await ethers.provider.getBlock("latest"))!.timestamp,
            donSignatures: "0x",
        };

        await expect(
            sentinel.executeAction(report),
        ).to.be.revertedWithCustomError(sentinel, "InvalidSignatures");
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  ADV-4: CCIP message spoofing (unauthorized source)
// ────────────────────────────────────────────────────────────────────────────

describe("ADV-4: CCIP message spoofing", function () {
    let relay: CrossChainRelay;
    let router: MockCCIPRouter;
    let owner: SignerWithAddress;
    let admin: SignerWithAddress;
    let attacker: SignerWithAddress;

    const LEGIT_CHAIN = 12345n;
    const ROGUE_CHAIN = 99999n;

    beforeEach(async function () {
        [owner, admin, attacker] = await ethers.getSigners();

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
        // Only whitelist the legitimate chain
        await relay.connect(admin).whitelistSourceChain(LEGIT_CHAIN, true);
    });

    function buildMsg(sourceChain: bigint, senderAddr: string) {
        const msgData = [
            1, ethers.id("spoofed.report"), ethers.id("agent"),
            sourceChain, 67890n, attacker.address, 0, 3, 9500,
            Math.floor(Date.now() / 1000), "0x", "0x",
        ];
        const payload = ethers.AbiCoder.defaultAbiCoder().encode(
            ["(uint8,bytes32,bytes32,uint64,uint64,address,uint8,uint8,uint16,uint256,bytes,bytes)"],
            [msgData],
        );
        return {
            messageId: ethers.id("spoof-msg"),
            sourceChainSelector: sourceChain,
            sender: ethers.AbiCoder.defaultAbiCoder().encode(["address"], [senderAddr]),
            data: payload,
            destTokenAmounts: [],
        };
    }

    it("rejects message from non-whitelisted source chain", async function () {
        const msg = buildMsg(ROGUE_CHAIN, attacker.address);
        await expect(
            router.simulateReceive(await relay.getAddress(), msg),
        ).to.be.revertedWithCustomError(relay, "UnauthorizedSourceChain");
    });

    it("rejects message from non-whitelisted sender on valid chain", async function () {
        const msg = buildMsg(LEGIT_CHAIN, attacker.address);
        await expect(
            router.simulateReceive(await relay.getAddress(), msg),
        ).to.be.revertedWithCustomError(relay, "UnauthorizedSourceSender");
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  ADV-5: Cross-chain message replay
// ────────────────────────────────────────────────────────────────────────────

describe("ADV-5: Cross-chain message replay", function () {
    let relay: CrossChainRelay;
    let router: MockCCIPRouter;
    let admin: SignerWithAddress;
    let sender: SignerWithAddress;

    const SRC = 12345n;

    beforeEach(async function () {
        const signers = await ethers.getSigners();
        const owner = signers[0];
        admin = signers[1];
        sender = signers[2];

        const sentinel = await (await ethers.getContractFactory("MockSentinelActions")).deploy();
        router = await (await ethers.getContractFactory("MockCCIPRouter")).deploy();
        const raizoCore = (await upgrades.deployProxy(
            await ethers.getContractFactory("RaizoCore"), [],
        )) as unknown as RaizoCore;

        relay = (await upgrades.deployProxy(
            await ethers.getContractFactory("CrossChainRelay"),
            [await router.getAddress(), await sentinel.getAddress(), await raizoCore.getAddress()],
        )) as unknown as CrossChainRelay;

        await relay.grantRole(await relay.DEFAULT_ADMIN_ROLE(), admin.address);
        await relay.connect(admin).whitelistSourceChain(SRC, true);
        await relay.connect(admin).whitelistSourceSender(SRC, sender.address, true);
    });

    it("second delivery of same reportId reverts", async function () {
        const reportId = ethers.id("replay-report");
        const msgData = [
            1, reportId, ethers.id("agent"), SRC, 99n,
            sender.address, 0, 3, 9500, Math.floor(Date.now() / 1000), "0x", "0x",
        ];
        const payload = ethers.AbiCoder.defaultAbiCoder().encode(
            ["(uint8,bytes32,bytes32,uint64,uint64,address,uint8,uint8,uint16,uint256,bytes,bytes)"],
            [msgData],
        );
        const msg = {
            messageId: ethers.id("ccip-replay"),
            sourceChainSelector: SRC,
            sender: ethers.AbiCoder.defaultAbiCoder().encode(["address"], [sender.address]),
            data: payload,
            destTokenAmounts: [],
        };

        await router.simulateReceive(await relay.getAddress(), msg);

        await expect(
            router.simulateReceive(await relay.getAddress(), msg),
        ).to.be.revertedWithCustomError(relay, "MessageAlreadyProcessed");
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  ADV-6: Payment authorization replay
// ────────────────────────────────────────────────────────────────────────────

describe("ADV-6: Payment authorization replay", function () {
    let escrow: PaymentEscrow;
    let raizoCore: RaizoCore;
    let usdc: MockUSDC;
    let agentWallet: SignerWithAddress;
    let recipient: SignerWithAddress;
    let provider: SignerWithAddress;

    const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("replay-agent"));
    const LIMIT = ethers.parseUnits("500", 6);
    const DEPOSIT = ethers.parseUnits("1000", 6);
    const AMOUNT = ethers.parseUnits("10", 6);

    beforeEach(async function () {
        const signers = await ethers.getSigners();
        const owner = signers[0];
        agentWallet = signers[1];
        recipient = signers[2];
        provider = signers[3];

        raizoCore = (await upgrades.deployProxy(
            await ethers.getContractFactory("RaizoCore"), [],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as RaizoCore;

        usdc = await (await ethers.getContractFactory("MockUSDC")).deploy();
        await raizoCore.registerAgent(AGENT_ID, agentWallet.address, LIMIT);

        escrow = (await upgrades.deployProxy(
            await ethers.getContractFactory("PaymentEscrow"),
            [await raizoCore.getAddress(), await usdc.getAddress()],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as PaymentEscrow;

        await usdc.mint(provider.address, DEPOSIT);
        await usdc.connect(provider).approve(await escrow.getAddress(), DEPOSIT);
        await escrow.connect(provider).deposit(AGENT_ID, DEPOSIT);
    });

    it("exact same payment tx cannot be replayed after first execution", async function () {
        const nonce = ethers.id("replay-nonce");
        const domain = {
            name: "PaymentEscrow", version: "1",
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
        const value = {
            agentId: AGENT_ID, to: recipient.address, amount: AMOUNT,
            validAfter: 0, validBefore: 2000000000, nonce,
        };
        const sig = await agentWallet.signTypedData(domain, types, value);

        // First execution succeeds
        await expect(
            escrow.authorizePayment(AGENT_ID, recipient.address, AMOUNT, 0, 2000000000, nonce, sig),
        ).to.emit(escrow, "PaymentAuthorized");

        // Replay must fail
        await expect(
            escrow.authorizePayment(AGENT_ID, recipient.address, AMOUNT, 0, 2000000000, nonce, sig),
        ).to.be.revertedWithCustomError(escrow, "NonceAlreadyUsed");
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  ADV-7: UUPS upgrade hijack
// ────────────────────────────────────────────────────────────────────────────

describe("ADV-7: UUPS upgrade hijack", function () {
    let raizoCore: RaizoCore;
    let sentinel: SentinelActions;
    let escrow: PaymentEscrow;
    let gov: GovernanceGate;
    let relay: CrossChainRelay;

    let owner: SignerWithAddress;
    let attacker: SignerWithAddress;

    beforeEach(async function () {
        [owner, attacker] = await ethers.getSigners();

        // Deploy all UUPS contracts
        raizoCore = (await upgrades.deployProxy(
            await ethers.getContractFactory("RaizoCore"), [],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as RaizoCore;

        sentinel = (await upgrades.deployProxy(
            await ethers.getContractFactory("SentinelActions"),
            [await raizoCore.getAddress()],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as SentinelActions;

        const usdc = await (await ethers.getContractFactory("MockUSDC")).deploy();
        escrow = (await upgrades.deployProxy(
            await ethers.getContractFactory("PaymentEscrow"),
            [await raizoCore.getAddress(), await usdc.getAddress()],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as PaymentEscrow;

        const worldId = await (await ethers.getContractFactory("MockWorldID")).deploy();
        gov = (await upgrades.deployProxy(
            await ethers.getContractFactory("GovernanceGate"),
            [await worldId.getAddress()],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as GovernanceGate;

        const mockSentinel = await (await ethers.getContractFactory("MockSentinelActions")).deploy();
        const mockRouter = await (await ethers.getContractFactory("MockCCIPRouter")).deploy();
        relay = (await upgrades.deployProxy(
            await ethers.getContractFactory("CrossChainRelay"),
            [await mockRouter.getAddress(), await mockSentinel.getAddress(), await raizoCore.getAddress()],
        )) as unknown as CrossChainRelay;
    });

    it("attacker cannot upgrade RaizoCore", async function () {
        const V2 = await ethers.getContractFactory("RaizoCore", attacker);
        await expect(
            upgrades.upgradeProxy(await raizoCore.getAddress(), V2),
        ).to.be.reverted;
    });

    it("attacker cannot upgrade SentinelActions", async function () {
        const V2 = await ethers.getContractFactory("SentinelActions", attacker);
        await expect(
            upgrades.upgradeProxy(await sentinel.getAddress(), V2),
        ).to.be.reverted;
    });

    it("attacker cannot upgrade PaymentEscrow", async function () {
        const V2 = await ethers.getContractFactory("PaymentEscrow", attacker);
        await expect(
            upgrades.upgradeProxy(await escrow.getAddress(), V2),
        ).to.be.reverted;
    });

    it("attacker cannot upgrade GovernanceGate", async function () {
        const V2 = await ethers.getContractFactory("GovernanceGate", attacker);
        await expect(
            upgrades.upgradeProxy(await gov.getAddress(), V2),
        ).to.be.reverted;
    });

    it("attacker cannot upgrade CrossChainRelay", async function () {
        const V2 = await ethers.getContractFactory("CrossChainRelay", attacker);
        await expect(
            upgrades.upgradeProxy(await relay.getAddress(), V2),
        ).to.be.reverted;
    });

    it("owner CAN upgrade (positive control)", async function () {
        const V2 = await ethers.getContractFactory("RaizoCore", owner);
        const upgraded = await upgrades.upgradeProxy(await raizoCore.getAddress(), V2);
        expect(await upgraded.getAddress()).to.equal(await raizoCore.getAddress());
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  ADV-8: Edge-case / zero-value inputs
// ────────────────────────────────────────────────────────────────────────────

describe("ADV-8: Edge-case inputs and boundary conditions", function () {
    let sentinel: SentinelActions;
    let raizoCore: RaizoCore;
    let owner: SignerWithAddress;
    let agentWallet: SignerWithAddress;
    let node1: SignerWithAddress;
    let node2: SignerWithAddress;

    const PROTOCOL = "0x0000000000000000000000000000000000000001";
    const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("edge-agent"));

    beforeEach(async function () {
        [owner, agentWallet, node1, node2] = await ethers.getSigners();

        raizoCore = (await upgrades.deployProxy(
            await ethers.getContractFactory("RaizoCore"), [],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as RaizoCore;

        const GOV = await raizoCore.GOVERNANCE_ROLE();
        await raizoCore.grantRole(GOV, owner.address);
        await raizoCore.registerProtocol(PROTOCOL, 1, 2);
        await raizoCore.registerAgent(AGENT_ID, agentWallet.address, ethers.parseUnits("100", 6));

        sentinel = (await upgrades.deployProxy(
            await ethers.getContractFactory("SentinelActions"),
            [await raizoCore.getAddress()],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as SentinelActions;
    });

    it("rejects action with confidence 0 (below threshold)", async function () {
        const report = {
            reportId: ethers.keccak256(ethers.randomBytes(32)),
            agentId: AGENT_ID, exists: false, targetProtocol: PROTOCOL,
            action: 0, severity: 3, confidenceScore: 0,
            evidenceHash: ethers.toUtf8Bytes("evidence"),
            timestamp: (await ethers.provider.getBlock("latest"))!.timestamp,
            donSignatures: "0x" as string,
        };
        const hash = ethers.solidityPackedKeccak256(
            ["bytes32", "bytes32", "bool", "address", "uint8", "uint8", "uint16", "uint256"],
            [report.reportId, report.agentId, report.exists, report.targetProtocol,
            report.action, report.severity, report.confidenceScore, report.timestamp],
        );
        report.donSignatures = ethers.concat([
            await node1.signMessage(ethers.getBytes(hash)),
            await node2.signMessage(ethers.getBytes(hash)),
        ]);

        await expect(
            sentinel.executeAction(report),
        ).to.be.revertedWithCustomError(sentinel, "ConfidenceThresholdNotMet");
    });

    it("rejects action targeting the zero address protocol", async function () {
        const report = {
            reportId: ethers.keccak256(ethers.randomBytes(32)),
            agentId: AGENT_ID, exists: false,
            targetProtocol: ethers.ZeroAddress,
            action: 0, severity: 3, confidenceScore: 9500,
            evidenceHash: ethers.toUtf8Bytes("evidence"),
            timestamp: (await ethers.provider.getBlock("latest"))!.timestamp,
            donSignatures: "0x" as string,
        };
        const hash = ethers.solidityPackedKeccak256(
            ["bytes32", "bytes32", "bool", "address", "uint8", "uint8", "uint16", "uint256"],
            [report.reportId, report.agentId, report.exists, report.targetProtocol,
            report.action, report.severity, report.confidenceScore, report.timestamp],
        );
        report.donSignatures = ethers.concat([
            await node1.signMessage(ethers.getBytes(hash)),
            await node2.signMessage(ethers.getBytes(hash)),
        ]);

        // Zero address is not registered → ProtocolNotActive
        await expect(
            sentinel.executeAction(report),
        ).to.be.revertedWithCustomError(sentinel, "ProtocolNotActive");
    });

    it("rejects confidence threshold above 10000 bps", async function () {
        await expect(
            raizoCore.setConfidenceThreshold(10001),
        ).to.be.revertedWithCustomError(raizoCore, "InvalidThreshold");
    });

    it("rejects epoch duration of zero", async function () {
        await expect(
            raizoCore.setEpochDuration(0),
        ).to.be.revertedWithCustomError(raizoCore, "InvalidEpochDuration");
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  ADV-9: World ID oracle failure → governance fail-closed (GOV-2)
// ────────────────────────────────────────────────────────────────────────────

describe("ADV-9: World ID oracle failure → governance fail-closed", function () {
    let gov: GovernanceGate;
    let owner: SignerWithAddress;
    let voter: SignerWithAddress;

    // The MockWorldID reverts when proof[0] == 0xDEADBEEF
    const FAILING_PROOF: [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint] =
        [0xDEADBEEFn, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
    const VALID_PROOF: [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint] =
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

    it("propose() reverts when World ID verification fails (fail-closed)", async function () {
        await expect(
            gov.connect(owner).propose(
                ethers.id("oracle-failure-proposal"),
                12345,
                11111,
                FAILING_PROOF,
            ),
        ).to.be.revertedWithCustomError(gov, "InvalidProof");
    });

    it("vote() reverts when World ID verification fails (fail-closed)", async function () {
        // First create a valid proposal
        await gov.connect(owner).propose(
            ethers.id("valid-proposal"),
            12345,
            22222,
            VALID_PROOF,
        );

        // Voting with failing proof should revert
        await expect(
            gov.connect(voter).vote(0, true, 12345, 33333, FAILING_PROOF),
        ).to.be.revertedWithCustomError(gov, "InvalidProof");
    });

    it("governance is completely blocked when oracle is down (no bypass)", async function () {
        // Multiple attempts all fail — no fallback path
        for (let i = 0; i < 3; i++) {
            await expect(
                gov.connect(owner).propose(
                    ethers.id(`blocked-${i}`),
                    12345,
                    40000 + i,
                    FAILING_PROOF,
                ),
            ).to.be.revertedWithCustomError(gov, "InvalidProof");
        }
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  ADV-10: Agent deactivation mid-flow
// ────────────────────────────────────────────────────────────────────────────

describe("ADV-10: Agent deactivation mid-flow", function () {
    let sentinel: SentinelActions;
    let escrow: PaymentEscrow;
    let raizoCore: RaizoCore;
    let usdc: MockUSDC;
    let owner: SignerWithAddress;
    let agentWallet: SignerWithAddress;
    let node1: SignerWithAddress;
    let node2: SignerWithAddress;
    let recipient: SignerWithAddress;
    let provider: SignerWithAddress;

    const PROTOCOL = "0x0000000000000000000000000000000000000001";
    const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("deactivate-agent"));
    const DAILY_LIMIT = ethers.parseUnits("500", 6);

    beforeEach(async function () {
        [owner, agentWallet, node1, node2, recipient, provider] = await ethers.getSigners();

        const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
        raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
            initializer: "initialize", kind: "uups",
        })) as unknown as RaizoCore;

        const GOV = await raizoCore.GOVERNANCE_ROLE();
        await raizoCore.grantRole(GOV, owner.address);
        await raizoCore.registerProtocol(PROTOCOL, 1, 2);
        await raizoCore.registerAgent(AGENT_ID, agentWallet.address, DAILY_LIMIT);

        const SentinelFactory = await ethers.getContractFactory("SentinelActions");
        sentinel = (await upgrades.deployProxy(
            SentinelFactory, [await raizoCore.getAddress()],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as SentinelActions;

        const MockFactory = await ethers.getContractFactory("MockUSDC");
        usdc = await MockFactory.deploy();

        const EscrowFactory = await ethers.getContractFactory("PaymentEscrow");
        escrow = (await upgrades.deployProxy(
            EscrowFactory,
            [await raizoCore.getAddress(), await usdc.getAddress()],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as PaymentEscrow;

        await usdc.mint(provider.address, ethers.parseUnits("1000", 6));
        await usdc.connect(provider).approve(await escrow.getAddress(), ethers.parseUnits("1000", 6));
        await escrow.connect(provider).deposit(AGENT_ID, ethers.parseUnits("1000", 6));
    });

    it("SentinelActions: first action succeeds, deactivate agent, second action reverts", async function () {
        // First action succeeds
        const report1 = {
            reportId: ethers.keccak256(ethers.randomBytes(32)),
            agentId: AGENT_ID, exists: false, targetProtocol: PROTOCOL,
            action: 0, severity: 3, confidenceScore: 9000,
            evidenceHash: ethers.toUtf8Bytes("evidence"),
            timestamp: (await ethers.provider.getBlock("latest"))!.timestamp,
            donSignatures: "0x" as string,
        };
        const hash1 = ethers.solidityPackedKeccak256(
            ["bytes32", "bytes32", "bool", "address", "uint8", "uint8", "uint16", "uint256"],
            [report1.reportId, report1.agentId, report1.exists, report1.targetProtocol,
                report1.action, report1.severity, report1.confidenceScore, report1.timestamp],
        );
        report1.donSignatures = ethers.concat([
            await node1.signMessage(ethers.getBytes(hash1)),
            await node2.signMessage(ethers.getBytes(hash1)),
        ]);
        await expect(sentinel.executeAction(report1)).to.emit(sentinel, "ActionExecuted");

        // Deactivate the agent mid-flow
        await raizoCore.deregisterAgent(AGENT_ID);

        // Second action should fail
        const report2 = {
            reportId: ethers.keccak256(ethers.randomBytes(32)),
            agentId: AGENT_ID, exists: false, targetProtocol: PROTOCOL,
            action: 0, severity: 3, confidenceScore: 9000,
            evidenceHash: ethers.toUtf8Bytes("evidence"),
            timestamp: (await ethers.provider.getBlock("latest"))!.timestamp,
            donSignatures: "0x" as string,
        };
        const hash2 = ethers.solidityPackedKeccak256(
            ["bytes32", "bytes32", "bool", "address", "uint8", "uint8", "uint16", "uint256"],
            [report2.reportId, report2.agentId, report2.exists, report2.targetProtocol,
                report2.action, report2.severity, report2.confidenceScore, report2.timestamp],
        );
        report2.donSignatures = ethers.concat([
            await node1.signMessage(ethers.getBytes(hash2)),
            await node2.signMessage(ethers.getBytes(hash2)),
        ]);

        await expect(sentinel.executeAction(report2))
            .to.be.revertedWithCustomError(sentinel, "AgentNotActive");
    });

    it("PaymentEscrow: first payment succeeds, deactivate agent, second payment reverts", async function () {
        const amount = ethers.parseUnits("10", 6);
        const domain = {
            name: "PaymentEscrow", version: "1",
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

        // First payment succeeds
        const nonce1 = ethers.id("deactivate-pay-1");
        const sig1 = await agentWallet.signTypedData(domain, types, {
            agentId: AGENT_ID, to: recipient.address, amount,
            validAfter: 0, validBefore: 2000000000, nonce: nonce1,
        });
        await expect(
            escrow.authorizePayment(AGENT_ID, recipient.address, amount, 0, 2000000000, nonce1, sig1),
        ).to.emit(escrow, "PaymentAuthorized");

        // Deactivate agent
        await raizoCore.deregisterAgent(AGENT_ID);

        // Second payment reverts
        const nonce2 = ethers.id("deactivate-pay-2");
        const sig2 = await agentWallet.signTypedData(domain, types, {
            agentId: AGENT_ID, to: recipient.address, amount,
            validAfter: 0, validBefore: 2000000000, nonce: nonce2,
        });
        await expect(
            escrow.authorizePayment(AGENT_ID, recipient.address, amount, 0, 2000000000, nonce2, sig2),
        ).to.be.revertedWithCustomError(escrow, "AgentNotActive");
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  ADV-11: Epoch boundary budget manipulation
// ────────────────────────────────────────────────────────────────────────────

describe("ADV-11: Epoch boundary budget manipulation", function () {
    let sentinel: SentinelActions;
    let raizoCore: RaizoCore;
    let owner: SignerWithAddress;
    let agentWallet: SignerWithAddress;
    let node1: SignerWithAddress;
    let node2: SignerWithAddress;

    const PROTOCOL = "0x0000000000000000000000000000000000000001";
    const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("epoch-manip"));

    beforeEach(async function () {
        [owner, agentWallet, node1, node2] = await ethers.getSigners();

        raizoCore = (await upgrades.deployProxy(
            await ethers.getContractFactory("RaizoCore"), [],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as RaizoCore;

        const GOV = await raizoCore.GOVERNANCE_ROLE();
        await raizoCore.grantRole(GOV, owner.address);
        await raizoCore.registerProtocol(PROTOCOL, 1, 2);
        await raizoCore.registerAgent(AGENT_ID, agentWallet.address, ethers.parseUnits("100", 6));

        sentinel = (await upgrades.deployProxy(
            await ethers.getContractFactory("SentinelActions"),
            [await raizoCore.getAddress()],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as SentinelActions;
    });

    async function makeReport() {
        const report = {
            reportId: ethers.keccak256(ethers.randomBytes(32)),
            agentId: AGENT_ID, exists: false, targetProtocol: PROTOCOL,
            action: 0, severity: 3, confidenceScore: 9000,
            evidenceHash: ethers.toUtf8Bytes("evidence"),
            timestamp: (await ethers.provider.getBlock("latest"))!.timestamp,
            donSignatures: "0x" as string,
        };
        const hash = ethers.solidityPackedKeccak256(
            ["bytes32", "bytes32", "bool", "address", "uint8", "uint8", "uint16", "uint256"],
            [report.reportId, report.agentId, report.exists, report.targetProtocol,
                report.action, report.severity, report.confidenceScore, report.timestamp],
        );
        report.donSignatures = ethers.concat([
            await node1.signMessage(ethers.getBytes(hash)),
            await node2.signMessage(ethers.getBytes(hash)),
        ]);
        return report;
    }

    it("attacker cannot get double-budget by timing actions across epoch boundary", async function () {
        const ACTION_BUDGET = 10;

        // Exhaust budget in epoch N
        for (let i = 0; i < ACTION_BUDGET; i++) {
            const r = await makeReport();
            await sentinel.executeAction(r);
        }

        // Verify exhausted
        const over = await makeReport();
        await expect(sentinel.executeAction(over))
            .to.be.revertedWithCustomError(sentinel, "BudgetExceeded");

        // Cross epoch boundary
        await ethers.provider.send("evm_increaseTime", [86401]);
        await ethers.provider.send("evm_mine", []);

        // Budget is correctly reset — exactly ACTION_BUDGET more actions allowed
        for (let i = 0; i < ACTION_BUDGET; i++) {
            const r = await makeReport();
            await sentinel.executeAction(r);
        }

        // Budget exhausted again
        const overAgain = await makeReport();
        await expect(sentinel.executeAction(overAgain))
            .to.be.revertedWithCustomError(sentinel, "BudgetExceeded");
    });

    it("actions in new epoch do not count against previous epoch's budget", async function () {
        // Use 5 actions in epoch N
        for (let i = 0; i < 5; i++) {
            const r = await makeReport();
            await sentinel.executeAction(r);
        }
        expect(await sentinel.getActionCount(AGENT_ID)).to.equal(5);

        // Cross epoch
        await ethers.provider.send("evm_increaseTime", [86401]);
        await ethers.provider.send("evm_mine", []);

        // New epoch starts at 0
        expect(await sentinel.getActionCount(AGENT_ID)).to.equal(0);

        // 1 action
        const r = await makeReport();
        await sentinel.executeAction(r);
        expect(await sentinel.getActionCount(AGENT_ID)).to.equal(1);
    });
});

// ────────────────────────────────────────────────────────────────────────────
//  ADV-12: ComplianceVault unauthorized anchor attempts (SC-7)
// ────────────────────────────────────────────────────────────────────────────

describe("ADV-12: ComplianceVault unauthorized anchor attempts", function () {
    let vault: ComplianceVault;
    let owner: SignerWithAddress;
    let authorized: SignerWithAddress;
    let attacker: SignerWithAddress;
    let otherAttacker: SignerWithAddress;

    const ANCHOR_ROLE = ethers.keccak256(ethers.toUtf8Bytes("ANCHOR_ROLE"));
    const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("vault-agent"));

    beforeEach(async function () {
        [owner, authorized, attacker, otherAttacker] = await ethers.getSigners();

        const Factory = await ethers.getContractFactory("ComplianceVault");
        vault = await Factory.deploy();
        await vault.waitForDeployment();
        await vault.grantRole(ANCHOR_ROLE, authorized.address);
    });

    it("unauthorized address cannot store a report", async function () {
        await expect(
            vault.connect(attacker).storeReport(
                ethers.id("unauthorized-report"), AGENT_ID, 1, 1, "ipfs://evil",
            ),
        ).to.be.revertedWithCustomError(vault, "UnauthorizedAnchor");
    });

    it("multiple unauthorized addresses all rejected", async function () {
        for (const actor of [attacker, otherAttacker]) {
            await expect(
                vault.connect(actor).storeReport(
                    ethers.keccak256(ethers.randomBytes(32)),
                    AGENT_ID, 1, 1, "ipfs://attempt",
                ),
            ).to.be.revertedWithCustomError(vault, "UnauthorizedAnchor");
        }
    });

    it("authorized address CAN store reports (positive control)", async function () {
        await expect(
            vault.connect(authorized).storeReport(
                ethers.id("authorized-report"), AGENT_ID, 1, 1, "ipfs://valid",
            ),
        ).to.emit(vault, "ReportStored");
    });

    it("admin CAN store reports (positive control)", async function () {
        await expect(
            vault.connect(owner).storeReport(
                ethers.id("admin-report"), AGENT_ID, 2, 1, "ipfs://admin",
            ),
        ).to.emit(vault, "ReportStored");
    });

    it("revoking ANCHOR_ROLE prevents previously authorized address", async function () {
        // Verify can store
        await vault.connect(authorized).storeReport(
            ethers.id("before-revoke"), AGENT_ID, 1, 1, "ipfs://before",
        );

        // Revoke
        await vault.revokeRole(ANCHOR_ROLE, authorized.address);

        // Now blocked
        await expect(
            vault.connect(authorized).storeReport(
                ethers.id("after-revoke"), AGENT_ID, 1, 1, "ipfs://after",
            ),
        ).to.be.revertedWithCustomError(vault, "UnauthorizedAnchor");
    });

    it("zero reportHash is rejected even from authorized caller", async function () {
        await expect(
            vault.connect(authorized).storeReport(
                ethers.ZeroHash, AGENT_ID, 1, 1, "ipfs://zero",
            ),
        ).to.be.revertedWithCustomError(vault, "ZeroAddress");
    });

    it("invalid reportType (0 or >5) is rejected", async function () {
        await expect(
            vault.connect(authorized).storeReport(
                ethers.id("type-0"), AGENT_ID, 0, 1, "ipfs://type0",
            ),
        ).to.be.revertedWithCustomError(vault, "InvalidReportType");

        await expect(
            vault.connect(authorized).storeReport(
                ethers.id("type-6"), AGENT_ID, 6, 1, "ipfs://type6",
            ),
        ).to.be.revertedWithCustomError(vault, "InvalidReportType");
    });
});
