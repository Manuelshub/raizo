/**
 * @file OperatorDashboard.test.ts
 * @notice WS-10 TDD RED-phase test suite for Operator Dashboard modules.
 *
 * Spec References:
 *   ARCHITECTURE.md §6   — Security Architecture: Monitoring & Response (Layer 6)
 *   AI_AGENTS.md §6.2    — Agent Monitoring & Health (budget util, consensus failure, latency)
 *   SMART_CONTRACTS.md §2 — All contract events: ActionExecuted, ReportStored, AlertSent,
 *                           ProposalCreated, VoteCast, ProposalExecuted, Deposited, PaymentAuthorized
 *   COMPLIANCE.md §9      — Compliance Scoring Model (weighted category formula: 0–100)
 *   COMPLIANCE.md §3      — ACE Pipeline (Summary → Dashboard: operator visibility)
 *   SECURITY.md §6.1      — Severity Levels: P0–P3 (dashboard alert classification)
 *
 * Strategy:
 *   Tests exercise four new dashboard logic modules via real deployed Solidity
 *   contracts in Hardhat's CJS Mocha runner. No external APIs — all events are
 *   emitted by on-chain transactions and indexed by the off-chain modules.
 *
 * Coverage:
 *   EVT-1→8:   EventIndexer (event indexing, filtering, pagination, aggregation)
 *   CSR-1→6:   ComplianceScoreReader (report retrieval, weighted score computation)
 *   AHM-1→8:   AgentHealthMonitor (budget utilization, wallet runway, health snapshot)
 *   GOV-1→8:   GovernanceLifecycleTracker (proposal lifecycle, vote aggregation, expiry)
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { Signer } from "ethers";
import { mine } from "@nomicfoundation/hardhat-network-helpers";
import {
    RaizoCore,
    SentinelActions,
    ComplianceVault,
    GovernanceGate,
    PaymentEscrow,
    MockUSDC,
    MockWorldID,
    MockSentinelActions as MockSentinelActionsType,
    MockCCIPRouter,
} from "../../typechain-types";
import { EventIndexer } from "../../workflows/logic/event-indexer";
import { ComplianceScoreReader } from "../../workflows/logic/compliance-score-reader";
import { AgentHealthMonitor } from "../../workflows/logic/agent-health-monitor";
import { GovernanceLifecycleTracker } from "../../workflows/logic/governance-lifecycle";

// ═══════════════════════════════════════════════════════════════════════════════
// 1. EVENT INDEXER (ARCHITECTURE.md §6 Layer 6, SMART_CONTRACTS.md §2)
// ═══════════════════════════════════════════════════════════════════════════════

describe("WS-10: Event Indexer (EVT-1 to 8)", function () {
    let raizoCore: RaizoCore;
    let sentinel: SentinelActions;
    let vault: ComplianceVault;
    let relay: any;
    let mockSentinel: MockSentinelActionsType;
    let mockRouter: MockCCIPRouter;
    let owner: Signer;
    let emergency: Signer;
    let agentWallet: Signer;
    let indexer: EventIndexer;

    const AGENT_ID = ethers.id("raizo.sentinel.evt.v1");
    const PROTOCOL_A = "0x0000000000000000000000000000000000000001";
    const CHAIN_ID = 1;

    before(async function () {
        [owner, emergency, agentWallet] = await ethers.getSigners();

        // Deploy RaizoCore
        const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
        raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
            initializer: "initialize", kind: "uups",
        })) as unknown as RaizoCore;
        await raizoCore.waitForDeployment();

        // Deploy SentinelActions
        const SentinelFactory = await ethers.getContractFactory("SentinelActions");
        sentinel = (await upgrades.deployProxy(SentinelFactory, [
            await raizoCore.getAddress(),
        ], { initializer: "initialize", kind: "uups" })) as unknown as SentinelActions;
        await sentinel.waitForDeployment();

        // Deploy ComplianceVault (non-upgradeable)
        const VaultFactory = await ethers.getContractFactory("ComplianceVault");
        vault = (await VaultFactory.deploy()) as unknown as ComplianceVault;
        await vault.waitForDeployment();

        // Deploy mocks for CrossChainRelay
        const MockSentinelFactory = await ethers.getContractFactory("MockSentinelActions");
        mockSentinel = await MockSentinelFactory.deploy();
        const MockRouterFactory = await ethers.getContractFactory("MockCCIPRouter");
        mockRouter = await MockRouterFactory.deploy();

        // Deploy CrossChainRelay
        const RelayFactory = await ethers.getContractFactory("CrossChainRelay");
        relay = (await upgrades.deployProxy(RelayFactory, [
            await mockRouter.getAddress(),
            await mockSentinel.getAddress(),
            await raizoCore.getAddress(),
        ]));
        await relay.waitForDeployment();

        // Setup roles
        const GOVERNANCE_ROLE = await raizoCore.GOVERNANCE_ROLE();
        await raizoCore.grantRole(GOVERNANCE_ROLE, await owner.getAddress());
        const EMERGENCY_ROLE = await sentinel.EMERGENCY_ROLE();
        await sentinel.grantRole(EMERGENCY_ROLE, await emergency.getAddress());
        const ANCHOR_ROLE = await vault.ANCHOR_ROLE();
        await vault.grantRole(ANCHOR_ROLE, await owner.getAddress());

        // Register protocol & agent
        await raizoCore.registerProtocol(PROTOCOL_A, CHAIN_ID, 2);
        await raizoCore.registerAgent(AGENT_ID, await agentWallet.getAddress(), ethers.parseUnits("100", 6));
        await raizoCore.setConfidenceThreshold(8500);

        // Emit EmergencyPause event
        await sentinel.connect(emergency).executeEmergencyPause(PROTOCOL_A);

        // Emit ReportStored events
        await vault.storeReport(ethers.id("report-1"), AGENT_ID, 1, CHAIN_ID, "ipfs://report-1");
        await vault.storeReport(ethers.id("report-2"), AGENT_ID, 4, CHAIN_ID, "ipfs://report-2");
        await vault.storeReport(ethers.id("report-3"), AGENT_ID, 1, 10, "ipfs://report-3");

        // Create the indexer with contract references
        indexer = new EventIndexer(sentinel, vault, relay);
    });

    it("EVT-1: indexes ActionExecuted / EmergencyPause events from SentinelActions", async function () {
        const events = await indexer.getSentinelEvents();
        expect(events.length).to.be.greaterThanOrEqual(1);
        const ep = events.find(e => e.eventName === "EmergencyPause");
        expect(ep).to.not.be.undefined;
        expect(ep!.args.protocol).to.equal(PROTOCOL_A);
    });

    it("EVT-2: indexes ReportStored events from ComplianceVault", async function () {
        const events = await indexer.getComplianceEvents();
        expect(events.length).to.equal(3);
        expect(events[0].args.reportHash).to.equal(ethers.id("report-1"));
    });

    it("EVT-3: indexes AlertSent events from CrossChainRelay", async function () {
        const events = await indexer.getRelayEvents();
        expect(events).to.be.an("array");
    });

    it("EVT-4: filters events by block range (fromBlock, toBlock)", async function () {
        const currentBlock = await ethers.provider.getBlockNumber();
        const events = await indexer.getComplianceEvents({
            fromBlock: 0, toBlock: currentBlock,
        });
        expect(events.length).to.equal(3);

        const futureEvents = await indexer.getComplianceEvents({
            fromBlock: currentBlock + 1000, toBlock: currentBlock + 2000,
        });
        expect(futureEvents.length).to.equal(0);
    });

    it("EVT-5: filters compliance events by report type", async function () {
        const amlEvents = await indexer.getComplianceEvents({ reportType: 1 });
        expect(amlEvents.length).to.equal(2);
        amlEvents.forEach(e => expect(e.args.reportType).to.equal(1));
    });

    it("EVT-6: paginates results with offset and limit", async function () {
        const page1 = await indexer.getComplianceEvents({ offset: 0, limit: 2 });
        expect(page1.length).to.equal(2);

        const page2 = await indexer.getComplianceEvents({ offset: 2, limit: 2 });
        expect(page2.length).to.equal(1);

        expect(page1[0].args.reportHash).to.not.equal(page2[0].args.reportHash);
    });

    it("EVT-7: aggregates event counts by type for dashboard summary", async function () {
        const summary = await indexer.getEventSummary();
        expect(summary).to.have.property("sentinelEvents");
        expect(summary).to.have.property("complianceEvents");
        expect(summary).to.have.property("relayEvents");
        expect(summary.complianceEvents).to.equal(3);
        expect(summary.sentinelEvents).to.be.greaterThanOrEqual(1);
    });

    it("EVT-8: returns empty array when no events match filters", async function () {
        const events = await indexer.getComplianceEvents({ reportType: 5 });
        expect(events).to.be.an("array");
        expect(events.length).to.equal(0);
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. COMPLIANCE SCORE READER (COMPLIANCE.md §9, SMART_CONTRACTS.md §2.3)
// ═══════════════════════════════════════════════════════════════════════════════

describe("WS-10: Compliance Score Reader (CSR-1 to 6)", function () {
    let vault: ComplianceVault;
    let owner: Signer;
    let reader: ComplianceScoreReader;

    const AGENT_ID = ethers.id("raizo.compliance.csr.v1");
    const CHAIN_ETH = 1;
    const CHAIN_BASE = 8453;

    before(async function () {
        [owner] = await ethers.getSigners();

        const VaultFactory = await ethers.getContractFactory("ComplianceVault");
        vault = (await VaultFactory.deploy()) as unknown as ComplianceVault;
        await vault.waitForDeployment();

        const ANCHOR_ROLE = await vault.ANCHOR_ROLE();
        await vault.grantRole(ANCHOR_ROLE, await owner.getAddress());

        // Store diverse reports
        await vault.storeReport(ethers.id("aml-1"), AGENT_ID, 1, CHAIN_ETH, "ipfs://aml-1");
        await vault.storeReport(ethers.id("aml-2"), AGENT_ID, 1, CHAIN_ETH, "ipfs://aml-2");
        await vault.storeReport(ethers.id("kyc-1"), AGENT_ID, 2, CHAIN_ETH, "ipfs://kyc-1");
        await vault.storeReport(ethers.id("esg-1"), AGENT_ID, 3, CHAIN_ETH, "ipfs://esg-1");
        await vault.storeReport(ethers.id("mica-1"), AGENT_ID, 4, CHAIN_ETH, "ipfs://mica-1");
        await vault.storeReport(ethers.id("mica-2"), AGENT_ID, 4, CHAIN_ETH, "ipfs://mica-2");
        await vault.storeReport(ethers.id("aml-base-1"), AGENT_ID, 1, CHAIN_BASE, "ipfs://aml-base-1");

        reader = new ComplianceScoreReader(vault);
    });

    it("CSR-1: reads total report count from ComplianceVault", async function () {
        const count = await reader.getReportCount();
        expect(count).to.equal(7);
    });

    it("CSR-2: retrieves reports filtered by type (AML=1, MiCA=4)", async function () {
        const amlReports = await reader.getReportsByType(1);
        expect(amlReports.length).to.equal(3);

        const micaReports = await reader.getReportsByType(4);
        expect(micaReports.length).to.equal(2);
    });

    it("CSR-3: retrieves reports filtered by chain ID", async function () {
        const ethReports = await reader.getReportsByChain(CHAIN_ETH);
        expect(ethReports.length).to.equal(6);

        const baseReports = await reader.getReportsByChain(CHAIN_BASE);
        expect(baseReports.length).to.equal(1);
    });

    it("CSR-4: computes per-chain compliance score using COMPLIANCE.md S9 weighted formula", async function () {
        const score = await reader.computeComplianceScore(CHAIN_ETH);
        expect(score.overall).to.be.a("number");
        expect(score.overall).to.be.greaterThan(0);
        expect(score.overall).to.be.lessThanOrEqual(100);
    });

    it("CSR-5: returns zero score when no reports exist for a chain", async function () {
        const score = await reader.computeComplianceScore(42161);
        expect(score.overall).to.equal(0);
    });

    it("CSR-6: returns breakdown by category with individual weights", async function () {
        const score = await reader.computeComplianceScore(CHAIN_ETH);
        expect(score).to.have.property("breakdown");
        expect(score.breakdown).to.have.property("aml");
        expect(score.breakdown).to.have.property("kyc");
        expect(score.breakdown).to.have.property("regulatory");
        expect(score.breakdown).to.have.property("reserve");
        Object.values(score.breakdown).forEach((v: any) => {
            expect(v).to.be.a("number");
            expect(v).to.be.greaterThanOrEqual(0);
            expect(v).to.be.lessThanOrEqual(100);
        });
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3. AGENT HEALTH MONITOR (AI_AGENTS.md §6.2, ARCHITECTURE.md §6 Layer 6)
// ═══════════════════════════════════════════════════════════════════════════════

describe("WS-10: Agent Health Monitor (AHM-1 to 8)", function () {
    let raizoCore: RaizoCore;
    let sentinel: SentinelActions;
    let escrow: PaymentEscrow;
    let usdc: MockUSDC;
    let owner: Signer;
    let agentWallet: Signer;
    let provider: Signer;
    let monitor: AgentHealthMonitor;

    const AGENT_ID = ethers.id("raizo.sentinel.ahm.v1");
    const DAILY_BUDGET = ethers.parseUnits("100", 6);
    const CHAIN_ID = 1;
    const PROTOCOL_A = "0x0000000000000000000000000000000000000001";

    before(async function () {
        [owner, agentWallet, provider] = await ethers.getSigners();

        const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
        raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
            initializer: "initialize", kind: "uups",
        })) as unknown as RaizoCore;
        await raizoCore.waitForDeployment();

        const SentinelFactory = await ethers.getContractFactory("SentinelActions");
        sentinel = (await upgrades.deployProxy(SentinelFactory, [
            await raizoCore.getAddress(),
        ], { initializer: "initialize", kind: "uups" })) as unknown as SentinelActions;
        await sentinel.waitForDeployment();

        const MockUSDCFactory = await ethers.getContractFactory("MockUSDC");
        usdc = (await MockUSDCFactory.deploy()) as unknown as MockUSDC;
        await usdc.waitForDeployment();

        const PaymentEscrowFactory = await ethers.getContractFactory("PaymentEscrow");
        escrow = (await upgrades.deployProxy(PaymentEscrowFactory, [
            await raizoCore.getAddress(),
            await usdc.getAddress(),
        ], { initializer: "initialize", kind: "uups" })) as unknown as PaymentEscrow;
        await escrow.waitForDeployment();

        const GOVERNANCE_ROLE = await raizoCore.GOVERNANCE_ROLE();
        await raizoCore.grantRole(GOVERNANCE_ROLE, await owner.getAddress());
        await raizoCore.registerProtocol(PROTOCOL_A, CHAIN_ID, 2);
        await raizoCore.registerAgent(AGENT_ID, await agentWallet.getAddress(), DAILY_BUDGET);
        await raizoCore.setConfidenceThreshold(8500);

        const depositAmount = ethers.parseUnits("200", 6);
        await usdc.mint(await provider.getAddress(), depositAmount);
        await usdc.connect(provider).approve(await escrow.getAddress(), depositAmount);
        await escrow.connect(provider).deposit(AGENT_ID, depositAmount);

        monitor = new AgentHealthMonitor(raizoCore, sentinel, escrow);
    });

    it("AHM-1: reads budget utilization (dailySpent / dailyBudgetUSDC)", async function () {
        const util = await monitor.getBudgetUtilization(AGENT_ID);
        expect(util).to.have.property("dailySpent");
        expect(util).to.have.property("dailyBudget");
        expect(util).to.have.property("utilizationPct");
        expect(util.utilizationPct).to.be.a("number");
        expect(util.utilizationPct).to.be.greaterThanOrEqual(0);
        expect(util.utilizationPct).to.be.lessThanOrEqual(100);
    });

    it("AHM-2: reads action budget utilization (actionCount / actionBudgetPerEpoch)", async function () {
        const util = await monitor.getActionBudgetUtilization(AGENT_ID);
        expect(util).to.have.property("actionsUsed");
        expect(util).to.have.property("actionBudget");
        expect(util).to.have.property("utilizationPct");
        expect(util.actionsUsed).to.be.a("number");
        expect(util.actionBudget).to.be.a("number");
    });

    it("AHM-3: detects low wallet balance (<24h runway) per AI_AGENTS.md S6.2", async function () {
        const health = await monitor.getWalletRunway(AGENT_ID);
        expect(health).to.have.property("balance");
        expect(health).to.have.property("dailyBudget");
        expect(health).to.have.property("runwayDays");
        expect(health).to.have.property("isLow");
        expect(health.runwayDays).to.equal(2);
        expect(health.isLow).to.be.false;
    });

    it("AHM-4: detects low wallet runway when balance is insufficient", async function () {
        const AGENT_LOW = ethers.id("raizo.sentinel.low.v1");
        const LOW_BUDGET = ethers.parseUnits("100", 6);
        await raizoCore.registerAgent(AGENT_LOW, await agentWallet.getAddress(), LOW_BUDGET);
        const smallDeposit = ethers.parseUnits("50", 6);
        await usdc.mint(await provider.getAddress(), smallDeposit);
        await usdc.connect(provider).approve(await escrow.getAddress(), smallDeposit);
        await escrow.connect(provider).deposit(AGENT_LOW, smallDeposit);

        const health = await monitor.getWalletRunway(AGENT_LOW);
        expect(health.runwayDays).to.equal(0);
        expect(health.isLow).to.be.true;
    });

    it("AHM-5: reports agent as active or inactive based on RaizoCore registration", async function () {
        const snapshot = await monitor.getHealthSnapshot(AGENT_ID);
        expect(snapshot.isActive).to.be.true;
    });

    it("AHM-6: returns full health snapshot for a given agentId", async function () {
        const snapshot = await monitor.getHealthSnapshot(AGENT_ID);
        expect(snapshot).to.have.property("agentId", AGENT_ID);
        expect(snapshot).to.have.property("isActive");
        expect(snapshot).to.have.property("budgetUtilization");
        expect(snapshot).to.have.property("actionBudgetUtilization");
        expect(snapshot).to.have.property("walletRunway");
        expect(snapshot.budgetUtilization).to.have.property("utilizationPct");
        expect(snapshot.walletRunway).to.have.property("runwayDays");
    });

    it("AHM-7: detects approaching budget exhaustion (>80% threshold per AI_AGENTS.md S6.2)", async function () {
        const snapshot = await monitor.getHealthSnapshot(AGENT_ID);
        expect(snapshot).to.have.property("budgetExhaustionAlert");
        expect(snapshot.budgetExhaustionAlert).to.be.false;
    });

    it("AHM-8: handles inactive/deregistered agent gracefully", async function () {
        const UNKNOWN_AGENT = ethers.id("raizo.unknown.agent.v1");
        const snapshot = await monitor.getHealthSnapshot(UNKNOWN_AGENT);
        expect(snapshot.isActive).to.be.false;
        expect(snapshot.budgetUtilization.utilizationPct).to.equal(0);
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 4. GOVERNANCE LIFECYCLE TRACKER (SMART_CONTRACTS.md §2.4, ARCHITECTURE.md §6)
// ═══════════════════════════════════════════════════════════════════════════════

describe("WS-10: Governance Lifecycle Tracker (GOV-1 to 8)", function () {
    let govGate: GovernanceGate;
    let worldId: MockWorldID;
    let owner: Signer;
    let proposer: Signer;
    let voter1: Signer;
    let voter2: Signer;
    let tracker: GovernanceLifecycleTracker;

    const DESCRIPTION_HASH = ethers.id("Update Confidence Threshold to 90%");
    const ROOT = 12345n;
    const PROOF: [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint] =
        [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];

    before(async function () {
        [owner, proposer, voter1, voter2] = await ethers.getSigners();

        // Deploy MockWorldID
        const MockWorldIDFactory = await ethers.getContractFactory("MockWorldID");
        worldId = (await MockWorldIDFactory.deploy()) as unknown as MockWorldID;
        await worldId.waitForDeployment();

        // Deploy GovernanceGate
        const GovernanceGateFactory = await ethers.getContractFactory("GovernanceGate");
        govGate = (await upgrades.deployProxy(GovernanceGateFactory, [
            await worldId.getAddress(),
        ], { initializer: "initialize", kind: "uups" })) as unknown as GovernanceGate;
        await govGate.waitForDeployment();

        // Create proposal #1
        const nullifierProposer = 100001n;
        const txPropose = await govGate.connect(proposer).propose(DESCRIPTION_HASH, ROOT, nullifierProposer, PROOF);
        const proposalReceipt = await txPropose.wait();

        // Cast votes on proposal #0 (within same block range, well within 7200 block period)
        // NOTE: proposalId = proposalCount++ (post-increment), so first proposal = ID 0
        const nullifierVoter1 = 100002n;
        await govGate.connect(voter1).vote(0, true, ROOT, nullifierVoter1, PROOF);

        const nullifierVoter2 = 100003n;
        await govGate.connect(voter2).vote(0, false, ROOT, nullifierVoter2, PROOF);

        tracker = new GovernanceLifecycleTracker(govGate);
    });

    it("GOV-1: tracks ProposalCreated event and returns proposal details", async function () {
        const proposals = await tracker.getProposals();
        expect(proposals.length).to.be.greaterThanOrEqual(1);
        const first = proposals[0];
        expect(first.proposalId).to.equal(0);
        expect(first.descriptionHash).to.equal(DESCRIPTION_HASH);
    });

    it("GOV-2: tracks VoteCast events and aggregates for/against totals", async function () {
        const votes = await tracker.getVoteSummary(0);
        expect(votes.forVotes).to.equal(1);
        expect(votes.againstVotes).to.equal(1);
        expect(votes.totalVotes).to.equal(2);
    });

    it("GOV-3: detects proposal status based on vote counts", async function () {
        const status = await tracker.getProposalStatus(0);
        expect(status).to.have.property("passed");
        expect(status).to.have.property("executed");
        expect(status.executed).to.be.false;
    });

    it("GOV-4: returns proposal lifecycle with all phases", async function () {
        const lifecycle = await tracker.getProposalLifecycle(0);
        expect(lifecycle).to.have.property("created");
        expect(lifecycle).to.have.property("votingActive");
        expect(lifecycle).to.have.property("executed");
        expect(lifecycle.created).to.be.true;
    });

    it("GOV-5: returns full lifecycle timeline with block numbers", async function () {
        const timeline = await tracker.getProposalTimeline(0);
        expect(timeline).to.have.property("createdAtBlock");
        expect(timeline).to.have.property("startBlock");
        expect(timeline).to.have.property("endBlock");
        expect(timeline.createdAtBlock).to.be.a("number");
        expect(timeline.startBlock).to.be.a("number");
        expect(timeline.endBlock).to.be.a("number");
        expect(timeline.endBlock).to.be.greaterThan(timeline.startBlock);
    });

    it("GOV-6: detects expired proposals (endBlock passed, not executed)", async function () {
        // Mine blocks past the voting period to expire proposal #1
        const proposal = await govGate.getProposal(0);
        const currentBlock = await ethers.provider.getBlockNumber();
        const blocksToMine = Number(proposal.endBlock) - currentBlock + 1;
        if (blocksToMine > 0) {
            await mine(blocksToMine);
        }
        const status = await tracker.getProposalStatus(0);
        expect(status).to.have.property("expired");
        expect(status.expired).to.be.true;
    });

    it("GOV-7: returns all active proposals (created but not executed/expired)", async function () {
        // Create a new proposal #2 that should be active
        const nullifier2 = 100004n;
        const descHash2 = ethers.id("Proposal #2: Raise action budget");
        await govGate.connect(proposer).propose(descHash2, ROOT, nullifier2, PROOF);

        const active = await tracker.getActiveProposals();
        const ids = active.map(p => p.proposalId);
        expect(ids).to.include(1);
    });

    it("GOV-8: computes participation rate (total votes / total proposals)", async function () {
        const participation = await tracker.getParticipationRate();
        expect(participation).to.have.property("totalVotesCast");
        expect(participation).to.have.property("totalProposals");
        expect(participation).to.have.property("avgVotesPerProposal");
        expect(participation.totalVotesCast).to.be.greaterThanOrEqual(2);
        expect(participation.totalProposals).to.be.greaterThanOrEqual(1);
        expect(participation.avgVotesPerProposal).to.be.a("number");
    });
});
