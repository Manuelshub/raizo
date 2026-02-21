/**
 * @file SentinelActions.fuzz.ts
 * @notice Deep fuzz testing for SentinelActions — property-based verification
 *         of budget enforcement, epoch boundaries, multi-agent isolation,
 *         confidence gating, action type coverage, and duplicate rejection.
 *
 * Test IDs map to implementation-guide.md §4.1:
 *   FUZZ-SA-1  Budget enforcement across random inputs
 *   FUZZ-SA-2  Epoch boundary budget reset
 *   FUZZ-SA-3  Multi-agent budget isolation
 *   FUZZ-SA-4  All 5 action types accepted
 *   FUZZ-SA-5  Confidence boundary precision
 *   FUZZ-SA-6  Rapid-fire same-block actions
 *   FUZZ-SA-7  DON signature length variations
 *   FUZZ-SA-8  Duplicate reportId rejection under stress
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { SentinelActions, RaizoCore } from "../../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("SentinelActions Deep Fuzz Suite", function () {
    // ────────────────────────────────────────────────────────────────────
    //  Shared setup helpers
    // ────────────────────────────────────────────────────────────────────

    const PROTOCOL_A = "0x0000000000000000000000000000000000000001";
    const BUDGET_USDC = ethers.parseUnits("1000", 6);
    const ACTION_BUDGET = 10; // default from RaizoCore

    async function deployFresh() {
        const signers = await ethers.getSigners();
        const [owner, agentWallet, node1, node2, agent2Wallet, agent3Wallet] = signers;

        const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
        const raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
            initializer: "initialize",
        })) as unknown as RaizoCore;
        await raizoCore.waitForDeployment();

        const SentinelFactory = await ethers.getContractFactory("SentinelActions");
        const sentinel = (await upgrades.deployProxy(
            SentinelFactory,
            [await raizoCore.getAddress()],
            { initializer: "initialize" },
        )) as unknown as SentinelActions;
        await sentinel.waitForDeployment();

        const GOV = await raizoCore.GOVERNANCE_ROLE();
        await raizoCore.grantRole(GOV, owner.address);
        await raizoCore.registerProtocol(PROTOCOL_A, 1, 2);

        return { raizoCore, sentinel, owner, agentWallet, node1, node2, agent2Wallet, agent3Wallet };
    }

    async function buildSignedReport(
        node1: SignerWithAddress,
        node2: SignerWithAddress,
        overrides: {
            reportId?: string;
            agentId?: string;
            confidenceScore?: number;
            action?: number;
            severity?: number;
        } = {},
    ) {
        const report = {
            reportId: overrides.reportId ?? ethers.keccak256(ethers.randomBytes(32)),
            agentId: overrides.agentId ?? ethers.keccak256(ethers.toUtf8Bytes("fuzz-agent")),
            exists: false,
            targetProtocol: PROTOCOL_A,
            action: overrides.action ?? 0,
            severity: overrides.severity ?? 3,
            confidenceScore: overrides.confidenceScore ?? 9000,
            evidenceHash: ethers.toUtf8Bytes("evidence"),
            timestamp: (await ethers.provider.getBlock("latest"))!.timestamp,
            donSignatures: "0x" as string,
        };

        const hash = ethers.solidityPackedKeccak256(
            ["bytes32", "bytes32", "bool", "address", "uint8", "uint8", "uint16", "uint256"],
            [report.reportId, report.agentId, report.exists, report.targetProtocol,
                report.action, report.severity, report.confidenceScore, report.timestamp],
        );
        const sig1 = await node1.signMessage(ethers.getBytes(hash));
        const sig2 = await node2.signMessage(ethers.getBytes(hash));
        report.donSignatures = ethers.concat([sig1, sig2]);

        return report;
    }

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-SA-1: Budget enforcement across random inputs
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-SA-1: Budget enforcement across random inputs", function () {
        it("should correctly enforce budget for 100 randomized reports", async function () {
            const { raizoCore, sentinel, agentWallet, node1, node2 } = await deployFresh();
            const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("fuzz-agent-sa1"));
            await raizoCore.registerAgent(AGENT_ID, agentWallet.address, BUDGET_USDC);

            let successCount = 0;

            for (let i = 0; i < 100; i++) {
                const confidence = Math.floor(Math.random() * 10000);
                const severity = Math.floor(Math.random() * 4);
                const report = await buildSignedReport(node1, node2, {
                    agentId: AGENT_ID,
                    confidenceScore: confidence,
                    severity,
                });

                if (confidence < 8500) {
                    await expect(sentinel.executeAction(report))
                        .to.be.revertedWithCustomError(sentinel, "ConfidenceThresholdNotMet")
                        .withArgs(report.confidenceScore, 8500);
                } else if (successCount >= ACTION_BUDGET) {
                    await expect(sentinel.executeAction(report))
                        .to.be.revertedWithCustomError(sentinel, "BudgetExceeded");
                } else {
                    await expect(sentinel.executeAction(report))
                        .to.emit(sentinel, "ActionExecuted");
                    successCount++;
                }
            }

            expect(successCount).to.be.lte(ACTION_BUDGET);
        });
    });

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-SA-2: Epoch boundary budget reset
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-SA-2: Epoch boundary budget reset", function () {
        it("budget resets when time crosses an epoch boundary", async function () {
            const { raizoCore, sentinel, agentWallet, node1, node2 } = await deployFresh();
            const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("epoch-agent"));
            await raizoCore.registerAgent(AGENT_ID, agentWallet.address, BUDGET_USDC);

            // Exhaust budget in current epoch
            for (let i = 0; i < ACTION_BUDGET; i++) {
                const r = await buildSignedReport(node1, node2, { agentId: AGENT_ID });
                await sentinel.executeAction(r);
            }

            // Verify budget is exhausted
            const overBudget = await buildSignedReport(node1, node2, { agentId: AGENT_ID });
            await expect(sentinel.executeAction(overBudget))
                .to.be.revertedWithCustomError(sentinel, "BudgetExceeded");

            // Advance past epoch boundary (1 day = default epoch)
            await ethers.provider.send("evm_increaseTime", [86401]);
            await ethers.provider.send("evm_mine", []);

            // Budget should be reset — new action should succeed
            const newEpochReport = await buildSignedReport(node1, node2, { agentId: AGENT_ID });
            await expect(sentinel.executeAction(newEpochReport))
                .to.emit(sentinel, "ActionExecuted");

            // Verify action count reset to 1
            const count = await sentinel.getActionCount(AGENT_ID);
            expect(count).to.equal(1);
        });

        it("fuzz: budget correctly tracks across multiple epoch rollovers", async function () {
            const { raizoCore, sentinel, agentWallet, node1, node2 } = await deployFresh();
            const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("multi-epoch"));
            await raizoCore.registerAgent(AGENT_ID, agentWallet.address, BUDGET_USDC);

            for (let epoch = 0; epoch < 5; epoch++) {
                // Use 3 random actions per epoch (well within budget)
                const actionsThisEpoch = Math.floor(Math.random() * 3) + 1;
                for (let j = 0; j < actionsThisEpoch; j++) {
                    const r = await buildSignedReport(node1, node2, { agentId: AGENT_ID });
                    await sentinel.executeAction(r);
                }

                const count = await sentinel.getActionCount(AGENT_ID);
                expect(count).to.equal(actionsThisEpoch);

                // Advance to next epoch
                await ethers.provider.send("evm_increaseTime", [86401]);
                await ethers.provider.send("evm_mine", []);
            }
        });
    });

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-SA-3: Multi-agent budget isolation
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-SA-3: Multi-agent budget isolation", function () {
        it("each agent's budget is tracked independently", async function () {
            const { raizoCore, sentinel, node1, node2, agentWallet, agent2Wallet, agent3Wallet } =
                await deployFresh();

            const agents = [
                { id: ethers.keccak256(ethers.toUtf8Bytes("agent-alpha")), wallet: agentWallet },
                { id: ethers.keccak256(ethers.toUtf8Bytes("agent-beta")), wallet: agent2Wallet },
                { id: ethers.keccak256(ethers.toUtf8Bytes("agent-gamma")), wallet: agent3Wallet },
            ];

            for (const a of agents) {
                await raizoCore.registerAgent(a.id, a.wallet.address, BUDGET_USDC);
            }

            // Each agent executes a random number of actions (1-5)
            const actionCounts: number[] = [];
            for (const a of agents) {
                const n = Math.floor(Math.random() * 5) + 1;
                for (let j = 0; j < n; j++) {
                    const r = await buildSignedReport(node1, node2, { agentId: a.id });
                    await sentinel.executeAction(r);
                }
                actionCounts.push(n);
            }

            // Verify each agent's count is independent
            for (let i = 0; i < agents.length; i++) {
                const count = await sentinel.getActionCount(agents[i].id);
                expect(count).to.equal(actionCounts[i],
                    `Agent ${i} count mismatch: expected ${actionCounts[i]}, got ${count}`);
            }
        });

        it("exhausting one agent's budget does not affect others", async function () {
            const { raizoCore, sentinel, node1, node2, agentWallet, agent2Wallet } =
                await deployFresh();

            const AGENT_A = ethers.keccak256(ethers.toUtf8Bytes("exhaust-a"));
            const AGENT_B = ethers.keccak256(ethers.toUtf8Bytes("fresh-b"));
            await raizoCore.registerAgent(AGENT_A, agentWallet.address, BUDGET_USDC);
            await raizoCore.registerAgent(AGENT_B, agent2Wallet.address, BUDGET_USDC);

            // Exhaust Agent A's budget
            for (let i = 0; i < ACTION_BUDGET; i++) {
                const r = await buildSignedReport(node1, node2, { agentId: AGENT_A });
                await sentinel.executeAction(r);
            }

            // Agent A is over budget
            const overA = await buildSignedReport(node1, node2, { agentId: AGENT_A });
            await expect(sentinel.executeAction(overA))
                .to.be.revertedWithCustomError(sentinel, "BudgetExceeded");

            // Agent B should still work
            const bReport = await buildSignedReport(node1, node2, { agentId: AGENT_B });
            await expect(sentinel.executeAction(bReport))
                .to.emit(sentinel, "ActionExecuted");
        });
    });

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-SA-4: All 5 action types accepted
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-SA-4: All 5 action types accepted", function () {
        it("PAUSE, RATE_LIMIT, DRAIN_BLOCK, ALERT, CUSTOM all execute successfully", async function () {
            const { raizoCore, sentinel, agentWallet, node1, node2 } = await deployFresh();
            const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("action-type-agent"));
            await raizoCore.registerAgent(AGENT_ID, agentWallet.address, BUDGET_USDC);

            const actionTypes = [0, 1, 2, 3, 4]; // PAUSE, RATE_LIMIT, DRAIN_BLOCK, ALERT, CUSTOM

            for (const actionType of actionTypes) {
                const r = await buildSignedReport(node1, node2, {
                    agentId: AGENT_ID,
                    action: actionType,
                });
                await expect(sentinel.executeAction(r))
                    .to.emit(sentinel, "ActionExecuted");
            }

            const count = await sentinel.getActionCount(AGENT_ID);
            expect(count).to.equal(5);
        });
    });

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-SA-5: Confidence boundary precision
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-SA-5: Confidence boundary precision", function () {
        let sentinel: SentinelActions;
        let raizoCore: RaizoCore;
        let node1: SignerWithAddress;
        let node2: SignerWithAddress;
        let AGENT_ID: string;

        before(async function () {
            const ctx = await deployFresh();
            sentinel = ctx.sentinel;
            raizoCore = ctx.raizoCore;
            node1 = ctx.node1;
            node2 = ctx.node2;
            AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("boundary-agent"));
            await raizoCore.registerAgent(AGENT_ID, ctx.agentWallet.address, BUDGET_USDC);
        });

        it("confidence 8499 (just below threshold) → revert", async function () {
            const r = await buildSignedReport(node1, node2, {
                agentId: AGENT_ID,
                confidenceScore: 8499,
            });
            await expect(sentinel.executeAction(r))
                .to.be.revertedWithCustomError(sentinel, "ConfidenceThresholdNotMet")
                .withArgs(8499, 8500);
        });

        it("confidence 8500 (exact threshold) → succeed", async function () {
            const r = await buildSignedReport(node1, node2, {
                agentId: AGENT_ID,
                confidenceScore: 8500,
            });
            await expect(sentinel.executeAction(r))
                .to.emit(sentinel, "ActionExecuted");
        });

        it("confidence 8501 (just above threshold) → succeed", async function () {
            const r = await buildSignedReport(node1, node2, {
                agentId: AGENT_ID,
                confidenceScore: 8501,
            });
            await expect(sentinel.executeAction(r))
                .to.emit(sentinel, "ActionExecuted");
        });

        it("confidence 0 → revert", async function () {
            const r = await buildSignedReport(node1, node2, {
                agentId: AGENT_ID,
                confidenceScore: 0,
            });
            await expect(sentinel.executeAction(r))
                .to.be.revertedWithCustomError(sentinel, "ConfidenceThresholdNotMet");
        });

        it("confidence 10000 (maximum) → succeed", async function () {
            const r = await buildSignedReport(node1, node2, {
                agentId: AGENT_ID,
                confidenceScore: 10000,
            });
            await expect(sentinel.executeAction(r))
                .to.emit(sentinel, "ActionExecuted");
        });
    });

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-SA-6: Rapid-fire same-block actions
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-SA-6: Rapid-fire same-block actions", function () {
        it("sequential actions within budget are all tracked correctly", async function () {
            const { raizoCore, sentinel, agentWallet, node1, node2 } = await deployFresh();
            const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("rapid-fire"));
            await raizoCore.registerAgent(AGENT_ID, agentWallet.address, BUDGET_USDC);

            for (let i = 0; i < ACTION_BUDGET; i++) {
                const r = await buildSignedReport(node1, node2, { agentId: AGENT_ID });
                await expect(sentinel.executeAction(r))
                    .to.emit(sentinel, "ActionExecuted");
            }

            // The 11th must fail
            const r = await buildSignedReport(node1, node2, { agentId: AGENT_ID });
            await expect(sentinel.executeAction(r))
                .to.be.revertedWithCustomError(sentinel, "BudgetExceeded");

            const count = await sentinel.getActionCount(AGENT_ID);
            expect(count).to.equal(ACTION_BUDGET);
        });
    });

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-SA-7: DON signature length variations
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-SA-7: DON signature length variations", function () {
        it("empty signatures (0 bytes) → InvalidSignatures", async function () {
            const { raizoCore, sentinel, agentWallet } = await deployFresh();
            const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("sig-len-agent"));
            await raizoCore.registerAgent(AGENT_ID, agentWallet.address, BUDGET_USDC);

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
                donSignatures: "0x", // empty
            };

            await expect(sentinel.executeAction(report))
                .to.be.revertedWithCustomError(sentinel, "InvalidSignatures");
        });

        it("non-empty signatures (valid length) → accepted", async function () {
            const { raizoCore, sentinel, agentWallet, node1, node2 } = await deployFresh();
            const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("sig-valid-agent"));
            await raizoCore.registerAgent(AGENT_ID, agentWallet.address, BUDGET_USDC);

            const r = await buildSignedReport(node1, node2, { agentId: AGENT_ID });
            await expect(sentinel.executeAction(r))
                .to.emit(sentinel, "ActionExecuted");
        });

        it("fuzz: various non-zero signature lengths are accepted", async function () {
            const { raizoCore, sentinel, agentWallet } = await deployFresh();
            const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("sig-fuzz-agent"));
            await raizoCore.registerAgent(AGENT_ID, agentWallet.address, BUDGET_USDC);

            // The current stub only checks length > 0, so any non-empty bytes pass
            const sigLengths = [32, 64, 65, 130, 195];
            for (const len of sigLengths) {
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
                    donSignatures: ethers.hexlify(ethers.randomBytes(len)),
                };

                await expect(sentinel.executeAction(report))
                    .to.emit(sentinel, "ActionExecuted");
            }
        });
    });

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-SA-8: Duplicate reportId rejection under stress
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-SA-8: Duplicate reportId rejection under stress", function () {
        it("accepts unique IDs and rejects all duplicates in a 50-report burst", async function () {
            const { raizoCore, sentinel, agentWallet, node1, node2 } = await deployFresh();
            const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("dup-stress-agent"));
            await raizoCore.registerAgent(AGENT_ID, agentWallet.address, BUDGET_USDC);

            // Only track IDs that were actually stored on-chain (accepted).
            // Budget-rejected IDs are never persisted so they aren't duplicates.
            const storedIds: string[] = [];
            let accepted = 0;

            for (let i = 0; i < 50; i++) {
                // 50% chance of reusing a stored reportId (if any exist)
                let reportId: string;
                const reuseExisting = storedIds.length > 0 && Math.random() < 0.5;

                if (reuseExisting) {
                    reportId = storedIds[Math.floor(Math.random() * storedIds.length)];
                } else {
                    reportId = ethers.keccak256(ethers.randomBytes(32));
                }

                const r = await buildSignedReport(node1, node2, {
                    agentId: AGENT_ID,
                    reportId,
                });

                if (reuseExisting) {
                    // This ID was stored on-chain → DuplicateReport
                    await expect(sentinel.executeAction(r))
                        .to.be.revertedWithCustomError(sentinel, "DuplicateReport");
                } else if (accepted >= ACTION_BUDGET) {
                    // New ID but budget exhausted → BudgetExceeded (ID not stored)
                    await expect(sentinel.executeAction(r))
                        .to.be.revertedWithCustomError(sentinel, "BudgetExceeded");
                } else {
                    // New ID, within budget → accepted and stored
                    await expect(sentinel.executeAction(r))
                        .to.emit(sentinel, "ActionExecuted");
                    storedIds.push(reportId);
                    accepted++;
                }
            }
        });
    });
});
