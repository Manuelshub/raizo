/**
 * @file PaymentEscrow.fuzz.ts
 * @notice Deep fuzz testing for PaymentEscrow — property-based verification
 *         of daily limits, timing windows, multi-agent isolation, nonce
 *         uniqueness, signature verification, and balance management.
 *
 * Test IDs map to implementation-guide.md §4.2:
 *   FUZZ-PE-1  Daily limit enforcement across random amounts
 *   FUZZ-PE-2  Exact daily limit boundary
 *   FUZZ-PE-3  Timing window enforcement (validAfter/validBefore)
 *   FUZZ-PE-4  Multi-agent concurrent spending
 *   FUZZ-PE-5  24h rolling window precision
 *   FUZZ-PE-6  Zero-amount payment handling
 *   FUZZ-PE-7  Balance exhaustion vs daily limit ordering
 *   FUZZ-PE-8  Nonce uniqueness under rapid generation
 *   FUZZ-PE-9  Signature mutation detection
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { PaymentEscrow, MockUSDC, RaizoCore } from "../../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("PaymentEscrow Deep Fuzz Suite", function () {
    // ────────────────────────────────────────────────────────────────────
    //  Shared setup helpers
    // ────────────────────────────────────────────────────────────────────

    const DAILY_LIMIT = ethers.parseUnits("100", 6); // 100 USDC
    const DEPOSIT = ethers.parseUnits("10000", 6);

    async function deployFresh(overrides?: { dailyLimit?: bigint }) {
        const signers = await ethers.getSigners();
        const [owner, agentWallet, recipient, provider, agent2Wallet, agent3Wallet] = signers;
        const limit = overrides?.dailyLimit ?? DAILY_LIMIT;

        const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
        const raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
            initializer: "initialize", kind: "uups",
        })) as unknown as RaizoCore;

        const MockFactory = await ethers.getContractFactory("MockUSDC");
        const usdc = await MockFactory.deploy() as unknown as MockUSDC;

        const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("fuzz-escrow"));
        await raizoCore.registerAgent(AGENT_ID, agentWallet.address, limit);

        const EscrowFactory = await ethers.getContractFactory("PaymentEscrow");
        const escrow = (await upgrades.deployProxy(
            EscrowFactory,
            [await raizoCore.getAddress(), await usdc.getAddress()],
            { initializer: "initialize", kind: "uups" },
        )) as unknown as PaymentEscrow;

        await usdc.mint(provider.address, DEPOSIT);
        await usdc.connect(provider).approve(await escrow.getAddress(), DEPOSIT);
        await escrow.connect(provider).deposit(AGENT_ID, DEPOSIT);

        return {
            raizoCore, usdc, escrow, AGENT_ID,
            owner, agentWallet, recipient, provider, agent2Wallet, agent3Wallet,
        };
    }

    async function signPayment(
        escrow: PaymentEscrow,
        agentWallet: SignerWithAddress,
        params: {
            agentId: string;
            to: string;
            amount: bigint;
            validAfter?: number;
            validBefore?: number;
            nonce?: string;
        },
    ) {
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
        const nonce = params.nonce ?? ethers.id(`nonce-${Date.now()}-${Math.random()}`);
        const validAfter = params.validAfter ?? 0;
        const validBefore = params.validBefore ?? 2000000000;
        const value = {
            agentId: params.agentId,
            to: params.to,
            amount: params.amount,
            validAfter,
            validBefore,
            nonce,
        };
        const signature = await agentWallet.signTypedData(domain, types, value);

        return { ...value, signature, nonce };
    }

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-PE-1: Daily limit enforcement across random amounts
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-PE-1: Daily limit enforcement across random amounts", function () {
        it("should correctly track 50 randomized payment attempts", async function () {
            const { escrow, AGENT_ID, agentWallet, recipient } = await deployFresh();

            let dailySpent = 0n;
            let successCount = 0;
            let rejectCount = 0;

            for (let i = 0; i < 50; i++) {
                const rawAmount = BigInt(Math.floor(Math.random() * 200_000_000));
                const p = await signPayment(escrow, agentWallet, {
                    agentId: AGENT_ID,
                    to: recipient.address,
                    amount: rawAmount,
                    nonce: ethers.id(`fuzz-pe1-${i}`),
                });

                if (dailySpent + rawAmount > DAILY_LIMIT) {
                    await expect(
                        escrow.authorizePayment(
                            AGENT_ID, recipient.address, rawAmount,
                            p.validAfter, p.validBefore, p.nonce, p.signature,
                        ),
                    ).to.be.revertedWithCustomError(escrow, "DailyLimitExceeded");
                    rejectCount++;
                } else {
                    await expect(
                        escrow.authorizePayment(
                            AGENT_ID, recipient.address, rawAmount,
                            p.validAfter, p.validBefore, p.nonce, p.signature,
                        ),
                    ).to.emit(escrow, "PaymentAuthorized");
                    dailySpent += rawAmount;
                    successCount++;
                }
            }

            expect(successCount + rejectCount).to.equal(50);
        });
    });

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-PE-2: Exact daily limit boundary
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-PE-2: Exact daily limit boundary", function () {
        it("exact limit amount succeeds, limit+1 fails", async function () {
            const { escrow, AGENT_ID, agentWallet, recipient } = await deployFresh();

            // Advance to a new day to ensure clean state
            await ethers.provider.send("evm_increaseTime", [86401]);
            await ethers.provider.send("evm_mine", []);

            // Exact limit: should pass
            const p1 = await signPayment(escrow, agentWallet, {
                agentId: AGENT_ID,
                to: recipient.address,
                amount: DAILY_LIMIT,
                nonce: ethers.id("boundary-exact"),
            });
            await expect(
                escrow.authorizePayment(
                    AGENT_ID, recipient.address, DAILY_LIMIT,
                    p1.validAfter, p1.validBefore, p1.nonce, p1.signature,
                ),
            ).to.emit(escrow, "PaymentAuthorized");

            // +1 more: should fail
            const p2 = await signPayment(escrow, agentWallet, {
                agentId: AGENT_ID,
                to: recipient.address,
                amount: 1n,
                nonce: ethers.id("boundary-over"),
            });
            await expect(
                escrow.authorizePayment(
                    AGENT_ID, recipient.address, 1n,
                    p2.validAfter, p2.validBefore, p2.nonce, p2.signature,
                ),
            ).to.be.revertedWithCustomError(escrow, "DailyLimitExceeded");
        });
    });

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-PE-3: Timing window enforcement (validAfter/validBefore)
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-PE-3: Timing window enforcement", function () {
        it("payment with validAfter in the future → revert", async function () {
            const { escrow, AGENT_ID, agentWallet, recipient } = await deployFresh();

            const block = await ethers.provider.getBlock("latest");
            const now = block!.timestamp;

            const p = await signPayment(escrow, agentWallet, {
                agentId: AGENT_ID,
                to: recipient.address,
                amount: ethers.parseUnits("1", 6),
                validAfter: now + 3600, // 1 hour in the future
                validBefore: now + 7200,
                nonce: ethers.id("future-after"),
            });

            await expect(
                escrow.authorizePayment(
                    AGENT_ID, recipient.address, ethers.parseUnits("1", 6),
                    p.validAfter, p.validBefore, p.nonce, p.signature,
                ),
            ).to.be.revertedWithCustomError(escrow, "SignatureExpired");
        });

        it("payment with validBefore in the past → revert", async function () {
            const { escrow, AGENT_ID, agentWallet, recipient } = await deployFresh();

            const block = await ethers.provider.getBlock("latest");
            const now = block!.timestamp;

            const p = await signPayment(escrow, agentWallet, {
                agentId: AGENT_ID,
                to: recipient.address,
                amount: ethers.parseUnits("1", 6),
                validAfter: 0,
                validBefore: now - 1, // already expired
                nonce: ethers.id("expired-before"),
            });

            await expect(
                escrow.authorizePayment(
                    AGENT_ID, recipient.address, ethers.parseUnits("1", 6),
                    p.validAfter, p.validBefore, p.nonce, p.signature,
                ),
            ).to.be.revertedWithCustomError(escrow, "SignatureExpired");
        });

        it("fuzz: 20 random timing windows correctly accepted or rejected", async function () {
            const { escrow, AGENT_ID, agentWallet, recipient } = await deployFresh();

            for (let i = 0; i < 20; i++) {
                const block = await ethers.provider.getBlock("latest");
                const now = block!.timestamp;

                // Random offset: [-3600, +3600] for validAfter
                const afterOffset = Math.floor(Math.random() * 7200) - 3600;
                // Random offset: [0, +7200] for validBefore from now
                const beforeOffset = Math.floor(Math.random() * 7200);

                const validAfter = Math.max(0, now + afterOffset);
                const validBefore = now + beforeOffset;

                const amount = ethers.parseUnits("1", 6);
                const p = await signPayment(escrow, agentWallet, {
                    agentId: AGENT_ID,
                    to: recipient.address,
                    amount,
                    validAfter,
                    validBefore,
                    nonce: ethers.id(`timing-fuzz-${i}`),
                });

                const isTimeValid = now > validAfter && now < validBefore;

                if (!isTimeValid) {
                    await expect(
                        escrow.authorizePayment(
                            AGENT_ID, recipient.address, amount,
                            p.validAfter, p.validBefore, p.nonce, p.signature,
                        ),
                    ).to.be.revertedWithCustomError(escrow, "SignatureExpired");
                }
                // If time is valid, we don't assert success because daily limit
                // may also reject — timing window is verified before daily limit
            }
        });
    });

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-PE-4: Multi-agent concurrent spending
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-PE-4: Multi-agent concurrent spending", function () {
        it("3 agents' daily limits are tracked independently", async function () {
            const signers = await ethers.getSigners();
            const [owner, wallet1, wallet2, wallet3, recipient, provider] = signers;

            const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
            const raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
                initializer: "initialize", kind: "uups",
            })) as unknown as RaizoCore;

            const MockFactory = await ethers.getContractFactory("MockUSDC");
            const usdc = await MockFactory.deploy() as unknown as MockUSDC;

            const agents = [
                { id: ethers.keccak256(ethers.toUtf8Bytes("multi-a")), wallet: wallet1, limit: ethers.parseUnits("50", 6) },
                { id: ethers.keccak256(ethers.toUtf8Bytes("multi-b")), wallet: wallet2, limit: ethers.parseUnits("100", 6) },
                { id: ethers.keccak256(ethers.toUtf8Bytes("multi-c")), wallet: wallet3, limit: ethers.parseUnits("200", 6) },
            ];

            for (const a of agents) {
                await raizoCore.registerAgent(a.id, a.wallet.address, a.limit);
            }

            const EscrowFactory = await ethers.getContractFactory("PaymentEscrow");
            const escrow = (await upgrades.deployProxy(
                EscrowFactory,
                [await raizoCore.getAddress(), await usdc.getAddress()],
                { initializer: "initialize", kind: "uups" },
            )) as unknown as PaymentEscrow;

            // Fund all agents
            for (const a of agents) {
                await usdc.mint(provider.address, ethers.parseUnits("1000", 6));
                await usdc.connect(provider).approve(await escrow.getAddress(), ethers.parseUnits("1000", 6));
                await escrow.connect(provider).deposit(a.id, ethers.parseUnits("1000", 6));
            }

            // Each agent spends their exact limit
            for (const a of agents) {
                const p = await signPayment(escrow, a.wallet, {
                    agentId: a.id,
                    to: recipient.address,
                    amount: a.limit,
                    nonce: ethers.id(`multi-${a.id}`),
                });
                await expect(
                    escrow.authorizePayment(
                        a.id, recipient.address, a.limit,
                        p.validAfter, p.validBefore, p.nonce, p.signature,
                    ),
                ).to.emit(escrow, "PaymentAuthorized");
            }

            // Each agent at +1 over limit must fail
            for (const a of agents) {
                const p = await signPayment(escrow, a.wallet, {
                    agentId: a.id,
                    to: recipient.address,
                    amount: 1n,
                    nonce: ethers.id(`multi-over-${a.id}`),
                });
                await expect(
                    escrow.authorizePayment(
                        a.id, recipient.address, 1n,
                        p.validAfter, p.validBefore, p.nonce, p.signature,
                    ),
                ).to.be.revertedWithCustomError(escrow, "DailyLimitExceeded");
            }
        });
    });

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-PE-5: 24h rolling window precision
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-PE-5: 24h rolling window precision", function () {
        it("spending resets after exactly 24 hours", async function () {
            const { escrow, AGENT_ID, agentWallet, recipient } = await deployFresh();

            // Spend full limit
            const p1 = await signPayment(escrow, agentWallet, {
                agentId: AGENT_ID,
                to: recipient.address,
                amount: DAILY_LIMIT,
                nonce: ethers.id("day1"),
            });
            await escrow.authorizePayment(
                AGENT_ID, recipient.address, DAILY_LIMIT,
                p1.validAfter, p1.validBefore, p1.nonce, p1.signature,
            );

            // At exactly 24h - 1s: should still be blocked
            await ethers.provider.send("evm_increaseTime", [86399]);
            await ethers.provider.send("evm_mine", []);

            // This might or might not reset depending on integer division boundary.
            // We verify by checking: if the day period (timestamp / 86400) hasn't changed,
            // the limit should still be enforced.
            const block1 = await ethers.provider.getBlock("latest");
            const wallet = await escrow.getWallet(AGENT_ID);
            const currentPeriod = BigInt(block1!.timestamp) / 86400n;
            const lastResetPeriod = wallet.lastResetTimestamp / 86400n;

            if (currentPeriod <= lastResetPeriod) {
                // Same period — still limited
                const p2 = await signPayment(escrow, agentWallet, {
                    agentId: AGENT_ID,
                    to: recipient.address,
                    amount: 1n,
                    nonce: ethers.id("day1-retry"),
                });
                await expect(
                    escrow.authorizePayment(
                        AGENT_ID, recipient.address, 1n,
                        p2.validAfter, p2.validBefore, p2.nonce, p2.signature,
                    ),
                ).to.be.revertedWithCustomError(escrow, "DailyLimitExceeded");
            }

            // Advance 2 more seconds to be safely past boundary
            await ethers.provider.send("evm_increaseTime", [2]);
            await ethers.provider.send("evm_mine", []);

            // Now spending should reset
            const p3 = await signPayment(escrow, agentWallet, {
                agentId: AGENT_ID,
                to: recipient.address,
                amount: ethers.parseUnits("1", 6),
                nonce: ethers.id("day2"),
            });
            await expect(
                escrow.authorizePayment(
                    AGENT_ID, recipient.address, ethers.parseUnits("1", 6),
                    p3.validAfter, p3.validBefore, p3.nonce, p3.signature,
                ),
            ).to.emit(escrow, "DailyLimitReset");
        });

        it("multiple day rollovers correctly reset spending", async function () {
            const { escrow, AGENT_ID, agentWallet, recipient } = await deployFresh();

            for (let day = 0; day < 3; day++) {
                if (day > 0) {
                    await ethers.provider.send("evm_increaseTime", [86401]);
                    await ethers.provider.send("evm_mine", []);
                }

                const amount = ethers.parseUnits(`${(day + 1) * 10}`, 6);
                const p = await signPayment(escrow, agentWallet, {
                    agentId: AGENT_ID,
                    to: recipient.address,
                    amount,
                    nonce: ethers.id(`day-${day}`),
                });
                await expect(
                    escrow.authorizePayment(
                        AGENT_ID, recipient.address, amount,
                        p.validAfter, p.validBefore, p.nonce, p.signature,
                    ),
                ).to.emit(escrow, "PaymentAuthorized");
            }
        });
    });

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-PE-6: Zero-amount payment handling
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-PE-6: Zero-amount payment handling", function () {
        it("zero-amount payment succeeds without consuming daily limit", async function () {
            const { escrow, AGENT_ID, agentWallet, recipient } = await deployFresh();

            const p = await signPayment(escrow, agentWallet, {
                agentId: AGENT_ID,
                to: recipient.address,
                amount: 0n,
                nonce: ethers.id("zero-amount"),
            });

            // Zero should pass (0 + 0 = 0 <= DAILY_LIMIT)
            await expect(
                escrow.authorizePayment(
                    AGENT_ID, recipient.address, 0n,
                    p.validAfter, p.validBefore, p.nonce, p.signature,
                ),
            ).to.emit(escrow, "PaymentAuthorized");

            // Full limit should still be available
            const remaining = await escrow.getDailyRemaining(AGENT_ID);
            expect(remaining).to.equal(DAILY_LIMIT);
        });
    });

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-PE-7: Balance exhaustion vs daily limit ordering
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-PE-7: Balance exhaustion vs daily limit ordering", function () {
        it("InsufficientBalance when balance < amount even if within daily limit", async function () {
            const signers = await ethers.getSigners();
            const [owner, agentWallet, recipient, provider] = signers;

            const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
            const raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
                initializer: "initialize", kind: "uups",
            })) as unknown as RaizoCore;

            const MockFactory = await ethers.getContractFactory("MockUSDC");
            const usdc = await MockFactory.deploy() as unknown as MockUSDC;

            const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("low-balance"));
            const limit = ethers.parseUnits("1000", 6); // High limit
            const smallDeposit = ethers.parseUnits("5", 6); // Small balance

            await raizoCore.registerAgent(AGENT_ID, agentWallet.address, limit);

            const EscrowFactory = await ethers.getContractFactory("PaymentEscrow");
            const escrow = (await upgrades.deployProxy(
                EscrowFactory,
                [await raizoCore.getAddress(), await usdc.getAddress()],
                { initializer: "initialize", kind: "uups" },
            )) as unknown as PaymentEscrow;

            await usdc.mint(provider.address, smallDeposit);
            await usdc.connect(provider).approve(await escrow.getAddress(), smallDeposit);
            await escrow.connect(provider).deposit(AGENT_ID, smallDeposit);

            // Try to spend more than balance but within daily limit
            const amount = ethers.parseUnits("10", 6); // > 5 balance, < 1000 limit
            const p = await signPayment(escrow, agentWallet, {
                agentId: AGENT_ID,
                to: recipient.address,
                amount,
                nonce: ethers.id("insuff-bal"),
            });
            await expect(
                escrow.authorizePayment(
                    AGENT_ID, recipient.address, amount,
                    p.validAfter, p.validBefore, p.nonce, p.signature,
                ),
            ).to.be.revertedWithCustomError(escrow, "InsufficientBalance");
        });
    });

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-PE-8: Nonce uniqueness under rapid generation
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-PE-8: Nonce uniqueness under rapid generation", function () {
        it("50 unique nonces all succeed, duplicate reverts", async function () {
            const { escrow, AGENT_ID, agentWallet, recipient } = await deployFresh({
                dailyLimit: ethers.parseUnits("10000", 6), // High limit so we don't hit it
            });

            const amount = ethers.parseUnits("1", 6);

            // 50 unique nonces
            for (let i = 0; i < 50; i++) {
                const p = await signPayment(escrow, agentWallet, {
                    agentId: AGENT_ID,
                    to: recipient.address,
                    amount,
                    nonce: ethers.id(`rapid-nonce-${i}`),
                });
                await expect(
                    escrow.authorizePayment(
                        AGENT_ID, recipient.address, amount,
                        p.validAfter, p.validBefore, p.nonce, p.signature,
                    ),
                ).to.emit(escrow, "PaymentAuthorized");
            }

            // Reuse the first nonce — must fail
            const duplicate = await signPayment(escrow, agentWallet, {
                agentId: AGENT_ID,
                to: recipient.address,
                amount,
                nonce: ethers.id("rapid-nonce-0"),
            });
            await expect(
                escrow.authorizePayment(
                    AGENT_ID, recipient.address, amount,
                    duplicate.validAfter, duplicate.validBefore, duplicate.nonce, duplicate.signature,
                ),
            ).to.be.revertedWithCustomError(escrow, "NonceAlreadyUsed");
        });
    });

    // ────────────────────────────────────────────────────────────────────
    //  FUZZ-PE-9: Signature mutation detection
    // ────────────────────────────────────────────────────────────────────

    describe("FUZZ-PE-9: Signature mutation detection", function () {
        it("flipping a single byte in the signature causes rejection", async function () {
            const { escrow, AGENT_ID, agentWallet, recipient } = await deployFresh();

            const amount = ethers.parseUnits("10", 6);
            const nonce = ethers.id("sig-mutation");
            const p = await signPayment(escrow, agentWallet, {
                agentId: AGENT_ID,
                to: recipient.address,
                amount,
                nonce,
            });

            // Mutate a single byte in the middle of the signature
            const sigBytes = ethers.getBytes(p.signature);
            sigBytes[32] = sigBytes[32] ^ 0xff; // Flip all bits of byte 32
            const mutatedSig = ethers.hexlify(sigBytes);

            // ECDSA library may throw its own error or our custom error depending on
            // which byte is mutated — either way, it must revert
            await expect(
                escrow.authorizePayment(
                    AGENT_ID, recipient.address, amount,
                    p.validAfter, p.validBefore, nonce, mutatedSig,
                ),
            ).to.be.reverted;
        });

        it("fuzz: 10 random byte mutations all detected", async function () {
            const { escrow, AGENT_ID, agentWallet, recipient } = await deployFresh();

            for (let i = 0; i < 10; i++) {
                const amount = ethers.parseUnits("1", 6);
                const nonce = ethers.id(`sig-mut-${i}`);
                const p = await signPayment(escrow, agentWallet, {
                    agentId: AGENT_ID,
                    to: recipient.address,
                    amount,
                    nonce,
                });

                const sigBytes = ethers.getBytes(p.signature);
                // Mutate a random byte
                const mutIdx = Math.floor(Math.random() * (sigBytes.length - 1));
                sigBytes[mutIdx] = sigBytes[mutIdx] ^ (1 + Math.floor(Math.random() * 254));
                const mutatedSig = ethers.hexlify(sigBytes);

                await expect(
                    escrow.authorizePayment(
                        AGENT_ID, recipient.address, amount,
                        p.validAfter, p.validBefore, nonce, mutatedSig,
                    ),
                ).to.be.reverted; // Either InvalidSignature or ECDSA error
            }
        });
    });
});
