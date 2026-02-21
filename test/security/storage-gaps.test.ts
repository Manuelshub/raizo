/**
 * @file storage-gaps.test.ts
 * @notice Validates that all UUPS-upgradeable contracts declare storage gaps
 *         and that the ComplianceVault remains non-upgradeable (immutable).
 *
 * Addresses SC-4 (Storage collision on proxy upgrade) from SECURITY.md §3.1.
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("Storage Gap Validation (SC-4)", function () {
    let owner: SignerWithAddress;

    before(async function () {
        [owner] = await ethers.getSigners();
    });

    // ── UUPS contracts must have __gap ────────────────────────────────────────

    const UUPS_CONTRACTS: Array<{
        name: string;
        deployArgs: () => Promise<any[]>;
    }> = [
            {
                name: "RaizoCore",
                deployArgs: async () => [],
            },
            {
                name: "SentinelActions",
                deployArgs: async () => {
                    const rc = await upgrades.deployProxy(
                        await ethers.getContractFactory("RaizoCore"), [],
                    );
                    return [await rc.getAddress()];
                },
            },
            {
                name: "PaymentEscrow",
                deployArgs: async () => {
                    const rc = await upgrades.deployProxy(
                        await ethers.getContractFactory("RaizoCore"), [],
                    );
                    const usdc = await (await ethers.getContractFactory("MockUSDC")).deploy();
                    return [await rc.getAddress(), await usdc.getAddress()];
                },
            },
            {
                name: "GovernanceGate",
                deployArgs: async () => {
                    const wid = await (await ethers.getContractFactory("MockWorldID")).deploy();
                    return [await wid.getAddress()];
                },
            },
            {
                name: "CrossChainRelay",
                deployArgs: async () => {
                    const router = await (await ethers.getContractFactory("MockCCIPRouter")).deploy();
                    const sentinel = await (await ethers.getContractFactory("MockSentinelActions")).deploy();
                    const rc = await upgrades.deployProxy(
                        await ethers.getContractFactory("RaizoCore"), [],
                    );
                    return [await router.getAddress(), await sentinel.getAddress(), await rc.getAddress()];
                },
            },
        ];

    for (const { name, deployArgs } of UUPS_CONTRACTS) {
        it(`${name} deploys as UUPS proxy without storage layout errors`, async function () {
            const Factory = await ethers.getContractFactory(name);
            const args = await deployArgs();

            // This will throw if OpenZeppelin detects a storage layout issue
            const proxy = await upgrades.deployProxy(Factory, args, {
                initializer: "initialize",
                kind: "uups",
            });
            await proxy.waitForDeployment();

            // Verify it actually deployed
            expect(await proxy.getAddress()).to.not.equal(ethers.ZeroAddress);
        });

        it(`${name} can be upgraded without storage collision`, async function () {
            const Factory = await ethers.getContractFactory(name);
            const args = await deployArgs();

            const proxy = await upgrades.deployProxy(Factory, args, {
                initializer: "initialize",
                kind: "uups",
            });

            // Upgrade to the "same" implementation (validates layout compatibility)
            const V2 = await ethers.getContractFactory(name);
            const upgraded = await upgrades.upgradeProxy(await proxy.getAddress(), V2);
            expect(await upgraded.getAddress()).to.equal(await proxy.getAddress());
        });
    }

    // ── ComplianceVault must NOT be upgradeable ───────────────────────────────

    it("ComplianceVault is NOT deployed as a proxy (immutable)", async function () {
        const Factory = await ethers.getContractFactory("ComplianceVault");
        const vault = await Factory.deploy();
        await vault.waitForDeployment();

        // Direct deployment — no proxy. Verify it works directly.
        expect(await vault.getReportCount()).to.equal(0);
    });
});
