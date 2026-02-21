/**
 * @file test/unit/TimelockUpgradeController.test.ts
 * @description TDD tests for the 48-hour timelock upgrade controller.
 *
 * Spec References:
 *   - SMART_CONTRACTS.md §3: "All UUPS upgrades require a 48-hour timelock + GovernanceGate approval"
 *   - SECURITY.md §3.1 SC-3: UUPS upgrade hijack prevention
 *
 * Test Groups:
 *   TL-1: Proposal lifecycle (propose → store → count)              (3 tests)
 *   TL-2: 48-hour timelock enforcement                               (3 tests)
 *   TL-3: Governance approval requirement                            (3 tests)
 *   TL-4: Cancellation flow                                          (3 tests)
 *   TL-5: Access control (PROPOSER/EXECUTOR/CANCELLER roles)        (4 tests)
 *   TL-6: Edge cases (zero addresses, non-existent, index retrieval) (4 tests)
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { TimelockUpgradeController } from "../../typechain-types";
import { time } from "@nomicfoundation/hardhat-network-helpers";

describe("TimelockUpgradeController (TL-1→6)", function () {
  let timelock: TimelockUpgradeController;
  let admin: SignerWithAddress;
  let proposer: SignerWithAddress;
  let executor: SignerWithAddress;
  let attacker: SignerWithAddress;

  const PROPOSER_ROLE = ethers.keccak256(ethers.toUtf8Bytes("PROPOSER_ROLE"));
  const EXECUTOR_ROLE = ethers.keccak256(ethers.toUtf8Bytes("EXECUTOR_ROLE"));
  const CANCELLER_ROLE = ethers.keccak256(
    ethers.toUtf8Bytes("CANCELLER_ROLE"),
  );

  const MOCK_PROXY = "0x0000000000000000000000000000000000000001";
  const MOCK_IMPL = "0x0000000000000000000000000000000000000002";
  const MOCK_GOV_ID = ethers.keccak256(ethers.toUtf8Bytes("gov-prop-1"));

  /**
   * Helper: propose an upgrade and return the proposalId from the event.
   */
  async function proposeAndGetId(
    signer: SignerWithAddress,
    proxy = MOCK_PROXY,
    impl = MOCK_IMPL,
  ): Promise<string> {
    const tx = await timelock.connect(signer).proposeUpgrade(proxy, impl);
    const receipt = await tx.wait();
    const parsedEvent = receipt?.logs
      .map((log) => {
        try {
          return timelock.interface.parseLog(log as any);
        } catch {
          return null;
        }
      })
      .find((e) => e?.name === "UpgradeProposed");
    return parsedEvent?.args?.proposalId;
  }

  beforeEach(async function () {
    [admin, proposer, executor, attacker] = await ethers.getSigners();

    const TimelockFactory = await ethers.getContractFactory(
      "TimelockUpgradeController",
    );
    timelock = (await TimelockFactory.deploy(
      admin.address,
      proposer.address,
      executor.address,
    )) as TimelockUpgradeController;
    await timelock.waitForDeployment();
  });

  // ── TL-1: Proposal lifecycle ──────────────────────────────────────────
  describe("TL-1: Proposal lifecycle", function () {
    it("should emit UpgradeProposed event on proposal creation", async function () {
      const tx = await timelock
        .connect(proposer)
        .proposeUpgrade(MOCK_PROXY, MOCK_IMPL);
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

    it("should store correct proposal data (proxy, impl, state=Pending)", async function () {
      const proposalId = await proposeAndGetId(proposer);
      const proposal = await timelock.getProposal(proposalId);

      expect(proposal.proxy).to.equal(MOCK_PROXY);
      expect(proposal.newImplementation).to.equal(MOCK_IMPL);
      expect(proposal.state).to.equal(1); // UpgradeState.Pending
    });

    it("should increment proposal count on each proposal", async function () {
      expect(await timelock.getProposalCount()).to.equal(0);
      await timelock.connect(proposer).proposeUpgrade(MOCK_PROXY, MOCK_IMPL);
      expect(await timelock.getProposalCount()).to.equal(1);
    });
  });

  // ── TL-2: 48-hour timelock enforcement ────────────────────────────────
  describe("TL-2: 48-hour timelock enforcement", function () {
    let proposalId: string;

    beforeEach(async function () {
      proposalId = await proposeAndGetId(proposer);
      await timelock
        .connect(proposer)
        .approveUpgrade(proposalId, MOCK_GOV_ID);
    });

    it("should have MIN_DELAY of exactly 48 hours", async function () {
      expect(await timelock.MIN_DELAY()).to.equal(48n * 60n * 60n);
    });

    it("should reject execution immediately after proposal (before 48h)", async function () {
      await expect(
        timelock.connect(executor).executeUpgrade(proposalId),
      ).to.be.revertedWithCustomError(timelock, "TimelockNotExpired");
    });

    it("should reject execution at 47 hours (1h before expiry)", async function () {
      await time.increase(47 * 60 * 60);
      await expect(
        timelock.connect(executor).executeUpgrade(proposalId),
      ).to.be.revertedWithCustomError(timelock, "TimelockNotExpired");
    });

    it("should successfully execute after 48h with approved proposal on real proxy", async function () {
      // Deploy a mock upgrade target that accepts upgradeToAndCall
      const MockTarget = await ethers.getContractFactory("MockUpgradeTarget");
      const mockProxy = await MockTarget.deploy();
      await mockProxy.waitForDeployment();
      const proxyAddress = await mockProxy.getAddress();

      const newImplAddress = "0x0000000000000000000000000000000000000099";

      // Propose, approve, wait 48h, execute
      const tx = await timelock
        .connect(proposer)
        .proposeUpgrade(proxyAddress, newImplAddress);
      const receipt = await tx.wait();
      const event = receipt?.logs
        .map((log) => {
          try {
            return timelock.interface.parseLog(log as any);
          } catch {
            return null;
          }
        })
        .find((e) => e?.name === "UpgradeProposed");
      const propId = event?.args?.proposalId;

      await timelock.connect(proposer).approveUpgrade(propId, MOCK_GOV_ID);
      await time.increase(48 * 60 * 60 + 1);

      await expect(timelock.connect(executor).executeUpgrade(propId))
        .to.emit(timelock, "UpgradeExecuted")
        .withArgs(propId, proxyAddress, newImplAddress);

      const proposal = await timelock.getProposal(propId);
      expect(proposal.state).to.equal(3); // UpgradeState.Executed
    });
  });

  // ── TL-3: Governance approval requirement ─────────────────────────────
  describe("TL-3: Governance approval requirement", function () {
    let proposalId: string;

    beforeEach(async function () {
      proposalId = await proposeAndGetId(proposer);
    });

    it("should reject execution without governance approval even after 48h", async function () {
      await time.increase(49 * 60 * 60);
      await expect(
        timelock.connect(executor).executeUpgrade(proposalId),
      ).to.be.revertedWithCustomError(timelock, "ProposalNotApproved");
    });

    it("should track governance approval state correctly", async function () {
      expect(await timelock.isApproved(proposalId)).to.be.false;
      await timelock
        .connect(proposer)
        .approveUpgrade(proposalId, MOCK_GOV_ID);
      expect(await timelock.isApproved(proposalId)).to.be.true;
    });

    it("should store the governance proposal ID reference", async function () {
      await timelock
        .connect(proposer)
        .approveUpgrade(proposalId, MOCK_GOV_ID);
      const proposal = await timelock.getProposal(proposalId);
      expect(proposal.governanceProposalId).to.equal(MOCK_GOV_ID);
    });
  });

  // ── TL-4: Cancellation flow ───────────────────────────────────────────
  describe("TL-4: Cancellation flow", function () {
    let proposalId: string;

    beforeEach(async function () {
      proposalId = await proposeAndGetId(proposer);
    });

    it("should emit UpgradeCancelled and set state to Cancelled", async function () {
      await expect(timelock.connect(admin).cancelUpgrade(proposalId))
        .to.emit(timelock, "UpgradeCancelled")
        .withArgs(proposalId);

      const proposal = await timelock.getProposal(proposalId);
      expect(proposal.state).to.equal(4); // UpgradeState.Cancelled
    });

    it("should prevent execution of a cancelled proposal", async function () {
      await timelock.connect(admin).cancelUpgrade(proposalId);
      await time.increase(49 * 60 * 60);
      await expect(
        timelock.connect(executor).executeUpgrade(proposalId),
      ).to.be.revertedWithCustomError(timelock, "ProposalNotPending");
    });

    it("should prevent double-cancellation", async function () {
      await timelock.connect(admin).cancelUpgrade(proposalId);
      await expect(
        timelock.connect(admin).cancelUpgrade(proposalId),
      ).to.be.revertedWithCustomError(timelock, "ProposalNotPending");
    });
  });

  // ── TL-5: Access control ──────────────────────────────────────────────
  describe("TL-5: Access control", function () {
    it("should reject proposeUpgrade from non-PROPOSER_ROLE", async function () {
      await expect(
        timelock.connect(attacker).proposeUpgrade(MOCK_PROXY, MOCK_IMPL),
      ).to.be.reverted;
    });

    it("should reject executeUpgrade from non-EXECUTOR_ROLE", async function () {
      const proposalId = await proposeAndGetId(proposer);
      await expect(
        timelock.connect(attacker).executeUpgrade(proposalId),
      ).to.be.reverted;
    });

    it("should reject cancelUpgrade from non-CANCELLER_ROLE", async function () {
      const proposalId = await proposeAndGetId(proposer);
      await expect(
        timelock.connect(attacker).cancelUpgrade(proposalId),
      ).to.be.reverted;
    });

    it("should reject approveUpgrade from non-PROPOSER_ROLE", async function () {
      const proposalId = await proposeAndGetId(proposer);
      await expect(
        timelock.connect(attacker).approveUpgrade(proposalId, MOCK_GOV_ID),
      ).to.be.reverted;
    });
  });

  // ── TL-6: Edge cases ──────────────────────────────────────────────────
  describe("TL-6: Edge cases", function () {
    it("should reject zero proxy address", async function () {
      await expect(
        timelock
          .connect(proposer)
          .proposeUpgrade(ethers.ZeroAddress, MOCK_IMPL),
      ).to.be.revertedWithCustomError(timelock, "InvalidAddress");
    });

    it("should reject zero implementation address", async function () {
      await expect(
        timelock
          .connect(proposer)
          .proposeUpgrade(MOCK_PROXY, ethers.ZeroAddress),
      ).to.be.revertedWithCustomError(timelock, "InvalidAddress");
    });

    it("should reject approving a non-existent proposal", async function () {
      const fakeId = ethers.keccak256(ethers.toUtf8Bytes("nonexistent"));
      await expect(
        timelock.connect(proposer).approveUpgrade(fakeId, MOCK_GOV_ID),
      ).to.be.revertedWithCustomError(timelock, "ProposalNotPending");
    });

    it("should return correct proposalId at index", async function () {
      const proposalId = await proposeAndGetId(proposer);
      expect(await timelock.getProposalIdAt(0)).to.equal(proposalId);
    });
  });
});
