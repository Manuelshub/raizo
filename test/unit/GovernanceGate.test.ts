import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { GovernanceGate, MockWorldID } from "../../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("GovernanceGate (TDD Red Phase)", function () {
  let govGate: GovernanceGate;
  let worldId: MockWorldID;
  let owner: SignerWithAddress;
  let proposer: SignerWithAddress;
  let voter: SignerWithAddress;

  const DESCRIPTION_HASH = ethers.id("Update Confidence Threshold to 90%");
  const ROOT = 12345;
  const NULLIFIER_HASH = 67890;
  const PROOF = [0, 0, 0, 0, 0, 0, 0, 0] as [
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
  ];
  const INVALID_PROOF = [
    BigInt("0xDEADBEEF"),
    BigInt(0),
    BigInt(0),
    BigInt(0),
    BigInt(0),
    BigInt(0),
    BigInt(0),
    BigInt(0),
  ] as [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];

  beforeEach(async function () {
    [owner, proposer, voter] = await ethers.getSigners();

    const MockWorldIDFactory = await ethers.getContractFactory("MockWorldID");
    worldId = await MockWorldIDFactory.deploy();

    const GovernanceGateFactory = await ethers.getContractFactory(
      "GovernanceGate",
    );
    govGate = (await upgrades.deployProxy(
      GovernanceGateFactory,
      [await worldId.getAddress()],
      {
        initializer: "initialize",
        kind: "uups",
      },
    )) as unknown as GovernanceGate;
    await govGate.waitForDeployment();
  });

  describe("Proposals", function () {
    it("should allow creating a proposal with valid World ID proof", async function () {
      await expect(
        govGate
          .connect(proposer)
          .propose(DESCRIPTION_HASH, ROOT, NULLIFIER_HASH, PROOF),
      ).to.emit(govGate, "ProposalCreated");

      const proposal = await govGate.getProposal(0);
      expect(proposal.proposer).to.equal(proposer.address);
      expect(proposal.descriptionHash).to.equal(DESCRIPTION_HASH);
    });

    it("should fail to propose with invalid World ID proof", async function () {
      await expect(
        govGate
          .connect(proposer)
          .propose(DESCRIPTION_HASH, ROOT, NULLIFIER_HASH, INVALID_PROOF),
      ).to.be.revertedWithCustomError(govGate, "InvalidProof");
    });
  });

  describe("Voting", function () {
    beforeEach(async function () {
      await govGate
        .connect(proposer)
        .propose(DESCRIPTION_HASH, ROOT, NULLIFIER_HASH, PROOF);
    });

    it("should allow voting with valid World ID proof", async function () {
      const voteNullifier = 11111;
      await expect(
        govGate.connect(voter).vote(0, true, ROOT, voteNullifier, PROOF),
      )
        .to.emit(govGate, "VoteCast")
        .withArgs(0, voter.address, true);

      const proposal = await govGate.getProposal(0);
      expect(proposal.forVotes).to.equal(1);
    });

    it("should prevent double voting with same nullifier", async function () {
      const voteNullifier = 11111;
      await govGate.connect(voter).vote(0, true, ROOT, voteNullifier, PROOF);

      await expect(
        govGate.connect(voter).vote(0, false, ROOT, voteNullifier, PROOF),
      )
        .to.be.revertedWithCustomError(govGate, "DoubleVoting")
        .withArgs(voteNullifier);
    });

    it("should fail to vote on expired proposal", async function () {
      await ethers.provider.send("evm_mine", []); // mine blocks to expire
      for (let i = 0; i < 7201; i++) await ethers.provider.send("evm_mine", []);

      await expect(
        govGate.connect(voter).vote(0, true, ROOT, 99999, PROOF),
      ).to.be.revertedWithCustomError(govGate, "ProposalExpired");
    });
  });

  describe("Execution", function () {
    beforeEach(async function () {
      await govGate
        .connect(proposer)
        .propose(DESCRIPTION_HASH, ROOT, NULLIFIER_HASH, PROOF);
      await govGate.connect(voter).vote(0, true, ROOT, 11111, PROOF);
      // Wait for proposal to end
      for (let i = 0; i < 7201; i++) await ethers.provider.send("evm_mine", []);
    });

    it("should execute a passed proposal", async function () {
      await expect(govGate.execute(0))
        .to.emit(govGate, "ProposalExecuted")
        .withArgs(0);

      const proposal = await govGate.getProposal(0);
      expect(proposal.executed).to.be.true;
    });

    it("should fail to execute if proposal did not pass", async function () {
      // Create another proposal that fails
      const p2Hash = ethers.id("Fail Proposal");
      await govGate.connect(proposer).propose(p2Hash, ROOT, 22222, PROOF);
      await govGate.connect(voter).vote(1, false, ROOT, 33333, PROOF);
      for (let i = 0; i < 7201; i++) await ethers.provider.send("evm_mine", []);

      await expect(govGate.execute(1))
        .to.be.revertedWithCustomError(govGate, "ProposalNotPassed")
        .withArgs(1);
    });
  });
});
