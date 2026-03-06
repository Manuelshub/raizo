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

  describe("DON-Attested Governance (CRE World ID Bridge)", function () {
    let attester: SignerWithAddress;
    const ATTESTER_ROLE = ethers.keccak256(ethers.toUtf8Bytes("ATTESTER_ROLE"));
    const ATTESTED_NULLIFIER = 777777;
    const ATTESTED_DESC = ethers.id("Enable enhanced monitoring for Aave v3");

    beforeEach(async function () {
      [, , , attester] = await ethers.getSigners();
      await govGate.grantRole(ATTESTER_ROLE, attester.address);
    });

    it("should create a proposal via proposeAttested (ATTESTER_ROLE)", async function () {
      await expect(
        govGate
          .connect(attester)
          .proposeAttested(ATTESTED_DESC, ATTESTED_NULLIFIER, proposer.address),
      )
        .to.emit(govGate, "ProposalCreated")
        .withArgs(0, proposer.address, ATTESTED_DESC);

      const proposal = await govGate.getProposal(0);
      expect(proposal.proposer).to.equal(proposer.address);
    });

    it("should cast a vote via voteAttested (ATTESTER_ROLE)", async function () {
      await govGate
        .connect(attester)
        .proposeAttested(ATTESTED_DESC, ATTESTED_NULLIFIER, proposer.address);

      const voteNullifier = 888888;
      await expect(
        govGate
          .connect(attester)
          .voteAttested(0, true, voteNullifier, voter.address),
      )
        .to.emit(govGate, "VoteCast")
        .withArgs(0, voter.address, true);

      const proposal = await govGate.getProposal(0);
      expect(proposal.forVotes).to.equal(1);
    });

    it("should reject attested proposal with reused nullifier (sybil resistance)", async function () {
      await govGate
        .connect(attester)
        .proposeAttested(ATTESTED_DESC, ATTESTED_NULLIFIER, proposer.address);

      await expect(
        govGate
          .connect(attester)
          .proposeAttested(
            ethers.id("Duplicate"),
            ATTESTED_NULLIFIER,
            voter.address,
          ),
      )
        .to.be.revertedWithCustomError(govGate, "DoubleVoting")
        .withArgs(ATTESTED_NULLIFIER);
    });

    it("should reject attested vote with reused nullifier (sybil resistance)", async function () {
      await govGate
        .connect(attester)
        .proposeAttested(ATTESTED_DESC, ATTESTED_NULLIFIER, proposer.address);

      const voteNullifier = 999999;
      await govGate
        .connect(attester)
        .voteAttested(0, true, voteNullifier, voter.address);

      await expect(
        govGate
          .connect(attester)
          .voteAttested(0, false, voteNullifier, proposer.address),
      )
        .to.be.revertedWithCustomError(govGate, "DoubleVoting")
        .withArgs(voteNullifier);
    });

    it("should reject proposeAttested from non-ATTESTER_ROLE", async function () {
      await expect(
        govGate
          .connect(proposer)
          .proposeAttested(ATTESTED_DESC, 12345, proposer.address),
      ).to.be.reverted;
    });

    it("should reject voteAttested from non-ATTESTER_ROLE", async function () {
      // First create a proposal via attester
      await govGate
        .connect(attester)
        .proposeAttested(ATTESTED_DESC, ATTESTED_NULLIFIER, proposer.address);

      await expect(
        govGate.connect(voter).voteAttested(0, true, 54321, voter.address),
      ).to.be.reverted;
    });

    it("should share nullifier space between direct and attested paths", async function () {
      // Use a nullifier via direct path
      await govGate
        .connect(proposer)
        .propose(DESCRIPTION_HASH, ROOT, NULLIFIER_HASH, PROOF);

      // Attempt to reuse same nullifier via attested path
      await expect(
        govGate
          .connect(attester)
          .proposeAttested(ATTESTED_DESC, NULLIFIER_HASH, voter.address),
      )
        .to.be.revertedWithCustomError(govGate, "DoubleVoting")
        .withArgs(NULLIFIER_HASH);
    });

    it("should allow attested proposal to be executed after voting", async function () {
      await govGate
        .connect(attester)
        .proposeAttested(ATTESTED_DESC, ATTESTED_NULLIFIER, proposer.address);
      await govGate
        .connect(attester)
        .voteAttested(0, true, 888888, voter.address);

      for (let i = 0; i < 7201; i++) await ethers.provider.send("evm_mine", []);

      await expect(govGate.execute(0))
        .to.emit(govGate, "ProposalExecuted")
        .withArgs(0);

      const proposal = await govGate.getProposal(0);
      expect(proposal.executed).to.be.true;
    });
  });
});
