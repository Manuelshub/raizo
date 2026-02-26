import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { RaizoCore } from "../../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("RaizoCore (Upgradeable)", function () {
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
  const CHAIN_ETHEREUM = 1;
  const RISK_HIGH = 3;
  const RISK_CRITICAL = 4;

  const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("agent-1"));
  const BUDGET_USDC = ethers.parseUnits("1000", 6);
  const ACTION_BUDGET = 10;

  beforeEach(async function () {
    [owner, governance, addr1, addr2] = await ethers.getSigners();

    const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
    raizo = (await upgrades.deployProxy(RaizoCoreFactory, [], {
      initializer: "initialize",
      kind: "uups",
    })) as unknown as RaizoCore;

    await raizo.waitForDeployment();
  });

  describe("Initialization", function () {
    it("should set the correct initial roles", async function () {
      expect(await raizo.hasRole(DEFAULT_ADMIN_ROLE, owner.address)).to.be.true;
    });

    it("should set default configurations", async function () {
      expect(await raizo.getConfidenceThreshold()).to.equal(8500);
      expect(await raizo.getEpochDuration()).to.equal(86400); // 1 day
    });

    it("should fail if initialized twice", async function () {
      await expect(raizo.initialize()).to.be.revertedWithCustomError(
        raizo,
        "InvalidInitialization",
      );
    });
  });

  describe("Protocol Management", function () {
    it("should register a protocol (Owner)", async function () {
      await expect(
        raizo.registerProtocol(PROTOCOL_A, CHAIN_ETHEREUM, RISK_HIGH),
      )
        .to.emit(raizo, "ProtocolRegistered")
        .withArgs(PROTOCOL_A, CHAIN_ETHEREUM, RISK_HIGH);

      const p = await raizo.getProtocol(PROTOCOL_A);
      expect(p.isActive).to.be.true;
      expect(p.riskTier).to.equal(RISK_HIGH);
    });

    it("should register a protocol (Governance)", async function () {
      await raizo.grantRole(GOVERNANCE_ROLE, governance.address);
      await raizo
        .connect(governance)
        .registerProtocol(PROTOCOL_A, CHAIN_ETHEREUM, RISK_HIGH);
      expect((await raizo.getProtocol(PROTOCOL_A)).isActive).to.be.true;
    });

    it("should revert if non-authorized tries to register", async function () {
      await expect(
        raizo
          .connect(addr1)
          .registerProtocol(PROTOCOL_A, CHAIN_ETHEREUM, RISK_HIGH),
      )
        .to.be.revertedWithCustomError(raizo, "CallerNotAdminOrGovernance")
        .withArgs(addr1.address);
    });

    it("should deregister a protocol", async function () {
      await raizo.registerProtocol(PROTOCOL_A, CHAIN_ETHEREUM, RISK_HIGH);
      await raizo.deregisterProtocol(PROTOCOL_A);
      expect((await raizo.getProtocol(PROTOCOL_A)).isActive).to.be.false;
    });
  });

  describe("Agent Management", function () {
    it("should register an agent (Admin only)", async function () {
      await expect(raizo.registerAgent(AGENT_ID, addr1.address, BUDGET_USDC))
        .to.emit(raizo, "AgentRegistered")
        .withArgs(AGENT_ID, addr1.address);

      const a = await raizo.getAgent(AGENT_ID);
      expect(a.isActive).to.be.true;
      expect(a.paymentWallet).to.equal(addr1.address);
    });

    it("should revert if governance tries to register agent", async function () {
      await raizo.grantRole(GOVERNANCE_ROLE, governance.address);
      // onlyRole(DEFAULT_ADMIN_ROLE) uses a string revert like "AccessControl: account ... is missing role ..."
      await expect(
        raizo
          .connect(governance)
          .registerAgent(AGENT_ID, addr1.address, BUDGET_USDC),
      )
        .to.be.revertedWithCustomError(
          raizo,
          "AccessControlUnauthorizedAccount",
        )
        .withArgs(governance.address, DEFAULT_ADMIN_ROLE);
    });
  });

  describe("Configuration", function () {
    it("should update epoch duration", async function () {
      await expect(raizo.setEpochDuration(3600))
        .to.emit(raizo, "ConfigUpdated")
        .withArgs("epochDuration", 3600);
      expect(await raizo.getEpochDuration()).to.equal(3600);
    });

    it("should revert if threshold is invalid", async function () {
      await raizo.grantRole(GOVERNANCE_ROLE, governance.address);
      await expect(
        raizo.connect(governance).setConfidenceThreshold(10001),
      ).to.be.revertedWithCustomError(raizo, "InvalidThreshold");
    });
  });

  describe("UUPS Upgradability", function () {
    it("should allow owner to upgrade", async function () {
      const RaizoCoreV2Factory = await ethers.getContractFactory("RaizoCore");
      const v2 = await upgrades.upgradeProxy(
        await raizo.getAddress(),
        RaizoCoreV2Factory,
      );
      expect(await v2.getAddress()).to.equal(await raizo.getAddress());
    });

    it("should fail to upgrade by non-owner", async function () {
      const RaizoCoreV2Factory = await ethers.getContractFactory(
        "RaizoCore",
        addr1,
      );
      await expect(
        upgrades.upgradeProxy(await raizo.getAddress(), RaizoCoreV2Factory),
      ).to.be.reverted;
    });
  });
});
