import { expect } from "chai";
import { ethers } from "hardhat";
import { RaizoCore } from "../../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("RaizoCore", function () {
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
  const PROTOCOL_B = "0x0000000000000000000000000000000000000002";
  const CHAIN_ETH = 1;
  const CHAIN_BASE = 8453;
  const RISK_LOW = 1;
  const RISK_MEDIUM = 2;
  const RISK_HIGH = 3;
  const RISK_CRITICAL = 4;
  const AGENT_ID_1 = ethers.keccak256(ethers.toUtf8Bytes("threat-sentinel-v1"));
  const AGENT_ID_2 = ethers.keccak256(
    ethers.toUtf8Bytes("compliance-reporter-v1"),
  );
  const DAILY_BUDGET = ethers.parseUnits("100", 6); // 100 USDC
  const ACTION_BUDGET = 50;

  beforeEach(async function () {
    [owner, governance, addr1, addr2] = await ethers.getSigners();

    const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
    raizo = (await RaizoCoreFactory.deploy()) as unknown as RaizoCore;

    await raizo.grantRole(GOVERNANCE_ROLE, governance.address);
  });


  describe("Deployment", function () {
    it("should set deployer as DEFAULT_ADMIN_ROLE", async function () {
      expect(await raizo.hasRole(DEFAULT_ADMIN_ROLE, owner.address)).to.be.true;
    });

    it("should set a default confidence threshold of 8500 (85%)", async function () {
      expect(await raizo.getConfidenceThreshold()).to.equal(8500);
    });

    it("should set a default epoch duration of 1 day", async function () {
      expect(await raizo.getEpochDuration()).to.equal(86400);
    });

    it("should start with zero registered protocols", async function () {
      expect(await raizo.getProtocolCount()).to.equal(0);
    });
  });

  describe("Protocol Management", function () {
    describe("registerProtocol", function () {
      it("should register a protocol with correct data", async function () {
        await raizo.registerProtocol(PROTOCOL_A, CHAIN_ETH, RISK_MEDIUM);

        const config = await raizo.getProtocol(PROTOCOL_A);
        expect(config.protocolAddress).to.equal(PROTOCOL_A);
        expect(config.chainId).to.equal(CHAIN_ETH);
        expect(config.riskTier).to.equal(RISK_MEDIUM);
        expect(config.isActive).to.be.true;
        expect(config.registeredAt).to.be.gt(0);
      });

      it("should emit ProtocolRegistered event", async function () {
        await expect(raizo.registerProtocol(PROTOCOL_A, CHAIN_ETH, RISK_MEDIUM))
          .to.emit(raizo, "ProtocolRegistered")
          .withArgs(PROTOCOL_A, CHAIN_ETH, RISK_MEDIUM);
      });

      it("should increment protocol count", async function () {
        await raizo.registerProtocol(PROTOCOL_A, CHAIN_ETH, RISK_LOW);
        expect(await raizo.getProtocolCount()).to.equal(1);

        await raizo.registerProtocol(PROTOCOL_B, CHAIN_BASE, RISK_HIGH);
        expect(await raizo.getProtocolCount()).to.equal(2);
      });

      it("should allow governance role to register protocols", async function () {
        await expect(
          raizo
            .connect(governance)
            .registerProtocol(PROTOCOL_A, CHAIN_ETH, RISK_LOW),
        ).to.not.be.reverted;
      });

      it("should revert if caller lacks admin or governance role", async function () {
        await expect(
          raizo
            .connect(addr1)
            .registerProtocol(PROTOCOL_A, CHAIN_ETH, RISK_LOW),
        ).to.be.reverted;
      });

      it("should revert on duplicate protocol registration", async function () {
        await raizo.registerProtocol(PROTOCOL_A, CHAIN_ETH, RISK_LOW);
        await expect(
          raizo.registerProtocol(PROTOCOL_A, CHAIN_ETH, RISK_LOW),
        ).to.be.revertedWithCustomError(raizo, "ProtocolAlreadyRegistered");
      });

      it("should revert on zero address", async function () {
        await expect(
          raizo.registerProtocol(ethers.ZeroAddress, CHAIN_ETH, RISK_LOW),
        ).to.be.revertedWithCustomError(raizo, "ZeroAddress");
      });

      it("should revert on invalid risk tier (0)", async function () {
        await expect(
          raizo.registerProtocol(PROTOCOL_A, CHAIN_ETH, 0),
        ).to.be.revertedWithCustomError(raizo, "InvalidRiskTier");
      });

      it("should revert on invalid risk tier (5+)", async function () {
        await expect(
          raizo.registerProtocol(PROTOCOL_A, CHAIN_ETH, 5),
        ).to.be.revertedWithCustomError(raizo, "InvalidRiskTier");
      });
    });

    describe("deregisterProtocol", function () {
      beforeEach(async function () {
        await raizo.registerProtocol(PROTOCOL_A, CHAIN_ETH, RISK_MEDIUM);
      });

      it("should deregister a protocol (set isActive to false)", async function () {
        await raizo.deregisterProtocol(PROTOCOL_A);
        const config = await raizo.getProtocol(PROTOCOL_A);
        expect(config.isActive).to.be.false;
      });

      it("should emit ProtocolDeregistered event", async function () {
        await expect(raizo.deregisterProtocol(PROTOCOL_A))
          .to.emit(raizo, "ProtocolDeregistered")
          .withArgs(PROTOCOL_A);
      });

      it("should decrement protocol count", async function () {
        await raizo.registerProtocol(PROTOCOL_B, CHAIN_BASE, RISK_HIGH);
        expect(await raizo.getProtocolCount()).to.equal(2);

        await raizo.deregisterProtocol(PROTOCOL_A);
        expect(await raizo.getProtocolCount()).to.equal(1);
      });

      it("should revert if protocol is not registered", async function () {
        await expect(
          raizo.deregisterProtocol(PROTOCOL_B),
        ).to.be.revertedWithCustomError(raizo, "ProtocolNotRegistered");
      });

      it("should revert if caller lacks admin or governance role", async function () {
        await expect(raizo.connect(addr1).deregisterProtocol(PROTOCOL_A)).to.be
          .reverted;
      });
    });

    describe("updateRiskTier", function () {
      beforeEach(async function () {
        await raizo.registerProtocol(PROTOCOL_A, CHAIN_ETH, RISK_LOW);
      });

      it("should update the risk tier", async function () {
        await raizo.updateRiskTier(PROTOCOL_A, RISK_CRITICAL);
        const config = await raizo.getProtocol(PROTOCOL_A);
        expect(config.riskTier).to.equal(RISK_CRITICAL);
      });

      it("should emit RiskTierUpdated event with old and new tiers", async function () {
        await expect(raizo.updateRiskTier(PROTOCOL_A, RISK_HIGH))
          .to.emit(raizo, "RiskTierUpdated")
          .withArgs(PROTOCOL_A, RISK_LOW, RISK_HIGH);
      });

      it("should revert if protocol is not registered", async function () {
        await expect(
          raizo.updateRiskTier(PROTOCOL_B, RISK_HIGH),
        ).to.be.revertedWithCustomError(raizo, "ProtocolNotRegistered");
      });

      it("should revert on invalid risk tier", async function () {
        await expect(
          raizo.updateRiskTier(PROTOCOL_A, 0),
        ).to.be.revertedWithCustomError(raizo, "InvalidRiskTier");
      });

      it("should revert if caller lacks access", async function () {
        await expect(raizo.connect(addr1).updateRiskTier(PROTOCOL_A, RISK_HIGH))
          .to.be.reverted;
      });
    });

    describe("getProtocol", function () {
      it("should return empty config for unregistered protocol", async function () {
        const config = await raizo.getProtocol(PROTOCOL_A);
        expect(config.protocolAddress).to.equal(ethers.ZeroAddress);
        expect(config.isActive).to.be.false;
      });
    });

    describe("getAllProtocols", function () {
      it("should return empty array when no protocols registered", async function () {
        const protocols = await raizo.getAllProtocols();
        expect(protocols.length).to.equal(0);
      });

      it("should return all active protocols", async function () {
        await raizo.registerProtocol(PROTOCOL_A, CHAIN_ETH, RISK_LOW);
        await raizo.registerProtocol(PROTOCOL_B, CHAIN_BASE, RISK_HIGH);

        const protocols = await raizo.getAllProtocols();
        expect(protocols.length).to.equal(2);
        expect(protocols[0].protocolAddress).to.equal(PROTOCOL_A);
        expect(protocols[1].protocolAddress).to.equal(PROTOCOL_B);
      });

      it("should exclude deregistered protocols", async function () {
        await raizo.registerProtocol(PROTOCOL_A, CHAIN_ETH, RISK_LOW);
        await raizo.registerProtocol(PROTOCOL_B, CHAIN_BASE, RISK_HIGH);
        await raizo.deregisterProtocol(PROTOCOL_A);

        const protocols = await raizo.getAllProtocols();
        expect(protocols.length).to.equal(1);
        expect(protocols[0].protocolAddress).to.equal(PROTOCOL_B);
      });
    });
  });

  describe("Agent Management", function () {
    describe("registerAgent", function () {
      it("should register an agent with correct data", async function () {
        await raizo.registerAgent(
          AGENT_ID_1,
          addr1.address,
          DAILY_BUDGET,
          ACTION_BUDGET,
        );

        const config = await raizo.getAgent(AGENT_ID_1);
        expect(config.agentId).to.equal(AGENT_ID_1);
        expect(config.paymentWallet).to.equal(addr1.address);
        expect(config.dailyBudgetUSDC).to.equal(DAILY_BUDGET);
        expect(config.actionBudgetPerEpoch).to.equal(ACTION_BUDGET);
        expect(config.isActive).to.be.true;
      });

      it("should emit AgentRegistered event", async function () {
        await expect(
          raizo.registerAgent(
            AGENT_ID_1,
            addr1.address,
            DAILY_BUDGET,
            ACTION_BUDGET,
          ),
        )
          .to.emit(raizo, "AgentRegistered")
          .withArgs(AGENT_ID_1, addr1.address);
      });

      it("should revert if caller is not admin", async function () {
        await expect(
          raizo
            .connect(addr1)
            .registerAgent(
              AGENT_ID_1,
              addr1.address,
              DAILY_BUDGET,
              ACTION_BUDGET,
            ),
        ).to.be.reverted;
      });

      it("should revert on duplicate agent ID", async function () {
        await raizo.registerAgent(
          AGENT_ID_1,
          addr1.address,
          DAILY_BUDGET,
          ACTION_BUDGET,
        );
        await expect(
          raizo.registerAgent(
            AGENT_ID_1,
            addr2.address,
            DAILY_BUDGET,
            ACTION_BUDGET,
          ),
        ).to.be.revertedWithCustomError(raizo, "AgentAlreadyRegistered");
      });

      it("should revert on zero payment wallet address", async function () {
        await expect(
          raizo.registerAgent(
            AGENT_ID_1,
            ethers.ZeroAddress,
            DAILY_BUDGET,
            ACTION_BUDGET,
          ),
        ).to.be.revertedWithCustomError(raizo, "ZeroAddress");
      });
    });

    describe("deregisterAgent", function () {
      beforeEach(async function () {
        await raizo.registerAgent(
          AGENT_ID_1,
          addr1.address,
          DAILY_BUDGET,
          ACTION_BUDGET,
        );
      });

      it("should deregister agent (set isActive to false)", async function () {
        await raizo.deregisterAgent(AGENT_ID_1);
        const config = await raizo.getAgent(AGENT_ID_1);
        expect(config.isActive).to.be.false;
      });

      it("should emit AgentDeregistered event", async function () {
        await expect(raizo.deregisterAgent(AGENT_ID_1))
          .to.emit(raizo, "AgentDeregistered")
          .withArgs(AGENT_ID_1);
      });

      it("should revert if agent is not registered", async function () {
        await expect(
          raizo.deregisterAgent(AGENT_ID_2),
        ).to.be.revertedWithCustomError(raizo, "AgentNotRegistered");
      });

      it("should revert if caller is not admin", async function () {
        await expect(raizo.connect(addr1).deregisterAgent(AGENT_ID_1)).to.be
          .reverted;
      });
    });

    describe("getAgent", function () {
      it("should return empty config for unregistered agent", async function () {
        const config = await raizo.getAgent(AGENT_ID_1);
        expect(config.agentId).to.equal(ethers.ZeroHash);
        expect(config.isActive).to.be.false;
      });
    });
  });

  describe("Configuration", function () {
    describe("setConfidenceThreshold", function () {
      it("should update the confidence threshold", async function () {
        await raizo.connect(governance).setConfidenceThreshold(9000);
        expect(await raizo.getConfidenceThreshold()).to.equal(9000);
      });

      it("should emit ConfidenceThresholdUpdated event", async function () {
        await expect(raizo.connect(governance).setConfidenceThreshold(9000))
          .to.emit(raizo, "ConfidenceThresholdUpdated")
          .withArgs(8500, 9000);
      });

      it("should allow admin to set threshold", async function () {
        await expect(raizo.setConfidenceThreshold(9000)).to.not.be.reverted;
      });

      it("should revert if caller lacks governance or admin role", async function () {
        await expect(raizo.connect(addr1).setConfidenceThreshold(9000)).to.be
          .reverted;
      });

      it("should revert if threshold exceeds 10000 bps (100%)", async function () {
        await expect(
          raizo.connect(governance).setConfidenceThreshold(10001),
        ).to.be.revertedWithCustomError(raizo, "InvalidThreshold");
      });

      it("should accept threshold of 0 (effectively disables actions)", async function () {
        await expect(raizo.connect(governance).setConfidenceThreshold(0)).to.not
          .be.reverted;
        expect(await raizo.getConfidenceThreshold()).to.equal(0);
      });

      it("should accept threshold of exactly 10000 (100%)", async function () {
        await expect(raizo.connect(governance).setConfidenceThreshold(10000)).to
          .not.be.reverted;
        expect(await raizo.getConfidenceThreshold()).to.equal(10000);
      });
    });

    describe("setEpochDuration", function () {
      it("should update the epoch duration", async function () {
        const oneWeek = 7 * 86400;
        await raizo.connect(governance).setEpochDuration(oneWeek);
        expect(await raizo.getEpochDuration()).to.equal(oneWeek);
      });

      it("should emit EpochDurationUpdated event", async function () {
        const oneWeek = 7 * 86400;
        await expect(raizo.connect(governance).setEpochDuration(oneWeek))
          .to.emit(raizo, "EpochDurationUpdated")
          .withArgs(86400, oneWeek);
      });

      it("should revert if duration is zero", async function () {
        await expect(
          raizo.connect(governance).setEpochDuration(0),
        ).to.be.revertedWithCustomError(raizo, "InvalidEpochDuration");
      });

      it("should revert if caller lacks governance or admin role", async function () {
        await expect(raizo.connect(addr1).setEpochDuration(86400)).to.be
          .reverted;
      });
    });
  });
});
