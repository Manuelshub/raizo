import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { GovernanceGate } from "../../typechain-types";

describe("GovernanceGate (Admin-Only Configuration)", function () {
  let govGate: GovernanceGate;
  let admin: SignerWithAddress;
  let pauser: SignerWithAddress;
  let user: SignerWithAddress;

  const INITIAL_THRESHOLD = 8500; // 85%
  const NEW_THRESHOLD = 9000; // 90%
  const PAUSE_DELAY = 100; // blocks

  beforeEach(async function () {
    [admin, pauser, user] = await ethers.getSigners();

    const GovernanceGateFactory = await ethers.getContractFactory(
      "GovernanceGate",
    );
    govGate = (await upgrades.deployProxy(
      GovernanceGateFactory,
      [admin.address, INITIAL_THRESHOLD],
      {
        initializer: "initialize",
        kind: "uups",
      },
    )) as unknown as GovernanceGate;
    await govGate.waitForDeployment();
  });

  describe("Initialization", function () {
    it("should initialize with correct admin and threshold", async function () {
      const config = await govGate.getConfig();
      expect(config.confidenceThreshold).to.equal(INITIAL_THRESHOLD);
      expect(config.emergencyPauseDelay).to.equal(0);
    });

    it("should grant DEFAULT_ADMIN_ROLE and EMERGENCY_PAUSER_ROLE to admin", async function () {
      const DEFAULT_ADMIN_ROLE =
        "0x0000000000000000000000000000000000000000000000000000000000000000";
      const EMERGENCY_PAUSER_ROLE = ethers.keccak256(
        ethers.toUtf8Bytes("EMERGENCY_PAUSER_ROLE"),
      );

      expect(
        await govGate.hasRole(DEFAULT_ADMIN_ROLE, admin.address),
      ).to.be.true;
      expect(
        await govGate.hasRole(EMERGENCY_PAUSER_ROLE, admin.address),
      ).to.be.true;
    });

    it("should not be paused on initialization", async function () {
      expect(await govGate.isPaused()).to.be.false;
    });
  });

  describe("Configuration Setters", function () {
    it("should allow admin to update confidence threshold", async function () {
      await expect(govGate.connect(admin).setConfidenceThreshold(NEW_THRESHOLD))
        .to.emit(govGate, "ConfigUpdated")
        .withArgs("confidenceThreshold", NEW_THRESHOLD);

      const config = await govGate.getConfig();
      expect(config.confidenceThreshold).to.equal(NEW_THRESHOLD);
    });

    it("should reject invalid confidence threshold (> 10000)", async function () {
      await expect(
        govGate.connect(admin).setConfidenceThreshold(10001),
      ).to.be.revertedWithCustomError(govGate, "InvalidThreshold");
    });

    it("should allow admin to update emergency pause delay", async function () {
      await expect(govGate.connect(admin).setEmergencyPauseDelay(PAUSE_DELAY))
        .to.emit(govGate, "ConfigUpdated")
        .withArgs("emergencyPauseDelay", PAUSE_DELAY);

      const config = await govGate.getConfig();
      expect(config.emergencyPauseDelay).to.equal(PAUSE_DELAY);
    });

    it("should reject non-admin from setting threshold", async function () {
      await expect(
        govGate.connect(user).setConfidenceThreshold(NEW_THRESHOLD),
      ).to.be.revertedWithCustomError(govGate, "AccessControlUnauthorizedAccount");
    });

    it("should reject non-admin from setting pause delay", async function () {
      await expect(
        govGate.connect(user).setEmergencyPauseDelay(PAUSE_DELAY),
      ).to.be.revertedWithCustomError(govGate, "AccessControlUnauthorizedAccount");
    });
  });

  describe("Emergency Pause Controls", function () {
    it("should allow emergency pauser to trigger pause", async function () {
      const EMERGENCY_PAUSER_ROLE = ethers.keccak256(
        ethers.toUtf8Bytes("EMERGENCY_PAUSER_ROLE"),
      );

      await govGate.grantRole(EMERGENCY_PAUSER_ROLE, pauser.address);

      await expect(govGate.connect(pauser).emergencyPause())
        .to.emit(govGate, "EmergencyPauseTriggered")
        .withArgs(pauser.address);

      expect(await govGate.isPaused()).to.be.true;
    });

    it("should allow admin to lift pause", async function () {
      const EMERGENCY_PAUSER_ROLE = ethers.keccak256(
        ethers.toUtf8Bytes("EMERGENCY_PAUSER_ROLE"),
      );

      await govGate.grantRole(EMERGENCY_PAUSER_ROLE, pauser.address);
      await govGate.connect(pauser).emergencyPause();

      await expect(govGate.connect(admin).unpause())
        .to.emit(govGate, "PauseLifted")
        .withArgs(admin.address);

      expect(await govGate.isPaused()).to.be.false;
    });

    it("should reject non-admin from lifting pause", async function () {
      const EMERGENCY_PAUSER_ROLE = ethers.keccak256(
        ethers.toUtf8Bytes("EMERGENCY_PAUSER_ROLE"),
      );

      await govGate.grantRole(EMERGENCY_PAUSER_ROLE, pauser.address);
      await govGate.connect(pauser).emergencyPause();

      await expect(
        govGate.connect(user).unpause(),
      ).to.be.revertedWithCustomError(govGate, "AccessControlUnauthorizedAccount");
    });

    it("should reject non-pauser from triggering emergency pause", async function () {
      await expect(
        govGate.connect(user).emergencyPause(),
      ).to.be.revertedWithCustomError(govGate, "AccessControlUnauthorizedAccount");
    });
  });

  describe("Configuration Getters", function () {
    it("should return correct confidence threshold", async function () {
      const threshold = await govGate.getConfidenceThreshold();
      expect(threshold).to.equal(INITIAL_THRESHOLD);
    });

    it("should return correct emergency pause delay", async function () {
      await govGate.connect(admin).setEmergencyPauseDelay(PAUSE_DELAY);
      const delay = await govGate.getEmergencyPauseDelay();
      expect(delay).to.equal(PAUSE_DELAY);
    });

    it("should return full config struct", async function () {
      await govGate.connect(admin).setConfidenceThreshold(NEW_THRESHOLD);
      await govGate.connect(admin).setEmergencyPauseDelay(PAUSE_DELAY);

      const config = await govGate.getConfig();
      expect(config.confidenceThreshold).to.equal(NEW_THRESHOLD);
      expect(config.emergencyPauseDelay).to.equal(PAUSE_DELAY);
    });
  });

  describe("UUPS Upgrade Authorization", function () {
    it("should reject non-admin from upgrading", async function () {
      const GovernanceGateFactory = await ethers.getContractFactory(
        "GovernanceGate",
        user,
      );

      await expect(
        upgrades.upgradeProxy(
          await govGate.getAddress(),
          GovernanceGateFactory,
        ),
      ).to.be.revertedWithCustomError(govGate, "AccessControlUnauthorizedAccount");
    });
  });
});
