import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import {
  CrossChainRelay,
  MockSentinelActions,
  MockCCIPRouter,
  RaizoCore,
} from "../../typechain-types";

describe("CrossChainRelay Unit Tests", function () {
  let relay: CrossChainRelay;
  let sentinel: MockSentinelActions;
  let router: MockCCIPRouter;
  let raizoCore: RaizoCore;
  let owner: SignerWithAddress;
  let admin: SignerWithAddress;
  let other: SignerWithAddress;

  const SOURCE_CHAIN_SELECTOR = 12345n;
  const DEST_CHAIN_SELECTOR = 67890n;
  const REPORT_ID = ethers.id("threat.report.1");
  const AGENT_ID = ethers.id("agent.1");

  beforeEach(async function () {
    [owner, admin, other] = await ethers.getSigners();

    // Deploy Mocks
    const MockSentinelFactory = await ethers.getContractFactory(
      "MockSentinelActions",
    );
    sentinel = await MockSentinelFactory.deploy();

    const MockRouterFactory = await ethers.getContractFactory("MockCCIPRouter");
    router = await MockRouterFactory.deploy();

    const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
    raizoCore = (await upgrades.deployProxy(
      RaizoCoreFactory,
      [],
    )) as unknown as RaizoCore;

    // Deploy Relay
    const RelayFactory = await ethers.getContractFactory("CrossChainRelay");
    relay = (await upgrades.deployProxy(RelayFactory, [
      await router.getAddress(),
      await sentinel.getAddress(),
      await raizoCore.getAddress(),
    ])) as unknown as CrossChainRelay;

    await relay.grantRole(await relay.DEFAULT_ADMIN_ROLE(), admin.address);
  });

  describe("Whitelisting", function () {
    it("should allow admin to whitelist source chain", async function () {
      await expect(
        relay.connect(admin).whitelistSourceChain(SOURCE_CHAIN_SELECTOR, true),
      )
        .to.emit(relay, "SourceChainWhitelisted")
        .withArgs(SOURCE_CHAIN_SELECTOR, true);
      expect(await relay.isSourceChainWhitelisted(SOURCE_CHAIN_SELECTOR)).to.be
        .true;
    });

    it("should allow admin to whitelist source sender", async function () {
      await relay
        .connect(admin)
        .whitelistSourceSender(SOURCE_CHAIN_SELECTOR, other.address, true);
      expect(
        await relay.isSourceSenderWhitelisted(
          SOURCE_CHAIN_SELECTOR,
          other.address,
        ),
      ).to.be.true;
    });

    it("should revert if non-admin tries to whitelist", async function () {
      await expect(
        relay.connect(other).whitelistSourceChain(SOURCE_CHAIN_SELECTOR, true),
      ).to.be.revertedWithCustomError(relay, "AccessDenied");
    });
  });

  describe("sendAlert", function () {
    it("should call router to send CCIP message", async function () {
      const payload = "0x";
      const actionType = 0; // PAUSE

      await expect(
        relay.sendAlert(
          DEST_CHAIN_SELECTOR,
          REPORT_ID,
          actionType,
          other.address,
          payload,
        ),
      ).to.emit(relay, "AlertSent");
      // Check router was called (would need more mock logic)
    });
  });

  describe("ccipReceive", function () {
    const createMessage = (
      sourceChain: bigint,
      sourceSender: string,
      reportId: string,
    ) => {
      const msgDataTuple = [
        1, // ACTION_EXECUTE
        reportId,
        AGENT_ID,
        sourceChain,
        DEST_CHAIN_SELECTOR,
        other.address,
        0, // PAUSE
        2, // HIGH
        9500,
        Math.floor(Date.now() / 1000),
        "0x",
        "0x",
      ];

      const payload = ethers.AbiCoder.defaultAbiCoder().encode(
        [
          "(uint8,bytes32,bytes32,uint64,uint64,address,uint8,uint8,uint16,uint256,bytes,bytes)",
        ],
        [msgDataTuple],
      );

      return {
        messageId: ethers.id("ccip.msg.1"),
        sourceChainSelector: sourceChain,
        sender: ethers.AbiCoder.defaultAbiCoder().encode(
          ["address"],
          [sourceSender],
        ),
        data: payload,
        destTokenAmounts: [],
      };
    };

    it("should revert if source chain is not whitelisted", async function () {
      const msg = createMessage(
        SOURCE_CHAIN_SELECTOR,
        other.address,
        REPORT_ID,
      );
      await expect(
        router.simulateReceive(await relay.getAddress(), msg),
      ).to.be.revertedWithCustomError(relay, "UnauthorizedSourceChain");
    });

    it("should revert if source sender is not whitelisted", async function () {
      await relay
        .connect(admin)
        .whitelistSourceChain(SOURCE_CHAIN_SELECTOR, true);
      const msg = createMessage(
        SOURCE_CHAIN_SELECTOR,
        other.address,
        REPORT_ID,
      );
      await expect(
        router.simulateReceive(await relay.getAddress(), msg),
      ).to.be.revertedWithCustomError(relay, "UnauthorizedSourceSender");
    });

    it("should execute action and emit event on valid message", async function () {
      await relay
        .connect(admin)
        .whitelistSourceChain(SOURCE_CHAIN_SELECTOR, true);
      await relay
        .connect(admin)
        .whitelistSourceSender(SOURCE_CHAIN_SELECTOR, other.address, true);

      const msg = createMessage(
        SOURCE_CHAIN_SELECTOR,
        other.address,
        REPORT_ID,
      );

      await expect(router.simulateReceive(await relay.getAddress(), msg))
        .to.emit(relay, "AlertExecuted")
        .withArgs(msg.messageId, other.address, 0);
    });

    it("should prevent duplicate report execution", async function () {
      await relay
        .connect(admin)
        .whitelistSourceChain(SOURCE_CHAIN_SELECTOR, true);
      await relay
        .connect(admin)
        .whitelistSourceSender(SOURCE_CHAIN_SELECTOR, other.address, true);

      const msg = createMessage(
        SOURCE_CHAIN_SELECTOR,
        other.address,
        REPORT_ID,
      );
      await router.simulateReceive(await relay.getAddress(), msg);

      await expect(
        router.simulateReceive(await relay.getAddress(), msg),
      ).to.be.revertedWithCustomError(relay, "MessageAlreadyProcessed");
    });
  });
});
