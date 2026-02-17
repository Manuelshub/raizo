import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import {
  CrossChainRelay,
  SentinelActions,
  RaizoCore,
  MockCCIPRouter,
  MockSentinelActions,
} from "../../typechain-types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

describe("CrossChainAlert Integration Simulation", function () {
  let hubRelay: CrossChainRelay;
  let hubSentinel: SentinelActions;
  let spokeRelay: CrossChainRelay;
  let spokeSentinel: SentinelActions;
  let hubCore: RaizoCore;
  let spokeCore: RaizoCore;
  let hubRouter: MockCCIPRouter;
  let spokeRouter: MockCCIPRouter;

  let owner: HardhatEthersSigner;
  let agent: HardhatEthersSigner;
  let protocolAddress: string;

  const AGENT_ID = ethers.id("agent.001");
  const HUB_CHAIN_SELECTOR = 1n;
  const SPOKE_CHAIN_SELECTOR = 2n;

  beforeEach(async function () {
    [owner, agent] = await ethers.getSigners();
    protocolAddress = ethers.Wallet.createRandom().address;

    // 1. Deploy Infrastructure Mocks
    const RouterFactory = await ethers.getContractFactory("MockCCIPRouter");
    hubRouter = await RouterFactory.deploy();
    spokeRouter = await RouterFactory.deploy();

    // 2. Deploy Hub Chain
    const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
    hubCore = (await upgrades.deployProxy(
      RaizoCoreFactory,
      [],
    )) as unknown as RaizoCore;

    const SentinelFactory = await ethers.getContractFactory("SentinelActions");
    hubSentinel = (await upgrades.deployProxy(SentinelFactory, [
      await hubCore.getAddress(),
    ])) as unknown as SentinelActions;

    const RelayFactory = await ethers.getContractFactory("CrossChainRelay");
    hubRelay = (await upgrades.deployProxy(RelayFactory, [
      await hubRouter.getAddress(),
      await hubSentinel.getAddress(),
      await hubCore.getAddress(),
    ])) as unknown as CrossChainRelay;

    await hubSentinel.setRelay(await hubRelay.getAddress());

    // 3. Deploy Spoke Chain (Simulated in same environment)
    spokeCore = (await upgrades.deployProxy(
      RaizoCoreFactory,
      [],
    )) as unknown as RaizoCore;
    spokeSentinel = (await upgrades.deployProxy(SentinelFactory, [
      await spokeCore.getAddress(),
    ])) as unknown as SentinelActions;
    spokeRelay = (await upgrades.deployProxy(RelayFactory, [
      await spokeRouter.getAddress(),
      await spokeSentinel.getAddress(),
      await spokeCore.getAddress(),
    ])) as unknown as CrossChainRelay;

    // 4. Setup Whitelisting
    await spokeRelay.whitelistSourceChain(HUB_CHAIN_SELECTOR, true);
    await spokeRelay.whitelistSourceSender(
      HUB_CHAIN_SELECTOR,
      await hubRelay.getAddress(),
      true,
    );

    // 5. Setup Registration on both
    for (const core of [hubCore, spokeCore]) {
      await core.registerAgent(AGENT_ID, agent.address, 1000);
      await core.registerProtocol(
        protocolAddress,
        Number(HUB_CHAIN_SELECTOR),
        1,
      );
    }
  });

  it("should propagate a CRITICAL alert from Hub to Spoke", async function () {
    const reportId = ethers.id("report.critical.001");
    const report = {
      reportId: reportId,
      agentId: AGENT_ID,
      exists: true,
      targetProtocol: protocolAddress,
      action: 0, // PAUSE
      severity: 3, // CRITICAL
      confidenceScore: 9500,
      evidenceHash: ethers.id("evidence"),
      timestamp: Math.floor(Date.now() / 1000),
      donSignatures: ethers.hexlify(ethers.randomBytes(65)),
    };

    // 1. Execute on Hub
    // We expect an AlertSent event from hubRelay when hubSentinel.executeAction is called
    await expect(hubSentinel.executeAction(report)).to.emit(
      hubRelay,
      "AlertSent",
    );

    // 2. Capture the cross-chain message data (In a real test we'd parse logs, here we simulate)
    // HubRelay called ccipSend on hubRouter.
    // We simulate the CCIP delivery to spokeRelay.ccipReceive

    const msgDataTuple = [
      1, // ACTION_EXECUTE
      reportId,
      AGENT_ID,
      HUB_CHAIN_SELECTOR,
      SPOKE_CHAIN_SELECTOR,
      protocolAddress,
      0, // PAUSE
      3, // CRITICAL
      9500,
      report.timestamp,
      "0x",
      report.donSignatures,
    ];

    const encodedData = ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "(uint8,bytes32,bytes32,uint64,uint64,address,uint8,uint8,uint16,uint256,bytes,bytes)",
      ],
      [msgDataTuple],
    );

    const ccipMessage = {
      messageId: ethers.id("ccip.delivered.1"),
      sourceChainSelector: HUB_CHAIN_SELECTOR,
      sender: ethers.AbiCoder.defaultAbiCoder().encode(
        ["address"],
        [await hubRelay.getAddress()],
      ),
      data: encodedData,
      destTokenAmounts: [],
    };

    // 3. Receive on Spoke
    await expect(spokeRelay.ccipReceive(ccipMessage))
      .to.emit(spokeRelay, "AlertReceived")
      .withArgs(ccipMessage.messageId, HUB_CHAIN_SELECTOR, reportId);

    // 4. Verify Execution on Spoke
    const activeActions = await spokeSentinel.getActiveActions(protocolAddress);
    expect(activeActions.length).to.equal(1);
    expect(activeActions[0].reportId).to.equal(reportId);
    expect(await spokeSentinel.isProtocolPaused(protocolAddress)).to.be.true;
  });

  it("should NOT propagate a LOW severity alert", async function () {
    const reportId = ethers.id("report.low.001");
    const report = {
      reportId: reportId,
      agentId: AGENT_ID,
      exists: true,
      targetProtocol: protocolAddress,
      action: 0, // PAUSE
      severity: 0, // LOW
      confidenceScore: 9500,
      evidenceHash: ethers.id("evidence"),
      timestamp: Math.floor(Date.now() / 1000),
      donSignatures: ethers.hexlify(ethers.randomBytes(65)),
    };

    // Execute on Hub - should NOT emit AlertSent
    await expect(hubSentinel.executeAction(report)).to.not.emit(
      hubRelay,
      "AlertSent",
    );
  });
});
