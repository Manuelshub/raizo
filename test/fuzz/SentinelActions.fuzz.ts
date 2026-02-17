import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { SentinelActions, RaizoCore } from "../../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("SentinelActions Fuzz Simulation", function () {
  let sentinel: SentinelActions;
  let raizoCore: RaizoCore;
  let owner: SignerWithAddress;
  let agentWallet: SignerWithAddress;
  let node1: SignerWithAddress;
  let node2: SignerWithAddress;

  const PROTOCOL_A = "0x0000000000000000000000000000000000000001";
  const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("fuzz-agent"));
  const BUDGET_USDC = ethers.parseUnits("1000", 6);
  const ACTION_BUDGET = 10;

  before(async function () {
    [owner, agentWallet, node1, node2] = await ethers.getSigners();

    const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
    raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
      initializer: "initialize",
    })) as unknown as RaizoCore;
    await raizoCore.waitForDeployment();

    const SentinelActionsFactory = await ethers.getContractFactory(
      "SentinelActions",
    );
    sentinel = (await upgrades.deployProxy(
      SentinelActionsFactory,
      [await raizoCore.getAddress()],
      { initializer: "initialize" },
    )) as unknown as SentinelActions;
    await sentinel.waitForDeployment();

    const GOVERNANCE_ROLE = await raizoCore.GOVERNANCE_ROLE();
    await raizoCore.grantRole(GOVERNANCE_ROLE, owner.address);

    await raizoCore.registerProtocol(PROTOCOL_A, 1, 2);
    await raizoCore.registerAgent(AGENT_ID, agentWallet.address, BUDGET_USDC);
  });

  it("should handle 50 randomized reports correctly", async function () {
    let successCount = 0;
    for (let i = 0; i < 50; i++) {
      const confidence = Math.floor(Math.random() * 10000); // 0 to 10000
      const report = {
        reportId: ethers.keccak256(ethers.randomBytes(32)),
        agentId: AGENT_ID,
        exists: false,
        targetProtocol: PROTOCOL_A,
        action: 0,
        severity: Math.floor(Math.random() * 4) as number,
        confidenceScore: confidence,
        evidenceHash: ethers.toUtf8Bytes("evidence"),
        timestamp: (await ethers.provider.getBlock("latest"))!.timestamp,
        donSignatures: "0x" as string,
      };

      const messageHash = ethers.solidityPackedKeccak256(
        [
          "bytes32",
          "bytes32",
          "bool",
          "address",
          "uint8",
          "uint8",
          "uint16",
          "uint256",
        ],
        [
          report.reportId,
          report.agentId,
          report.exists,
          report.targetProtocol,
          report.action,
          report.severity,
          report.confidenceScore,
          report.timestamp,
        ],
      );

      const sig1 = await node1.signMessage(ethers.getBytes(messageHash));
      const sig2 = await node2.signMessage(ethers.getBytes(messageHash));
      report.donSignatures = ethers.concat([sig1, sig2]);

      if (confidence < 8500) {
        await expect(sentinel.executeAction(report))
          .to.be.revertedWithCustomError(sentinel, "ConfidenceThresholdNotMet")
          .withArgs(report.confidenceScore, 8500);
      } else if (successCount >= ACTION_BUDGET) {
        const epoch = Math.floor(report.timestamp / 86400);
        await expect(sentinel.executeAction(report))
          .to.be.revertedWithCustomError(sentinel, "BudgetExceeded")
          .withArgs(AGENT_ID, epoch);
      } else {
        await expect(sentinel.executeAction(report)).to.emit(
          sentinel,
          "ActionExecuted",
        );
        successCount++;
      }
    }
  });
});
