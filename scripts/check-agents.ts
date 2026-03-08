import { ethers } from "hardhat";
import { keccak256, toUtf8Bytes } from "ethers";

async function main() {
  const coreAddr = "0xc52009177331A66ee06d2cC11E51D885Fcb67cBe";
  const core = await ethers.getContractAt("RaizoCore", coreAddr);
  
  const agents = [
    { id: keccak256(toUtf8Bytes("raizo-threat-sentinel-v1")), name: "Threat Sentinel" },
    { id: "0x1111111111111111111111111111111111111111111111111111111111111111", name: "Compliance Reporter" },
    { id: keccak256(toUtf8Bytes("gov-bridge")), name: "World ID Bridge" }
  ];
  
  for (const agent of agents) {
    const config = await core.getAgent(agent.id);
    console.log(`Agent: ${agent.name} (${agent.id})`);
    console.log(`- isActive: ${config.isActive}`);
    console.log(`- wallet: ${config.paymentWallet}`);
  }
}

main().catch(console.error);
