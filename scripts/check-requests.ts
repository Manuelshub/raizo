import { ethers } from "hardhat";

async function main() {
  const gateAddr = "0xf472ae388224674d0068776841eF466484b04E0C";
  const gate = await ethers.getContractAt("GovernanceGate", gateAddr);
  
  const total = await gate.pendingRequestCount();
  console.log(`Total Pending Requests: ${total}`);
  
  if (total > 0) {
      const last = await gate.getPendingRequest(total - 1n);
      console.log(`Last Request (#${total - 1n}):`);
      console.log(`- Requester: ${last.requester}`);
      console.log(`- Processed: ${last.processed}`);
  }
}

main().catch(console.error);
