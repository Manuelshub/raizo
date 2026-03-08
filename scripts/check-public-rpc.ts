import { ethers } from "hardhat";

async function main() {
  const coreAddr = "0xc52009177331A66ee06d2cC11E51D885Fcb67cBe";
  const publicProvider = new ethers.JsonRpcProvider("https://ethereum-sepolia-rpc.publicnode.com");
  
  const core = new ethers.Contract(
    coreAddr,
    ["function getAllProtocols() external view returns (tuple(address protocolAddress, uint16 chainId, uint8 riskTier, bool isActive, uint256 registeredAt)[] memory)"],
    publicProvider
  );

  console.log("Checking RaizoCore at", coreAddr, "on PUBLIC RPC...");
  try {
    const protocols = await core.getAllProtocols();
    console.log("Protocols count:", protocols.length);
    protocols.forEach((p: any, i: number) => {
      console.log(`  [${i}] ${p.protocolAddress} (Chain: ${p.chainId}, Active: ${p.isActive})`);
    });
  } catch (e: any) {
    console.error("Error fetching protocols from public RPC:", e.message);
  }
}

main().catch(console.error);
