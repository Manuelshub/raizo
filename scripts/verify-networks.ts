import { ethers } from "hardhat";

async function checkRpc(name: string, url: string, address: string) {
  const provider = new ethers.JsonRpcProvider(url);
  try {
    const code = await provider.getCode(address);
    console.log(`[${name}] Code at ${address}: ${code === "0x" ? "NOT FOUND" : "FOUND (" + code.length + " bytes)"}`);
    if (code !== "0x") {
        const core = new ethers.Contract(address, ["function getAllProtocols() external view returns (tuple(address protocolAddress, uint16 chainId, uint8 riskTier, bool isActive, uint256 registeredAt)[] memory)"], provider);
        const protocols = await core.getAllProtocols();
        console.log(`[${name}] Protocols count: ${protocols.length}`);
    }
  } catch (e: any) {
    console.log(`[${name}] Error: ${e.message}`);
  }
}

async function main() {
  const coreAddr = "0xc52009177331A66ee06d2cC11E51D885Fcb67cBe";
  
  await checkRpc("Tenderly Gateway", "https://sepolia.gateway.tenderly.co", coreAddr);
  await checkRpc("Publicnode", "https://ethereum-sepolia-rpc.publicnode.com", coreAddr);
  await checkRpc("Ankr", "https://rpc.ankr.com/eth_sepolia", coreAddr);
}

main().catch(console.error);
