import { ethers } from "hardhat";

async function main() {
  const coreAddr = "0xc52009177331A66ee06d2cC11E51D885Fcb67cBe";
  const provider = new ethers.JsonRpcProvider("https://ethereum-sepolia-rpc.publicnode.com");
  
  const core = new ethers.Contract(
    coreAddr,
    ["function owner() external view returns (address)"],
    provider
  );

  console.log("Checking owner of RaizoCore at", coreAddr, "on Publicnode...");
  try {
    const owner = await core.owner();
    console.log("Owner:", owner);
    const deployer = "0xF89227c33F8Ef6f623ad9303e72cf8dc17f7643F";
    console.log("Matches Deployer?", owner.toLowerCase() === deployer.toLowerCase());
  } catch (e: any) {
    console.error("Error fetching owner:", e.message);
  }
}

main().catch(console.error);
