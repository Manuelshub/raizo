import { ethers } from "hardhat";

async function main() {
  const coreAddr = "0xc52009177331A66ee06d2cC11E51D885Fcb67cBe";
  const deployer = "0xF89227c33F8Ef6f623ad9303e72cf8dc17f7643F";
  
  const core = await ethers.getContractAt("RaizoCore", coreAddr);
  
  const ADMIN_ROLE = await core.DEFAULT_ADMIN_ROLE();
  const GOV_ROLE = await core.GOVERNANCE_ROLE();
  
  const hasAdmin = await core.hasRole(ADMIN_ROLE, deployer);
  const hasGov = await core.hasRole(GOV_ROLE, deployer);
  
  console.log(`Roles for ${deployer} on RaizoCore:`);
  console.log(`- has DEFAULT_ADMIN_ROLE: ${hasAdmin}`);
  console.log(`- has GOVERNANCE_ROLE: ${hasGov}`);
}

main().catch(console.error);
