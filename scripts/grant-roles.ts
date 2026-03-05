import { ethers } from "hardhat";

async function main() {
  const complianceVaultAddress = "0x92B10171c849f3b9DBE355658eFE7E84084E42B9";
  const raizoConsumerAddress = "0xd96b4ABfE8097AD706D1aD786cE518E210339639";

  console.log(
    `Granting ANCHOR_ROLE to ${raizoConsumerAddress} on ComplianceVault ${complianceVaultAddress}...`,
  );

  const vault = await ethers.getContractAt(
    "ComplianceVault",
    complianceVaultAddress,
  );
  const ANCHOR_ROLE = await vault.ANCHOR_ROLE();

  const tx = await vault.grantRole(ANCHOR_ROLE, raizoConsumerAddress);
  await tx.wait();

  console.log(
    "Success! RaizoConsumer now has permission to anchor compliance reports.",
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
