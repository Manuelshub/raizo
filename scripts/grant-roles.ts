import { ethers } from "hardhat";

async function main() {
  const complianceVaultAddress = "0x70fa099b0b667EE5F01E992D48855d804C8F92b0";
  const raizoConsumerAddress = "0xCfD3071B32C3aBf8EbaADA62C9671e8598B3bB9B";

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
