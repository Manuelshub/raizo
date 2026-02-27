import { ethers, upgrades } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * Raizo — Full Stack Deployment Script
 *
 * Deploy order (dependency-resolved):
 * 1. RaizoCore        (UUPS proxy, no init args)
 * 2. GovernanceGate   (UUPS proxy, needs worldId)
 * 3. SentinelActions  (UUPS proxy, needs raizoCore)
 * 4. PaymentEscrow    (UUPS proxy, needs raizoCore + USDC)
 * 5. ComplianceVault  (immutable, constructor grants admin)
 * 6. CrossChainRelay  (UUPS proxy, needs router + sentinel + raizoCore)
 *
 * Output: deployments/<network>-<timestamp>.json
 */

// --- Testnet Addresses ---
const TESTNET_ADDRESSES: Record<string, { worldId: string; usdc: string; ccipRouter: string }> = {
  sepolia: {
    worldId: "0x0000000000000000000000000000000000000000",   // Placeholder — no World ID on Sepolia
    usdc: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",      // Circle USDC on Sepolia
    ccipRouter: "0x0BF3dE8c5D3e8A2B34D2BEeB17ABfCeBaf363A59",  // Chainlink CCIP Router Sepolia
  },
  baseSepolia: {
    worldId: "0x0000000000000000000000000000000000000000",
    usdc: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",      // Circle USDC on Base Sepolia
    ccipRouter: "0xD3b06cEbF099CE7DA4AcCf578aaebFDBd6e88a93",  // Chainlink CCIP Router Base Sepolia
  },
  hardhat: {
    worldId: "0x0000000000000000000000000000000000000000",
    usdc: "0x0000000000000000000000000000000000000000",
    ccipRouter: "0x0000000000000000000000000000000000000000",
  },
  virtualSepolia: {
    worldId: "0x0000000000000000000000000000000000000000",
    usdc: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
    ccipRouter: "0x0BF3dE8c5D3e8A2B34D2BEeB17ABfCeBaf363A59",
  },
};

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = (await ethers.provider.getNetwork()).name || "unknown";
  const chainId = (await ethers.provider.getNetwork()).chainId;

  console.log(`\n Raizo Deployment — ${network} (chainId: ${chainId})`);
  console.log(`   Deployer: ${deployer.address}`);
  console.log(`   Balance:  ${ethers.formatEther(await ethers.provider.getBalance(deployer.address))} ETH\n`);

  const addrs = TESTNET_ADDRESSES[network] || TESTNET_ADDRESSES.hardhat;
  const deployed: Record<string, string> = {};

  // --- 1. RaizoCore ---
  console.log("1/6 Deploying RaizoCore (UUPS proxy)...");
  const RaizoCore = await ethers.getContractFactory("RaizoCore");
  const raizoCore = await upgrades.deployProxy(RaizoCore, [], { kind: "uups" });
  await raizoCore.waitForDeployment();
  deployed.RaizoCore = await raizoCore.getAddress();
  console.log(`      RaizoCore: ${deployed.RaizoCore}`);

  // --- 2. GovernanceGate ---
  console.log("2/6 Deploying GovernanceGate (UUPS proxy)...");
  const GovernanceGate = await ethers.getContractFactory("GovernanceGate");
  const governanceGate = await upgrades.deployProxy(GovernanceGate, [addrs.worldId], { kind: "uups" });
  await governanceGate.waitForDeployment();
  deployed.GovernanceGate = await governanceGate.getAddress();
  console.log(`      GovernanceGate: ${deployed.GovernanceGate}`);

  // --- 3. SentinelActions ---
  console.log("3/6 Deploying SentinelActions (UUPS proxy)...");
  const SentinelActions = await ethers.getContractFactory("SentinelActions");
  const sentinelActions = await upgrades.deployProxy(SentinelActions, [deployed.RaizoCore], { kind: "uups" });
  await sentinelActions.waitForDeployment();
  deployed.SentinelActions = await sentinelActions.getAddress();
  console.log(`      SentinelActions: ${deployed.SentinelActions}`);

  // --- 4. PaymentEscrow ---
  console.log("4/6 Deploying PaymentEscrow (UUPS proxy)...");
  const PaymentEscrow = await ethers.getContractFactory("PaymentEscrow");
  const paymentEscrow = await upgrades.deployProxy(PaymentEscrow, [deployed.RaizoCore, addrs.usdc], { kind: "uups" });
  await paymentEscrow.waitForDeployment();
  deployed.PaymentEscrow = await paymentEscrow.getAddress();
  console.log(`      PaymentEscrow: ${deployed.PaymentEscrow}`);

  // --- 5. ComplianceVault ---
  console.log("5/6 Deploying ComplianceVault (immutable)...");
  const ComplianceVault = await ethers.getContractFactory("ComplianceVault");
  const complianceVault = await ComplianceVault.deploy();
  await complianceVault.waitForDeployment();
  deployed.ComplianceVault = await complianceVault.getAddress();
  console.log(`      ComplianceVault: ${deployed.ComplianceVault}`);

  // --- 6. CrossChainRelay ---
  console.log("6/6 Deploying CrossChainRelay (UUPS proxy)...");
  const CrossChainRelay = await ethers.getContractFactory("CrossChainRelay");
  const crossChainRelay = await upgrades.deployProxy(
    CrossChainRelay,
    [addrs.ccipRouter, deployed.SentinelActions, deployed.RaizoCore],
    { kind: "uups" }
  );
  await crossChainRelay.waitForDeployment();
  deployed.CrossChainRelay = await crossChainRelay.getAddress();
  console.log(`      CrossChainRelay: ${deployed.CrossChainRelay}`);

  // --- Write Output ---
  const output = {
    network,
    chainId: Number(chainId),
    deployer: deployer.address,
    deployedAt: new Date().toISOString(),
    contracts: deployed,
  };

  const outDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

  const outFile = path.join(outDir, `${network}-${Date.now()}.json`);
  fs.writeFileSync(outFile, JSON.stringify(output, null, 2));

  console.log(`\nDeployment manifest: ${outFile}`);
  console.log("\n--- Deployed Addresses ---");
  for (const [name, addr] of Object.entries(deployed)) {
    console.log(`  ${name}: ${addr}`);
  }
  console.log("");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
