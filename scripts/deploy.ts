/**
 * @file scripts/deploy.ts
 * @description Production deployment script for all Raizo contracts.
 *
 * Deployment order (dependency graph):
 *   1. RaizoCore (no deps)
 *   2. MockUSDC / MockWorldID / MockCCIPRouter (test environments only)
 *   3. SentinelActions (needs RaizoCore)
 *   4. PaymentEscrow (needs RaizoCore + USDC)
 *   5. GovernanceGate (needs WorldID)
 *   6. CrossChainRelay (needs CCIPRouter + SentinelActions + RaizoCore)
 *   7. ComplianceVault (immutable, no deps)
 *   8. TimelockUpgradeController (needs admin + proposer + executor addresses)
 *
 * Post-deployment configuration:
 *   - Grant GOVERNANCE_ROLE on RaizoCore to GovernanceGate
 *   - Grant ANCHOR_ROLE on ComplianceVault to the DON agent address
 *   - Grant EMERGENCY_ROLE on SentinelActions to multi-sig
 *   - Set CrossChainRelay on SentinelActions
 *
 * Supports: local hardhat, Sepolia, Base Sepolia, mainnet, Base mainnet
 */

import { ethers, upgrades, network } from "hardhat";

// ── Network Configuration ──
interface NetworkConfig {
  ccipRouter: string;
  usdc: string;
  worldId: string;
  multisig: string;
  deployMocks: boolean;
}

const NETWORK_CONFIGS: Record<string, NetworkConfig> = {
  hardhat: {
    ccipRouter: "",
    usdc: "",
    worldId: "",
    multisig: "",
    deployMocks: true,
  },
  localhost: {
    ccipRouter: "",
    usdc: "",
    worldId: "",
    multisig: "",
    deployMocks: true,
  },
  sepolia: {
    ccipRouter: "0x0BF3dE8c5D3e8A2B34D2BEeB17ABfCeBaf363A59",
    usdc: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
    worldId: "0x469449f251692E0779667583026b5A1E99512157",
    multisig: "",
    deployMocks: false,
  },
  baseSepolia: {
    ccipRouter: "0xD3b06cEbF099CE7DA4AcCf578aaebFDBd6e88a93",
    usdc: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    worldId: "0x42FF98C4E85212a5D31358ACbFe76a621b50fC02",
    multisig: "",
    deployMocks: false,
  },
};

// ── Deployment Result ──
export interface DeploymentResult {
  raizoCore: string;
  sentinelActions: string;
  paymentEscrow: string;
  governanceGate: string;
  crossChainRelay: string;
  complianceVault: string;
  timelockController: string;
  mockUSDC?: string;
  mockWorldID?: string;
  mockCCIPRouter?: string;
}

/**
 * Deploy all Raizo contracts in dependency order.
 */
export async function deployAll(): Promise<DeploymentResult> {
  const [deployer] = await ethers.getSigners();
  const networkName = network.name;
  const config = NETWORK_CONFIGS[networkName] || NETWORK_CONFIGS.hardhat;

  console.log(`\n🚀 Deploying Raizo to ${networkName}`);
  console.log(`   Deployer: ${deployer.address}\n`);

  const result: Partial<DeploymentResult> = {};

  // ── Step 1: Deploy mocks (test environments only) ──
  let usdcAddress = config.usdc;
  let worldIdAddress = config.worldId;
  let ccipRouterAddress = config.ccipRouter;

  if (config.deployMocks) {
    console.log("📦 Deploying mock contracts...");

    const MockUSDC = await ethers.getContractFactory("MockUSDC");
    const mockUsdc = await MockUSDC.deploy();
    await mockUsdc.waitForDeployment();
    usdcAddress = await mockUsdc.getAddress();
    result.mockUSDC = usdcAddress;
    console.log(`   MockUSDC:       ${usdcAddress}`);

    const MockWorldID = await ethers.getContractFactory("MockWorldID");
    const mockWorldId = await MockWorldID.deploy();
    await mockWorldId.waitForDeployment();
    worldIdAddress = await mockWorldId.getAddress();
    result.mockWorldID = worldIdAddress;
    console.log(`   MockWorldID:    ${worldIdAddress}`);

    const MockCCIPRouter = await ethers.getContractFactory("MockCCIPRouter");
    const mockRouter = await MockCCIPRouter.deploy();
    await mockRouter.waitForDeployment();
    ccipRouterAddress = await mockRouter.getAddress();
    result.mockCCIPRouter = ccipRouterAddress;
    console.log(`   MockCCIPRouter: ${ccipRouterAddress}`);
  }

  // ── Step 2: Deploy RaizoCore (UUPS proxy) ──
  console.log("\n🏗️  Deploying core contracts...");

  const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
  const raizoCore = await upgrades.deployProxy(RaizoCoreFactory, [], {
    initializer: "initialize",
    kind: "uups",
  });
  await raizoCore.waitForDeployment();
  const raizoCoreAddress = await raizoCore.getAddress();
  result.raizoCore = raizoCoreAddress;
  console.log(`   RaizoCore:          ${raizoCoreAddress}`);

  // ── Step 3: Deploy SentinelActions (UUPS proxy) ──
  const SentinelActionsFactory =
    await ethers.getContractFactory("SentinelActions");
  const sentinelActions = await upgrades.deployProxy(
    SentinelActionsFactory,
    [raizoCoreAddress],
    {
      initializer: "initialize",
      kind: "uups",
    },
  );
  await sentinelActions.waitForDeployment();
  const sentinelActionsAddress = await sentinelActions.getAddress();
  result.sentinelActions = sentinelActionsAddress;
  console.log(`   SentinelActions:    ${sentinelActionsAddress}`);

  // ── Step 4: Deploy PaymentEscrow (UUPS proxy) ──
  const PaymentEscrowFactory =
    await ethers.getContractFactory("PaymentEscrow");
  const paymentEscrow = await upgrades.deployProxy(
    PaymentEscrowFactory,
    [raizoCoreAddress, usdcAddress],
    {
      initializer: "initialize",
      kind: "uups",
    },
  );
  await paymentEscrow.waitForDeployment();
  const paymentEscrowAddress = await paymentEscrow.getAddress();
  result.paymentEscrow = paymentEscrowAddress;
  console.log(`   PaymentEscrow:      ${paymentEscrowAddress}`);

  // ── Step 5: Deploy GovernanceGate (UUPS proxy) ──
  const GovernanceGateFactory =
    await ethers.getContractFactory("GovernanceGate");
  const governanceGate = await upgrades.deployProxy(
    GovernanceGateFactory,
    [worldIdAddress],
    {
      initializer: "initialize",
      kind: "uups",
    },
  );
  await governanceGate.waitForDeployment();
  const governanceGateAddress = await governanceGate.getAddress();
  result.governanceGate = governanceGateAddress;
  console.log(`   GovernanceGate:     ${governanceGateAddress}`);

  // ── Step 6: Deploy CrossChainRelay (UUPS proxy) ──
  const CrossChainRelayFactory =
    await ethers.getContractFactory("CrossChainRelay");
  const crossChainRelay = await upgrades.deployProxy(
    CrossChainRelayFactory,
    [ccipRouterAddress, sentinelActionsAddress, raizoCoreAddress],
    {
      initializer: "initialize",
      kind: "uups",
    },
  );
  await crossChainRelay.waitForDeployment();
  const crossChainRelayAddress = await crossChainRelay.getAddress();
  result.crossChainRelay = crossChainRelayAddress;
  console.log(`   CrossChainRelay:    ${crossChainRelayAddress}`);

  // ── Step 7: Deploy ComplianceVault (immutable, no proxy) ──
  const ComplianceVaultFactory =
    await ethers.getContractFactory("ComplianceVault");
  const complianceVault = await ComplianceVaultFactory.deploy();
  await complianceVault.waitForDeployment();
  const complianceVaultAddress = await complianceVault.getAddress();
  result.complianceVault = complianceVaultAddress;
  console.log(`   ComplianceVault:    ${complianceVaultAddress}`);

  // ── Step 8: Deploy TimelockUpgradeController (immutable) ──
  const TimelockFactory = await ethers.getContractFactory(
    "TimelockUpgradeController",
  );
  const multisigAddr = config.multisig || deployer.address;
  const timelockController = await TimelockFactory.deploy(
    multisigAddr,
    multisigAddr,
    multisigAddr,
  );
  await timelockController.waitForDeployment();
  const timelockAddress = await timelockController.getAddress();
  result.timelockController = timelockAddress;
  console.log(`   TimelockController: ${timelockAddress}`);

  // ── Step 9: Post-deployment configuration ──
  console.log("\n⚙️  Configuring roles and cross-references...");

  const GOVERNANCE_ROLE = ethers.keccak256(
    ethers.toUtf8Bytes("GOVERNANCE_ROLE"),
  );
  const ANCHOR_ROLE = ethers.keccak256(ethers.toUtf8Bytes("ANCHOR_ROLE"));
  const EMERGENCY_ROLE = ethers.keccak256(
    ethers.toUtf8Bytes("EMERGENCY_ROLE"),
  );

  // Grant GOVERNANCE_ROLE on RaizoCore to GovernanceGate
  await raizoCore.grantRole(GOVERNANCE_ROLE, governanceGateAddress);
  console.log(`   ✅ Granted GOVERNANCE_ROLE on RaizoCore → GovernanceGate`);

  // Grant ANCHOR_ROLE on ComplianceVault to deployer (initial setup)
  await complianceVault.grantRole(ANCHOR_ROLE, deployer.address);
  console.log(`   ✅ Granted ANCHOR_ROLE on ComplianceVault → deployer`);

  // Grant EMERGENCY_ROLE on SentinelActions to multisig
  await sentinelActions.grantRole(EMERGENCY_ROLE, multisigAddr);
  console.log(`   ✅ Granted EMERGENCY_ROLE on SentinelActions → multisig`);

  // Set CrossChainRelay on SentinelActions
  const sentinelWithSetRelay = await ethers.getContractAt(
    "SentinelActions",
    sentinelActionsAddress,
  );
  await sentinelWithSetRelay.setRelay(crossChainRelayAddress);
  console.log(`   ✅ Set CrossChainRelay on SentinelActions`);

  console.log("\n✅ Deployment complete!\n");

  // ── Summary ──
  const fullResult = result as DeploymentResult;
  console.log("┌─────────────────────────────────────────────────────┐");
  console.log("│              RAIZO DEPLOYMENT SUMMARY               │");
  console.log("├─────────────────────────────────────────────────────┤");
  console.log(`│ Network:             ${networkName.padEnd(30)}│`);
  console.log(`│ RaizoCore:           ${raizoCoreAddress.substring(0, 28)}… │`);
  console.log(`│ SentinelActions:     ${sentinelActionsAddress.substring(0, 28)}… │`);
  console.log(`│ PaymentEscrow:       ${paymentEscrowAddress.substring(0, 28)}… │`);
  console.log(`│ GovernanceGate:      ${governanceGateAddress.substring(0, 28)}… │`);
  console.log(`│ CrossChainRelay:     ${crossChainRelayAddress.substring(0, 28)}… │`);
  console.log(`│ ComplianceVault:     ${complianceVaultAddress.substring(0, 28)}… │`);
  console.log(`│ TimelockController:  ${timelockAddress.substring(0, 28)}… │`);
  console.log("└─────────────────────────────────────────────────────┘");

  return fullResult;
}

// Execute when run directly
if (require.main === module) {
  deployAll()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
