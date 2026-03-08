import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import { RaizoCore } from "../typechain-types";

/**
 * Raizo Protocol Registration Script
 * 
 * Usage:
 * npx hardhat run scripts/registerProtocols.ts -- --network sepolia \
 *   --protocol 0x1234...abcd --chain-id 11155111 --risk-tier 4 \
 *   --protocol 0x5678...efgh --chain-id 137 --risk-tier 3 \
 *   --agent agentId:0xabcd...1234:1000000:100
 * 
 * Agent format: agentId:paymentWallet:dailyBudgetUSDC:actionBudgetPerEpoch
 * 
 * Risk Tiers:
 * 1 = Low (Basic monitoring)
 * 2 = Medium (Enhanced monitoring) 
 * 3 = High (Aggressive rate limiting)
 * 4 = Critical (Immediate circuit breaker)
 */

interface ProtocolRegistration {
  address: string;
  chainId: bigint;
  riskTier: number;
}

interface AgentRegistration {
  agentId: string;
  paymentWallet: string;
  dailyBudgetUSDC: string;
  actionBudgetPerEpoch: string;
}

// Chain ID mappings for uint16 compatibility
// Note: Contract uses uint16, so we can't use full chain IDs or CCIP selectors
// Using simplified IDs that fit in uint16 (0-65535)
const CHAIN_ID_MAPPING: Record<string, number> = {
  '11155111': 11155,  // Sepolia Testnet → Use 11155 (last 5 digits, fits uint16)
  '137': 137,         // Polygon Mainnet
  '1': 1,             // Ethereum Mainnet
  '8453': 8453,       // Base Mainnet
  '42161': 42161,     // Arbitrum Mainnet
  '10': 10,           // Optimism Mainnet
} as const;

function parseArguments(): {
  deploymentFile: string;
  protocols: ProtocolRegistration[];
  agents: AgentRegistration[];
} {
  // Use environment variables and remaining arguments
  // Hardhat doesn't support custom CLI parameters, so we use ENV vars + positional args
  const deploymentFile = process.env.DEPLOYMENT_FILE || "";
  const protocolArgs = process.env.PROTOCOLS || "";
  const agentArgs = process.env.AGENTS || "";

  const protocols: ProtocolRegistration[] = [];
  const agents: AgentRegistration[] = [];

  // Parse protocols from ENV: "addr1:chain1:tier1,addr2:chain2:tier2"
  if (protocolArgs) {
    const protocolList = protocolArgs.split(',');
    for (const protocol of protocolList) {
      const [address, chainId, riskTier] = protocol.split(':');
      if (address && chainId && riskTier) {
        protocols.push({
          address: address.trim(),
          chainId: BigInt(chainId.trim().replace('n', '')),
          riskTier: parseInt(riskTier.trim()),
        });
      }
    }
  }

  // Parse agents from ENV: "id1:wallet1:budget1:actionBudget1,id2:wallet2:budget2:actionBudget2"
  if (agentArgs) {
    const agentList = agentArgs.split(',');
    for (const agent of agentList) {
      const [agentId, wallet, budget, actionBudget] = agent.split(':');
      if (agentId && wallet && budget && actionBudget) {
        agents.push({
          agentId: agentId.trim(),
          paymentWallet: wallet.trim(),
          dailyBudgetUSDC: budget.trim(),
          actionBudgetPerEpoch: actionBudget.trim(),
        });
      }
    }
  }

  // Auto-detect deployment file if not provided
  let finalDeploymentFile = deploymentFile;
  if (!finalDeploymentFile) {
    const deploymentsDir = path.join(__dirname, "..", "deployments");
    if (!fs.existsSync(deploymentsDir)) {
      throw new Error("No deployments directory found and no deployment file specified");
    }
    
    const files = fs.readdirSync(deploymentsDir)
      .filter(f => f.startsWith("sepolia-") && f.endsWith(".json"))
      .sort()
      .reverse();
    
    if (files.length === 0) {
      throw new Error("No Sepolia deployment files found");
    }
    
    finalDeploymentFile = path.join(deploymentsDir, files[0]);
    console.log(`Auto-detected deployment file: ${finalDeploymentFile}`);
  }

  if (protocols.length === 0) {
    throw new Error("At least one protocol must be specified via PROTOCOLS environment variable");
    console.log("Example: PROTOCOLS=\"0x1234...abcd:11155111:4,0x5678...efgh:137:3\"");
  }

  return { deploymentFile: finalDeploymentFile, protocols, agents };
}

function validateProtocolRegistration(registration: ProtocolRegistration): void {
  if (!ethers.isAddress(registration.address)) {
    throw new Error(`Invalid protocol address: ${registration.address}`);
  }
  
  if (!CHAIN_ID_MAPPING[Number(registration.chainId)]) {
    throw new Error(`Unsupported chain ID: ${registration.chainId}. Supported: ${Object.keys(CHAIN_ID_MAPPING).join(", ")}`);
  }
  
  if (registration.riskTier < 1 || registration.riskTier > 4) {
    throw new Error(`Invalid risk tier: ${registration.riskTier}. Must be 1-4`);
  }
}

function validateAgentRegistration(registration: AgentRegistration): void {
  if (!registration.agentId || registration.agentId.length === 0) {
    throw new Error("Agent ID cannot be empty");
  }
  
  if (!ethers.isAddress(registration.paymentWallet)) {
    throw new Error(`Invalid payment wallet address: ${registration.paymentWallet}`);
  }
  
  const budget = BigInt(registration.dailyBudgetUSDC);
  if (budget <= 0n) {
    throw new Error("Daily budget must be greater than 0");
  }
  
  if (budget > 1000000n * 10n ** 6n) { // 1M USDC max
    throw new Error("Daily budget exceeds maximum of 1,000,000 USDC");
  }
  
  const actionBudget = BigInt(registration.actionBudgetPerEpoch);
  if (actionBudget <= 0n) {
    throw new Error("Action budget must be greater than 0");
  }
  
  if (actionBudget > 1000n) { // 1000 actions per epoch max
    throw new Error("Action budget exceeds maximum of 1,000 actions per epoch");
  }
}

async function loadDeployment(deploymentFile: string) {
  if (!fs.existsSync(deploymentFile)) {
    throw new Error(`Deployment file not found: ${deploymentFile}`);
  }
  
  const deployment = JSON.parse(fs.readFileSync(deploymentFile, "utf8"));
  
  if (!deployment.contracts?.RaizoCore) {
    throw new Error("RaizoCore contract not found in deployment file");
  }
  
  return deployment;
}

async function registerProtocols(
  raizoCore: RaizoCore,
  protocols: ProtocolRegistration[]
): Promise<void> {
  console.log("\n=== Registering Protocols ===");
  
  for (const protocol of protocols) {
    validateProtocolRegistration(protocol);
    
    const mappedChainId = CHAIN_ID_MAPPING[String(protocol.chainId)]!;
    
    console.log(`\nRegistering protocol: ${protocol.address}`);
    console.log(`  Chain ID: ${protocol.chainId} → Mapped to: ${mappedChainId} (uint16 compatible)`);
    console.log(`  Risk Tier: ${protocol.riskTier}`);
    
    try {
      const tx = await raizoCore.registerProtocol(
        protocol.address,
        mappedChainId,  // Use mapped chain ID that fits in uint16
        protocol.riskTier
      );
      
      const receipt = await tx.wait();
      
      console.log(`  ✅ Registered successfully`);
      console.log(`  📄 Transaction: ${tx.hash}`);
      console.log(`  ⛽ Gas used: ${receipt?.gasUsed?.toString()}`);
      
      // Verify registration
      const config = await raizoCore.getProtocol(protocol.address);
      console.log(`  🔍 Verified: Active=${config.isActive}, Tier=${config.riskTier}`);
      
    } catch (error: any) {
      if (error.message.includes("ProtocolAlreadyRegistered")) {
        console.log(`  ⚠️  Protocol already registered`);
        
        // Try to update risk tier if different
        const config = await raizoCore.getProtocol(protocol.address);
        if (Number(config.riskTier) !== protocol.riskTier) {
          console.log(`  🔄 Updating risk tier from ${config.riskTier} to ${protocol.riskTier}`);
          const updateTx = await raizoCore.updateRiskTier(protocol.address, protocol.riskTier);
          await updateTx.wait();
          console.log(`  ✅ Risk tier updated`);
        }
      } else {
        console.error(`  ❌ Registration failed: ${error.message}`);
        throw error;
      }
    }
  }
}

async function registerAgents(
  raizoCore: RaizoCore,
  agents: AgentRegistration[]
): Promise<void> {
  if (agents.length === 0) {
    console.log("\n=== No Agents to Register ===");
    return;
  }
  
  console.log("\n=== Registering Agents ===");
  
  for (const agent of agents) {
    validateAgentRegistration(agent);
    
    console.log(`\nRegistering agent: ${agent.agentId}`);
    console.log(`  Payment Wallet: ${agent.paymentWallet}`);
    console.log(`  Daily Budget: ${ethers.formatUnits(agent.dailyBudgetUSDC, 6)} USDC`);
    console.log(`  Action Budget: ${agent.actionBudgetPerEpoch} actions per epoch`);
    
    try {
      const agentIdBytes32 = ethers.keccak256(ethers.toUtf8Bytes(agent.agentId));
      const dailyBudgetUSDC = ethers.parseUnits(agent.dailyBudgetUSDC, 6);
      const actionBudget = BigInt(agent.actionBudgetPerEpoch);
      
      const tx = await raizoCore.registerAgent(
        agentIdBytes32,
        agent.paymentWallet,
        dailyBudgetUSDC,
        actionBudget
      );
      
      const receipt = await tx.wait();
      
      console.log(`  ✅ Agent registered successfully`);
      console.log(`  📄 Transaction: ${tx.hash}`);
      console.log(`  ⛽ Gas used: ${receipt?.gasUsed?.toString()}`);
      
      // Verify registration
      const config = await raizoCore.getAgent(agentIdBytes32);
      console.log(`  🔍 Verified: Active=${config.isActive}, Budget=${ethers.formatUnits(config.dailyBudgetUSDC, 6)} USDC`);
      
    } catch (error: any) {
      if (error.message.includes("AgentAlreadyRegistered")) {
        console.log(`  ⚠️  Agent already registered`);
      } else {
        console.error(`  ❌ Agent registration failed: ${error.message}`);
        throw error;
      }
    }
  }
}

async function displaySystemStatus(raizoCore: RaizoCore): Promise<void> {
  console.log("\n=== System Status ===");
  
  try {
    const protocols = await raizoCore.getAllProtocols();
    console.log(`\n📊 Registered Protocols: ${protocols.length}`);
    
    for (const protocol of protocols) {
      if (protocol.isActive) {
        console.log(`  🛡️  ${protocol.protocolAddress} - Tier ${protocol.riskTier} (Chain: ${protocol.chainId})`);
      }
    }
    
    const confidenceThreshold = await raizoCore.getConfidenceThreshold();
    const epochDuration = await raizoCore.getEpochDuration();
    
    console.log(`\n⚙️  Configuration:`);
    console.log(`  Confidence Threshold: ${Number(confidenceThreshold)} basis points (${Number(confidenceThreshold) / 100}%)`);
    console.log(`  Epoch Duration: ${epochDuration.toString()} seconds (${(Number(epochDuration) / 3600).toFixed(1)} hours)`);
    
  } catch (error: any) {
    console.error(`❌ Failed to fetch system status: ${error.message}`);
  }
}

async function main() {
  try {
    console.log("🚀 Raizo Protocol Registration Script");
    console.log("=====================================");
    
    // Parse command line arguments
    const { deploymentFile, protocols, agents } = parseArguments();
    
    // Load deployment
    const deployment = await loadDeployment(deploymentFile);
    console.log(`📦 Loaded deployment from: ${deploymentFile}`);
    console.log(`🌐 Network: ${deployment.network} (Chain ID: ${deployment.chainId})`);
    console.log(`📋 RaizoCore: ${deployment.contracts.RaizoCore}`);
    
    // Get signer
    const [signer] = await ethers.getSigners();
    console.log(`👤 Signer: ${signer.address}`);
    console.log(`💰 Balance: ${ethers.formatEther(await ethers.provider.getBalance(signer.address))} ETH`);
    
    // Connect to RaizoCore
    const raizoCore = await ethers.getContractAt("RaizoCore", deployment.contracts.RaizoCore) as RaizoCore;
    
    // Check permissions
    const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;
    const GOVERNANCE_ROLE = ethers.keccak256(ethers.toUtf8Bytes("GOVERNANCE_ROLE"));
    
    const isAdmin = await raizoCore.hasRole(DEFAULT_ADMIN_ROLE, signer.address);
    const isGovernance = await raizoCore.hasRole(GOVERNANCE_ROLE, signer.address);
    
    if (!isAdmin && !isGovernance) {
      throw new Error("Signer does not have admin or governance role");
    }
    
    console.log(`🔐 Permissions: Admin=${isAdmin}, Governance=${isGovernance}`);
    
    // Register protocols
    await registerProtocols(raizoCore, protocols);
    
    // Register agents
    await registerAgents(raizoCore, agents);
    
    // Display final status
    await displaySystemStatus(raizoCore);
    
    console.log("\n✅ Registration completed successfully!");
    
  } catch (error: any) {
    console.error(`\n❌ Registration failed: ${error.message}`);
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error("Unexpected error:", error);
  process.exitCode = 1;
});
