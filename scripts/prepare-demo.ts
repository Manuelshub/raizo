import { ethers } from "hardhat";
import { keccak256, toUtf8Bytes, ZeroAddress } from "ethers";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log(`\n--- Preparing Raizo Demo on Sepolia ---`);
  console.log(`Deployer: ${deployer.address}\n`);

  // --- 1. Deployed Addresses (from manifest) ---
  const coreAddr = "0xc52009177331A66ee06d2cC11E51D885Fcb67cBe";
  const sentinelAddr = "0x6721e1C5D038880C64d2AEf073eF146f9Ae71C3e";
  const govGateAddr = "0xf472ae388224674d0068776841eF466484b04E0C";
  const vaultAddr = "0x70fa099b0b667EE5F01E992D48855d804C8F92b0";
  const cacheAddr = "0x3c9CB117F781a97A41f046D7E793e43B2D39EBaC";
  const consumerAddr = "0xCfD3071B32C3aBf8EbaADA62C9671e8598B3bB9B";

  const core = await ethers.getContractAt("RaizoCore", coreAddr);
  const govGate = await ethers.getContractAt("GovernanceGate", govGateAddr);
  const cache = await ethers.getContractAt("TelemetryCache", cacheAddr);
  const vault = await ethers.getContractAt("ComplianceVault", vaultAddr);

  // --- 2. Fix Protocols ---
  console.log("Step 1: Cleaning up stale protocols...");
  const oldProtocols = [
    "0x6Ae43d3271ff6888e7Fc43Fd7321a503ff738951",
    "0x0227628f3F023bb0B980b67D528571c95c6DaC1c"
  ];

  for (const addr of oldProtocols) {
    try {
      const tx = await core.deregisterProtocol(addr);
      await tx.wait();
      console.log(`   Deregistered ${addr}`);
    } catch (_) {}
  }

  console.log("\nStep 2: Registering valid Sepolia protocols (Aave, GHO, USDC)...");
  const sepoliaChainId = 11155111;
  const newProtocols = [
    { addr: "0x94a9D9AC8a22534E3FaCa9F4e7F2E2cf85d5E4C8", tier: 3 }, // Aave
    { addr: "0x3e3FE7dBc6B4C189E7128855dD526361c49b40Af", tier: 2 }, // GHO
    { addr: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", tier: 1 }  // USDC
  ];

  for (const p of newProtocols) {
    try {
      const config = await core.getProtocol(p.addr);
      if (config.isActive) {
        console.log(`   ${p.addr} already registered (Tier ${config.riskTier})`);
        continue;
      }
      const tx = await core.registerProtocol(p.addr, sepoliaChainId, p.tier);
      await tx.wait();
      console.log(`   Registered ${p.addr} (Tier ${p.tier})`);
    } catch (e: any) {
      console.warn(`   Failed to check/register ${p.addr}: ${e.message.slice(0, 100)}...`);
    }
  }

  // --- 3. Register Agents ---
  console.log("\nStep 3: Registering Agents in RaizoCore...");
  const agents = [
    { id: keccak256(toUtf8Bytes("raizo-threat-sentinel-v1")), name: "Threat Sentinel" },
    { id: "0x1111111111111111111111111111111111111111111111111111111111111111", name: "Compliance Reporter" },
    { id: keccak256(toUtf8Bytes("gov-bridge")), name: "World ID Bridge" }
  ];

  for (const agent of agents) {
    try {
      const config = await core.getAgent(agent.id);
      if (config.isActive) {
        console.log(`   Agent ${agent.name} already active.`);
        continue;
      }
      // agentId, paymentWallet, dailyBudget (500 USDC), actionBudget (10)
      const tx = await core.registerAgent(agent.id, deployer.address, 500_000_000n, 10n);
      await tx.wait();
      console.log(`   Registered Agent: ${agent.name} (${agent.id.slice(0, 10)}...)`);
    } catch (e: any) {
      console.warn(`   Failed to check/register ${agent.name}: ${e.message.slice(0, 100)}...`);
    }
  }

  // --- 4. Additional Roles ---
  console.log("\nStep 4: Granting RECORDER_ROLE on TelemetryCache...");
  const RECORDER_ROLE = keccak256(toUtf8Bytes("RECORDER_ROLE"));
  try {
      const tx = await cache.grantRole(RECORDER_ROLE, consumerAddr);
      await tx.wait();
      console.log("   RECORDER_ROLE granted to RaizoConsumer.");
  } catch(e: any) {
      console.log("   Already granted or failed: " + e.message);
  }

  // --- 5. Seed World ID Proof Request ---
  console.log("\nStep 5: Seeding World ID Proof Request in GovernanceGate...");
  try {
      const mockIdkitResponse = toUtf8Bytes(JSON.stringify({
          protocol_version: "4.0",
          nonce: "0x" + keccak256(toUtf8Bytes("demo-nonce-2026")).slice(2),
          action: "vote",
          environment: "staging",
          responses: [
            {
               identifier: "app_demo_raizo_sentinel",
               issuer_schema_id: 1, // wid-v1-orb
               nullifier: "0x2222222222222222222222222222222222222222222222222222222222222222",
               expires_at_min: Math.floor(Date.now() / 1000) + 3600,
               proof: [
                 "0x3333333333333333333333333333333333333333333333333333333333333331",
                 "0x3333333333333333333333333333333333333333333333333333333333333332",
                 "0x3333333333333333333333333333333333333333333333333333333333333333",
                 "0x3333333333333333333333333333333333333333333333333333333333333334",
                 "0x1111111111111111111111111111111111111111111111111111111111111111" // 5th is Merkle Root
               ]
            }
          ]
      }));
      const descHash = keccak256(toUtf8Bytes("Demo Proposal: Increase Risk Threshold"));
      
      const tx = await govGate.submitProofRequest(mockIdkitResponse, descHash);
      await tx.wait();
      console.log("   Seed proof request submitted successfully.");
  } catch (e: any) {
      console.warn("   Failed to seed proof request: " + e.message);
  }

  console.log(`\n--- Preparation Complete. Demo Ready! ---\n`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
