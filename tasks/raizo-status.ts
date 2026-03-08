import { task } from "hardhat/config";
import { HardhatRuntimeEnvironment } from "hardhat/types";

task("raizo-status", "Prints the current status of all registered protocols")
  .addOptionalParam(
    "core",
    "RaizoCore address",
    "0xc52009177331A66ee06d2cC11E51D885Fcb67cBe",
  )
  .addOptionalParam(
    "sentinel",
    "SentinelActions address",
    "0x6721e1C5D038880C64d2AEf073eF146f9Ae71C3e",
  )
  .addOptionalParam(
    "vault",
    "ComplianceVault address",
    "0x70fa099b0b667EE5F01E992D48855d804C8F92b0",
  )
  .setAction(async (taskArgs, hre: HardhatRuntimeEnvironment) => {
    const { ethers } = hre;

    console.log("\n--- Raizo System Status Report ---");
    console.log(`Core: ${taskArgs.core}`);
    console.log(`Sentinel: ${taskArgs.sentinel}`);
    console.log(`Vault: ${taskArgs.vault}\n`);

    const core = await ethers.getContractAt("RaizoCore", taskArgs.core);
    const sentinel = await ethers.getContractAt(
      "SentinelActions",
      taskArgs.sentinel,
    );
    const vault = await ethers.getContractAt("ComplianceVault", taskArgs.vault);

    // Verify code exists at addresses
    const addresses = [
      { name: "Core", addr: taskArgs.core },
      { name: "Sentinel", addr: taskArgs.sentinel },
      { name: "Vault", addr: taskArgs.vault },
    ];

    for (const { name, addr } of addresses) {
      const code = await ethers.provider.getCode(addr);
      if (code === "0x") {
        console.error(
          `❌ Error: No contract found at ${name} address ${addr} on network ${hre.network.name}.`,
        );
        console.error(`   Ensure you are using the correct --network flag.\n`);
        return;
      }
    }

    try {
      const count = await vault.getReportCount();
      console.log(`Total reports in vault: ${count}`);
    } catch (e: any) {
      console.warn(`Failed to fetch report count: ${e.message}`);
    }

    const protocols = await core.getAllProtocols();

    if (protocols.length === 0) {
      console.log("No protocols registered.");
      return;
    }

    console.log(`Found ${protocols.length} protocols. Fetching details...\n`);

    const tableData = [];

    for (const p of protocols) {
      console.log(
        `Analyzing protocol: ${p.protocolAddress} on chain ${p.chainId}`,
      );

      let isPaused = false;
      let activeActions = [];
      let relayAddress = "0x0";
      try {
        isPaused = await sentinel.isProtocolPaused(p.protocolAddress);
        activeActions = await sentinel.getActiveActions(p.protocolAddress);
        relayAddress = await sentinel.relay();
      } catch (e: any) {
        // Silently fail if relay() is not yet implemented or accessible
      }

      let destSelector = 0n;
      try {
        destSelector = await core.getRelayChain(p.chainId);
      } catch (e: any) {
        // Core might be older version without getRelayChain
      }

      let latestReport = null;
      try {
        // Try getting reports for the protocol's chain
        let reports = await vault.getReportsByChain(p.chainId);

        // If empty and p.chainId is 1, try probing for Sepolia explicitly
        if (reports.length === 0 && p.chainId === 1n) {
          reports = await vault.getReportsByChain(11155111);
        }

        latestReport = reports.length > 0 ? reports[reports.length - 1] : null;
      } catch (e: any) {
        // Vault error
      }

      tableData.push({
        Address: p.protocolAddress,
        Chain: p.chainId.toString(),
        Tier: p.riskTier.toString(),
        Status: isPaused ? "⚠️ PAUSED" : "✅ ACTIVE",
        Threats: activeActions.length.toString(),
        "Cross-Chain":
          destSelector !== 0n ? `Mapped (${destSelector})` : "Local Only",
        Relay:
          relayAddress !== "0x0000000000000000000000000000000000000000"
            ? "Configured"
            : "None",
        Compliance: latestReport ? "Anchored" : "Pending",
      });
    }

    console.table(tableData);
    console.log("\n--- End of Report ---\n");
  });
