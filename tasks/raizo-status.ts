import { task } from "hardhat/config";
import { HardhatRuntimeEnvironment } from "hardhat/types";

task("raizo-status", "Prints the current status of all registered protocols")
  .addOptionalParam(
    "core",
    "RaizoCore address",
    "0x85EC882f1cE7F310Ce6D12379B505d7589b34Ac3",
  )
  .addOptionalParam(
    "sentinel",
    "SentinelActions address",
    "0x7832c3Cdea8EAD7206BfE54e3B24679C2975d787",
  )
  .addOptionalParam(
    "vault",
    "ComplianceVault address",
    "0x92B10171c849f3b9DBE355658eFE7E84084E42B9",
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
