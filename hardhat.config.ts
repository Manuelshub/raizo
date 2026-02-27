import * as dotenv from "dotenv";
dotenv.config();

// Tenderly plugin reads these variables directly from process.env at import time.
// We disable them during tests to avoid destructive contract wrapping and fatal FetchErrors (update checks).
if (process.argv.includes("test")) {
  process.env.TENDERLY_AUTOMATIC_VERIFICATION = "false";
  process.env.TENDERLY_ENABLE_OUTDATED_VERSION_CHECK = "false";
}

import "@openzeppelin/hardhat-upgrades";
import "@nomicfoundation/hardhat-toolbox";
import "@tenderly/hardhat-tenderly";

import { HardhatUserConfig } from "hardhat/types/config";

const { TENDERLY_PRIVATE_VERIFICATION, TENDERLY_AUTOMATIC_VERIFICATION } =
  process.env;

const privateVerification = TENDERLY_PRIVATE_VERIFICATION === "true";
const automaticVerifications = TENDERLY_AUTOMATIC_VERIFICATION === "true";

console.log("Using private verification?", privateVerification);
console.log("Using automatic verification?", automaticVerifications);
console.log(
  "Using automatic population of hardhat-verify `etherscan` configuration? ",
  process.env.TENDERLY_AUTOMATIC_POPULATE_HARDHAT_VERIFY_CONFIG === "true",
);

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.23",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      viaIR: true,
    },
  },
  networks: {
    virtualSepolia: {
      url: `${process.env.TENDERLY_TESTNET_RPC_URL ?? ""}`,
      accounts: [process.env.DEPLOYER_PRIVATE_KEY ?? ""],
    },
    sepolia: {
      url: `${process.env.SEPOLIA_RPC_URL ?? ""}`,
      accounts: [process.env.SEPOLIA_PRIVATE_KEY ?? ""],
    },
  },
  tenderly: {
    project: process.env.TENDERLY_PROJECT ?? "",
    username: process.env.TENDERLY_USERNAME ?? "",
    privateVerification,
    automaticVerifications,
  },
};

// eslint-disable-next-line import/no-default-export
export default config;
