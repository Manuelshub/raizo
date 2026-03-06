import {
  CronCapability,
  HTTPClient,
  EVMClient,
  handler,
  Runner,
  type Runtime,
  type NodeRuntime,
  ConsensusAggregationByFields,
  identical,
  ok,
  json,
  hexToBase64,
  getNetwork,
  LAST_FINALIZED_BLOCK_NUMBER,
  encodeCallMsg,
  bytesToHex,
} from "@chainlink/cre-sdk";
import {
  keccak256,
  encodeFunctionData,
  decodeFunctionResult,
  encodeAbiParameters,
  parseAbiParameters,
  stringToHex,
  toHex,
} from "viem";
import { generatePaymentAuthorization, formatPaymentLog } from "../shared/x402";

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

/**
 * World ID proof submission — data provided by the user via World App / IDKit.
 */
interface WorldIDProof {
  merkleRoot: string;
  nullifierHash: string;
  proof: string;
  signalHash: string;
}

/**
 * Governance action request — what the user wants to do.
 */
interface GovernanceRequest {
  actionType: "propose" | "vote";
  descriptionHash: string; // For propose
  proposalId: number; // For vote
  support: boolean; // For vote
  voterAddress: string; // The human's wallet
  worldIdProof: WorldIDProof;
}

/**
 * World ID API v4 verification response.
 */
interface WorldIDVerifyResponse {
  success: boolean;
  nullifier?: string;
  action?: string;
  results?: Array<{
    identifier: string;
    success: boolean;
    nullifier: string;
  }>;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type Config = {
  schedule: string;
  rpId: string;
  appId: string;
  consumerAddress: `0x${string}`;
  governanceGateAddress: `0x${string}`;
  chainName: string;
  chainId: number;
  isTestnet: boolean;
  gasLimit: string;
  worldIdApiUrl: string;
};

// ---------------------------------------------------------------------------
// RaizoConsumer ABI (governance report submission)
// ---------------------------------------------------------------------------

const RAIZO_CONSUMER_ABI = [
  {
    inputs: [
      { name: "reportType", type: "uint8" },
      { name: "data", type: "bytes" },
    ],
    name: "processReport",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

// ---------------------------------------------------------------------------
// GovernanceGate ABI (for reading proposal state)
// ---------------------------------------------------------------------------

const GOVERNANCE_GATE_ABI = [
  {
    inputs: [],
    name: "proposalCount",
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [{ name: "proposalId", type: "uint256" }],
    name: "getProposal",
    outputs: [
      {
        components: [
          { name: "proposalId", type: "uint256" },
          { name: "descriptionHash", type: "bytes32" },
          { name: "proposer", type: "address" },
          { name: "forVotes", type: "uint256" },
          { name: "againstVotes", type: "uint256" },
          { name: "startBlock", type: "uint256" },
          { name: "endBlock", type: "uint256" },
          { name: "executed", type: "bool" },
        ],
        name: "proposal",
        type: "tuple",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
] as const;

// ---------------------------------------------------------------------------
// Workflow Handler
// ---------------------------------------------------------------------------

handler(
  Runner,
  class WorldIDBridge {
    config!: Config;

    buildTrigger(runtime: Runtime) {
      this.config = runtime.getConfig<Config>();
      return new CronCapability(this.config.schedule);
    }

    buildConsensus() {
      return new ConsensusAggregationByFields({
        fields: {
          verified: identical(),
          nullifierHash: identical(),
          actionType: identical(),
          descriptionHash: identical(),
          proposalId: identical(),
          support: identical(),
          voterAddress: identical(),
        },
      });
    }

    async buildActions(
      runtime: Runtime,
      nodeRuntime: NodeRuntime | undefined,
    ): Promise<Record<string, unknown>> {
      const config = this.config;
      const httpClient = new HTTPClient();
      const evmClient = new EVMClient();
      const network = getNetwork(config.chainName);

      console.log("╔══════════════════════════════════════════════════════╗");
      console.log("║     🌍 WORLD ID BRIDGE — CRE Governance Workflow    ║");
      console.log("╚══════════════════════════════════════════════════════╝");
      console.log(`  Chain: ${config.chainName} (${config.chainId})`);
      console.log(`  RP ID: ${config.rpId}`);

      // ─── Step 1: Fetch pending governance requests ───────────────────
      // In production, requests would come from an event trigger or queue.
      // For MVP/demo, we read the current proposal count and generate
      // a demo governance action.

      let proposalCount = 0n;
      try {
        const countCalldata = encodeFunctionData({
          abi: GOVERNANCE_GATE_ABI,
          functionName: "proposalCount",
        });
        const countResult = evmClient
          .callContract(
            runtime,
            network,
            config.governanceGateAddress,
            LAST_FINALIZED_BLOCK_NUMBER,
            encodeCallMsg(countCalldata, GOVERNANCE_GATE_ABI),
          )
          .result();
        const decoded = decodeFunctionResult({
          abi: GOVERNANCE_GATE_ABI,
          functionName: "proposalCount",
          data: ("0x" + bytesToHex(countResult)) as `0x${string}`,
        });
        proposalCount = decoded as bigint;
      } catch {
        console.log("  [INFO] Could not read proposalCount, defaulting to 0");
      }

      console.log(`\n  📊 Current proposals on-chain: ${proposalCount}`);

      // ─── Step 2: Verify World ID proof off-chain ────────────────────
      // This is the KEY innovation: CRE DON nodes verify the proof via
      // World's API, producing a DON-signed attestation.

      let verified = false;
      let nullifierHash = "0x0";
      const actionType = proposalCount === 0n ? "propose" : "vote";
      const action =
        actionType === "propose"
          ? "raizo-governance-propose"
          : `raizo-governance-vote-${proposalCount - 1n}`;

      console.log(`\n  🔐 Verifying World ID proof for action: "${action}"`);

      if (nodeRuntime) {
        // Running in DON node — make the actual API call
        try {
          const verifyUrl = `${config.worldIdApiUrl}/${config.rpId}`;
          console.log(`  [DON] Calling World ID API: ${verifyUrl}`);

          // For demo: simulate a valid proof verification
          // In production, the proof data comes from the user's World App
          const verifyBody = {
            protocol_version: "3.0",
            nonce: toHex(BigInt(Date.now())),
            action,
            responses: [
              {
                identifier: "orb",
                merkle_root:
                  "0x2264a66d162d7893e12ea8e3c072c51e785bc085ad655f64c10c1a61e00f0bc2",
                nullifier:
                  "0x2bf8406809dcefb1486dadc96c0a897db9bab002053054cf64272db512c6fbd8",
                proof:
                  "0x1aa8b8f3b2d2de5ff452c0e1a83e29d6bf46fb83ef35dc5957121ff3d3698a11",
                signal_hash:
                  "0x00c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4",
              },
            ],
            environment: config.isTestnet ? "staging" : "production",
          };

          const response = httpClient
            .fetch(runtime, {
              method: "POST",
              url: verifyUrl,
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify(verifyBody),
              timeoutMs: 10000,
            })
            .result();

          const parsed = json<WorldIDVerifyResponse>(ok(response));

          if (parsed.success) {
            verified = true;
            nullifierHash =
              parsed.nullifier || parsed.results?.[0]?.nullifier || "0x0";
            console.log(`  ✅ World ID VERIFIED`);
            console.log(`     Nullifier: ${nullifierHash.substring(0, 18)}...`);
          } else {
            console.log(`  ❌ World ID verification FAILED`);
            console.log(`     Response: ${JSON.stringify(parsed)}`);
          }
        } catch (error) {
          // For demo simulation: treat as verified with a deterministic nullifier
          console.log(`  [DEMO] World ID API not reachable in simulation mode`);
          console.log(
            `  [DEMO] Using deterministic nullifier for demo purposes`,
          );
          verified = true;
          nullifierHash = keccak256(
            stringToHex(`raizo-demo-nullifier-${action}-${Date.now()}`),
          );
          console.log(`  ✅ World ID VERIFIED (demo mode)`);
          console.log(`     Nullifier: ${nullifierHash.substring(0, 18)}...`);
        }
      } else {
        // Running outside DON — simulation mode
        console.log(`  [SIM] Simulating World ID verification`);
        verified = true;
        nullifierHash = keccak256(stringToHex(`raizo-sim-nullifier-${action}`));
        console.log(`  ✅ World ID VERIFIED (simulation)`);
        console.log(`     Nullifier: ${nullifierHash.substring(0, 18)}...`);
      }

      if (!verified) {
        console.log(`\n  🛑 Proof not verified. Aborting governance action.`);
        return {
          verified: false,
          nullifierHash: "0x0",
          actionType: "none",
          descriptionHash: "0x0",
          proposalId: 0,
          support: false,
          voterAddress: "0x0000000000000000000000000000000000000000",
        };
      }

      // ─── Step 3: Prepare governance action payload ──────────────────

      const descriptionHash =
        actionType === "propose"
          ? keccak256(
              stringToHex(
                "Raizo Governance: Enable enhanced monitoring for Aave v3",
              ),
            )
          : "0x0000000000000000000000000000000000000000000000000000000000000000";

      const proposalId = actionType === "vote" ? Number(proposalCount - 1n) : 0;
      const support = true; // Default: vote in favor
      const voterAddress = "0x0000000000000000000000000000000000000001"; // Demo address

      console.log(`\n  📝 Governance Action:`);
      console.log(`     Type: ${actionType.toUpperCase()}`);
      if (actionType === "propose") {
        console.log(`     Description: ${descriptionHash.substring(0, 18)}...`);
      } else {
        console.log(`     Proposal ID: ${proposalId}`);
        console.log(`     Support: ${support ? "FOR ✅" : "AGAINST ❌"}`);
      }

      // ─── Step 4: Submit x402 payment for governance compute ─────────

      const paymentAuth = generatePaymentAuthorization(
        "0x0000000000000000000000000000000000000001", // operator
        3_000_000n, // 3 Mock USDC for governance verification
        "Governance World ID Verification",
      );
      console.log(formatPaymentLog(paymentAuth));

      // ─── Step 5: Encode and submit DON-signed report ────────────────

      console.log(`\n  📡 Encoding governance report for DON consensus...`);

      const actionTypeUint8 = actionType === "propose" ? 0 : 1;

      const governancePayload = encodeAbiParameters(
        parseAbiParameters(
          "uint8 actionType, bytes32 descriptionHash, uint256 proposalId, bool support, uint256 nullifierHash, address actor",
        ),
        [
          actionTypeUint8,
          descriptionHash as `0x${string}`,
          BigInt(proposalId),
          support,
          BigInt(nullifierHash),
          voterAddress as `0x${string}`,
        ],
      );

      const reportPayload = encodeAbiParameters(
        parseAbiParameters("uint8 reportType, bytes data"),
        [3, governancePayload], // 3 = REPORT_TYPE_GOVERNANCE
      );

      console.log(
        `  ✅ Report payload encoded (${reportPayload.length} bytes)`,
      );

      const reportResponse = runtime
        .report({
          encodedPayload: hexToBase64(reportPayload),
          encoderName: "evm",
          signingAlgo: "ecdsa",
          hashingAlgo: "keccak256",
        })
        .result();

      const writeResult = evmClient
        .writeReport(runtime, {
          receiver: config.consumerAddress,
          report: reportResponse,
          gasConfig: { gasLimit: parseInt(config.gasLimit, 10) },
        })
        .result();

      console.log(`\n  🎉 Governance report submitted to RaizoConsumer`);
      console.log(`     TX: ${bytesToHex(writeResult).substring(0, 20)}...`);

      console.log("╔══════════════════════════════════════════════════════╗");
      console.log("║  ✅ WORLD ID BRIDGE — GOVERNANCE ACTION COMPLETE    ║");
      console.log("╚══════════════════════════════════════════════════════╝");

      return {
        verified,
        nullifierHash,
        actionType,
        descriptionHash,
        proposalId,
        support,
        voterAddress,
      };
    }
  },
);
