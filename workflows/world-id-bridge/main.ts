import {
  CronCapability,
  HTTPClient,
  EVMClient,
  handler,
  Runner,
  type Runtime,
  type NodeRuntime,
  getNetwork,
  LATEST_BLOCK_NUMBER,
  encodeCallMsg,
  bytesToHex,
  hexToBase64,
  json,
  ok,
  ConsensusAggregationByFields,
  identical,
} from "@chainlink/cre-sdk";
import {
  keccak256,
  encodeFunctionData,
  decodeFunctionResult,
  encodeAbiParameters,
  parseAbiParameters,
  stringToHex,
} from "viem";


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
  operatorAddress: `0x${string}`;
};

interface WorldIDVerifyResponse {
  success: boolean;
  code?: string;
  detail?: string;
  results?: Array<{
    identifier: string;
    success: boolean;
    nullifier?: string;
    code?: string;
    detail?: string;
  }>;
}


const GOVERNANCE_GATE_ABI = [
  {
    inputs: [],
    name: "pendingRequestCount",
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [{ name: "requestId", type: "uint256" }],
    name: "getPendingRequest",
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "requester", type: "address" },
          { name: "descriptionHash", type: "bytes32" },
          { name: "idkitResponse", type: "bytes" },
          { name: "processed", type: "bool" },
          { name: "submittedBlock", type: "uint256" },
        ],
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "proposalCount",
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
    type: "function",
  },
] as const;


const submitPaymentReport = (
  runtime: Runtime<Config>,
  agentIdHex: `0x${string}`,
  amount: bigint,
) => {
  const { operatorAddress } = runtime.config;
  const nonce = keccak256(agentIdHex);
  runtime.log(
    `[x402] Authorizing ${amount} to ${operatorAddress} (nonce: ${nonce.slice(
      0,
      10,
    )}...)`,
  );
};


const hexToUtf8 = (hex: string): string => {
  let s = hex.startsWith("0x") ? hex.slice(2) : hex;
  let str = "";
  for (let i = 0; i < s.length; i += 2) {
    str += String.fromCharCode(parseInt(s.substr(i, 2), 16));
  }
  return str;
};

const performVerification = (
  nodeRuntime: NodeRuntime<Config>,
  idkitResponseHex: string,
): { verified: boolean; nullifierHash: string } => {
  const { rpId, worldIdApiUrl } = nodeRuntime.config;
  const http = new HTTPClient();

  // Construct URL: POST /api/v4/verify/{rp_id}
  const verifyUrl = `${worldIdApiUrl}/${rpId}`;

  // 1. Decode the IDKit response from hex (stored on-chain as bytes)
  // Transparent Relay: We forward the JSON exactly as it was stored.
  let idkitJson: string;
  try {
    idkitJson = hexToUtf8(idkitResponseHex);
    nodeRuntime.log(`[WorldID] Relaying IDKit Response: ${idkitJson}`);
  } catch (err) {
    nodeRuntime.log(`[WorldID] Failed to decode hex to UTF8: ${err}`);
    return {
      verified: false,
      nullifierHash: "0x0",
    };
  }

  nodeRuntime.log(`[WorldID] Endpoint: ${verifyUrl}`);

  try {
    // 2. Forward the payload AS-IS
    const response = http
      .sendRequest(nodeRuntime, {
        url: verifyUrl,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: hexToBase64(stringToHex(idkitJson)),
      })
      .result();

    if (!ok(response)) {
      const statusCode = (response as any).statusCode;
      const errorBody = json(response);
      nodeRuntime.log(`[WorldID] API returned non-OK status: ${statusCode}. Body: ${JSON.stringify(errorBody)}`);
      return {
        verified: false,
        nullifierHash: "0x0",
      };
    }

    // 3. Extract the nullifier from the API response for DON consensus
    const parsed = json(response) as unknown as WorldIDVerifyResponse;
    if (parsed.success && parsed.results && parsed.results.length > 0) {
      const result = parsed.results[0];
      if (result.success) {
          const nullifier = result.nullifier || "0x0";
          nodeRuntime.log(`[WorldID] Verified! Nullifier: ${nullifier.slice(0, 18)}...`);
          return { verified: true, nullifierHash: nullifier };
      } else {
          nodeRuntime.log(`[WorldID] Result failed: ${result.code} - ${result.detail}`);
          return { verified: false, nullifierHash: "0x0" };
      }
    } else {
      nodeRuntime.log(`[WorldID] Request failed: ${parsed.code} - ${parsed.detail}`);
      return { verified: false, nullifierHash: "0x0" };
    }
  } catch (err) {
    nodeRuntime.log(`[WorldID] Error during relay: ${err}`);
    return { verified: false, nullifierHash: "0x0" };
  }
};


const onCronTrigger = async (runtime: Runtime<Config>) => {
  const {
    consumerAddress,
    governanceGateAddress,
    chainName,
    isTestnet,
    gasLimit,
  } = runtime.config;

  runtime.log(`=== Raizo World ID Bridge: Cycle Start (${chainName}) ===`);

  const network = getNetwork({
    chainFamily: "evm",
    chainSelectorName: chainName,
    isTestnet,
  });
  if (!network) throw new Error(`Unknown chain: ${chainName}`);

  const evmClient = new EVMClient(network.chainSelector.selector);

  // 1. Read pending request count from GovernanceGate
  let pendingCount = 0n;
  try {
    const reply = evmClient
      .callContract(runtime, {
        call: encodeCallMsg({
          from: "0x0000000000000000000000000000000000000000",
          to: governanceGateAddress,
          data: encodeFunctionData({
            abi: GOVERNANCE_GATE_ABI,
            functionName: "pendingRequestCount",
          }),
        }),
        blockNumber: LATEST_BLOCK_NUMBER,
      })
      .result();

    pendingCount = decodeFunctionResult({
      abi: GOVERNANCE_GATE_ABI,
      functionName: "pendingRequestCount",
      data: bytesToHex(reply.data) as `0x${string}`,
    }) as bigint;
    runtime.log(`[State] Total pending requests found: ${pendingCount}`);
  } catch (err) {
    runtime.log(`[State] Error reading pendingRequestCount: ${err}`);
  }

  if (pendingCount === 0n) {
    runtime.log("=== Raizo Threat Sentinel: Scan complete ===");
    return "Success";
  }

  // 2. Scan for the most recent unprocessed request (iterate backwards)
  let targetRequestId = -1n;
  let idkitResponseHex = "";
  let requesterAddress = "";
  let descriptionHash = "";

  for (let i = pendingCount - 1n; i >= 0n; i--) {
    try {
      const reqReply = evmClient
        .callContract(runtime, {
          call: encodeCallMsg({
            from: "0x0000000000000000000000000000000000000000",
            to: governanceGateAddress,
            data: encodeFunctionData({
              abi: GOVERNANCE_GATE_ABI,
              functionName: "getPendingRequest",
              args: [i],
            }),
          }),
          blockNumber: LATEST_BLOCK_NUMBER,
        })
        .result();

      const decoded = decodeFunctionResult({
        abi: GOVERNANCE_GATE_ABI,
        functionName: "getPendingRequest",
        data: bytesToHex(reqReply.data) as `0x${string}`,
      }) as any;

      const request = decoded;
      if (!request.processed) {
        targetRequestId = i;
        idkitResponseHex = request.idkitResponse;
        requesterAddress = request.requester;
        descriptionHash = request.descriptionHash;
        break;
      }
    } catch (err) {
      runtime.log(`[State] Error reading request ${i}: ${err}`);
    }
  }

  if (targetRequestId < 0n) {
    runtime.log("[Raizo] All requests already processed. Cycle complete.");
    return "AllProcessed";
  }

  runtime.log(
    `[WorldID] Processing request #${targetRequestId} from ${requesterAddress}`,
  );

  // 3. Proof Verification (DON Consensus)
  const result = runtime
    .runInNodeMode(
      performVerification,
      ConsensusAggregationByFields<{
        verified: boolean;
        nullifierHash: string;
      }>({
        verified: identical,
        nullifierHash: identical,
      }),
    )(idkitResponseHex)
    .result() as { verified: boolean; nullifierHash: string };

  if (!result.verified) {
    runtime.log(
      `[Raizo] Request #${targetRequestId} failed: World ID verification rejected.`,
    );
    return "Rejected";
  }

  runtime.log(
    `[WorldID] Verified! Nullifier: ${result.nullifierHash.slice(0, 18)}...`,
  );

  // 4. x402 Internal Settlement
  submitPaymentReport(
    runtime,
    keccak256(stringToHex("gov-bridge")),
    3_000_000n,
  );

  // 5. Submit attested governance action on-chain
  const govData = encodeAbiParameters(
    parseAbiParameters(
      "uint8 actionType, bytes32 descriptionHash, uint256 proposalId, bool support, uint256 nullifierHash, address actor",
    ),
    [
      0, // actionType: propose
      descriptionHash as `0x${string}`,
      0n, // proposalId (not applicable for propose)
      true,
      BigInt(result.nullifierHash),
      requesterAddress as `0x${string}`,
    ],
  );

  const reportPayload = encodeAbiParameters(
    parseAbiParameters("uint8 reportType, bytes data"),
    [3, govData], // 3 = REPORT_TYPE_GOVERNANCE
  );

  const signedReport = runtime
    .report({
      encodedPayload: hexToBase64(reportPayload),
      encoderName: "evm",
      signingAlgo: "ecdsa",
      hashingAlgo: "keccak256",
    })
    .result();

  const writeResult = evmClient
    .writeReport(runtime, {
      receiver: consumerAddress,
      report: signedReport,
      gasConfig: { gasLimit: gasLimit },
    })
    .result();

  runtime.log(
    `=== Raizo World ID Bridge: Request #${targetRequestId} Complete. TX: ${bytesToHex(
      writeResult.txHash || new Uint8Array(32),
    )} ===`,
  );

  return "Success";
};


const initWorkflow = (config: Config) => {
  const cron = new CronCapability();
  return [handler(cron.trigger({ schedule: config.schedule }), onCronTrigger)];
};

export async function main() {
  const runner = await Runner.newRunner<Config>();
  await runner.run(initWorkflow);
}
