/**
 * @file abis/index.ts
 * @notice Typed ABI exports for on-chain writes from CRE workflows.
 * Generated from Hardhat artifacts — re-run `npm run compile` to refresh.
 */

export const sentinelActionsAbi = [
    {
        inputs: [
            {
                components: [
                    { internalType: "bytes32", name: "reportId", type: "bytes32" },
                    { internalType: "bytes32", name: "agentId", type: "bytes32" },
                    { internalType: "bool", name: "exists", type: "bool" },
                    { internalType: "address", name: "targetProtocol", type: "address" },
                    {
                        internalType: "enum ISentinelActions.ActionType",
                        name: "action",
                        type: "uint8",
                    },
                    {
                        internalType: "enum ISentinelActions.Severity",
                        name: "severity",
                        type: "uint8",
                    },
                    {
                        internalType: "uint16",
                        name: "confidenceScore",
                        type: "uint16",
                    },
                    { internalType: "bytes", name: "evidenceHash", type: "bytes" },
                    { internalType: "uint256", name: "timestamp", type: "uint256" },
                    { internalType: "bytes", name: "donSignatures", type: "bytes" },
                ],
                internalType: "struct ISentinelActions.ThreatReport",
                name: "report",
                type: "tuple",
            },
        ],
        name: "executeAction",
        outputs: [],
        stateMutability: "nonpayable",
        type: "function",
    },
] as const;

export const complianceVaultAbi = [
    {
        inputs: [
            { internalType: "bytes32", name: "reportHash", type: "bytes32" },
            { internalType: "bytes32", name: "agentId", type: "bytes32" },
            { internalType: "uint8", name: "reportType", type: "uint8" },
            { internalType: "uint16", name: "chainId", type: "uint16" },
            { internalType: "string", name: "reportURI", type: "string" },
        ],
        name: "storeReport",
        outputs: [],
        stateMutability: "nonpayable",
        type: "function",
    },
] as const;

export const crossChainRelayAbi = [
    {
        inputs: [
            { internalType: "uint64", name: "destChainSelector", type: "uint64" },
            { internalType: "bytes32", name: "reportId", type: "bytes32" },
            { internalType: "uint8", name: "actionType", type: "uint8" },
            { internalType: "address", name: "targetProtocol", type: "address" },
            { internalType: "bytes", name: "payload", type: "bytes" },
        ],
        name: "sendAlert",
        outputs: [{ internalType: "bytes32", name: "messageId", type: "bytes32" }],
        stateMutability: "nonpayable",
        type: "function",
    },
] as const;
