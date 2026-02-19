/**
 * @file events.fixtures.ts
 * @notice Fixture factories for EVM events and cross-chain messages
 */

import { ethers } from "hardhat";
import {
  ThreatEvent,
  ProtocolDeployment,
  PropagationMessage,
} from "../../workflows/logic/types";

/**
 * Build ThreatReported event payload
 */
export function buildThreatReportedEvent(
  overrides: Partial<ThreatEvent> = {},
): ThreatEvent {
  const reportId = ethers.id(`threat-report-${Date.now()}`);
  const agentId = ethers.id("raizo.sentinel.v1");

  return {
    reportId,
    agentId,
    sourceChain: 1, // Ethereum
    targetProtocol: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    action: 0, // PAUSE
    severity: 3, // CRITICAL
    confidenceScore: 9700, // 97%
    evidenceHash: ethers.id("Critical exploit detected"),
    timestamp: Math.floor(Date.now() / 1000),
    ...overrides,
  };
}

/**
 * Build CRITICAL severity event (triggers ALL_CHAINS propagation)
 */
export function buildCriticalThreatEvent(): ThreatEvent {
  return buildThreatReportedEvent({
    severity: 3, // CRITICAL
    action: 0, // PAUSE
    confidenceScore: 9800,
  });
}

/**
 * Build HIGH severity event (triggers SAME_PROTOCOL propagation)
 */
export function buildHighThreatEvent(): ThreatEvent {
  return buildThreatReportedEvent({
    severity: 2, // HIGH
    action: 2, // DRAIN_BLOCK
    confidenceScore: 9000,
  });
}

/**
 * Build MEDIUM severity event (triggers RELATED_ALERT)
 */
export function buildMediumThreatEvent(): ThreatEvent {
  return buildThreatReportedEvent({
    severity: 1, // MEDIUM
    action: 1, // RATE_LIMIT
    confidenceScore: 7500,
  });
}

/**
 * Build LOW severity event (triggers LOCAL_ONLY)
 */
export function buildLowThreatEvent(): ThreatEvent {
  return buildThreatReportedEvent({
    severity: 0, // LOW
    action: 3, // ALERT
    confidenceScore: 6000,
  });
}

/**
 * Build protocol deployment (multi-chain)
 */
export function buildMultiChainDeployment(
  protocol: string = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
): ProtocolDeployment {
  return {
    protocol,
    chains: [1, 10, 8453, 42161], // Ethereum, Optimism, Base, Arbitrum
    relatedProtocols: [
      "0x1111111111111111111111111111111111111111", // Related protocol 1
      "0x2222222222222222222222222222222222222222", // Related protocol 2
    ],
  };
}

/**
 * Build protocol deployment (single chain - LOCAL_ONLY scenario)
 */
export function buildSingleChainDeployment(
  protocol: string = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
): ProtocolDeployment {
  return {
    protocol,
    chains: [1], // Only Ethereum
    relatedProtocols: [], // No related protocols
  };
}

/**
 * Build protocol deployment (multi-chain with related protocols)
 */
export function buildRelatedProtocolDeployment(
  protocol: string = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
): ProtocolDeployment {
  return {
    protocol,
    chains: [1], // Single chain
    relatedProtocols: [
      "0x1111111111111111111111111111111111111111",
      "0x2222222222222222222222222222222222222222",
      "0x3333333333333333333333333333333333333333",
    ],
  };
}

/**
 * Build propagation message
 */
export function buildPropagationMessage(
  destChain: number,
  event: ThreatEvent,
): PropagationMessage {
  return {
    destChain,
    reportId: event.reportId,
    targetProtocol: event.targetProtocol,
    action: event.action,
    severity: event.severity,
  };
}

/**
 * Build batch of propagation messages (ALL_CHAINS scenario)
 */
export function buildAllChainsPropagation(
  event: ThreatEvent = buildCriticalThreatEvent(),
  monitoredChains: number[] = [1, 10, 8453, 42161],
): PropagationMessage[] {
  // Exclude source chain
  const targetChains = monitoredChains.filter((c) => c !== event.sourceChain);

  return targetChains.map((destChain) =>
    buildPropagationMessage(destChain, event),
  );
}

/**
 * Build empty propagation (LOCAL_ONLY scenario)
 */
export function buildLocalOnlyPropagation(): PropagationMessage[] {
  return [];
}

/**
 * Build EVM log payload (for EVMLogTrigger simulation)
 */
export interface EVMLogPayload {
  log: {
    address: string;
    topics: string[];
    data: string;
    blockNumber: number;
    transactionHash: string;
    logIndex: number;
  };
}

export function buildEVMLogPayload(event: ThreatEvent): EVMLogPayload {
  // Encode ThreatReported event
  // event ThreatReported(
  //   bytes32 indexed reportId,
  //   bytes32 indexed agentId,
  //   address indexed targetProtocol,
  //   ActionType action,
  //   Severity severity,
  //   uint16 confidenceScore
  // );

  const topics = [
    ethers.id(
      "ThreatReported(bytes32,bytes32,address,uint8,uint8,uint16)",
    ),
    event.reportId,
    event.agentId,
    ethers.zeroPadValue(event.targetProtocol, 32),
  ];

  // Encode non-indexed parameters in data field
  const abiCoder = ethers.AbiCoder.defaultAbiCoder();
  const data = abiCoder.encode(
    ["uint8", "uint8", "uint16"],
    [event.action, event.severity, event.confidenceScore],
  );

  return {
    log: {
      address: "0xSENTINEL_ACTIONS_CONTRACT_ADDRESS", // Placeholder
      topics,
      data,
      blockNumber: 20_000_000,
      transactionHash: ethers.id(`tx-${Date.now()}`),
      logIndex: 0,
    },
  };
}

/**
 * Build CCIP message for cross-chain alert
 */
export interface CCIPMessage {
  sourceChainSelector: bigint;
  sender: string;
  data: string; // ABI-encoded PropagationMessage
  destChainSelector: bigint;
  receiver: string;
  gasLimit: bigint;
  strict: boolean;
}

export function buildCCIPMessage(
  msg: PropagationMessage,
  sourceChainSelector: bigint = 1234567890n,
  destChainSelector: bigint = 9876543210n,
): CCIPMessage {
  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  // Encode PropagationMessage
  const data = abiCoder.encode(
    ["bytes32", "address", "uint8", "uint8"],
    [
      msg.reportId,
      msg.targetProtocol,
      msg.action,
      msg.severity,
    ],
  );

  return {
    sourceChainSelector,
    sender: "0xCROSS_CHAIN_RELAY_SOURCE", // Source relay contract
    data,
    destChainSelector,
    receiver: "0xCROSS_CHAIN_RELAY_DEST", // Destination relay contract
    gasLimit: 200_000n,
    strict: false,
  };
}

/**
 * Build batch of CCIP messages
 */
export function buildCCIPMessageBatch(
  messages: PropagationMessage[],
  sourceChainSelector: bigint = 1234567890n,
): CCIPMessage[] {
  const destSelectors: Record<number, bigint> = {
    1: 1234567890n, // Ethereum
    10: 2345678901n, // Optimism
    8453: 3456789012n, // Base
    42161: 4567890123n, // Arbitrum
  };

  return messages.map((msg) =>
    buildCCIPMessage(
      msg,
      sourceChainSelector,
      destSelectors[msg.destChain] || 9999999999n,
    ),
  );
}

/**
 * Build ActionExecuted event (emitted after successful execution)
 */
export interface ActionExecutedEvent {
  reportId: string;
  protocol: string;
  action: number;
  severity: number;
  confidence: number;
}

export function buildActionExecutedEvent(
  threat: ThreatEvent,
): ActionExecutedEvent {
  return {
    reportId: threat.reportId,
    protocol: threat.targetProtocol,
    action: threat.action,
    severity: threat.severity,
    confidence: threat.confidenceScore,
  };
}

/**
 * Build ReportStored event (emitted by ComplianceVault)
 */
export interface ReportStoredEvent {
  reportHash: string;
  agentId: string;
  reportType: number;
  chainId: number;
}

export function buildReportStoredEvent(
  reportHash: string,
  agentId: string = ethers.id("raizo.compliance.v1"),
  reportType: number = 4, // MiCA
  chainId: number = 1,
): ReportStoredEvent {
  return {
    reportHash,
    agentId,
    reportType,
    chainId,
  };
}

/**
 * Mock EVM event filter response
 */
export interface EventFilterResponse {
  events: any[];
  fromBlock: number;
  toBlock: number;
}

export function buildEventFilterResponse(
  events: any[],
  fromBlock: number = 19_000_000,
  toBlock: number = 20_000_000,
): EventFilterResponse {
  return {
    events,
    fromBlock,
    toBlock,
  };
}
