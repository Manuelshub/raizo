/**
 * Indexer Integration Module
 * 
 * Provides transaction metrics and mempool signals for TelemetryFrame.
 * Per AI_AGENTS.md §3.2, this module populates:
 * - transactionMetrics: volumeUSD, uniqueAddresses, largeTransactions, failedTxRatio
 * - mempoolSignals: pendingLargeWithdrawals, flashLoanBorrows, suspiciousCalldata
 * 
 * Implementation Strategy:
 * 1. For testnet/MVP: Use direct RPC queries with block range analysis
 * 2. For production: Integrate The Graph subgraph for efficient historical queries
 */

import type { NodeRuntime } from "@chainlink/cre-sdk";
import { HTTPClient, ok, json, hexToBase64 } from "@chainlink/cre-sdk";
import { stringToHex } from "viem";

// ---------------------------------------------------------------------------
// Interfaces (aligned with AI_AGENTS.md §3.2)
// ---------------------------------------------------------------------------

export interface TransactionMetrics {
  volumeUSD: bigint;
  uniqueAddresses: number;
  largeTransactions: number; // > $1M threshold
  failedTxRatio: number;
}

export interface MempoolSignals {
  pendingLargeWithdrawals: number;
  flashLoanBorrows: number;
  suspiciousCalldata: string[];
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const LARGE_TX_THRESHOLD_USD = 1_000_000; // $1M threshold per spec
const BLOCK_LOOKBACK = 100; // Analyze last 100 blocks for metrics
const FLASH_LOAN_SIGNATURES = [
  "0x5cffe9de", // flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)
  "0xab9c4b5d", // flashLoan(address,address,uint256,bytes)
  "0xe0232b42", // flashLoanSimple(address,address,uint256,bytes,uint16)
];

// Common withdrawal function signatures
const WITHDRAWAL_SIGNATURES = [
  "0x2e1a7d4d", // withdraw(uint256)
  "0x3ccfd60b", // withdraw()
  "0x00f714ce", // withdraw(uint256,address)
  "0x69328dec", // withdraw(address,uint256)
];

// ---------------------------------------------------------------------------
// RPC-Based Indexer (MVP Implementation)
// ---------------------------------------------------------------------------

/**
 * Fetches transaction metrics for a protocol over the last N blocks.
 * Uses direct RPC calls to analyze transaction patterns.
 * 
 * @param nodeRuntime - CRE NodeRuntime for HTTP access
 * @param protocolAddress - Target protocol contract address
 * @param rpcUrl - Ethereum RPC endpoint
 * @param ethPriceUSD - Current ETH price for USD conversion
 * @returns TransactionMetrics populated per spec
 */
export function fetchTransactionMetrics(
  nodeRuntime: NodeRuntime<any>,
  protocolAddress: string,
  rpcUrl: string,
  ethPriceUSD: number,
): TransactionMetrics {
  const http = new HTTPClient();

  try {
    // Get latest block number
    nodeRuntime.log(`[Indexer] [API] Requesting latest block number from ${rpcUrl}`);
    nodeRuntime.log(`[Indexer] [API] Method: eth_blockNumber`);
    
    const latestBlockResp = http
      .sendRequest(nodeRuntime, {
        url: rpcUrl,
        method: "POST",
        body: hexToBase64(stringToHex(JSON.stringify({
          jsonrpc: "2.0",
          method: "eth_blockNumber",
          params: [],
          id: 1,
        }))),
      })
      .result();

    nodeRuntime.log(`[Indexer] [API] Response status: ${latestBlockResp.statusCode}`);
    
    if (!ok(latestBlockResp)) {
      nodeRuntime.log(
        `[Indexer] [API] Failed to fetch latest block: ${latestBlockResp.statusCode}`,
      );
      return getEmptyMetrics();
    }
    
    nodeRuntime.log(`[Indexer] [API] Successfully fetched latest block number`);

    const latestBlockData = json(latestBlockResp) as any;
    const latestBlock = parseInt(latestBlockData.result, 16);
    const fromBlock = Math.max(0, latestBlock - BLOCK_LOOKBACK);

    nodeRuntime.log(
      `[Indexer] Analyzing blocks ${fromBlock} to ${latestBlock} for ${protocolAddress}`,
    );

    // Fetch logs for the protocol (all events)
    nodeRuntime.log(`[Indexer] [API] Requesting logs from ${rpcUrl}`);
    nodeRuntime.log(`[Indexer] [API] Method: eth_getLogs`);
    nodeRuntime.log(`[Indexer] [API] Params: address=${protocolAddress}, fromBlock=${fromBlock}, toBlock=${latestBlock}`);
    
    const logsResp = http
      .sendRequest(nodeRuntime, {
        url: rpcUrl,
        method: "POST",
        body: hexToBase64(stringToHex(JSON.stringify({
          jsonrpc: "2.0",
          method: "eth_getLogs",
          params: [
            {
              address: protocolAddress,
              fromBlock: `0x${fromBlock.toString(16)}`,
              toBlock: `0x${latestBlock.toString(16)}`,
            },
          ],
          id: 2,
        }))),
      })
      .result();

    nodeRuntime.log(`[Indexer] [API] Response status: ${logsResp.statusCode}`);
    
    if (!ok(logsResp)) {
      nodeRuntime.log(
        `[Indexer] [API] Failed to fetch logs: ${logsResp.statusCode}`,
      );
      return getEmptyMetrics();
    }
    
    nodeRuntime.log(`[Indexer] [API] Successfully fetched logs`);

    const logsData = json(logsResp) as any;
    const logs = logsData.result || [];

    // Extract unique transaction hashes
    const txHashes = [...new Set(logs.map((log: any) => log.transactionHash))];
    nodeRuntime.log(
      `[Indexer] Found ${txHashes.length} transactions in ${logs.length} events`,
    );

    // Analyze transactions
    const uniqueAddresses = new Set<string>();
    let totalVolumeWei = 0n;
    let largeTransactions = 0;
    let failedTxCount = 0;

    // Sample up to 50 transactions to avoid rate limits
    const sampleSize = Math.min(txHashes.length, 50);
    for (let i = 0; i < sampleSize; i++) {
      const txHash = txHashes[i];

      try {
        nodeRuntime.log(`[Indexer] [API] Fetching transaction ${i + 1}/${sampleSize}: ${txHash}`);
        
        const txResp = http
          .sendRequest(nodeRuntime, {
            url: rpcUrl,
            method: "POST",
            body: hexToBase64(stringToHex(JSON.stringify({
              jsonrpc: "2.0",
              method: "eth_getTransactionByHash",
              params: [txHash],
              id: 3 + i,
            }))),
          })
          .result();

        nodeRuntime.log(`[Indexer] [API] Transaction response status: ${txResp.statusCode}`);
        
        if (!ok(txResp)) continue;

        const txData = json(txResp) as any;
        const tx = txData.result;

        if (!tx) continue;

        // Track unique addresses
        uniqueAddresses.add(tx.from.toLowerCase());
        if (tx.to) uniqueAddresses.add(tx.to.toLowerCase());

        // Calculate volume
        const valueWei = BigInt(tx.value || "0x0");
        totalVolumeWei += valueWei;

        // Check if large transaction (> $1M)
        const valueETH = Number(valueWei) / 1e18;
        const valueUSD = valueETH * ethPriceUSD;
        if (valueUSD > LARGE_TX_THRESHOLD_USD) {
          largeTransactions++;
        }

        // Check transaction receipt for failure
        nodeRuntime.log(`[Indexer] [API] Fetching receipt for tx ${i + 1}/${sampleSize}: ${txHash}`);
        
        const receiptResp = http
          .sendRequest(nodeRuntime, {
            url: rpcUrl,
            method: "POST",
            body: hexToBase64(stringToHex(JSON.stringify({
              jsonrpc: "2.0",
              method: "eth_getTransactionReceipt",
              params: [txHash],
              id: 1000 + i,
            }))),
          })
          .result();

        nodeRuntime.log(`[Indexer] [API] Receipt response status: ${receiptResp.statusCode}`);
        
        if (ok(receiptResp)) {
          const receiptData = json(receiptResp) as any;
          const receipt = receiptData.result;
          if (receipt && receipt.status === "0x0") {
            failedTxCount++;
          }
        }
      } catch (e) {
        nodeRuntime.log(`[Indexer] Error processing tx ${txHash}: ${e}`);
      }
    }

    // Calculate metrics
    const volumeUSD = BigInt(
      Math.floor((Number(totalVolumeWei) / 1e18) * ethPriceUSD),
    );
    const failedTxRatio =
      sampleSize > 0 ? failedTxCount / sampleSize : 0;

    nodeRuntime.log(
      `[Indexer] Metrics: volume=$${volumeUSD}, unique=${uniqueAddresses.size}, large=${largeTransactions}, failed=${(failedTxRatio * 100).toFixed(1)}%`,
    );

    return {
      volumeUSD,
      uniqueAddresses: uniqueAddresses.size,
      largeTransactions,
      failedTxRatio,
    };
  } catch (e) {
    nodeRuntime.log(`[Indexer] fetchTransactionMetrics error: ${e}`);
    return getEmptyMetrics();
  }
}

/**
 * Fetches mempool signals for a protocol.
 * Analyzes pending transactions for suspicious patterns.
 * 
 * @param nodeRuntime - CRE NodeRuntime for HTTP access
 * @param protocolAddress - Target protocol contract address
 * @param rpcUrl - Ethereum RPC endpoint
 * @returns MempoolSignals populated per spec
 */
export function fetchMempoolSignals(
  nodeRuntime: NodeRuntime<any>,
  protocolAddress: string,
  rpcUrl: string,
): MempoolSignals {
  const http = new HTTPClient();

  try {
    // Fetch pending transactions
    // Note: Most public RPCs don't support txpool_content, so we use eth_getBlockByNumber with "pending"
    nodeRuntime.log(`[Indexer] [API] Requesting pending block from ${rpcUrl}`);
    nodeRuntime.log(`[Indexer] [API] Method: eth_getBlockByNumber`);
    nodeRuntime.log(`[Indexer] [API] Params: ["pending", true]`);
    
    const pendingResp = http
      .sendRequest(nodeRuntime, {
        url: rpcUrl,
        method: "POST",
        body: hexToBase64(stringToHex(JSON.stringify({
          jsonrpc: "2.0",
          method: "eth_getBlockByNumber",
          params: ["pending", true],
          id: 1,
        }))),
      })
      .result();
    
    nodeRuntime.log(`[Indexer] [API] Response status: ${pendingResp.statusCode}`);

    if (!ok(pendingResp)) {
      nodeRuntime.log(
        `[Indexer] [API] Failed to fetch pending block: ${pendingResp.statusCode}`,
      );
      return getEmptyMempoolSignals();
    }
    
    nodeRuntime.log(`[Indexer] [API] Successfully fetched pending block`);

    const pendingData = json(pendingResp) as any;
    const pendingBlock = pendingData.result;

    if (!pendingBlock || !pendingBlock.transactions) {
      nodeRuntime.log(`[Indexer] No pending transactions available`);
      return getEmptyMempoolSignals();
    }

    const transactions = pendingBlock.transactions;
    nodeRuntime.log(
      `[Indexer] Analyzing ${transactions.length} pending transactions`,
    );

    let pendingLargeWithdrawals = 0;
    let flashLoanBorrows = 0;
    const suspiciousCalldata: string[] = [];

    // Analyze pending transactions targeting the protocol
    for (const tx of transactions) {
      if (
        !tx.to ||
        tx.to.toLowerCase() !== protocolAddress.toLowerCase()
      ) {
        continue;
      }

      const input = tx.input || "0x";
      const methodSig = input.slice(0, 10);

      // Detect flash loan borrows
      if (FLASH_LOAN_SIGNATURES.includes(methodSig)) {
        flashLoanBorrows++;
        nodeRuntime.log(
          `[Indexer] Detected pending flash loan: ${tx.hash}`,
        );
      }

      // Detect large withdrawals
      if (WITHDRAWAL_SIGNATURES.includes(methodSig)) {
        const valueWei = BigInt(tx.value || "0x0");
        const valueETH = Number(valueWei) / 1e18;
        if (valueETH > 10) {
          // > 10 ETH withdrawal
          pendingLargeWithdrawals++;
          nodeRuntime.log(
            `[Indexer] Detected large pending withdrawal: ${tx.hash} (${valueETH.toFixed(2)} ETH)`,
          );
        }
      }

      // Detect suspicious calldata patterns
      if (input.length > 10000) {
        // Unusually large calldata
        suspiciousCalldata.push(tx.hash);
        nodeRuntime.log(
          `[Indexer] Suspicious large calldata: ${tx.hash} (${input.length} bytes)`,
        );
      }

      // Detect potential reentrancy patterns (multiple calls in calldata)
      const callCount = (input.match(/0x[a-fA-F0-9]{8}/g) || []).length;
      if (callCount > 5) {
        suspiciousCalldata.push(tx.hash);
        nodeRuntime.log(
          `[Indexer] Suspicious multi-call pattern: ${tx.hash} (${callCount} calls)`,
        );
      }
    }

    nodeRuntime.log(
      `[Indexer] Mempool signals: withdrawals=${pendingLargeWithdrawals}, flashLoans=${flashLoanBorrows}, suspicious=${suspiciousCalldata.length}`,
    );

    return {
      pendingLargeWithdrawals,
      flashLoanBorrows,
      suspiciousCalldata: suspiciousCalldata.slice(0, 10), // Limit to 10 for LLM context
    };
  } catch (e) {
    nodeRuntime.log(`[Indexer] fetchMempoolSignals error: ${e}`);
    return getEmptyMempoolSignals();
  }
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

function getEmptyMetrics(): TransactionMetrics {
  return {
    volumeUSD: 0n,
    uniqueAddresses: 0,
    largeTransactions: 0,
    failedTxRatio: 0,
  };
}

function getEmptyMempoolSignals(): MempoolSignals {
  return {
    pendingLargeWithdrawals: 0,
    flashLoanBorrows: 0,
    suspiciousCalldata: [],
  };
}
