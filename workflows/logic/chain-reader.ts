/**
 * @file chain-reader.ts
 * @notice Chain Reader — normalizes raw on-chain data into TelemetryFrame.
 *
 * Spec References:
 *   AI_AGENTS.md §3.2 — Data Ingestion Schema (TVL, mempool, tx anomaly)
 *   AI_AGENTS.md §8   — Performance Targets (<15s end-to-end detection)
 *   SECURITY.md §5    — Staleness detection for oracle latency
 *
 * Architecture:
 *   - Fetches raw chain data from an aggregated chain-reader endpoint
 *   - Normalizes Wei-denominated strings → bigint
 *   - Computes derived metrics (TVL delta %, failed tx ratio, price deviation %)
 *   - Detects stale data via configurable oracleLatency threshold
 *   - Returns a fully-typed TelemetryFrame ready for the threat pipeline
 */

import { SimpleFetch } from "./workflow-helpers";
import { TelemetryFrame } from "./types";

export interface ChainReaderConfig {
    rpcUrl: string;
    stalenessThresholdSec?: number;
}

/**
 * Raw chain data as returned by the aggregated endpoint.
 * String-encoded numbers are converted to bigint during normalization.
 */
interface RawChainData {
    chainId: number;
    block: { number: number; timestamp: number };
    tvl: { currentUSD: string; oneHourAgoUSD: string; twentyFourHourAgoUSD?: string };
    transactions: {
        count: number;
        volumeWei: string;
        failedCount: number;
        largeCount: number;
        uniqueAddresses: number;
    };
    contractState: {
        owner: string;
        paused: boolean;
        pendingUpgrade: boolean;
        approvals: number;
    };
    mempool: {
        pendingWithdrawals: number;
        flashLoans: number;
        suspiciousCalldata: string[];
    };
    threatIntel: {
        cves: string[];
        patterns: any[];
        darkWebMentions: number;
        sentiment: number;
    };
    price: {
        tokenPriceUSD: string;
        deviationBps: number;
        latencySeconds: number;
    };
}

/**
 * Computes percentage change: ((current - previous) / previous) * 100
 * Returns 0 if previous is zero to avoid division by zero.
 */
function computeDeltaPercent(current: bigint, previous: bigint): number {
    if (previous === 0n) return 0;
    // Use Number for the final result since percentages fit in f64
    return Number((current - previous) * 10000n / previous) / 100;
}

export class ChainReader {
    private config: ChainReaderConfig;

    constructor(config: ChainReaderConfig) {
        this.config = config;
    }

    /**
     * Fetches raw chain data and normalizes it into a TelemetryFrame.
     * @param fetch - SimpleFetch adapter (injectable for testing)
     * @param protocolAddress - The protocol address to query
     */
    async readTelemetry(fetch: SimpleFetch, protocolAddress: string): Promise<TelemetryFrame> {
        const url = `${this.config.rpcUrl}?protocol=${encodeURIComponent(protocolAddress)}`;
        const res = await fetch(url, { method: "GET" });

        if (!res.ok) {
            throw new Error(`Chain reader endpoint returned ${res.status}`);
        }

        const raw: RawChainData = JSON.parse(res.body);
        return this.normalize(raw);
    }

    private normalize(raw: RawChainData): TelemetryFrame {
        const currentTVL = BigInt(raw.tvl.currentUSD);
        const previousTVL = BigInt(raw.tvl.oneHourAgoUSD);
        const delta1h = computeDeltaPercent(currentTVL, previousTVL);

        // Compute 24h delta if the endpoint provides the field, otherwise 0
        const twentyFourHourAgoTVL = raw.tvl.twentyFourHourAgoUSD
            ? BigInt(raw.tvl.twentyFourHourAgoUSD)
            : 0n;
        const delta24h = twentyFourHourAgoTVL > 0n
            ? computeDeltaPercent(currentTVL, twentyFourHourAgoTVL)
            : 0;

        const failedTxRatio = raw.transactions.count > 0
            ? raw.transactions.failedCount / raw.transactions.count
            : 0;

        // Convert basis points to percentage (1800 bps → 18.0%)
        const priceDeviation = raw.price.deviationBps / 100;

        // Staleness detection (SECURITY.md §5)
        const stalenessThreshold = this.config.stalenessThresholdSec ?? Infinity;
        if (raw.price.latencySeconds > stalenessThreshold) {
            throw new Error(
                `Stale oracle data: latency ${raw.price.latencySeconds}s exceeds threshold ${stalenessThreshold}s`,
            );
        }

        return {
            chainId: raw.chainId,
            blockNumber: raw.block.number,
            tvl: {
                current: currentTVL,
                delta1h,
                delta24h,
            },
            transactionMetrics: {
                volumeUSD: BigInt(raw.transactions.volumeWei),
                uniqueAddresses: raw.transactions.uniqueAddresses,
                largeTransactions: raw.transactions.largeCount,
                failedTxRatio,
            },
            contractState: {
                owner: raw.contractState.owner,
                paused: raw.contractState.paused,
                pendingUpgrade: raw.contractState.pendingUpgrade,
                unusualApprovals: raw.contractState.approvals,
            },
            mempoolSignals: {
                pendingLargeWithdrawals: raw.mempool.pendingWithdrawals,
                flashLoanBorrows: raw.mempool.flashLoans,
                suspiciousCalldata: raw.mempool.suspiciousCalldata,
            },
            threatIntel: {
                activeCVEs: raw.threatIntel.cves,
                exploitPatterns: raw.threatIntel.patterns.map(p => ({
                    patternId: p.patternId ?? "unknown",
                    category: p.category ?? "logic_error",
                    severity: p.severity ?? "low",
                    indicators: p.indicators ?? [],
                    confidence: p.confidence ?? 0,
                })),
                darkWebMentions: raw.threatIntel.darkWebMentions,
                socialSentiment: raw.threatIntel.sentiment,
            },
            priceData: {
                tokenPrice: BigInt(raw.price.tokenPriceUSD),
                priceDeviation,
                oracleLatency: raw.price.latencySeconds,
            },
        };
    }
}
