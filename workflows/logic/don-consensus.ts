/**
 * @file don-consensus.ts
 * @notice DON (Decentralized Oracle Network) Consensus Simulation.
 *
 * Spec References:
 *   AI_AGENTS.md §3.5 — DON Consensus Model (⅔+ agreement, median aggregation)
 *   AI_AGENTS.md §8   — Performance Targets (<10s consensus)
 *   SECURITY.md §3.5  — Node divergence handling, safe fallback
 *
 * Architecture:
 *   - Simulates a multi-node oracle consensus for threat assessments
 *   - Requires ⅔+ agreement (rounded up) on recommendedAction for consensus
 *   - Computes median risk score across all participating nodes
 *   - Falls back to ALERT on divergence (no supermajority)
 *   - Produces a BLS-style aggregated signature stub (placeholder for real BLS)
 */

import { ThreatAssessment, RecommendedAction } from "./types";

export interface DonConsensusConfig {
    nodeCount: number;
}

export interface ConsensusResult {
    consensusReached: boolean;
    agreedAction: RecommendedAction;
    medianScore: number;
    aggregatedSignature: string;
    nodeCount: number;
    agreementCount: number;
}

/**
 * Computes the median of a sorted numeric array.
 */
function median(sorted: number[]): number {
    const n = sorted.length;
    if (n === 0) return 0;
    const mid = Math.floor(n / 2);
    if (n % 2 === 1) return sorted[mid];
    return (sorted[mid - 1] + sorted[mid]) / 2;
}

/**
 * Generates a BLS aggregated signature stub.
 * In production this would be a real BLS12-381 aggregate; here we produce
 * a deterministic hex string of the correct length (48 bytes = 96 hex chars).
 */
function generateBLSStub(nodeCount: number): string {
    // 48-byte BLS signature stub (96 hex chars)
    const bytes = new Uint8Array(48);
    // Fill with a pattern based on nodeCount for determinism in tests
    for (let i = 0; i < 48; i++) {
        bytes[i] = (nodeCount * 17 + i * 31) & 0xff;
    }
    return "0x" + Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

export class DonConsensus {
    private config: DonConsensusConfig;

    constructor(config: DonConsensusConfig) {
        this.config = config;
    }

    /**
     * Aggregates multiple node assessments into a consensus result.
     * @param assessments - One assessment per node
     * @returns ConsensusResult with agreement status, action, and median score
     * @throws Error if assessments array is empty
     */
    aggregate(assessments: ThreatAssessment[]): ConsensusResult {
        if (assessments.length === 0) {
            throw new Error("No assessments provided for DON consensus");
        }

        // Count votes per action
        const actionCounts = new Map<string, number>();
        for (const a of assessments) {
            const count = actionCounts.get(a.recommendedAction) ?? 0;
            actionCounts.set(a.recommendedAction, count + 1);
        }

        // Find the action with the most votes
        let maxAction = "ALERT";
        let maxCount = 0;
        for (const [action, count] of actionCounts) {
            if (count > maxCount) {
                maxCount = count;
                maxAction = action;
            }
        }

        // ⅔ threshold (rounded up): ceil(n * 2/3)
        const threshold = Math.ceil(assessments.length * 2 / 3);
        const consensusReached = maxCount >= threshold;

        // If no consensus, fall back to ALERT (safe default per §3.5)
        const agreedAction = consensusReached
            ? (maxAction as RecommendedAction)
            : "ALERT";

        // Median risk score
        const scores = assessments.map(a => a.overallRiskScore).sort((a, b) => a - b);
        const medianScore = median(scores);

        return {
            consensusReached,
            agreedAction,
            medianScore,
            aggregatedSignature: generateBLSStub(assessments.length),
            nodeCount: assessments.length,
            agreementCount: maxCount,
        };
    }
}
