/**
 * @file compliance-score-reader.ts
 * @notice WS-10 — ComplianceScoreReader: Reads per-chain compliance scores from
 *         ComplianceVault using the weighted scoring model from COMPLIANCE.md §9.
 *
 * Spec References:
 *   COMPLIANCE.md §9      — Compliance Scoring Model (weighted category formula)
 *   COMPLIANCE.md §3      — ACE Pipeline: Summary → Dashboard (operator visibility)
 *   SMART_CONTRACTS.md §2.3 — ComplianceVault views: getReportsByType, getReportsByChain
 *
 * Scoring Formula (COMPLIANCE.md §9):
 *   finalScore = Σ (categoryScore_i × weight_i)
 *   | Category               | Weight | Report Type(s) |
 *   |------------------------|--------|----------------|
 *   | AML adherence          | 0.30   | type=1 (AML)   |
 *   | KYC coverage           | 0.20   | type=2 (KYC)   |
 *   | Regulatory disclosures | 0.20   | type=4 (MiCA)  |
 *   | Reserve adequacy       | 0.15   | type=3 (ESG)   |
 *   | Incident history       | 0.15   | type=5 (Custom) |
 */

import { BaseContract } from "ethers";

/** Score breakdown by compliance category */
export interface ScoreBreakdown {
    aml: number;        // AML adherence (weight 0.30)
    kyc: number;        // KYC coverage (weight 0.20)
    regulatory: number; // Regulatory disclosures (weight 0.20)
    reserve: number;    // Reserve adequacy (weight 0.15)
    incident: number;   // Incident history (weight 0.15)
}

/** Complete compliance score result */
export interface ComplianceScore {
    chainId: number;
    overall: number;  // 0–100 composite score
    breakdown: ScoreBreakdown;
    reportCount: number;
}

/** On-chain ComplianceRecord shape (mirrors Solidity struct) */
interface ComplianceRecord {
    reportHash: string;
    agentId: string;
    reportType: number;
    timestamp: bigint;
    chainId: number;
    reportURI: string;
}

/** Category weights from COMPLIANCE.md §9 */
const CATEGORY_WEIGHTS: Record<string, { weight: number; reportType: number }> = {
    aml:        { weight: 0.30, reportType: 1 },
    kyc:        { weight: 0.20, reportType: 2 },
    regulatory: { weight: 0.20, reportType: 4 }, // MiCA
    reserve:    { weight: 0.15, reportType: 3 }, // ESG
    incident:   { weight: 0.15, reportType: 5 }, // Custom
};

/**
 * ComplianceScoreReader — Reads compliance reports from ComplianceVault and
 * computes weighted compliance scores per chain using the model defined in
 * COMPLIANCE.md §9.
 *
 * Score derivation: Each category gets 100 points if at least one report of
 * that type exists for the queried chain, 0 otherwise. The overall score is
 * the weighted sum across all categories (0–100 scale).
 *
 * Production enhancement: Replace binary presence with deeper report analysis
 * (e.g., violation count → penalty deduction) once full report contents are
 * available from Confidential Compute off-chain storage.
 */
export class ComplianceScoreReader {
    constructor(private readonly vault: BaseContract) {}

    /**
     * Get total report count across all chains and types.
     */
    async getReportCount(): Promise<number> {
        const count = await (this.vault as any).getReportCount();
        return Number(count);
    }

    /**
     * Get reports filtered by report type (1=AML, 2=KYC, 3=ESG, 4=MiCA, 5=Custom).
     */
    async getReportsByType(reportType: number): Promise<ComplianceRecord[]> {
        const records = await (this.vault as any).getReportsByType(reportType);
        return records.map((r: any) => this.normalizeRecord(r));
    }

    /**
     * Get reports filtered by chain ID.
     */
    async getReportsByChain(chainId: number): Promise<ComplianceRecord[]> {
        const records = await (this.vault as any).getReportsByChain(chainId);
        return records.map((r: any) => this.normalizeRecord(r));
    }

    /**
     * Compute the composite compliance score for a given chain using the
     * COMPLIANCE.md §9 weighted formula.
     *
     * Each category earns 100 if ≥1 report of that type exists for the chain.
     * Overall = Σ(categoryScore × weight), clamped to [0, 100].
     */
    async computeComplianceScore(chainId: number): Promise<ComplianceScore> {
        const chainReports = await this.getReportsByChain(chainId);

        if (chainReports.length === 0) {
            return {
                chainId,
                overall: 0,
                breakdown: { aml: 0, kyc: 0, regulatory: 0, reserve: 0, incident: 0 },
                reportCount: 0,
            };
        }

        // Build a set of report types present for this chain
        const presentTypes = new Set(chainReports.map(r => Number(r.reportType)));

        // Compute per-category scores
        const breakdown: ScoreBreakdown = {
            aml: 0,
            kyc: 0,
            regulatory: 0,
            reserve: 0,
            incident: 0,
        };

        let overall = 0;

        for (const [category, config] of Object.entries(CATEGORY_WEIGHTS)) {
            const categoryScore = presentTypes.has(config.reportType) ? 100 : 0;
            (breakdown as any)[category] = categoryScore;
            overall += categoryScore * config.weight;
        }

        // Clamp to [0, 100]
        overall = Math.min(100, Math.max(0, Math.round(overall)));

        return {
            chainId,
            overall,
            breakdown,
            reportCount: chainReports.length,
        };
    }

    // ── Internal Helpers ─────────────────────────────────────────────────

    /**
     * Normalize a raw Solidity struct return into a plain object.
     */
    private normalizeRecord(raw: any): ComplianceRecord {
        return {
            reportHash: raw.reportHash ?? raw[0],
            agentId: raw.agentId ?? raw[1],
            reportType: Number(raw.reportType ?? raw[2]),
            timestamp: BigInt(raw.timestamp ?? raw[3]),
            chainId: Number(raw.chainId ?? raw[4]),
            reportURI: raw.reportURI ?? raw[5],
        };
    }
}
