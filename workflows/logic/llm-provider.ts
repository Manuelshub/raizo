/**
 * @file llm-provider.ts
 * @notice LLM Provider integration for AI agent threat assessment.
 *
 * Spec References:
 *   AI_AGENTS.md §7   — LLM Provider Strategy (GPT-4o / Claude via Confidential Compute)
 *   AI_AGENTS.md §3.3 — Structured Output enforcement (JSON response_format)
 *   AI_AGENTS.md §3.6 — Anti-Hallucination Safeguards (evidence citation validation)
 *   SECURITY.md §3.2  — AI/LLM Threats (prompt injection, key exfiltration)
 *
 * Architecture:
 *   - Sends TelemetryFrame to an OpenAI-compatible chat completion API
 *   - Enforces structured JSON output via response_format: { type: "json_object" }
 *   - Validates response against ThreatAssessment schema
 *   - Retries on transient 5xx failures with configurable max retries
 *   - Multi-provider fallback (primary → secondary) for resilience
 *   - Clamps overallRiskScore to [0.0, 1.0]
 *   - Filters invalid evidenceCitations (anti-hallucination)
 *   - Serializes BigInt fields as strings for JSON transport
 */

import { SimpleFetch } from "./workflow-helpers";
import { TelemetryFrame, ThreatAssessment } from "./types";
import { SYSTEM_PROMPT } from "./threat-logic";

export interface LlmProviderConfig {
    apiUrl: string;
    apiKey: string;
    model: string;
    maxRetries?: number;
    fallback?: {
        apiUrl: string;
        apiKey: string;
        model: string;
    };
}

/** Valid top-level TelemetryFrame field paths for evidence citation validation */
const VALID_TELEMETRY_PATHS = new Set([
    "chainId", "blockNumber",
    "tvl.current", "tvl.delta1h", "tvl.delta24h",
    "transactionMetrics.volumeUSD", "transactionMetrics.uniqueAddresses",
    "transactionMetrics.largeTransactions", "transactionMetrics.failedTxRatio",
    "contractState.owner", "contractState.paused", "contractState.pendingUpgrade",
    "contractState.unusualApprovals",
    "mempoolSignals.pendingLargeWithdrawals", "mempoolSignals.flashLoanBorrows",
    "mempoolSignals.suspiciousCalldata",
    "threatIntel.activeCVEs", "threatIntel.exploitPatterns",
    "threatIntel.darkWebMentions", "threatIntel.socialSentiment",
    "priceData.tokenPrice", "priceData.priceDeviation", "priceData.oracleLatency",
]);

/**
 * Serializes a TelemetryFrame to a JSON-safe object (BigInt → string)
 */
function serializeTelemetry(telemetry: TelemetryFrame): Record<string, any> {
    return JSON.parse(JSON.stringify(telemetry, (_key, value) =>
        typeof value === "bigint" ? value.toString() : value
    ));
}

/**
 * Validates that a parsed object conforms to the ThreatAssessment interface
 */
function validateAssessment(data: any): asserts data is ThreatAssessment {
    if (typeof data !== "object" || data === null) {
        throw new Error("LLM response validation failed: not an object");
    }
    if (typeof data.overallRiskScore !== "number") {
        throw new Error("LLM response validation failed: missing overallRiskScore");
    }
    if (typeof data.threatDetected !== "boolean") {
        throw new Error("LLM response validation failed: missing threatDetected");
    }
    if (!Array.isArray(data.threats)) {
        throw new Error("LLM response validation failed: missing threats array");
    }
    const validActions = ["NONE", "ALERT", "RATE_LIMIT", "DRAIN_BLOCK", "PAUSE"];
    if (!validActions.includes(data.recommendedAction)) {
        throw new Error("LLM response validation failed: invalid recommendedAction");
    }
    if (typeof data.reasoning !== "string") {
        throw new Error("LLM response validation failed: missing reasoning");
    }
    if (!Array.isArray(data.evidenceCitations)) {
        throw new Error("LLM response validation failed: missing evidenceCitations");
    }
}

/**
 * Filters evidence citations to only include valid TelemetryFrame paths.
 * Anti-hallucination safeguard per AI_AGENTS.md §3.6.
 */
function filterEvidenceCitations(citations: string[]): string[] {
    return citations.filter(c => VALID_TELEMETRY_PATHS.has(c));
}

/**
 * Clamps a number to [0.0, 1.0] range
 */
function clampScore(score: number): number {
    return Math.max(0.0, Math.min(1.0, score));
}

export class LlmProvider {
    private config: LlmProviderConfig;

    constructor(config: LlmProviderConfig) {
        this.config = { maxRetries: 3, ...config };
    }

    /**
     * Sends telemetry to the LLM and returns a validated ThreatAssessment.
     */
    async assess(fetch: SimpleFetch, telemetry: TelemetryFrame): Promise<ThreatAssessment> {
        try {
            return await this.callProvider(fetch, this.config.apiUrl, this.config.apiKey, this.config.model, telemetry);
        } catch (primaryError) {
            if (this.config.fallback) {
                return await this.callProvider(
                    fetch,
                    this.config.fallback.apiUrl,
                    this.config.fallback.apiKey,
                    this.config.fallback.model,
                    telemetry,
                );
            }
            throw primaryError;
        }
    }

    private async callProvider(
        fetch: SimpleFetch,
        apiUrl: string,
        apiKey: string,
        model: string,
        telemetry: TelemetryFrame,
    ): Promise<ThreatAssessment> {
        const serialized = serializeTelemetry(telemetry);

        const body = JSON.stringify({
            model,
            response_format: { type: "json_object" },
            messages: [
                { role: "system", content: SYSTEM_PROMPT },
                { role: "user", content: JSON.stringify(serialized) },
            ],
        });

        let lastError: Error | null = null;
        const maxRetries = this.config.maxRetries ?? 3;

        for (let attempt = 0; attempt < maxRetries; attempt++) {
            const res = await fetch(apiUrl, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${apiKey}`,
                },
                body,
            });

            if (res.ok) {
                return this.parseResponse(res.body, apiUrl);
            }

            if (res.status >= 500) {
                lastError = new Error(`LLM provider returned ${res.status}`);
                continue; // Retry on server errors
            }

            // Client errors (4xx) are not retryable
            throw new Error(`LLM provider returned ${res.status}: ${res.body}`);
        }

        throw lastError ?? new Error("LLM provider exhausted all retries");
    }

    private parseResponse(responseBody: string, apiUrl: string): ThreatAssessment {
        const parsed = JSON.parse(responseBody);

        // Support both OpenAI and Anthropic response formats
        let content: string;
        if (parsed.choices?.[0]?.message?.content) {
            // OpenAI format
            content = parsed.choices[0].message.content;
        } else if (parsed.content?.[0]?.text) {
            // Anthropic/Claude format
            content = parsed.content[0].text;
        } else {
            throw new Error("LLM response validation failed: unrecognized response format");
        }

        const assessment = JSON.parse(content);
        validateAssessment(assessment);

        // Post-processing: clamp score and filter hallucinated citations
        assessment.overallRiskScore = clampScore(assessment.overallRiskScore);
        assessment.evidenceCitations = filterEvidenceCitations(assessment.evidenceCitations);

        return assessment;
    }
}
