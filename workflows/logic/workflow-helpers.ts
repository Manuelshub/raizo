/**
 * @file workflow-helpers.ts
 * @notice Pure helper functions extracted from CRE workflow callbacks.
 * These functions are SDK-independent, making them directly testable
 * in Hardhat's Mocha/CJS test runner without the ESM CRE SDK.
 *
 * Each helper encapsulates one HTTP fetch + parse step from the workflow.
 * Callers (the workflow callbacks) use these helpers via the CRE HTTPClient.
 * Tests can call these helpers directly with a mock fetch function.
 */

import { TelemetryFrame, ThreatAssessment, RegulatoryRule } from "./types";
import { ProtocolDeployment } from "./types";
import { runCompliancePipeline } from "./compliance-logic";
import { ComplianceReport } from "./types";
import {
    HeuristicAnalyzer,
    HEURISTIC_GATE_THRESHOLD,
    SYSTEM_PROMPT,
    runSentinelPipeline,
} from "./threat-logic";
import { runCoordinatorPipeline, parseThreatReportedEvent } from "./coordinator-logic";

/** Simple HTTP response shape for testing */
export interface FetchResponse {
    ok: boolean;
    status: number;
    body: string;
}

/** Minimal HTTP fetcher type — testable without CRE SDK */
export type SimpleFetch = (url: string, opts?: RequestInit) => Promise<FetchResponse>;

// ─── Threat Sentinel helpers ──────────────────────────────────────────────────

export async function fetchTelemetry(
    fetch: SimpleFetch,
    telemetryApiUrl: string,
): Promise<TelemetryFrame> {
    const res = await fetch(telemetryApiUrl, { method: "GET" });
    if (!res.ok) throw new Error(`Telemetry fetch failed: ${res.status}`);
    return JSON.parse(res.body, (_k, v) => {
        // Revive numeric bigint fields
        if (typeof v === "string" && /^\d+$/.test(v) && v.length > 10) return BigInt(v);
        return v;
    });
}

export async function fetchLLMAssessment(
    fetch: SimpleFetch,
    llmApiUrl: string,
    telemetry: TelemetryFrame,
): Promise<ThreatAssessment> {
    const res = await fetch(llmApiUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            system: SYSTEM_PROMPT,
            telemetry: JSON.parse(JSON.stringify(telemetry, (_, v) =>
                typeof v === "bigint" ? v.toString() : v
            )),
        }),
    });
    if (!res.ok) throw new Error(`LLM request failed: ${res.status}`);
    return JSON.parse(res.body);
}

/** Full sentinel pipeline: fetch → heuristic → LLM → report */
export async function runSentinelWorkflow(
    fetch: SimpleFetch,
    config: {
        telemetryApiUrl: string;
        llmApiUrl: string;
        agentId: string;
        targetProtocol: string;
    },
): Promise<{ status: "skipped" | "no_threat" | "reported" | "error"; calldata?: string }> {
    try {
        const telemetry = await fetchTelemetry(fetch, config.telemetryApiUrl);

        // Heuristic gate
        const heuristic = new HeuristicAnalyzer();
        const { baseRiskScore } = heuristic.score(telemetry);
        if (baseRiskScore < HEURISTIC_GATE_THRESHOLD) {
            return { status: "skipped" };
        }

        // LLM assessment
        const assessment = await fetchLLMAssessment(fetch, config.llmApiUrl, telemetry);
        const report = runSentinelPipeline(config.agentId, config.targetProtocol, telemetry, assessment);

        if (!report) return { status: "no_threat" };

        return { status: "reported", calldata: `report:${JSON.stringify(report)}` };
    } catch (e) {
        return { status: "error" };
    }
}

// ─── Compliance Reporter helpers ──────────────────────────────────────────────

export async function fetchComplianceData(
    fetch: SimpleFetch,
    config: {
        rulesApiUrl: string;
        metricsApiUrl: string;
        sanctionsApiUrl: string;
    },
): Promise<{ rules: RegulatoryRule[]; metrics: Record<string, unknown>; sanctions: string[] }> {
    const [rulesRes, metricsRes, sanctionsRes] = await Promise.all([
        fetch(config.rulesApiUrl, { method: "GET" }),
        fetch(config.metricsApiUrl, { method: "GET" }),
        fetch(config.sanctionsApiUrl, { method: "GET" }),
    ]);

    if (!rulesRes.ok) throw new Error(`Rules fetch failed: ${rulesRes.status}`);
    if (!metricsRes.ok) throw new Error(`Metrics fetch failed: ${metricsRes.status}`);
    if (!sanctionsRes.ok) throw new Error(`Sanctions fetch failed: ${sanctionsRes.status}`);

    return {
        rules: JSON.parse(rulesRes.body),
        metrics: JSON.parse(metricsRes.body),
        sanctions: JSON.parse(sanctionsRes.body),
    };
}

/** Full compliance pipeline */
export async function runComplianceWorkflow(
    fetch: SimpleFetch,
    config: { rulesApiUrl: string; metricsApiUrl: string; sanctionsApiUrl: string; chainId: number },
): Promise<{ status: "compliant" | "flagged" | "error"; report?: ComplianceReport }> {
    try {
        const { rules, metrics, sanctions } = await fetchComplianceData(fetch, config);
        const report = runCompliancePipeline(config.chainId, rules, metrics as any, sanctions);
        const status = report.riskSummary.complianceScore === 100 ? "compliant" : "flagged";
        return { status, report };
    } catch (e) {
        return { status: "error" };
    }
}

// ─── Cross-Chain Coordinator helpers ─────────────────────────────────────────

export async function fetchProtocolDeployment(
    fetch: SimpleFetch,
    registryUrl: string,
    protocolAddress: string,
): Promise<ProtocolDeployment> {
    const url = `${registryUrl}?protocol=${protocolAddress}`;
    const res = await fetch(url, { method: "GET" });
    if (!res.ok) throw new Error(`Registry fetch failed: ${res.status}`);
    return JSON.parse(res.body);
}

/** Full coordinator pipeline */
export async function runCoordinatorWorkflow(
    fetch: SimpleFetch,
    eventPayload: any,
    config: {
        deploymentRegistryUrl: string;
        monitoredChainIds: number[];
        monitoredChainSelectors: string[];
    },
): Promise<{ status: "local_only" | "propagated" | "error"; messages?: ReturnType<typeof runCoordinatorPipeline> }> {
    try {
        const event = parseThreatReportedEvent(eventPayload.log ?? eventPayload);
        const deployment = await fetchProtocolDeployment(
            fetch,
            config.deploymentRegistryUrl,
            event.targetProtocol,
        );
        const messages = runCoordinatorPipeline(event, deployment, config.monitoredChainIds);
        return { status: messages.length > 0 ? "propagated" : "local_only", messages };
    } catch (e) {
        return { status: "error" };
    }
}
