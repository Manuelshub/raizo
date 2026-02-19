/**
 * @file nock-handlers.ts
 * @notice Reusable nock interceptors for workflow correctness tests.
 * Each factory function returns a configured nock scope that intercepts
 * the specified API URL and verifies request shape.
 *
 * Usage:
 *   const scope = interceptTelemetryApi("http://localhost:3001", telemetryFixture);
 *   // ... run workflow ...
 *   scope.isDone(); // true if request was made
 */

import nock from "nock";
import { TelemetryFrame, ThreatAssessment, RegulatoryRule } from "../../workflows/logic/types";
import { ProtocolDeployment } from "../../workflows/logic/types";

// ─── Threat Sentinel ─────────────────────────────────────────────────────────

export function interceptTelemetryApi(
    baseUrl: string,
    response: TelemetryFrame,
): nock.Scope {
    const url = new URL(baseUrl);
    return nock(url.origin)
        .get(url.pathname)
        .reply(200, JSON.stringify(response, (_k, v) =>
            typeof v === "bigint" ? v.toString() : v
        ), { "Content-Type": "application/json" });
}

export function interceptLlmApi(
    baseUrl: string,
    response: ThreatAssessment,
    validateRequest?: (body: Record<string, unknown>) => void,
): nock.Scope {
    const url = new URL(baseUrl);
    return nock(url.origin)
        .post(url.pathname)
        .reply(function (_uri, requestBody) {
            if (validateRequest) {
                validateRequest(requestBody as Record<string, unknown>);
            }
            return [200, JSON.stringify(response), { "Content-Type": "application/json" }];
        });
}

// ─── Compliance Reporter ──────────────────────────────────────────────────────

export function interceptRulesApi(
    baseUrl: string,
    rules: RegulatoryRule[],
): nock.Scope {
    const url = new URL(baseUrl);
    return nock(url.origin)
        .get(url.pathname)
        .reply(200, JSON.stringify(rules), { "Content-Type": "application/json" });
}

export function interceptMetricsApi(
    baseUrl: string,
    metrics: Record<string, number>,
): nock.Scope {
    const url = new URL(baseUrl);
    return nock(url.origin)
        .get(url.pathname)
        .reply(200, JSON.stringify(metrics), { "Content-Type": "application/json" });
}

export function interceptSanctionsApi(
    baseUrl: string,
    sanctionedAddresses: string[],
): nock.Scope {
    const url = new URL(baseUrl);
    return nock(url.origin)
        .get(url.pathname)
        .reply(200, JSON.stringify(sanctionedAddresses), { "Content-Type": "application/json" });
}

// ─── Cross-Chain Coordinator ──────────────────────────────────────────────────

export function interceptDeploymentRegistry(
    baseUrl: string,
    protocol: string,
    deployment: ProtocolDeployment,
): nock.Scope {
    const url = new URL(baseUrl);
    return nock(url.origin)
        .get(url.pathname)
        .query({ protocol })
        .reply(200, JSON.stringify(deployment), { "Content-Type": "application/json" });
}

// ─── Error responses ──────────────────────────────────────────────────────────

export function interceptApiError(
    baseUrl: string,
    method: "GET" | "POST" = "GET",
    statusCode = 500,
): nock.Scope {
    const url = new URL(baseUrl);
    if (method === "POST") {
        return nock(url.origin).post(url.pathname).reply(statusCode, "Internal Server Error");
    }
    return nock(url.origin).get(url.pathname).reply(statusCode, "Internal Server Error");
}
