/**
 * @file threat-sentinel.correct.test.ts
 * @notice Workflow correctness tests for the Threat Sentinel.
 *
 * Strategy: rather than importing the CRE workflow callback (which imports the
 * ESM-only CRE SDK, incompatible with Hardhat's CJS runner), we test the inner
 * logic extracted to `workflows/logic/workflow-helpers.ts`.
 *
 * Coverage:
 *  D1 - Data Contract: LLM request body contains system prompt + BigInt-serialized telemetry
 *  D2 - Control Flow: skipped (below gate) / no_threat (low LLM) / reported (high LLM)
 *  D4 - On-Chain Write: report struct fields are correct (agentId, targetProtocol, action)
 */

import { expect } from "chai";
import nock from "nock";
import {
    runSentinelWorkflow,
    fetchTelemetry,
    fetchLLMAssessment,
    SimpleFetch,
    FetchResponse,
} from "../../workflows/logic/workflow-helpers";
import {
    buildCleanTelemetry,
    buildFlashLoanDrainTelemetry,
    buildBelowGateTelemetry,
} from "../fixtures/telemetry.fixtures";
import { ThreatAssessment } from "../../workflows/logic/types";
import { HEURISTIC_GATE_THRESHOLD } from "../../workflows/logic/threat-logic";

/** Serialize BigInt as string for JSON (fixtures contain BigInt fields) */
const bigint = (_k: string, v: unknown) => (typeof v === "bigint" ? v.toString() : v);
const toJson = (obj: unknown) => JSON.stringify(obj, bigint);

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const TELEMETRY_URL = "http://localhost:3001/telemetry";
const LLM_URL = "http://localhost:3002/llm";

const SENTINEL_CONFIG = {
    telemetryApiUrl: TELEMETRY_URL,
    llmApiUrl: LLM_URL,
    agentId: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    targetProtocol: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
};

function buildHighRiskAssessment(overrides?: Partial<ThreatAssessment>): ThreatAssessment {
    return {
        overallRiskScore: 0.96,
        threatDetected: true,
        threats: [{ category: "flash_loan", confidence: 0.96, indicators: ["TVL drop"], estimatedImpactUSD: 1_000_000 }],
        recommendedAction: "PAUSE",
        reasoning: "Flash loan drain detected.",
        evidenceCitations: ["tvl.delta1h"],
        ...overrides,
    };
}

/** A simple fetch implementation that uses nock-intercepted HTTP under the hood */
const nodeFetch: SimpleFetch = async (url, opts) => {
    const http = await import("http");
    return new Promise<FetchResponse>((resolve, reject) => {
        const parsedUrl = new URL(url);
        const reqBody = opts?.body as string | undefined;
        const reqOptions: import("http").RequestOptions = {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port ? parseInt(parsedUrl.port) : 80,
            path: parsedUrl.pathname + parsedUrl.search,
            method: opts?.method ?? "GET",
            headers: {
                ...(opts?.headers as Record<string, string> | undefined),
                ...(reqBody ? { "Content-Length": Buffer.byteLength(reqBody).toString() } : {}),
            },
        };
        const req = http.request(reqOptions, (res) => {
            let body = "";
            res.on("data", (chunk) => { body += chunk; });
            res.on("end", () => resolve({
                ok: (res.statusCode ?? 500) >= 200 && (res.statusCode ?? 500) < 300,
                status: res.statusCode ?? 500,
                body,
            }));
        });
        req.on("error", reject);
        if (reqBody) req.write(reqBody);
        req.end();
    });
};

// ─── Test suite ───────────────────────────────────────────────────────────────

describe("Threat Sentinel — Workflow Correctness", function () {
    beforeEach(function () { nock.cleanAll(); });
    afterEach(function () { nock.cleanAll(); });

    // ─── T-2: Heuristic gate suppresses LLM call ──────────────────────────────
    it("[T-2] skips LLM when heuristic score is below gate threshold", async function () {
        nock("http://localhost:3001").get("/telemetry")
            .reply(200, toJson(buildBelowGateTelemetry()), { "Content-Type": "application/json" });
        // No LLM interceptor — exception if LLM is hit

        const result = await runSentinelWorkflow(nodeFetch, SENTINEL_CONFIG);
        expect(result.status).to.equal("skipped");
    });

    // ─── T-3: LLM returns low score → no report ───────────────────────────────
    it("[T-3] returns no_threat when LLM score is below action threshold", async function () {
        nock("http://localhost:3001").get("/telemetry")
            .reply(200, toJson(buildFlashLoanDrainTelemetry()), { "Content-Type": "application/json" });
        nock("http://localhost:3002").post("/llm")
            .reply(200, JSON.stringify({
                overallRiskScore: 0.35,
                threatDetected: false,
                threats: [],
                recommendedAction: "NONE",
                reasoning: "Normal.",
                evidenceCitations: [],
            }), { "Content-Type": "application/json" });

        const result = await runSentinelWorkflow(nodeFetch, SENTINEL_CONFIG);
        expect(result.status).to.equal("no_threat");
    });

    // ─── T-1: High-risk path → report returned ────────────────────────────────
    it("[T-1] returns reported with report payload when threat is detected", async function () {
        nock("http://localhost:3001").get("/telemetry")
            .reply(200, toJson(buildFlashLoanDrainTelemetry()), { "Content-Type": "application/json" });
        nock("http://localhost:3002").post("/llm")
            .reply(200, toJson(buildHighRiskAssessment()), { "Content-Type": "application/json" });

        const result = await runSentinelWorkflow(nodeFetch, SENTINEL_CONFIG);
        expect(result.status).to.equal("reported");
        expect(result.calldata).to.include("agentId");
        expect(result.calldata).to.include("targetProtocol");
    });

    // ─── T-7: BigInt serialization in LLM body ────────────────────────────────
    it("[T-7] serializes BigInt telemetry fields as strings in LLM request body", async function () {
        const telemetry = buildFlashLoanDrainTelemetry();
        let capturedBody: Record<string, unknown> | null = null;

        nock("http://localhost:3002").post("/llm").reply(function (_uri, body) {
            capturedBody = body as Record<string, unknown>;
            return [200, JSON.stringify(buildHighRiskAssessment()), { "Content-Type": "application/json" }];
        });

        await fetchLLMAssessment(nodeFetch, LLM_URL, telemetry);

        expect(capturedBody).to.not.be.null;
        const tel = (capturedBody as any).telemetry;
        expect(tel).to.exist;
        // All BigInt fields must land as strings
        expect(tel.tvl?.current).to.be.a("string");
        expect(tel.transactionMetrics?.volumeUSD).to.be.a("string");
        expect(tel.priceData?.tokenPrice).to.be.a("string");
    });

    // ─── T-4: Escalation table overrides LLM action ───────────────────────────
    it("[T-4] escalation table overrides LLM recommendedAction regardless of LLM output", async function () {
        nock("http://localhost:3001").get("/telemetry")
            .reply(200, toJson(buildFlashLoanDrainTelemetry()), { "Content-Type": "application/json" });
        nock("http://localhost:3002").post("/llm")
            // LLM says PAUSE but score=0.72 → escalation table should override to RATE_LIMIT
            .reply(200, toJson(buildHighRiskAssessment({ overallRiskScore: 0.72, recommendedAction: "PAUSE" })), { "Content-Type": "application/json" });

        const result = await runSentinelWorkflow(nodeFetch, SENTINEL_CONFIG);
        expect(result.status).to.equal("reported");
        // D4: report must have action derived from escalation table (RATE_LIMIT for 0.72)
        const report = JSON.parse(result.calldata!.replace("report:", ""));
        // buildThreatReport stores action as numeric enum (ACTION_ENUM["RATE_LIMIT"] = 1)
        expect(report.action).to.equal(1); // 1 = RATE_LIMIT in ACTION_ENUM
    });

    // ─── T-5: Telemetry API error ─────────────────────────────────────────────
    it("[T-5] returns error status when telemetry API responds with 500", async function () {
        nock("http://localhost:3001").get("/telemetry").reply(500, "Internal Server Error");

        const result = await runSentinelWorkflow(nodeFetch, SENTINEL_CONFIG);
        expect(result.status).to.equal("error");
    });
});
