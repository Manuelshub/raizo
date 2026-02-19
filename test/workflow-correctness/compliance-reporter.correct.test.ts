/**
 * @file compliance-reporter.correct.test.ts
 * @notice Workflow correctness tests for the Compliance Reporter.
 *
 * Uses `workflow-helpers.ts` to avoid CRE SDK ESM/CJS conflict.
 *
 * Coverage:
 *  D1 - Data Contract: 3 separate HTTP requests (rules, metrics, sanctions)
 *  D2 - Control Flow: compliant / flagged / error return statuses
 *  D4 - On-Chain Write: report struct verifiable from returned report object
 */

import { expect } from "chai";
import nock from "nock";
import {
    runComplianceWorkflow,
    fetchComplianceData,
    SimpleFetch,
    FetchResponse,
} from "../../workflows/logic/workflow-helpers";
import { RegulatoryRule } from "../../workflows/logic/types";

// ─── Shared fetch impl (same pattern as sentinel tests) ───────────────────────

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

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const RULES_URL = "http://localhost:3003/rules";
const METRICS_URL = "http://localhost:3004/metrics";
const SANCTIONS_URL = "http://localhost:3005/sanctions";

const BASE_CFG = {
    rulesApiUrl: RULES_URL,
    metricsApiUrl: METRICS_URL,
    sanctionsApiUrl: SANCTIONS_URL,
    chainId: 1,
};

const AML_VIOLATION_RULE: RegulatoryRule = {
    ruleId: "AML-001",
    framework: "AML",
    version: "1.0",
    effectiveDate: Math.floor(Date.now() / 1000),
    condition: { metric: "tx.valueUSD", operator: "gt", threshold: 10_000 },
    action: { type: "report", severity: "violation", narrative: "High value tx" },
    regulatoryReference: "FATF Rec 10",
    jurisdiction: ["Global"],
};

const SAFE_RULE: RegulatoryRule = {
    ...AML_VIOLATION_RULE,
    ruleId: "AML-SAFE",
    condition: { metric: "tx.valueUSD", operator: "gt", threshold: 1_000_000 },
};

const WARNING_RULE: RegulatoryRule = {
    ...AML_VIOLATION_RULE,
    ruleId: "AML-WARN",
    condition: { metric: "tx.valueUSD", operator: "gt", threshold: 1_000 },
    action: { type: "flag", severity: "warning", narrative: "Warn: elevated tx" },
};

const SANCTIONS_RULE: RegulatoryRule = {
    ...AML_VIOLATION_RULE,
    ruleId: "SANC-001",
    condition: { metric: "sender", operator: "matches", threshold: "" },
};

// ─── Test suite ───────────────────────────────────────────────────────────────

describe("Compliance Reporter — Workflow Correctness", function () {
    beforeEach(function () { nock.cleanAll(); });
    afterEach(function () { nock.cleanAll(); });

    // ─── C-2: Clean path ──────────────────────────────────────────────────────
    it("[C-2] returns compliant when no rules fire", async function () {
        nock("http://localhost:3003").get("/rules").reply(200, JSON.stringify([SAFE_RULE]));
        nock("http://localhost:3004").get("/metrics").reply(200, JSON.stringify({ "tx.valueUSD": 500 }));
        nock("http://localhost:3005").get("/sanctions").reply(200, JSON.stringify([]));

        const result = await runComplianceWorkflow(nodeFetch, BASE_CFG);
        expect(result.status).to.equal("compliant");
        expect(result.report?.riskSummary.complianceScore).to.equal(100);
        expect(result.report?.findings).to.have.length(0);
    });

    // ─── C-1: Violations found ────────────────────────────────────────────────
    it("[C-1] returns flagged when a violation rule fires", async function () {
        nock("http://localhost:3003").get("/rules").reply(200, JSON.stringify([AML_VIOLATION_RULE]));
        nock("http://localhost:3004").get("/metrics").reply(200, JSON.stringify({ "tx.valueUSD": 15_000 }));
        nock("http://localhost:3005").get("/sanctions").reply(200, JSON.stringify([]));

        const result = await runComplianceWorkflow(nodeFetch, BASE_CFG);
        expect(result.status).to.equal("flagged");
        expect(result.report?.findings).to.have.length(1);
        expect(result.report?.findings[0].ruleId).to.equal("AML-001");
        expect(result.report?.findings[0].severity).to.equal("violation");
        // D4: reportId is a valid hex string
        expect(result.report?.metadata.reportId).to.match(/^0x[0-9a-f]+$/i);
    });

    // ─── C-3: Sanctions match ─────────────────────────────────────────────────
    it("[C-3] flags a transaction matching the sanctions list", async function () {
        nock("http://localhost:3003").get("/rules").reply(200, JSON.stringify([SANCTIONS_RULE]));
        nock("http://localhost:3004").get("/metrics").reply(200, JSON.stringify({ sender: "0xdead" }));
        nock("http://localhost:3005").get("/sanctions").reply(200, JSON.stringify(["0xdead", "0xbeef"]));

        const result = await runComplianceWorkflow(nodeFetch, BASE_CFG);
        expect(result.status).to.equal("flagged");
        expect(result.report?.findings).to.have.length(1);
    });

    // ─── D1: Three HTTP requests made ─────────────────────────────────────────
    it("[D1] makes exactly three API requests (rules, metrics, sanctions) per sweep", async function () {
        const rulesScope = nock("http://localhost:3003").get("/rules").reply(200, JSON.stringify([SAFE_RULE]));
        const metricsScope = nock("http://localhost:3004").get("/metrics").reply(200, JSON.stringify({ "tx.valueUSD": 100 }));
        const sanctionsScope = nock("http://localhost:3005").get("/sanctions").reply(200, JSON.stringify([]));

        await fetchComplianceData(nodeFetch, BASE_CFG);

        expect(rulesScope.isDone()).to.be.true;
        expect(metricsScope.isDone()).to.be.true;
        expect(sanctionsScope.isDone()).to.be.true;
    });

    // ─── C-4: Score calculation for mixed findings ────────────────────────────
    it("[C-4] computes score as 100 - violations*20 - warnings*5", async function () {
        // 1 violation + 1 warning → 100 - 20 - 5 = 75
        nock("http://localhost:3003").get("/rules").reply(200, JSON.stringify([AML_VIOLATION_RULE, WARNING_RULE]));
        nock("http://localhost:3004").get("/metrics").reply(200, JSON.stringify({ "tx.valueUSD": 15_000 }));
        nock("http://localhost:3005").get("/sanctions").reply(200, JSON.stringify([]));

        const result = await runComplianceWorkflow(nodeFetch, BASE_CFG);
        expect(result.status).to.equal("flagged");
        expect(result.report?.riskSummary.complianceScore).to.equal(75);
        expect(result.report?.findings).to.have.length(2);
    });

    // ─── C-5: Rules API error ─────────────────────────────────────────────────
    it("[C-5] returns error when the rules API responds with 500", async function () {
        nock("http://localhost:3003").get("/rules").reply(500, "Internal Server Error");

        const result = await runComplianceWorkflow(nodeFetch, BASE_CFG);
        expect(result.status).to.equal("error");
    });
});
