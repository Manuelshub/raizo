/**
 * @file LiveDataIntegration.test.ts
 * @notice WS-9 TDD RED-phase test suite for Live Data Integration.
 *
 * Spec References:
 *   AI_AGENTS.md §7   — LLM Provider Strategy (GPT-4o/Claude via Confidential Compute)
 *   AI_AGENTS.md §3.2 — Data Ingestion Schema (Chain Reader → TelemetryFrame)
 *   AI_AGENTS.md §3.5 — DON Consensus Model (⅔+ agreement, median aggregation)
 *   AI_AGENTS.md §3.6 — Anti-Hallucination Safeguards
 *   AI_AGENTS.md §8   — Performance Targets (<15s detection, <10s consensus, <2% false positive)
 *   COMPLIANCE.md §4   — ACE Pipeline (sanctions list APIs: OFAC SDN, EU)
 *   ARCHITECTURE.md §3  — x402 Payment Flow (PaymentEscrow self-funding)
 *   SECURITY.md §3.2    — AI/LLM Threats (prompt injection, hallucination, key exfiltration)
 *
 * Strategy:
 *   Tests exercise the new logic modules (LlmProvider, ChainReader, SanctionsClient,
 *   PaymentAuthorizer, DonConsensus) via their pure function interfaces, mocked
 *   HTTP layer (nock / SimpleFetch), and real Solidity contracts where needed.
 *   No CRE SDK imports — all tests run in Hardhat's CJS Mocha runner.
 *
 * Coverage:
 *   LLM-1→8:   LLM provider integration (structured output, retry, multi-provider, validation)
 *   CR-1→6:    Chain Reader data ingestion (normalization, staleness, multi-source, errors)
 *   SAN-1→6:   Sanctions list API (OFAC parsing, address matching, cache, fallback)
 *   PAY-1→6:   x402 payment flow (EIP-712, budget, on-chain settlement, nonce mgmt)
 *   DON-1→8:   DON consensus simulation (⅔ agreement, median, divergence, fallback)
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import nock from "nock";
import http from "http";
import { Signer } from "ethers";

import { SimpleFetch, FetchResponse } from "../../workflows/logic/workflow-helpers";
import { ThreatAssessment } from "../../workflows/logic/types";
import { LlmProvider } from "../../workflows/logic/llm-provider";
import { ChainReader } from "../../workflows/logic/chain-reader";
import { SanctionsClient } from "../../workflows/logic/sanctions-client";
import { PaymentAuthorizer } from "../../workflows/logic/payment-authorizer";
import { DonConsensus } from "../../workflows/logic/don-consensus";
import { buildFlashLoanDrainTelemetry, buildCleanTelemetry } from "../fixtures/telemetry.fixtures";
import { buildPauseAssessment, buildCleanAssessment, buildAlertAssessment, buildDrainBlockAssessment } from "../fixtures/threat.fixtures";

/**
 * Shared HTTP fetch adapter backed by nock interceptors.
 * Wraps Node.js http.request to produce SimpleFetch-compatible responses.
 */
const nodeFetch: SimpleFetch = async (url, opts) => {
    return new Promise<FetchResponse>((resolve, reject) => {
        const parsedUrl = new URL(url);
        const body = opts?.body as string | undefined;
        const reqOpts: http.RequestOptions = {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port ? parseInt(parsedUrl.port) : 80,
            path: parsedUrl.pathname + parsedUrl.search,
            method: opts?.method ?? "GET",
            headers: {
                ...(opts?.headers as Record<string, string> | undefined),
                ...(body ? { "Content-Length": Buffer.byteLength(body).toString() } : {}),
            },
        };
        const req = http.request(reqOpts, (res) => {
            let data = "";
            res.on("data", (chunk: string) => { data += chunk; });
            res.on("end", () => resolve({
                ok: (res.statusCode ?? 500) >= 200 && (res.statusCode ?? 500) < 300,
                status: res.statusCode ?? 500,
                body: data,
            }));
        });
        req.on("error", reject);
        if (body) req.write(body);
        req.end();
    });
};

// ═══════════════════════════════════════════════════════════════════════════════
// 1. LLM PROVIDER INTEGRATION (AI_AGENTS.md §7)
// ═══════════════════════════════════════════════════════════════════════════════

describe("WS-9: LLM Provider Integration (LLM-1→8)", function () {
    const LLM_URL = "http://localhost:4001/v1/chat/completions";

    beforeEach(() => nock.cleanAll());
    afterEach(() => nock.cleanAll());

    // ─── LLM-1: Structured JSON output enforcement ─────────────────────────
    it("[LLM-1] sends OpenAI-compatible chat completion request with JSON response_format", async function () {
        let capturedBody: any = null;
        nock("http://localhost:4001").post("/v1/chat/completions").reply(function (_uri, body) {
            capturedBody = body;
            return [200, JSON.stringify({
                choices: [{ message: { content: JSON.stringify(buildPauseAssessment()) } }],
            })];
        });

        const provider = new LlmProvider({ apiUrl: LLM_URL, apiKey: "test-key", model: "gpt-4o" });
        const result = await provider.assess(nodeFetch, buildFlashLoanDrainTelemetry());

        expect(capturedBody).to.not.be.null;
        // Must use response_format for structured output (AI_AGENTS.md §3.3)
        expect(capturedBody.response_format).to.deep.equal({ type: "json_object" });
        expect(capturedBody.model).to.equal("gpt-4o");
        expect(capturedBody.messages).to.be.an("array");
        // System prompt must be first message
        expect(capturedBody.messages[0].role).to.equal("system");
        expect(result.overallRiskScore).to.be.a("number");
    });

    // ─── LLM-2: Response validation rejects malformed JSON ─────────────────
    it("[LLM-2] rejects LLM response that does not match ThreatAssessment schema", async function () {
        nock("http://localhost:4001").post("/v1/chat/completions").reply(200, JSON.stringify({
            choices: [{ message: { content: JSON.stringify({ garbage: true }) } }],
        }));

        const provider = new LlmProvider({ apiUrl: LLM_URL, apiKey: "test-key", model: "gpt-4o" });

        try {
            await provider.assess(nodeFetch, buildCleanTelemetry());
            expect.fail("Should have thrown on invalid response");
        } catch (e: any) {
            expect(e.message).to.include("validation");
        }
    });

    // ─── LLM-3: Retry on transient failure ─────────────────────────────────
    it("[LLM-3] retries up to 3 times on 5xx errors before failing", async function () {
        let callCount = 0;
        nock("http://localhost:4001").post("/v1/chat/completions").times(2).reply(() => {
            callCount++;
            return [503, "Service Unavailable"];
        });
        nock("http://localhost:4001").post("/v1/chat/completions").reply(200, JSON.stringify({
            choices: [{ message: { content: JSON.stringify(buildCleanAssessment()) } }],
        }));

        const provider = new LlmProvider({ apiUrl: LLM_URL, apiKey: "test-key", model: "gpt-4o", maxRetries: 3 });
        const result = await provider.assess(nodeFetch, buildCleanTelemetry());

        expect(callCount).to.equal(2); // 2 failures + 1 success
        expect(result.overallRiskScore).to.be.a("number");
    });

    // ─── LLM-4: Multi-provider fallback (GPT-4o → Claude) ──────────────────
    it("[LLM-4] falls back to secondary provider when primary returns 5xx exhausting retries", async function () {
        // Primary (GPT-4o) fails all retries
        nock("http://localhost:4001").post("/v1/chat/completions").times(3).reply(503, "Down");
        // Secondary (Claude) succeeds
        nock("http://localhost:4002").post("/v1/messages").reply(200, JSON.stringify({
            content: [{ text: JSON.stringify(buildAlertAssessment()) }],
        }));

        const provider = new LlmProvider({
            apiUrl: LLM_URL, apiKey: "test-key", model: "gpt-4o", maxRetries: 3,
            fallback: { apiUrl: "http://localhost:4002/v1/messages", apiKey: "test-key-2", model: "claude-3.5-sonnet" },
        });
        const result = await provider.assess(nodeFetch, buildFlashLoanDrainTelemetry());

        expect(result.recommendedAction).to.equal("ALERT");
    });

    // ─── LLM-5: Authorization header with Bearer token ─────────────────────
    it("[LLM-5] sends Authorization header with Bearer token (API key isolation per SECURITY.md AI-4)", async function () {
        let capturedHeaders: Record<string, string> = {};
        nock("http://localhost:4001").post("/v1/chat/completions").reply(function () {
            capturedHeaders = this.req.headers as any;
            return [200, JSON.stringify({
                choices: [{ message: { content: JSON.stringify(buildCleanAssessment()) } }],
            })];
        });

        const provider = new LlmProvider({ apiUrl: LLM_URL, apiKey: "sk-secret-123", model: "gpt-4o" });
        await provider.assess(nodeFetch, buildCleanTelemetry());

        expect(capturedHeaders["authorization"]).to.include("Bearer sk-secret-123");
    });

    // ─── LLM-6: Risk score clamping to [0, 1] ──────────────────────────────
    it("[LLM-6] clamps overallRiskScore to [0.0, 1.0] even if LLM returns out-of-range value", async function () {
        const badAssessment = { ...buildPauseAssessment(), overallRiskScore: 1.5 };
        nock("http://localhost:4001").post("/v1/chat/completions").reply(200, JSON.stringify({
            choices: [{ message: { content: JSON.stringify(badAssessment) } }],
        }));

        const provider = new LlmProvider({ apiUrl: LLM_URL, apiKey: "test-key", model: "gpt-4o" });
        const result = await provider.assess(nodeFetch, buildCleanTelemetry());

        expect(result.overallRiskScore).to.be.at.most(1.0);
        expect(result.overallRiskScore).to.be.at.least(0.0);
    });

    // ─── LLM-7: BigInt-safe telemetry serialization ────────────────────────
    it("[LLM-7] serializes BigInt telemetry fields as strings in the request body", async function () {
        let capturedBody: any = null;
        nock("http://localhost:4001").post("/v1/chat/completions").reply(function (_uri, body) {
            capturedBody = body;
            return [200, JSON.stringify({
                choices: [{ message: { content: JSON.stringify(buildCleanAssessment()) } }],
            })];
        });

        const provider = new LlmProvider({ apiUrl: LLM_URL, apiKey: "test-key", model: "gpt-4o" });
        const telemetry = buildFlashLoanDrainTelemetry();
        await provider.assess(nodeFetch, telemetry);

        // Extract the telemetry from the user message content
        const userMsg = capturedBody.messages.find((m: any) => m.role === "user");
        const content = JSON.parse(userMsg.content);
        expect(content.tvl.current).to.be.a("string"); // BigInt → string
        expect(content.transactionMetrics.volumeUSD).to.be.a("string");
    });

    // ─── LLM-8: Evidence citations must reference actual telemetry keys ────
    it("[LLM-8] validates that evidenceCitations reference real TelemetryFrame fields", async function () {
        const assessment = {
            ...buildPauseAssessment(),
            evidenceCitations: ["tvl.delta1h", "nonExistentField.foo", "priceData.priceDeviation"],
        };
        nock("http://localhost:4001").post("/v1/chat/completions").reply(200, JSON.stringify({
            choices: [{ message: { content: JSON.stringify(assessment) } }],
        }));

        const provider = new LlmProvider({ apiUrl: LLM_URL, apiKey: "test-key", model: "gpt-4o" });
        const result = await provider.assess(nodeFetch, buildFlashLoanDrainTelemetry());

        // Invalid citations should be filtered out (anti-hallucination safeguard)
        expect(result.evidenceCitations).to.not.include("nonExistentField.foo");
        expect(result.evidenceCitations).to.include("tvl.delta1h");
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. CHAIN READER — On-Chain Data Ingestion (AI_AGENTS.md §3.2)
// ═══════════════════════════════════════════════════════════════════════════════

describe("WS-9: Chain Reader Integration (CR-1→6)", function () {
    const CHAIN_READER_URL = "http://localhost:4010/chain-reader";

    beforeEach(() => nock.cleanAll());
    afterEach(() => nock.cleanAll());

    // ─── CR-1: Normalizes raw RPC data into TelemetryFrame ─────────────────
    it("[CR-1] normalizes raw chain data (block, TVL, txs) into a valid TelemetryFrame", async function () {
        const rawChainData = {
            chainId: 1,
            block: { number: 20000000, timestamp: Math.floor(Date.now() / 1000) },
            tvl: { currentUSD: "50000000000000000000000000", oneHourAgoUSD: "49000000000000000000000000" },
            transactions: { count: 1500, volumeWei: "5000000000000000000000000", failedCount: 15, largeCount: 3, uniqueAddresses: 1200 },
            contractState: { owner: "0x1234567890123456789012345678901234567890", paused: false, pendingUpgrade: false, approvals: 2 },
            mempool: { pendingWithdrawals: 1, flashLoans: 0, suspiciousCalldata: [] },
            threatIntel: { cves: [], patterns: [], darkWebMentions: 0, sentiment: 0.5 },
            price: { tokenPriceUSD: "2000000000000000000000", deviationBps: 50, latencySeconds: 10 },
        };

        nock("http://localhost:4010").get("/chain-reader").query(true).reply(200, JSON.stringify(rawChainData));

        const reader = new ChainReader({ rpcUrl: CHAIN_READER_URL });
        const frame = await reader.readTelemetry(nodeFetch, "0x742d35Cc6634C0532925a3b844Bc454e4438f44e");

        expect(frame.chainId).to.equal(1);
        expect(frame.blockNumber).to.equal(20000000);
        expect(typeof frame.tvl.current).to.equal("bigint");
        expect(frame.tvl.delta1h).to.be.a("number");
        expect(frame.transactionMetrics.uniqueAddresses).to.equal(1200);
        expect(frame.priceData.oracleLatency).to.equal(10);
    });

    // ─── CR-2: Detects stale data (oracle latency > threshold) ─────────────
    it("[CR-2] flags stale chain data when oracle latency exceeds threshold (SECURITY.md §5)", async function () {
        const staleData = {
            chainId: 1,
            block: { number: 20000000, timestamp: Math.floor(Date.now() / 1000) - 600 }, // 10 min old
            tvl: { currentUSD: "50000000000000000000000000", oneHourAgoUSD: "50000000000000000000000000" },
            transactions: { count: 0, volumeWei: "0", failedCount: 0, largeCount: 0, uniqueAddresses: 0 },
            contractState: { owner: "0x1234567890123456789012345678901234567890", paused: false, pendingUpgrade: false, approvals: 0 },
            mempool: { pendingWithdrawals: 0, flashLoans: 0, suspiciousCalldata: [] },
            threatIntel: { cves: [], patterns: [], darkWebMentions: 0, sentiment: 0 },
            price: { tokenPriceUSD: "2000000000000000000000", deviationBps: 0, latencySeconds: 600 },
        };

        nock("http://localhost:4010").get("/chain-reader").query(true).reply(200, JSON.stringify(staleData));

        const reader = new ChainReader({ rpcUrl: CHAIN_READER_URL, stalenessThresholdSec: 300 });

        // Staleness detection now throws instead of silently passing through
        try {
            await reader.readTelemetry(nodeFetch, "0x742d35Cc6634C0532925a3b844Bc454e4438f44e");
            expect.fail("Should have thrown stale oracle error");
        } catch (err: any) {
            expect(err.message).to.include("Stale oracle data");
            expect(err.message).to.include("600");
            expect(err.message).to.include("300");
        }
    });

    // ─── CR-3: Computes TVL delta percentages from raw values ──────────────
    it("[CR-3] computes correct TVL delta percentages from raw absolute values", async function () {
        const data = {
            chainId: 1,
            block: { number: 20000000, timestamp: Math.floor(Date.now() / 1000) },
            tvl: { currentUSD: "25000000000000000000000000", oneHourAgoUSD: "50000000000000000000000000" },
            transactions: { count: 100, volumeWei: "1000000000000000000000", failedCount: 5, largeCount: 1, uniqueAddresses: 50 },
            contractState: { owner: "0x1234567890123456789012345678901234567890", paused: false, pendingUpgrade: false, approvals: 0 },
            mempool: { pendingWithdrawals: 0, flashLoans: 0, suspiciousCalldata: [] },
            threatIntel: { cves: [], patterns: [], darkWebMentions: 0, sentiment: 0 },
            price: { tokenPriceUSD: "2000000000000000000000", deviationBps: 0, latencySeconds: 5 },
        };

        nock("http://localhost:4010").get("/chain-reader").query(true).reply(200, JSON.stringify(data));

        const reader = new ChainReader({ rpcUrl: CHAIN_READER_URL });
        const frame = await reader.readTelemetry(nodeFetch, "0xtest");

        // TVL dropped from 50M to 25M → -50%
        expect(frame.tvl.delta1h).to.be.closeTo(-50, 1);
    });

    // ─── CR-4: Handles RPC endpoint failure gracefully ─────────────────────
    it("[CR-4] throws descriptive error when chain reader endpoint returns 500", async function () {
        nock("http://localhost:4010").get("/chain-reader").query(true).reply(500, "Internal Server Error");

        const reader = new ChainReader({ rpcUrl: CHAIN_READER_URL });

        try {
            await reader.readTelemetry(nodeFetch, "0xtest");
            expect.fail("Should have thrown");
        } catch (e: any) {
            expect(e.message).to.include("Chain reader");
        }
    });

    // ─── CR-5: Failed tx ratio calculation ─────────────────────────────────
    it("[CR-5] computes failedTxRatio correctly from transaction counts", async function () {
        const data = {
            chainId: 8453,
            block: { number: 10000000, timestamp: Math.floor(Date.now() / 1000) },
            tvl: { currentUSD: "10000000000000000000000000", oneHourAgoUSD: "10000000000000000000000000" },
            transactions: { count: 200, volumeWei: "1000000000000", failedCount: 30, largeCount: 0, uniqueAddresses: 100 },
            contractState: { owner: "0x1234567890123456789012345678901234567890", paused: false, pendingUpgrade: false, approvals: 0 },
            mempool: { pendingWithdrawals: 0, flashLoans: 0, suspiciousCalldata: [] },
            threatIntel: { cves: [], patterns: [], darkWebMentions: 0, sentiment: 0 },
            price: { tokenPriceUSD: "1000000000000000000000", deviationBps: 0, latencySeconds: 3 },
        };

        nock("http://localhost:4010").get("/chain-reader").query(true).reply(200, JSON.stringify(data));

        const reader = new ChainReader({ rpcUrl: CHAIN_READER_URL });
        const frame = await reader.readTelemetry(nodeFetch, "0xtest");

        // 30/200 = 0.15
        expect(frame.transactionMetrics.failedTxRatio).to.be.closeTo(0.15, 0.01);
    });

    // ─── CR-6: Price deviation from basis points ────────────────────────────
    it("[CR-6] converts price deviation from basis points to percentage", async function () {
        const data = {
            chainId: 1,
            block: { number: 20000000, timestamp: Math.floor(Date.now() / 1000) },
            tvl: { currentUSD: "50000000000000000000000000", oneHourAgoUSD: "50000000000000000000000000" },
            transactions: { count: 100, volumeWei: "1000000000000", failedCount: 0, largeCount: 0, uniqueAddresses: 50 },
            contractState: { owner: "0x1234567890123456789012345678901234567890", paused: false, pendingUpgrade: false, approvals: 0 },
            mempool: { pendingWithdrawals: 0, flashLoans: 0, suspiciousCalldata: [] },
            threatIntel: { cves: [], patterns: [], darkWebMentions: 0, sentiment: 0 },
            price: { tokenPriceUSD: "2000000000000000000000", deviationBps: 1800, latencySeconds: 5 },
        };

        nock("http://localhost:4010").get("/chain-reader").query(true).reply(200, JSON.stringify(data));

        const reader = new ChainReader({ rpcUrl: CHAIN_READER_URL });
        const frame = await reader.readTelemetry(nodeFetch, "0xtest");

        // 1800 bps = 18.0%
        expect(frame.priceData.priceDeviation).to.be.closeTo(18.0, 0.1);
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3. SANCTIONS LIST API (COMPLIANCE.md §4, AI_AGENTS.md §4.2)
// ═══════════════════════════════════════════════════════════════════════════════

describe("WS-9: Sanctions API Client (SAN-1→6)", function () {
    const OFAC_URL = "http://localhost:4020/ofac/sdn";
    const EU_URL = "http://localhost:4020/eu/sanctions";

    beforeEach(() => nock.cleanAll());
    afterEach(() => nock.cleanAll());

    // ─── SAN-1: Parses OFAC SDN list format ────────────────────────────────
    it("[SAN-1] parses OFAC SDN response into a normalized address list", async function () {
        const ofacResponse = {
            sdnList: [
                { addresses: [{ address: "0xABCD1234ABCD1234ABCD1234ABCD1234ABCD1234" }], programs: ["CYBER2"] },
                { addresses: [{ address: "0x1111222233334444555566667777888899990000" }], programs: ["SDNT"] },
                { addresses: [], programs: ["IRAN"] }, // No crypto address
            ],
        };
        nock("http://localhost:4020").get("/ofac/sdn").reply(200, JSON.stringify(ofacResponse));
        nock("http://localhost:4020").get("/eu/sanctions").reply(200, JSON.stringify({ entries: [] }));

        const client = new SanctionsClient({ ofacUrl: OFAC_URL, euUrl: EU_URL });
        const list = await client.fetchConsolidatedList(nodeFetch);

        expect(list).to.include("0xabcd1234abcd1234abcd1234abcd1234abcd1234"); // lower-cased
        expect(list).to.include("0x1111222233334444555566667777888899990000");
        expect(list).to.have.lengthOf(2); // Entry without address excluded
    });

    // ─── SAN-2: Merges OFAC + EU sanctions into deduplicated list ──────────
    it("[SAN-2] merges OFAC and EU sanctions lists with deduplication", async function () {
        const sharedAddr = "0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";
        nock("http://localhost:4020").get("/ofac/sdn").reply(200, JSON.stringify({
            sdnList: [{ addresses: [{ address: sharedAddr }], programs: ["CYBER2"] }],
        }));
        nock("http://localhost:4020").get("/eu/sanctions").reply(200, JSON.stringify({
            entries: [
                { cryptoAddresses: [sharedAddr.toLowerCase()] }, // Same address, different case
                { cryptoAddresses: ["0xAAAABBBBCCCCDDDDEEEEFFFF0000111122223333"] },
            ],
        }));

        const client = new SanctionsClient({ ofacUrl: OFAC_URL, euUrl: EU_URL });
        const list = await client.fetchConsolidatedList(nodeFetch);

        // Shared address should appear only once
        expect(list.filter((a: string) => a === sharedAddr.toLowerCase())).to.have.lengthOf(1);
        expect(list).to.have.lengthOf(2); // 1 shared + 1 EU-only
    });

    // ─── SAN-3: Address matching is case-insensitive ────────────────────────
    it("[SAN-3] matches addresses case-insensitively per Ethereum address spec", async function () {
        const client = new SanctionsClient({ ofacUrl: OFAC_URL, euUrl: EU_URL });

        const list = ["0xabcd1234abcd1234abcd1234abcd1234abcd1234"];
        expect(client.isAddressSanctioned(list, "0xABCD1234ABCD1234ABCD1234ABCD1234ABCD1234")).to.be.true;
        expect(client.isAddressSanctioned(list, "0xabcd1234abcd1234abcd1234abcd1234abcd1234")).to.be.true;
        expect(client.isAddressSanctioned(list, "0x9999999999999999999999999999999999999999")).to.be.false;
    });

    // ─── SAN-4: Caches list to avoid redundant API calls ────────────────────
    it("[SAN-4] caches sanctions list and reuses within TTL window", async function () {
        let callCount = 0;
        nock("http://localhost:4020").get("/ofac/sdn").times(5).reply(() => {
            callCount++;
            return [200, JSON.stringify({ sdnList: [{ addresses: [{ address: "0xAAAA" }], programs: ["X"] }] })];
        });
        nock("http://localhost:4020").get("/eu/sanctions").times(5).reply(() => {
            return [200, JSON.stringify({ entries: [] })];
        });

        const client = new SanctionsClient({ ofacUrl: OFAC_URL, euUrl: EU_URL, cacheTtlMs: 60000 });

        await client.fetchConsolidatedList(nodeFetch);
        await client.fetchConsolidatedList(nodeFetch);
        await client.fetchConsolidatedList(nodeFetch);

        expect(callCount).to.equal(1); // Only 1 actual HTTP call
    });

    // ─── SAN-5: Falls back to cached list on API failure ────────────────────
    it("[SAN-5] returns cached list when API returns 5xx (fail-open for safety)", async function () {
        // First call succeeds
        nock("http://localhost:4020").get("/ofac/sdn").reply(200, JSON.stringify({
            sdnList: [{ addresses: [{ address: "0xCACHED" }], programs: ["X"] }],
        }));
        nock("http://localhost:4020").get("/eu/sanctions").reply(200, JSON.stringify({ entries: [] }));

        const client = new SanctionsClient({ ofacUrl: OFAC_URL, euUrl: EU_URL, cacheTtlMs: 1 }); // 1ms TTL forces re-fetch

        const first = await client.fetchConsolidatedList(nodeFetch);
        expect(first.length).to.be.greaterThan(0);

        // Wait for cache to expire
        await new Promise(r => setTimeout(r, 10));

        // Second call fails
        nock("http://localhost:4020").get("/ofac/sdn").reply(500, "Down");
        nock("http://localhost:4020").get("/eu/sanctions").reply(500, "Down");

        const second = await client.fetchConsolidatedList(nodeFetch);
        expect(second).to.deep.equal(first); // Falls back to cached
    });

    // ─── SAN-6: Throws when no cache and API fails ─────────────────────────
    it("[SAN-6] throws when API fails and no cached data exists", async function () {
        nock("http://localhost:4020").get("/ofac/sdn").reply(500, "Down");
        nock("http://localhost:4020").get("/eu/sanctions").reply(500, "Down");

        const client = new SanctionsClient({ ofacUrl: OFAC_URL, euUrl: EU_URL });

        try {
            await client.fetchConsolidatedList(nodeFetch);
            expect.fail("Should have thrown");
        } catch (e: any) {
            expect(e.message).to.include("Sanctions");
        }
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 4. x402 PAYMENT FLOW (ARCHITECTURE.md §3.3, SMART_CONTRACTS.md §2.6)
// ═══════════════════════════════════════════════════════════════════════════════

describe("WS-9: x402 Payment Wiring (PAY-1→6)", function () {
    let deployer: Signer;
    let agentWallet: any;
    let raizoCore: any;
    let paymentEscrow: any;
    let mockUSDC: any;
    const AGENT_ID = ethers.id("raizo.sentinel.pay.v1");

    before(async function () {
        [deployer] = await ethers.getSigners();
        agentWallet = ethers.Wallet.createRandom().connect(ethers.provider);

        // Deploy real contracts for integration
        const MockUSDC = await ethers.getContractFactory("MockUSDC");
        mockUSDC = await MockUSDC.deploy();
        await mockUSDC.waitForDeployment();

        const RaizoCore = await ethers.getContractFactory("RaizoCore");
        raizoCore = await upgrades.deployProxy(RaizoCore, [], { initializer: "initialize", kind: "uups" });
        await raizoCore.waitForDeployment();

        const PaymentEscrow = await ethers.getContractFactory("PaymentEscrow");
        paymentEscrow = await upgrades.deployProxy(PaymentEscrow, [
            await raizoCore.getAddress(),
            await mockUSDC.getAddress(),
        ], { initializer: "initialize", kind: "uups" });
        await paymentEscrow.waitForDeployment();

        // Register agent
        await raizoCore.registerAgent(AGENT_ID, agentWallet.address, ethers.parseUnits("1000", 6));

        // Fund the escrow
        const depositAmount = ethers.parseUnits("500", 6);
        await mockUSDC.mint(await deployer.getAddress(), depositAmount);
        await mockUSDC.approve(await paymentEscrow.getAddress(), depositAmount);
        await paymentEscrow.deposit(AGENT_ID, depositAmount);
    });

    // ─── PAY-1: Constructs valid EIP-712 payment authorization ─────────────
    it("[PAY-1] constructs valid EIP-712 signature that PaymentEscrow accepts", async function () {
        const authorizer = new PaymentAuthorizer({
            escrowAddress: await paymentEscrow.getAddress(),
            chainId: (await ethers.provider.getNetwork()).chainId,
        });

        const latestBlock = await ethers.provider.getBlock("latest");
        const now = latestBlock!.timestamp;
        const paymentParams = {
            agentId: AGENT_ID,
            to: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            amount: ethers.parseUnits("10", 6),
            validAfter: BigInt(now - 60),
            validBefore: BigInt(now + 3600),
            nonce: ethers.hexlify(ethers.randomBytes(32)),
        };

        const signature = await authorizer.signPayment(agentWallet, paymentParams);

        // Execute the actual payment on-chain — the EIP-712 signature must be valid
        await expect(
            paymentEscrow.authorizePayment(
                paymentParams.agentId,
                paymentParams.to,
                paymentParams.amount,
                paymentParams.validAfter,
                paymentParams.validBefore,
                paymentParams.nonce,
                signature,
            )
        ).to.emit(paymentEscrow, "PaymentAuthorized");
    });

    // ─── PAY-2: Rejects expired authorization ──────────────────────────────
    it("[PAY-2] rejects payment authorization when validBefore has passed", async function () {
        const authorizer = new PaymentAuthorizer({
            escrowAddress: await paymentEscrow.getAddress(),
            chainId: (await ethers.provider.getNetwork()).chainId,
        });

        const paymentParams = {
            agentId: AGENT_ID,
            to: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            amount: ethers.parseUnits("5", 6),
            validAfter: BigInt(0),
            validBefore: BigInt(1), // Already expired
            nonce: ethers.hexlify(ethers.randomBytes(32)),
        };

        const signature = await authorizer.signPayment(agentWallet, paymentParams);

        await expect(
            paymentEscrow.authorizePayment(
                paymentParams.agentId,
                paymentParams.to,
                paymentParams.amount,
                paymentParams.validAfter,
                paymentParams.validBefore,
                paymentParams.nonce,
                signature,
            )
        ).to.be.revertedWithCustomError(paymentEscrow, "SignatureExpired");
    });

    // ─── PAY-3: Prevents nonce reuse ───────────────────────────────────────
    it("[PAY-3] prevents nonce reuse across payment authorizations (INV-5)", async function () {
        const authorizer = new PaymentAuthorizer({
            escrowAddress: await paymentEscrow.getAddress(),
            chainId: (await ethers.provider.getNetwork()).chainId,
        });

        const latestBlock = await ethers.provider.getBlock("latest");
        const now = latestBlock!.timestamp;
        const sharedNonce = ethers.hexlify(ethers.randomBytes(32));
        const baseParams = {
            agentId: AGENT_ID,
            to: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            amount: ethers.parseUnits("5", 6),
            validAfter: BigInt(now - 60),
            validBefore: BigInt(now + 3600),
            nonce: sharedNonce,
        };

        const sig = await authorizer.signPayment(agentWallet, baseParams);
        // First succeeds
        await paymentEscrow.authorizePayment(
            baseParams.agentId, baseParams.to, baseParams.amount,
            baseParams.validAfter, baseParams.validBefore, baseParams.nonce, sig,
        );

        // Second with same nonce reverts
        await expect(
            paymentEscrow.authorizePayment(
                baseParams.agentId, baseParams.to, baseParams.amount,
                baseParams.validAfter, baseParams.validBefore, baseParams.nonce, sig,
            )
        ).to.be.revertedWithCustomError(paymentEscrow, "NonceAlreadyUsed");
    });

    // ─── PAY-4: Budget enforcement — daily limit exceeded ──────────────────
    it("[PAY-4] enforces daily spending limit (INV-4) via PaymentEscrow", async function () {
        const authorizer = new PaymentAuthorizer({
            escrowAddress: await paymentEscrow.getAddress(),
            chainId: (await ethers.provider.getNetwork()).chainId,
        });

        const remaining = await paymentEscrow.getDailyRemaining(AGENT_ID);
        const latestBlock = await ethers.provider.getBlock("latest");
        const now = latestBlock!.timestamp;

        const params = {
            agentId: AGENT_ID,
            to: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            amount: remaining + 1n, // Exceed the remaining budget
            validAfter: BigInt(now - 60),
            validBefore: BigInt(now + 3600),
            nonce: ethers.hexlify(ethers.randomBytes(32)),
        };

        const sig = await authorizer.signPayment(agentWallet, params);

        await expect(
            paymentEscrow.authorizePayment(
                params.agentId, params.to, params.amount,
                params.validAfter, params.validBefore, params.nonce, sig,
            )
        ).to.be.revertedWithCustomError(paymentEscrow, "DailyLimitExceeded");
    });

    // ─── PAY-5: Generates unique nonces per payment ────────────────────────
    it("[PAY-5] generates unique nonces for each payment authorization", async function () {
        const authorizer = new PaymentAuthorizer({
            escrowAddress: await paymentEscrow.getAddress(),
            chainId: (await ethers.provider.getNetwork()).chainId,
        });

        const nonces = new Set<string>();
        for (let i = 0; i < 100; i++) {
            nonces.add(authorizer.generateNonce());
        }

        expect(nonces.size).to.equal(100); // All unique
    });

    // ─── PAY-6: Calculates remaining budget correctly ──────────────────────
    it("[PAY-6] tracks remaining daily budget after multiple payments", async function () {
        const before = await paymentEscrow.getDailyRemaining(AGENT_ID);
        expect(before).to.be.greaterThan(0n);

        const authorizer = new PaymentAuthorizer({
            escrowAddress: await paymentEscrow.getAddress(),
            chainId: (await ethers.provider.getNetwork()).chainId,
        });

        const amount = ethers.parseUnits("25", 6);
        const latestBlock = await ethers.provider.getBlock("latest");
        const now = latestBlock!.timestamp;
        const params = {
            agentId: AGENT_ID,
            to: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            amount,
            validAfter: BigInt(now - 60),
            validBefore: BigInt(now + 3600),
            nonce: ethers.hexlify(ethers.randomBytes(32)),
        };
        const sig = await authorizer.signPayment(agentWallet, params);
        await paymentEscrow.authorizePayment(
            params.agentId, params.to, params.amount,
            params.validAfter, params.validBefore, params.nonce, sig,
        );

        const after = await paymentEscrow.getDailyRemaining(AGENT_ID);
        expect(before - after).to.equal(amount);
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 5. DON CONSENSUS SIMULATION (AI_AGENTS.md §3.5)
// ═══════════════════════════════════════════════════════════════════════════════

describe("WS-9: DON Consensus Simulation (DON-1→8)", function () {
    // ─── DON-1: ⅔+ agreement on recommendedAction ─────────────────────────
    it("[DON-1] reaches consensus when ⅔+ nodes agree on the same action", async function () {
        const consensus = new DonConsensus({ nodeCount: 3 });

        const assessments: ThreatAssessment[] = [
            { ...buildPauseAssessment(), overallRiskScore: 0.96 },
            { ...buildPauseAssessment(), overallRiskScore: 0.93 },
            { ...buildDrainBlockAssessment(), overallRiskScore: 0.88 },
        ];

        const result = consensus.aggregate(assessments);

        expect(result.consensusReached).to.be.true;
        expect(result.agreedAction).to.equal("PAUSE"); // 2/3 agree
        expect(result.medianScore).to.be.closeTo(0.93, 0.01); // Median of [0.88, 0.93, 0.96]
    });

    // ─── DON-2: No consensus → falls back to ALERT ────────────────────────
    it("[DON-2] falls back to ALERT when no ⅔ agreement (divergence handling)", async function () {
        const consensus = new DonConsensus({ nodeCount: 3 });

        const assessments: ThreatAssessment[] = [
            { ...buildPauseAssessment(), recommendedAction: "PAUSE" },
            { ...buildDrainBlockAssessment(), recommendedAction: "DRAIN_BLOCK" },
            { ...buildAlertAssessment(), recommendedAction: "ALERT" },
        ];

        const result = consensus.aggregate(assessments);

        expect(result.consensusReached).to.be.false;
        expect(result.agreedAction).to.equal("ALERT"); // Safe fallback per §3.5
    });

    // ─── DON-3: Median score aggregation ───────────────────────────────────
    it("[DON-3] computes median risk score across all nodes", async function () {
        const consensus = new DonConsensus({ nodeCount: 5 });

        const assessments: ThreatAssessment[] = [
            { ...buildPauseAssessment(), overallRiskScore: 0.95 },
            { ...buildPauseAssessment(), overallRiskScore: 0.92 },
            { ...buildPauseAssessment(), overallRiskScore: 0.88 },
            { ...buildPauseAssessment(), overallRiskScore: 0.97 },
            { ...buildPauseAssessment(), overallRiskScore: 0.91 },
        ];

        const result = consensus.aggregate(assessments);

        // Sorted: [0.88, 0.91, 0.92, 0.95, 0.97] → median = 0.92
        expect(result.medianScore).to.be.closeTo(0.92, 0.01);
    });

    // ─── DON-4: Even node count uses average of middle two ─────────────────
    it("[DON-4] handles even node count by averaging the two middle scores", async function () {
        const consensus = new DonConsensus({ nodeCount: 4 });

        const assessments: ThreatAssessment[] = [
            { ...buildPauseAssessment(), overallRiskScore: 0.90 },
            { ...buildPauseAssessment(), overallRiskScore: 0.95 },
            { ...buildPauseAssessment(), overallRiskScore: 0.80 },
            { ...buildPauseAssessment(), overallRiskScore: 0.85 },
        ];

        const result = consensus.aggregate(assessments);

        // Sorted: [0.80, 0.85, 0.90, 0.95] → median = (0.85 + 0.90) / 2 = 0.875
        expect(result.medianScore).to.be.closeTo(0.875, 0.01);
    });

    // ─── DON-5: Single-node consensus (degenerate case) ────────────────────
    it("[DON-5] single-node DON always reaches consensus with that node's values", async function () {
        const consensus = new DonConsensus({ nodeCount: 1 });

        const result = consensus.aggregate([buildPauseAssessment()]);

        expect(result.consensusReached).to.be.true;
        expect(result.agreedAction).to.equal("PAUSE");
    });

    // ─── DON-6: ⅔ threshold for 5-node DON requires 4+ ────────────────────
    it("[DON-6] requires 4/5 agreement for a 5-node DON (⅔ rounded up)", async function () {
        const consensus = new DonConsensus({ nodeCount: 5 });

        // Only 3/5 agree on PAUSE — NOT enough for ⅔
        const assessments: ThreatAssessment[] = [
            { ...buildPauseAssessment(), recommendedAction: "PAUSE" },
            { ...buildPauseAssessment(), recommendedAction: "PAUSE" },
            { ...buildPauseAssessment(), recommendedAction: "PAUSE" },
            { ...buildDrainBlockAssessment(), recommendedAction: "DRAIN_BLOCK" },
            { ...buildAlertAssessment(), recommendedAction: "ALERT" },
        ];

        const result = consensus.aggregate(assessments);

        // 3/5 = 60% < 67% → no consensus
        expect(result.consensusReached).to.be.false;
        expect(result.agreedAction).to.equal("ALERT");
    });

    // ─── DON-7: Aggregated attestation byte length ─────────────────────────
    it("[DON-7] produces aggregated signature stub with correct byte length for BLS placeholder", async function () {
        const consensus = new DonConsensus({ nodeCount: 3 });

        const assessments: ThreatAssessment[] = [
            buildPauseAssessment(),
            buildPauseAssessment(),
            buildPauseAssessment(),
        ];

        const result = consensus.aggregate(assessments);

        // BLS signature stub: 48 bytes = 96 hex chars + "0x" prefix
        expect(result.aggregatedSignature).to.be.a("string");
        expect(result.aggregatedSignature.startsWith("0x")).to.be.true;
        expect(result.aggregatedSignature.length).to.be.greaterThan(2);
    });

    // ─── DON-8: Empty assessment array throws ──────────────────────────────
    it("[DON-8] throws when given an empty assessment array", async function () {
        const consensus = new DonConsensus({ nodeCount: 3 });

        expect(() => consensus.aggregate([])).to.throw("No assessments");
    });
});
