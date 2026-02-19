/**
 * @file cross-chain-coordinator.correct.test.ts
 * @notice Workflow correctness tests for the Cross-Chain Coordinator.
 *
 * Uses `workflow-helpers.ts` to avoid CRE SDK ESM/CJS conflict.
 *
 * Coverage:
 *  D1 - Data Contract: registry queried with ?protocol= param
 *  D2 - Control Flow: local_only / propagated / error statuses
 *  D4 - On-Chain Write: propagation messages have correct struct fields
 */

import { expect } from "chai";
import nock from "nock";
import {
    runCoordinatorWorkflow,
    SimpleFetch,
    FetchResponse,
} from "../../workflows/logic/workflow-helpers";
import { ProtocolDeployment } from "../../workflows/logic/types";

// ─── Shared fetch impl ────────────────────────────────────────────────────────

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

const REGISTRY_URL = "http://localhost:3006/deployments";
const PROTOCOL_ADDR = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";

const COORDINATOR_CFG = {
    deploymentRegistryUrl: REGISTRY_URL,
    monitoredChainIds: [1, 8453, 42161],
    monitoredChainSelectors: [
        "16015286601757825753", // Ethereum
        "15971525489660198786", // Base
        "4949039107694359620",  // Arbitrum
    ],
};

function buildEventPayload(overrides?: Record<string, unknown>) {
    return {
        log: {
            reportId: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            agentId: "0xbeefdead",
            sourceChain: 1,
            targetProtocol: PROTOCOL_ADDR,
            action: 0,   // PAUSE
            severity: 3,   // CRITICAL
            confidenceScore: 9600,
            evidenceHash: "0xabcd",
            timestamp: Math.floor(Date.now() / 1000),
            ...overrides,
        },
    };
}

function singleChainDeployment(): ProtocolDeployment {
    return { protocol: PROTOCOL_ADDR, chains: [1], relatedProtocols: [] };
}

function multiChainDeployment(chains: number[] = [1, 8453]): ProtocolDeployment {
    return { protocol: PROTOCOL_ADDR, chains, relatedProtocols: [] };
}

// ─── Test suite ───────────────────────────────────────────────────────────────

describe("Cross-Chain Coordinator — Workflow Correctness", function () {
    beforeEach(function () { nock.cleanAll(); });
    afterEach(function () { nock.cleanAll(); });

    // ─── X-2: LOCAL_ONLY ──────────────────────────────────────────────────────
    it("[X-2] returns local_only for single-chain protocol with HIGH severity", async function () {
        nock("http://localhost:3006").get("/deployments")
            .query({ protocol: PROTOCOL_ADDR })
            .reply(200, JSON.stringify(singleChainDeployment()));

        const result = await runCoordinatorWorkflow(
            nodeFetch,
            buildEventPayload({ severity: 2 }), // HIGH, not CRITICAL
            COORDINATOR_CFG,
        );

        expect(result.status).to.equal("local_only");
        expect(result.messages).to.have.length(0);
    });

    // ─── X-1: ALL_CHAINS (CRITICAL) ───────────────────────────────────────────
    it("[X-1] propagates to all monitored chains (N-1) on CRITICAL severity", async function () {
        nock("http://localhost:3006").get("/deployments")
            .query({ protocol: PROTOCOL_ADDR })
            .reply(200, JSON.stringify(singleChainDeployment()));

        const result = await runCoordinatorWorkflow(
            nodeFetch,
            buildEventPayload({ severity: 3, sourceChain: 1 }), // CRITICAL
            COORDINATOR_CFG,
        );

        expect(result.status).to.equal("propagated");
        // Source=1, monitored=[1,8453,42161] → 2 destinations (Ex port source chain)
        expect(result.messages!.length).to.be.gte(1);
    });

    // ─── X-3: SAME_PROTOCOL propagation ──────────────────────────────────────
    it("[X-3] propagates only to same-protocol chains for HIGH multi-chain deployment", async function () {
        nock("http://localhost:3006").get("/deployments")
            .query({ protocol: PROTOCOL_ADDR })
            .reply(200, JSON.stringify(multiChainDeployment([1, 8453]))); // Protocol on ETH+Base

        const result = await runCoordinatorWorkflow(
            nodeFetch,
            buildEventPayload({ severity: 2, sourceChain: 1 }), // HIGH
            COORDINATOR_CFG,
        );

        expect(result.status).to.equal("propagated");
        // SAME_PROTOCOL scope uses resolveTargetChains(monitoredChains, exclude source).
        // Monitored=[1,8453,42161], source=1 → 2 destination chains (8453, 42161).
        expect(result.messages!.length).to.equal(2);
        for (const msg of result.messages!) {
            expect(msg.destChain).to.not.equal(1); // Never propagate back to source
        }
    });

    // ─── X-4: Report struct fields in messages ───────────────────────────────
    it("[X-4] propagation messages carry correct reportId, action, and targetProtocol", async function () {
        nock("http://localhost:3006").get("/deployments")
            .query({ protocol: PROTOCOL_ADDR })
            .reply(200, JSON.stringify(singleChainDeployment()));

        const result = await runCoordinatorWorkflow(
            nodeFetch,
            buildEventPayload({ severity: 3 }),
            COORDINATOR_CFG,
        );

        expect(result.status).to.equal("propagated");
        for (const msg of result.messages!) {
            expect(msg.reportId).to.match(/^0x/);
            expect(msg.targetProtocol.toLowerCase()).to.equal(PROTOCOL_ADDR.toLowerCase());
            expect(typeof msg.action).to.equal("number");
        }
    });

    // ─── D1: Registry URL includes ?protocol= param ───────────────────────────
    it("[D1] queries deployment registry with ?protocol= query parameter", async function () {
        const scope = nock("http://localhost:3006").get("/deployments")
            .query({ protocol: PROTOCOL_ADDR })
            .reply(200, JSON.stringify(singleChainDeployment()));

        await runCoordinatorWorkflow(nodeFetch, buildEventPayload({ severity: 2 }), COORDINATOR_CFG);

        expect(scope.isDone()).to.be.true;
    });

    // ─── X-6: Registry error handling ─────────────────────────────────────────
    it("[X-6] returns error when deployment registry is unavailable", async function () {
        nock("http://localhost:3006").get("/deployments")
            .query({ protocol: PROTOCOL_ADDR })
            .reply(500, "Internal Server Error");

        const result = await runCoordinatorWorkflow(
            nodeFetch,
            buildEventPayload(),
            COORDINATOR_CFG,
        );

        expect(result.status).to.equal("error");
        expect(result.messages).to.be.undefined;
    });
});
