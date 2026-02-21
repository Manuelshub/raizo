/**
 * @file scripts/api-stub.ts
 * @notice Lightweight HTTP server serving realistic stub data for CRE workflow
 *         simulation. This provides endpoints that match what the 3 workflows
 *         expect: telemetry, LLM assessment, compliance rules/metrics/sanctions,
 *         and deployment registry.
 *
 * Usage:
 *   npx ts-node scripts/api-stub.ts
 *   # Starts on http://localhost:4200
 *
 * This is NOT a mock — it serves structurally correct data matching the
 * TelemetryFrame, ThreatAssessment, RegulatoryRule[], and ProtocolDeployment
 * interfaces from the master specification.
 */

import http from "http";

const PORT = 4200;

// ─── Telemetry Endpoint ──────────────────────────────────────────────────────
// Returns a TelemetryFrame-compatible JSON (BigInt fields as strings for JSON)
const TELEMETRY_RESPONSE = JSON.stringify({
  chainId: 1,
  blockNumber: 20_500_000,
  tvl: {
    current: "75000000000000000000000000",   // $75M
    delta1h: -12.5,                           // -12.5% drop (suspicious)
    delta24h: -8.2,
  },
  transactionMetrics: {
    volumeUSD: "15000000000000000000000000",  // $15M
    uniqueAddresses: 2500,
    largeTransactions: 8,                     // Elevated
    failedTxRatio: 0.07,                      // 7% failure rate
  },
  contractState: {
    owner: "0x1F1392C0B7021fEeFBDe347bf2929b563c4294F2",
    paused: false,
    pendingUpgrade: false,
    unusualApprovals: 3,
  },
  mempoolSignals: {
    pendingLargeWithdrawals: 5,
    flashLoanBorrows: 3,                      // Active flash loans
    suspiciousCalldata: ["0xdeadbeef"],
  },
  threatIntel: {
    activeCVEs: [],
    exploitPatterns: [],
    darkWebMentions: 2,
    socialSentiment: -0.3,
  },
  priceData: {
    tokenPrice: "2000000000000000000000",     // $2000
    priceDeviation: 4.5,                      // 4.5% deviation
    oracleLatency: 8,
  },
});

// ─── LLM Assessment Endpoint ─────────────────────────────────────────────────
// Returns a ThreatAssessment matching the spec schema
const LLM_RESPONSE = JSON.stringify({
  overallRiskScore: 0.78,
  threatDetected: true,
  threats: [
    {
      category: "flash_loan",
      confidence: 0.78,
      indicators: [
        "Multiple flash loan borrows detected in mempool",
        "TVL dropping 12.5% in 1 hour",
        "Elevated large transaction count",
      ],
      estimatedImpactUSD: 500000,
    },
  ],
  recommendedAction: "RATE_LIMIT",
  reasoning:
    "Flash loan activity combined with TVL decline and price deviation suggests potential exploit. " +
    "Heuristic signals corroborate mempool anomalies. Recommend rate-limiting pending investigation.",
  evidenceCitations: [
    "mempoolSignals.flashLoanBorrows",
    "tvl.delta1h",
    "priceData.priceDeviation",
    "transactionMetrics.largeTransactions",
  ],
});

// ─── Compliance Rules Endpoint ───────────────────────────────────────────────
const RULES_RESPONSE = JSON.stringify([
  {
    ruleId: "AML-001",
    framework: "AML",
    version: "1.0",
    effectiveDate: Math.floor(Date.now() / 1000) - 86400,
    condition: { metric: "tx.valueUSD", operator: "gt", threshold: 10000 },
    action: {
      type: "report",
      severity: "violation",
      narrative: "Transaction value exceeds AML reporting threshold of $10,000",
    },
    regulatoryReference: "FATF Recommendation 10",
    jurisdiction: ["Global"],
  },
  {
    ruleId: "MiCA-002",
    framework: "MiCA",
    version: "1.0",
    effectiveDate: Math.floor(Date.now() / 1000) - 86400,
    condition: { metric: "daily.volume", operator: "gt", threshold: 5000000 },
    action: {
      type: "flag",
      severity: "warning",
      narrative: "Daily volume exceeds MiCA Art. 23 threshold for enhanced reporting",
    },
    regulatoryReference: "MiCA Art. 23",
    jurisdiction: ["EU"],
  },
]);

// ─── Compliance Metrics Endpoint ─────────────────────────────────────────────
const METRICS_RESPONSE = JSON.stringify({
  "tx.valueUSD": 25000,      // Triggers AML-001
  "daily.volume": 8000000,   // Triggers MiCA-002
  "address.riskScore": 0.15,
  sender: "0xCleanAddress",
});

// ─── Sanctions List Endpoint ─────────────────────────────────────────────────
const SANCTIONS_RESPONSE = JSON.stringify([
  "0xSanctioned1111111111111111111111111111",
  "0xSanctioned2222222222222222222222222222",
]);

// ─── Deployment Registry Endpoint ────────────────────────────────────────────
function buildDeploymentResponse(protocol: string) {
  return JSON.stringify({
    protocol,
    chains: [1, 11155111],    // Mainnet + Sepolia
    relatedProtocols: [],
  });
}

// ─── HTTP Server ─────────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
  const path = url.pathname;

  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");

  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);

  switch (path) {
    case "/telemetry":
      res.writeHead(200);
      res.end(TELEMETRY_RESPONSE);
      break;

    case "/llm/assess":
      // Collect POST body (workflow sends telemetry payload)
      let body = "";
      req.on("data", (chunk) => { body += chunk; });
      req.on("end", () => {
        res.writeHead(200);
        res.end(LLM_RESPONSE);
      });
      break;

    case "/rules":
      res.writeHead(200);
      res.end(RULES_RESPONSE);
      break;

    case "/metrics":
      res.writeHead(200);
      res.end(METRICS_RESPONSE);
      break;

    case "/sanctions":
      res.writeHead(200);
      res.end(SANCTIONS_RESPONSE);
      break;

    case "/deployments": {
      const protocol = url.searchParams.get("protocol") ?? "0x0000";
      res.writeHead(200);
      res.end(buildDeploymentResponse(protocol));
      break;
    }

    case "/health":
      res.writeHead(200);
      res.end(JSON.stringify({ status: "ok", timestamp: Date.now() }));
      break;

    default:
      res.writeHead(404);
      res.end(JSON.stringify({ error: "Not found", path }));
  }
});

server.listen(PORT, () => {
  console.log(`\n🔌 Raizo API Stub Server running on http://localhost:${PORT}`);
  console.log(`   Endpoints:`);
  console.log(`     GET  /telemetry      → TelemetryFrame`);
  console.log(`     POST /llm/assess     → ThreatAssessment`);
  console.log(`     GET  /rules          → RegulatoryRule[]`);
  console.log(`     GET  /metrics        → Protocol metrics`);
  console.log(`     GET  /sanctions      → Sanctions list`);
  console.log(`     GET  /deployments    → ProtocolDeployment`);
  console.log(`     GET  /health         → Health check\n`);
});
