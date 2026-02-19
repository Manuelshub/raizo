# Raizo Integration Test Strategy

> **Version:** 1.0.0  
> **Last Updated:** 2026-02-19  
> **Status:** Implementation Guide

---

## 1. Philosophy: Testing Distributed Systems

### 1.1 Boundary Identification

Raizo spans four distinct execution boundaries:

```
┌─────────────────────────────────────────────────────────────┐
│ WASM Runtime (CRE Simulator)                                │
│ • Deterministic TypeScript execution                        │
│ • Handler trigger → callback → return value                 │
│ • Runtime logs, config validation                           │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│ DON Consensus Layer (Mocked in Simulator)                   │
│ • consensusIdenticalAggregation() → all nodes same result   │
│ • consensusMedianAggregation() → median of numeric results  │
│ • runInNodeMode() → simulates per-node execution            │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│ HTTP Boundary (MSW Mocks)                                   │
│ • Telemetry API, LLM API, Threat Intel, Sanctions List     │
│ • Request shape validation (headers, body, method)          │
│ • Deterministic response fixtures                           │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│ EVM Boundary (Hardhat/Anvil Fork)                           │
│ • Smart contract state (RaizoCore, SentinelActions, etc.)   │
│ • Event emissions (ActionExecuted, ReportStored)            │
│ • ABI-encoded calldata correctness                          │
│ • Access control enforcement                                │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Test Layering Strategy

| Layer             | Tool/Framework         | Scope                                                   | Assertion Focus                                     |
| ----------------- | ---------------------- | ------------------------------------------------------- | --------------------------------------------------- |
| **Unit**          | Vitest/Jest            | Pure functions (escalateAction, evaluateRule)           | Logic correctness, edge cases, boundary conditions  |
| **Integration**   | CRE Simulator + MSW    | Workflow execution with mocked HTTP/DON                 | Workflow behavior, conditional paths, return values |
| **Contract**      | Hardhat + Ethers       | On-chain state transitions                              | Event emissions, storage changes, reverts           |
| **End-to-End**    | CRE Sim + Anvil + MSW  | Full pipeline (trigger → HTTP → DON → on-chain write)  | Calldata encoding, receiver address, state changes  |
| **Fuzz**          | Foundry/Echidna        | Contract invariants under adversarial inputs            | Access control, overflow, reentrancy                |

---

## 2. Critical Paths to Cover

### 2.1 Threat Sentinel (threat-detection.ts)

#### Happy Path
```
┌────────┐   ┌──────────┐   ┌──────────┐   ┌─────────┐   ┌──────────────┐
│ Cron   │──▶│ Fetch    │──▶│ Heuristic│──▶│   LLM   │──▶│ SentinelActions│
│ Tick   │   │ Telemetry│   │ Gate OK  │   │ Analysis│   │ .executeAction()│
└────────┘   └──────────┘   └──────────┘   └─────────┘   └──────────────┘
                                              ▲
                                              │ DON consensus
                                              │ (3/3 nodes agree)
```

**Assertions:**
- ✅ HTTP request to telemetryApiUrl with correct headers
- ✅ Heuristic score ≥ `HEURISTIC_GATE_THRESHOLD` → LLM called
- ✅ LLM API called with SYSTEM_PROMPT + telemetry JSON
- ✅ DON consensus aggregates LLM results (all nodes identical)
- ✅ `escalateAction()` maps score → correct ActionType enum
- ✅ ABI-encoded calldata matches `ISentinelActions.executeAction(ThreatReport)`
- ✅ `receiver` address = `config.sentinelContractAddress`
- ✅ On-chain: `ActionExecuted` event emitted with correct reportId
- ✅ On-chain: `ThreatReport` stored with `exists=true`
- ✅ Workflow returns `"reported"`

#### Gate Suppression Path
```
┌────────┐   ┌──────────┐   ┌──────────┐
│ Cron   │──▶│ Fetch    │──▶│ Heuristic│──▶ STOP (LLM not called)
│ Tick   │   │ Telemetry│   │ Gate FAIL│
└────────┘   └──────────┘   └──────────┘
```

**Assertions:**
- ✅ Heuristic score < `HEURISTIC_GATE_THRESHOLD`
- ✅ LLM API never invoked (0 HTTP requests to llmApiUrl)
- ✅ No on-chain write (no `runtime.report()` call)
- ✅ Workflow returns `"skipped"`

#### Low-Risk Path (LLM says no threat)
```
┌────────┐   ┌──────────┐   ┌──────────┐   ┌─────────┐
│ Cron   │──▶│ Fetch    │──▶│ Heuristic│──▶│   LLM   │──▶ STOP
│ Tick   │   │ Telemetry│   │ Gate OK  │   │ score=0.4│
└────────┘   └──────────┘   └──────────┘   └─────────┘
```

**Assertions:**
- ✅ LLM called but returns `overallRiskScore < 0.85`
- ✅ `runSentinelPipeline()` returns `null`
- ✅ No on-chain write
- ✅ Workflow returns `"no_threat"`

---

### 2.2 Cross-Chain Coordinator (cross-chain-coordinator.ts)

#### Multi-Chain Propagation
```
┌────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────┐
│ EVMLog │──▶│ Parse    │──▶│ Fetch    │──▶│ Evaluate     │
│ Trigger│   │ Event    │   │ Deployment│  │ Scope=ALL_CHAINS│
└────────┘   └──────────┘   └──────────┘   └──────┬───────┘
                                                    │
                                     ┌──────────────▼──────────────┐
                                     │ CCIP Send to Chain A, B, C  │
                                     │ (CrossChainRelay.sendAlert) │
                                     └─────────────────────────────┘
```

**Assertions:**
- ✅ HTTP request to `deploymentRegistryUrl?protocol=0xAddr`
- ✅ `evaluateScope()` returns `ALL_CHAINS` for severity=3 (CRITICAL)
- ✅ `buildPropagationMessages()` excludes source chain
- ✅ ABI-encoded calldata for `CrossChainRelay.sendAlert()` with CCIP params
- ✅ One `runtime.report()` call per destination chain
- ✅ Workflow returns `"propagated"`

#### LOCAL_ONLY Path
```
┌────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────┐
│ EVMLog │──▶│ Parse    │──▶│ Fetch    │──▶│ Evaluate     │
│ Trigger│   │ Event    │   │ Deployment│  │ Scope=LOCAL  │
└────────┘   └──────────┘   └──────────┘   └──────┬───────┘
                                                    │
                                            ┌───────▼───────┐
                                            │ No CCIP sends │
                                            └───────────────┘
```

**Assertions:**
- ✅ `deployment.chains.length === 1` → scope = LOCAL_ONLY
- ✅ `buildPropagationMessages()` returns empty array
- ✅ Zero on-chain writes
- ✅ Workflow returns `"local_only"`

---

### 2.3 Compliance Reporter (compliance-reporter.ts)

#### Violations Found
```
┌────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────┐
│ Cron   │──▶│ Fetch    │──▶│ Evaluate │──▶│ ComplianceVault│
│ Trigger│   │ Rules +  │   │ Rules    │   │ .storeReport()│
│        │   │ Metrics  │   │ (2 viols)│   │               │
└────────┘   └──────────┘   └──────────┘   └──────────────┘
```

**Assertions:**
- ✅ HTTP requests: rulesApiUrl, metricsApiUrl, sanctionsApiUrl
- ✅ `evaluateRule()` correctly matches conditions (gt, lt, eq, in, matches)
- ✅ `generateComplianceReport()` calculates correct complianceScore
- ✅ `findings.length > 0` → on-chain write triggered
- ✅ ABI-encoded calldata matches `IComplianceVault.storeReport()`
- ✅ On-chain: `ReportStored` event emitted with reportHash
- ✅ Workflow returns `"reported"`

#### Clean Path (No Violations)
```
┌────────┐   ┌──────────┐   ┌──────────┐
│ Cron   │──▶│ Fetch    │──▶│ Evaluate │──▶ STOP (no write)
│ Trigger│   │ Rules +  │   │ Rules    │
│        │   │ Metrics  │   │ (0 viols)│
└────────┘   └──────────┘   └──────────┘
```

**Assertions:**
- ✅ All rules evaluated, none matched
- ✅ `findings.length === 0` → no on-chain write
- ✅ Workflow returns `"clean"`

---

## 3. Mocking Strategy

### 3.1 HTTP Layer (MSW)

```typescript
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';

const handlers = [
  // Telemetry API
  http.get('http://localhost:3001/telemetry', () => {
    return HttpResponse.json(buildTelemetryFixture());
  }),
  
  // LLM API
  http.post('http://localhost:3002/llm', async ({ request }) => {
    const body = await request.json();
    // Validate prompt structure
    expect(body.system).toContain('Raizo Sentinel');
    return HttpResponse.json(buildThreatAssessmentFixture());
  }),
  
  // Sanctions API (Confidential Compute)
  http.get('http://localhost:3003/sanctions', () => {
    return HttpResponse.json(['0x1234...', '0x5678...']);
  }),
];

const server = setupServer(...handlers);
```

### 3.2 DON Consensus Simulation

CRE simulator automatically handles `runInNodeMode()` and consensus aggregation:

```typescript
// In test setup
const config: SentinelConfig = {
  schedule: '*/10 * * * * *',
  chainSelector: '1234567890',
  telemetryApiUrl: 'http://localhost:3001/telemetry',
  llmApiUrl: 'http://localhost:3002/llm',
  // ...
};

// CRE simulator will:
// 1. Execute callback with mocked Runtime
// 2. Simulate DON nodes calling runInNodeMode fn
// 3. Apply consensusIdenticalAggregation() or consensusMedianAggregation()
// 4. Return aggregated result
```

### 3.3 EVM Boundary (Hardhat Network)

```typescript
import { ethers } from 'hardhat';

beforeEach(async () => {
  // Deploy contracts on Hardhat network
  const RaizoCore = await ethers.getContractFactory('RaizoCore');
  raizoCore = await RaizoCore.deploy();
  
  const SentinelActions = await ethers.getContractFactory('SentinelActions');
  sentinelActions = await SentinelActions.deploy(raizoCore.address);
  
  // Register protocol and agent
  await raizoCore.registerProtocol(mockProtocol.address, 1, 3);
  await raizoCore.registerAgent(agentId, paymentWallet, 1000_000000);
});
```

---

## 4. Assertion Layer Design

### 4.1 HTTP Request Shape

```typescript
// In MSW handler
http.post('http://localhost:3002/llm', async ({ request }) => {
  const contentType = request.headers.get('Content-Type');
  expect(contentType).toBe('application/json');
  
  const body = await request.json();
  expect(body).toMatchObject({
    system: expect.stringContaining('Raizo Sentinel'),
    telemetry: {
      chainId: expect.any(Number),
      blockNumber: expect.any(Number),
      tvl: expect.objectContaining({
        current: expect.any(String), // BigInt serialized as string
      }),
    },
  });
  
  return HttpResponse.json(buildThreatAssessmentFixture());
});
```

### 4.2 ABI-Encoded Calldata

```typescript
import { encodeFunctionData, decodeEventLog } from 'viem';
import { sentinelActionsAbi } from '../abis';

test('should encode ThreatReport correctly', () => {
  const report = buildThreatReportFixture();
  
  // Workflow should call encodeFunctionData()
  const expectedCalldata = encodeFunctionData({
    abi: sentinelActionsAbi,
    functionName: 'executeAction',
    args: [report],
  });
  
  // Capture actual calldata from runtime.report()
  const actualCalldata = captureReportCalldata();
  
  expect(actualCalldata).toBe(expectedCalldata);
});
```

### 4.3 On-Chain State Changes

```typescript
test('should emit ActionExecuted event', async () => {
  // Trigger workflow
  await executeThreatDetectionWorkflow(config);
  
  // Query Hardhat network for events
  const filter = sentinelActions.filters.ActionExecuted();
  const events = await sentinelActions.queryFilter(filter);
  
  expect(events).toHaveLength(1);
  expect(events[0].args.reportId).toBe(expectedReportId);
  expect(events[0].args.protocol).toBe(targetProtocol);
  expect(events[0].args.action).toBe(0); // PAUSE
});

test('should store ThreatReport in contract state', async () => {
  await executeThreatDetectionWorkflow(config);
  
  const stored = await sentinelActions.getActiveActions(targetProtocol);
  
  expect(stored).toHaveLength(1);
  expect(stored[0].exists).toBe(true);
  expect(stored[0].confidenceScore).toBe(9500); // 95.00%
});
```

### 4.4 Workflow Return Values

```typescript
test('should return correct status strings', async () => {
  // Test each path
  const result1 = await runWorkflow(highRiskConfig);
  expect(result1).toBe('reported');
  
  const result2 = await runWorkflow(lowHeuristicConfig);
  expect(result2).toBe('skipped');
  
  const result3 = await runWorkflow(lowLLMScoreConfig);
  expect(result3).toBe('no_threat');
});
```

---

## 5. Implementation Gaps to Flag

### 5.1 **CRITICAL:** Empty DON Signatures

**Current State:**
```typescript
// In workflows/logic/threat-logic.ts
export function buildThreatReport(...): ThreatReport {
  return {
    // ...
    donSignatures: "0x", // ⚠️ EMPTY PLACEHOLDER
  };
}
```

**Contract Expectation:**
```solidity
// In contracts/core/SentinelActions.sol
function executeAction(ThreatReport calldata report) external {
    _verifySignatures(report);  // ⚠️ Will revert on empty signatures
    // ...
}

function _verifySignatures(ThreatReport calldata report) internal view {
    if (report.donSignatures.length == 0) {
        revert InvalidSignatures();
    }
    // TODO: Actual ECDSA verification against DON pubkeys
}
```

**Resolution Strategy:**
1. **Short-term (Tests):** Mock `_verifySignatures()` to accept `"0x"` in test contracts
2. **Production:** CRE runtime must populate `report.donSignatures` with aggregated BLS/ECDSA signatures from DON consensus

**Test Implementation:**
```typescript
// Deploy MockSentinelActions with signature check disabled
const MockSentinel = await ethers.getContractFactory('MockSentinelActions');
mockSentinel = await MockSentinel.deploy({ skipSignatureCheck: true });
```

---

### 5.2 Missing ABI Encoding

**Current State:**
```typescript
// In workflows/threat-detection.ts (line 176)
const writeData = "0x"; // TODO: Use encodeFunctionData from viem with proper ABI
runtime.report(prepareReportRequest(writeData)).result();
```

**Required Implementation:**
```typescript
import { encodeFunctionData } from 'viem';
import { sentinelActionsAbi } from './abis/SentinelActions';

const calldata = encodeFunctionData({
  abi: sentinelActionsAbi,
  functionName: 'executeAction',
  args: [report],
});

const reportRequest = prepareReportRequest(calldata);
reportRequest.receiver = config.sentinelContractAddress;

runtime.report(reportRequest).result();
```

**Test Should Verify:**
- ✅ Calldata decodes to correct function selector (`0x` + keccak256("executeAction(...)").slice(0,8))
- ✅ ABI-decoded args match ThreatReport struct
- ✅ Receiver address matches configured contract

---

### 5.3 EVM Log Trigger Not Implemented

**Current State:**
```typescript
// In workflows/cross-chain-coordinator.ts (line 141)
// NOTE: EVMLogTrigger is not yet available or documented in CRE SDK v1.1.0
// Using cron as placeholder until event trigger pattern is clarified
const cron = new cre.capabilities.CronCapability();
const trigger = cron.trigger({ schedule: "*/30 * * * * *" });
```

**Required Pattern (Per CRE Docs):**
```typescript
const evmClient = new cre.capabilities.EVMClient(BigInt(chainSelector));

const trigger = evmClient.logTrigger({
  addresses: [hexToBase64(config.sentinelContractAddress)],
  topics: [
    '0x' + keccak256('ThreatReported(bytes32,bytes32,address,uint8,uint8,uint16)').slice(0, 64)
  ],
});

return [handler(trigger, onThreatReported)];
```

**Test Should Verify:**
- ✅ Workflow responds to emitted `ThreatReported` event
- ✅ Event log correctly parsed into ThreatEvent struct
- ✅ No polling delay (event-driven execution)

---

### 5.4 BigInt JSON Serialization

**Current Issue:**
```typescript
// TelemetryFrame contains bigint fields
interface TelemetryFrame {
  tvl: { current: bigint };  // ⚠️ JSON.stringify() throws on bigint
  transactionMetrics: { volumeUSD: bigint };
  priceData: { tokenPrice: bigint };
}
```

**Current Workaround:**
```typescript
// In threat-detection.ts (line 126)
body: JSON.stringify({
  system: SYSTEM_PROMPT,
  telemetry: JSON.parse(JSON.stringify(telemetry, (_, v) => 
    typeof v === 'bigint' ? v.toString() : v  // ✅ Manual conversion
  )),
}),
```

**Better Solution:**
```typescript
// In types.ts — use string types for JSON-serializable schemas
interface TelemetryFrameDTO {
  tvl: { current: string };  // Already stringified
  // ...
}

// Convert at boundary
function toDTO(frame: TelemetryFrame): TelemetryFrameDTO {
  return {
    ...frame,
    tvl: { ...frame.tvl, current: frame.tvl.current.toString() },
  };
}
```

---

## 6. Test File Organization

```
test/
├── fixtures/
│   ├── telemetry.fixtures.ts
│   ├── threat.fixtures.ts
│   ├── compliance.fixtures.ts
│   └── events.fixtures.ts
├── mocks/
│   ├── msw-handlers.ts
│   └── contracts.mocks.ts
├── integration/
│   ├── threat-detection.integration.test.ts
│   ├── cross-chain-coordinator.integration.test.ts
│   ├── compliance-reporter.integration.test.ts
│   └── cre-sim.test.ts (existing — focus on logic layer)
└── e2e/
    └── full-pipeline.e2e.test.ts
```

---

## 7. Execution Plan

### Phase 1: Fixture Factories (Week 1)
- [ ] Implement `buildTelemetryFrame()`, `buildThreatAssessment()`, etc.
- [ ] Add builder methods for edge cases (high risk, low risk, gate suppression)

### Phase 2: MSW Setup (Week 1)
- [ ] Configure MSW server with all API handlers
- [ ] Add request validation in handlers
- [ ] Create response fixtures for deterministic tests

### Phase 3: Contract Mocks (Week 2)
- [ ] Deploy MockSentinelActions with signature check disabled
- [ ] Deploy MockComplianceVault
- [ ] Implement test helper: `deployRaizoTestStack()`

### Phase 4: Workflow Integration Tests (Week 2-3)
- [ ] Threat Detection: 3 critical paths
- [ ] Cross-Chain Coordinator: 2 critical paths
- [ ] Compliance Reporter: 2 critical paths

### Phase 5: ABI Encoding Implementation (Week 3)
- [ ] Add viem dependency
- [ ] Implement `encodeFunctionData()` in all workflows
- [ ] Verify calldata correctness in tests

### Phase 6: E2E Test (Week 4)
- [ ] Full pipeline test: cron → HTTP → DON → on-chain
- [ ] Event emission verification
- [ ] Cross-chain CCIP message validation

---

## 8. Success Criteria

A successful test suite will:

✅ **Cover all critical paths** listed in §2  
✅ **Validate HTTP request shapes** (headers, body, method)  
✅ **Assert ABI-encoded calldata correctness** against contract ABIs  
✅ **Verify on-chain state changes** (events, storage, access control)  
✅ **Flag implementation gaps** (signatures, ABI encoding, EVM log trigger)  
✅ **Achieve >90% code coverage** on workflow logic layer  
✅ **Run in CI/CD** with deterministic, fast execution (<5min total)  
✅ **Serve as documentation** for CRE workflow patterns and best practices
