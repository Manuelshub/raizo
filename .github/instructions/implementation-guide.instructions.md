---
applyTo: '**'
---

**PRODUCTION CODE REQUIREMENTS**

**Code Quality Standards:**
- Production-grade only: Use battle-tested patterns from OpenZeppelin (e.g., AccessControl, UUPS, ReentrancyGuard), Chainlink services (DONs, CCIP, CRE plugins), and audited libraries; achieve 100% test coverage with fuzzing.
- Name things for what they DO: Descriptive contracts (e.g., ProtocolSentinel), functions (e.g., predictAndPauseVulnerability), errors (e.g., InvalidRiskThreshold), events (e.g., SafeguardTriggered).
- Real-world resilience: Account for reentrancy, oracle downtime, gas limits, multi-chain forks, external data malformations, and regulatory pauses.

**Required Elements:**
- Explicit error handling: Custom errors with context (e.g., `error RiskThresholdExceeded(uint256 current)`), modifiers for access/reentrancy, recovery via pausable circuit breakers.
- Input validation: Check msg.sender roles, calldata bounds, oracle responses; use `require`/`revert` with specific messages for all external calls.
- Resource management: Optimize storage (pack variables, use immutable/constant), avoid unbounded loops, manage proxy storage slots in upgrades.
- Logging: Emit events at decision points (e.g., RiskDetected, ComplianceReportGenerated); no console.log in deployed code.
- Performance: Document gas profiles (via hardhat-gas-reporter) for O(n) or higher ops; enable Solidity optimizer (runs=200+), prefer calldata over memory.
- Concurrency safety: Strictly follow Checks-Effects-Interactions; nonReentrant on all state-changing functions.

**Testing Requirements:**
- Scenario-driven only: Focus on non-trivial, production-critical flows (e.g., full agentic risk prediction → safeguard trigger → cross-chain CCIP execution) over isolated getters/setters; no "1+1 == 2" unit tests—target 90%+ branch coverage via integration suites.
- Multi-layered: Unit tests for core logic (e.g., LLM-mocked predictions), fuzz tests for inputs/attacks (using hardhat-fuzz or Foundry integration), and end-to-end simulations (e.g., Hardhat Network forking mainnet to test oracle failures, gas exhaustion, and multi-chain forks).
- Edge case coverage: Explicit tests for reentrancy exploits, oracle downtime (via mocks), regulatory pauses (simulated via World ID sybil checks), high-volume data (e.g., 1k+ transaction anomalies), and upgrade safety (storage gaps, UUPS proxies).
- Tooling and automation: Use Chai for assertions, Waffle for contract interactions, hardhat-deploy for fixtures, solidity-coverage for reports, and hardhat-gas-reporter for benchmarks; run via `hardhat test --fork` for real-world state; include CI pipelines with Tenderly Virtual TestNets for CRE workflow validation.
- Verification hooks: Tests must assert events, state changes, and external interactions (e.g., `expect(await sentinel.getRiskScore()).to.equal(expected)` with mocked DONs); fuzz for randomness in AI predictions; snapshot tests for compliance report generation.
- Performance and resilience: Gas audits in tests (assert < threshold for critical paths); simulate network conditions (e.g., high latency via custom providers); ensure tests run in <5min on CI.

**Documentation & Verification:**
- ALWAYS check current docs: Solidity 0.8.x, OpenZeppelin 5.x, Chainlink Hardhat plugin/CCIP/CRE, Hardhat 3.x before adding features.
- Verify method/API existence: Cross-check interfaces (e.g., IRouterClient for CCIP, AggregatorV3Interface for oracles) in docs, ABIs, or Etherscan.
- If uncertain about signatures (e.g., x402 flow), flag in comments or use Hardhat tasks to confirm.
- Align with Raizo architecture: CRE orchestration, agentic workflows, multi-chain (Ethereum/Base), World ID integration, ACE compliance.

**Forbidden:**
- Placeholder comments like "// TODO: add pause", "// TODO: handle oracle".
- Generic `revert()` or unchecked math without explicit audit note and gas reporter proof.
- Theoretical optimizations (e.g., assembly tweaks) without profiling via Hardhat gas reporter.
- Over-engineered proxies or inheritance without OZ UUPS/Transparent and storage gap checks.
- Calling unverified methods (e.g., raw CCIP send) without plugin integration or interface import.
- Trivial tests: No isolated happy-path units without failure simulations or attack vectors.

**Verification Checklist:**
- Does this code handle reentrancy, oracle failure, and gas exhaustion?
- Can this deploy to mainnet (or testnet fork) without modifications?
- Are storage slots, gas limits, and cross-chain costs considered?
- Is the naming self-documenting and aligned with patterns?
- Have I verified this function/interface exists in the exact version (OZ/Chainlink/Hardhat)?
- Does this align with documented Raizo specs and Chainlink integration requirements?
- Do tests cover real-world scenarios (fuzz, forks, edges) with measurable coverage?
- Is the implementation consistent with the master specification in the docs
