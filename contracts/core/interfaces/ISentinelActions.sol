// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ISentinelActions
 * @notice Interface for the Raizo executor contract — handles protective actions
 *         triggered by verified DON reports.
 */
interface ISentinelActions {
    // ─── Enums ───
    enum ActionType {
        PAUSE, // Full contract pause
        RATE_LIMIT, // Reduce throughput
        DRAIN_BLOCK, // Block large withdrawals
        ALERT, // Emit alert event only (no state change)
        CUSTOM // Arbitrary calldata execution
    }

    enum Severity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    // ─── Structs ───
    struct ThreatReport {
        bytes32 reportId;
        bytes32 agentId;
        bool exists;
        address targetProtocol;
        ActionType action;
        Severity severity;
        uint16 confidenceScore; // basis points
        bytes evidenceHash; // IPFS/Arweave CID of full evidence
        uint256 timestamp;
        bytes donSignatures; // Aggregated DON attestation
    }

    // ─── Errors ───
    error DuplicateReport(bytes32 reportId);
    error ProtocolNotActive(address protocol);
    error AgentNotActive(bytes32 agentId);
    error ConfidenceThresholdNotMet(uint16 actual, uint16 required);
    error BudgetExceeded(bytes32 agentId, uint256 epoch);
    error ReportNotFound(bytes32 reportId);
    error ReportNotActive(bytes32 reportId);
    error InvalidSignatures();
    error EmergencyPauseAlreadyActive(address protocol);

    // ─── Actions ───
    function executeAction(ThreatReport calldata report) external;
    function executeEmergencyPause(address protocol) external;
    function liftAction(bytes32 reportId) external;

    // ─── State ───
    function getActiveActions(
        address protocol
    ) external view returns (ThreatReport[] memory);
    function isProtocolPaused(address protocol) external view returns (bool);
    function getActionCount(bytes32 agentId) external view returns (uint256);

    // ─── Events ───
    event ActionExecuted(
        bytes32 indexed reportId,
        address indexed protocol,
        ActionType action,
        Severity severity,
        uint16 confidence
    );
    event ActionLifted(bytes32 indexed reportId, address indexed protocol);
    event EmergencyPause(address indexed protocol, address indexed caller);
}
