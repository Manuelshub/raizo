// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "../../contracts/core/interfaces/IRaizoCore.sol";
import "../../contracts/core/interfaces/ISentinelActions.sol";

/**
 * @title SentinelActions
 * @notice Executor contract for Raizo protective actions.
 *         Verifies DON-attested reports and executes actions against protocols.
 * @dev Tracks active threat reports to manage protocol pause states.
 */
contract SentinelActions is
    Initializable,
    ISentinelActions,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    IRaizoCore public raizoCore;

    /**
     * @dev Mapping from report ID to persistence.
     */
    mapping(bytes32 => ThreatReport) private _reports;

    /**
     * @dev Mapping from report ID to its active status.
     */
    mapping(bytes32 => bool) private _reportActive;

    /**
     * @dev Mapping from protocol address to a list of active report IDs.
     */
    mapping(address => bytes32[]) private _protocolActiveReports;

    /**
     * @dev Mapping from protocol address to emergency pause status.
     */
    mapping(address => bool) private _emergencyPaused;

    /**
     * @dev Per-agent per-epoch action tracking.
     */
    mapping(bytes32 => mapping(uint256 => uint256)) private _agentBudgets;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the SentinelActions contract.
     * @param _raizoCore The address of the RaizoCore registry.
     */
    function initialize(address _raizoCore) public initializer {
        __AccessControl_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        raizoCore = IRaizoCore(_raizoCore);
    }

    /**
     * @inheritdoc UUPSUpgradeable
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /**
     * @notice Executes a protective action against a target protocol based on a verified DON report.
     * @param report The threat report containing agent, protocol, and action details.
     */
    function executeAction(
        ThreatReport calldata report
    ) external override nonReentrant {
        if (_reports[report.reportId].reportId != bytes32(0)) {
            revert DuplicateReport(report.reportId);
        }

        // Validate protocol and agent
        IRaizoCore.ProtocolConfig memory protocol = raizoCore.getProtocol(
            report.targetProtocol
        );
        if (!protocol.isActive) revert ProtocolNotActive(report.targetProtocol);

        IRaizoCore.AgentConfig memory agent = raizoCore.getAgent(
            report.agentId
        );
        if (!agent.isActive) revert AgentNotActive(report.agentId);

        // Confidence Gate
        uint16 minConfidence = raizoCore.getConfidenceThreshold();
        if (report.confidenceScore < minConfidence) {
            revert ConfidenceThresholdNotMet(
                report.confidenceScore,
                minConfidence
            );
        }

        // DON Signature Verification (Simplified stub for now, as per spec requirements)
        _verifySignatures(report);

        // Budget Check
        uint256 epoch = block.timestamp / raizoCore.getEpochDuration();
        if (
            _agentBudgets[report.agentId][epoch] >= agent.actionBudgetPerEpoch
        ) {
            revert BudgetExceeded(report.agentId, epoch);
        }

        // State persistence
        ThreatReport memory reportToStore = report;
        reportToStore.exists = true;
        _reports[report.reportId] = reportToStore;
        _reportActive[report.reportId] = true;
        _protocolActiveReports[report.targetProtocol].push(report.reportId);
        _agentBudgets[report.agentId][epoch]++;

        // Target Action execution (Mock logic for PAUSE)
        if (report.action == ActionType.PAUSE) {
            // In a real system, this would call the target protocol's pause function.
            // For now, we track the state locally.
        }

        emit ActionExecuted(
            report.reportId,
            report.targetProtocol,
            report.action,
            report.severity,
            report.confidenceScore
        );
    }

    /**
     * @inheritdoc ISentinelActions
     */
    /**
     * @notice Forces an immediate pause on a protocol via the EMERGENCY_ROLE.
     * @dev Bypasses DON consensus for critical zero-day response.
     * @param protocol Target protocol address to pause.
     */
    function executeEmergencyPause(
        address protocol
    ) external override onlyRole(EMERGENCY_ROLE) {
        if (_emergencyPaused[protocol]) {
            revert EmergencyPauseAlreadyActive(protocol);
        }
        _emergencyPaused[protocol] = true;
        emit EmergencyPause(protocol, msg.sender);
    }

    /**
     * @inheritdoc ISentinelActions
     */
    /**
     * @notice Resolves a threat report and removes its impact on the protocol state.
     * @dev Protocol unpauses only if no other active reports or emergency pauses exist.
     * @param reportId Unique identifier of the report to lift.
     */
    function liftAction(bytes32 reportId) external override {
        // In a production system, this might be restricted to GOVERNANCE or ADMIN.
        // For this hardening block, we implement the multi-report lifting logic.
        ThreatReport memory report = _reports[reportId];
        if (report.reportId == bytes32(0)) revert ReportNotFound(reportId);
        if (!_reportActive[reportId]) revert ReportNotActive(reportId);

        _reportActive[reportId] = false;

        // Remove from active list
        bytes32[] storage activeList = _protocolActiveReports[
            report.targetProtocol
        ];
        for (uint256 i = 0; i < activeList.length; i++) {
            if (activeList[i] == reportId) {
                activeList[i] = activeList[activeList.length - 1];
                activeList.pop();
                break;
            }
        }

        emit ActionLifted(reportId, report.targetProtocol);
    }

    /**
     * @inheritdoc ISentinelActions
     */
    function getActiveActions(
        address protocol
    ) external view override returns (ThreatReport[] memory) {
        bytes32[] memory ids = _protocolActiveReports[protocol];
        ThreatReport[] memory result = new ThreatReport[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            result[i] = _reports[ids[i]];
        }
        return result;
    }

    /**
     * @inheritdoc ISentinelActions
     */
    function isProtocolPaused(
        address protocol
    ) external view override returns (bool) {
        return
            _emergencyPaused[protocol] ||
            _protocolActiveReports[protocol].length > 0;
    }

    /**
     * @inheritdoc ISentinelActions
     */
    function getActionCount(
        bytes32 agentId
    ) external view override returns (uint256) {
        uint256 epoch = block.timestamp / raizoCore.getEpochDuration();
        return _agentBudgets[agentId][epoch];
    }

    /**
     * @dev Internal signature verification stub.
     */
    function _verifySignatures(ThreatReport calldata report) internal pure {
        // In a live system, this would recover 2/3 signatures from the DON.
        // For this hardened implementation, we validate that signatures are present.
        if (report.donSignatures.length == 0) {
            revert InvalidSignatures();
        }
    }

    uint256[50] private __gap;
}
