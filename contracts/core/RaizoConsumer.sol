// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ReceiverTemplate} from "../cre/ReceiverTemplate.sol";
import {ISentinelActions} from "./interfaces/ISentinelActions.sol";
import {IComplianceVault} from "./interfaces/IComplianceVault.sol";

/**
 * @title RaizoConsumer
 * @notice CRE consumer contract that receives workflow reports and routes them
 *         to the appropriate executor (SentinelActions or ComplianceVault).
 * @dev Inherits ReceiverTemplate for forwarder validation. Report payload is
 *      a tagged union: abi.encode(uint8 reportType, bytes data).
 *
 *      Report types:
 *        0 = Threat report → SentinelActions.executeAction(ThreatReport)
 *        1 = Compliance anchor → ComplianceVault.storeReport(...)
 */
contract RaizoConsumer is ReceiverTemplate {
    /// @notice Report type identifiers.
    uint8 public constant REPORT_TYPE_THREAT = 0;
    uint8 public constant REPORT_TYPE_COMPLIANCE = 1;

    ISentinelActions public sentinel;
    IComplianceVault public vault;

    error InvalidReportType(uint8 reportType);
    error SentinelNotConfigured();
    error VaultNotConfigured();

    event ThreatReportForwarded(
        bytes32 indexed reportId,
        address indexed protocol
    );
    event ComplianceReportAnchored(bytes32 indexed reportHash, uint16 chainId);

    /**
     * @param _forwarderAddress Chainlink KeystoneForwarder (or MockForwarder for simulation).
     * @param _sentinel SentinelActions executor contract.
     * @param _vault ComplianceVault storage contract.
     */
    constructor(
        address _forwarderAddress,
        address _sentinel,
        address _vault
    ) ReceiverTemplate(_forwarderAddress) {
        sentinel = ISentinelActions(_sentinel);
        vault = IComplianceVault(_vault);
    }

    /**
     * @notice Routes decoded report to the appropriate on-chain executor.
     * @param report ABI-encoded: (uint8 reportType, bytes data)
     */
    function _processReport(bytes calldata report) internal override {
        (uint8 reportType, bytes memory data) = abi.decode(
            report,
            (uint8, bytes)
        );

        if (reportType == REPORT_TYPE_THREAT) {
            _handleThreatReport(data);
        } else if (reportType == REPORT_TYPE_COMPLIANCE) {
            _handleComplianceReport(data);
        } else {
            revert InvalidReportType(reportType);
        }
    }

    /**
     * @dev Decodes ThreatReport and forwards to SentinelActions.executeAction.
     */
    function _handleThreatReport(bytes memory data) internal {
        if (address(sentinel) == address(0)) revert SentinelNotConfigured();

        ISentinelActions.ThreatReport memory threatReport = abi.decode(
            data,
            (ISentinelActions.ThreatReport)
        );

        sentinel.executeAction(threatReport);

        emit ThreatReportForwarded(
            threatReport.reportId,
            threatReport.targetProtocol
        );
    }

    /**
     * @dev Decodes compliance anchoring params and forwards to ComplianceVault.storeReport.
     */
    function _handleComplianceReport(bytes memory data) internal {
        if (address(vault) == address(0)) revert VaultNotConfigured();

        (
            bytes32 reportHash,
            bytes32 agentId,
            uint8 reportType,
            uint16 chainId,
            string memory reportURI
        ) = abi.decode(data, (bytes32, bytes32, uint8, uint16, string));

        vault.storeReport(reportHash, agentId, reportType, chainId, reportURI);

        emit ComplianceReportAnchored(reportHash, chainId);
    }

    /// @notice Update SentinelActions address. Owner-only.
    function setSentinel(address _sentinel) external onlyOwner {
        sentinel = ISentinelActions(_sentinel);
    }

    /// @notice Update ComplianceVault address. Owner-only.
    function setVault(address _vault) external onlyOwner {
        vault = IComplianceVault(_vault);
    }
}
