// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ReceiverTemplate} from "../cre/ReceiverTemplate.sol";
import {ISentinelActions} from "./interfaces/ISentinelActions.sol";
import {IComplianceVault} from "./interfaces/IComplianceVault.sol";
import {IPaymentEscrow} from "./interfaces/IPaymentEscrow.sol";
import {IGovernanceGate} from "./interfaces/IGovernanceGate.sol";

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
 *        2 = Payment authorization → PaymentEscrow.authorizePayment(...)
 *        3 = Governance action → GovernanceGate.proposeAttested/voteAttested
 */
contract RaizoConsumer is ReceiverTemplate {
    /// @notice Report type identifiers.
    uint8 public constant REPORT_TYPE_THREAT = 0;
    uint8 public constant REPORT_TYPE_COMPLIANCE = 1;
    uint8 public constant REPORT_TYPE_PAYMENT = 2;
    uint8 public constant REPORT_TYPE_GOVERNANCE = 3;

    ISentinelActions public sentinel;
    IComplianceVault public vault;
    IPaymentEscrow public escrow;
    IGovernanceGate public governanceGate;

    error InvalidReportType(uint8 reportType);
    error SentinelNotConfigured();
    error VaultNotConfigured();
    error EscrowNotConfigured();
    error GovernanceGateNotConfigured();

    event ReportReceived(uint8 indexed reportType, bytes32 indexed sourceHash);
    event ThreatReportForwarded(
        bytes32 indexed reportId,
        address indexed protocol
    );
    event ComplianceReportAnchored(bytes32 indexed reportHash, uint32 chainId);
    event PaymentAuthorizationProcessed(
        bytes32 indexed agentId,
        bytes32 indexed nonce
    );
    event GovernanceActionProcessed(
        uint8 indexed actionType,
        uint256 indexed nullifierHash
    );

    /**
     * @param _forwarderAddress Chainlink KeystoneForwarder (or MockForwarder for simulation).
     * @param _sentinel SentinelActions executor contract.
     * @param _vault ComplianceVault storage contract.
     */
    constructor(
        address _forwarderAddress,
        address _sentinel,
        address _vault,
        address _escrow,
        address _governanceGate
    ) ReceiverTemplate(_forwarderAddress) {
        sentinel = ISentinelActions(_sentinel);
        vault = IComplianceVault(_vault);
        escrow = IPaymentEscrow(_escrow);
        governanceGate = IGovernanceGate(_governanceGate);
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

        emit ReportReceived(reportType, keccak256(report));

        if (reportType == REPORT_TYPE_THREAT) {
            _handleThreatReport(data);
        } else if (reportType == REPORT_TYPE_COMPLIANCE) {
            _handleComplianceReport(data);
        } else if (reportType == REPORT_TYPE_PAYMENT) {
            _handlePaymentAuthorization(data);
        } else if (reportType == REPORT_TYPE_GOVERNANCE) {
            _handleGovernanceAction(data);
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
            uint32 chainId,
            string memory reportURI
        ) = abi.decode(data, (bytes32, bytes32, uint8, uint32, string));

        vault.storeReport(reportHash, agentId, reportType, chainId, reportURI);

        emit ComplianceReportAnchored(reportHash, chainId);
    }

    /**
     * @dev Decodes payment authorization and forwards to PaymentEscrow.authorizePayment.
     */
    function _handlePaymentAuthorization(bytes memory data) internal {
        if (address(escrow) == address(0)) revert EscrowNotConfigured();

        (
            bytes32 agentId,
            address to,
            uint256 amount,
            uint256 validAfter,
            uint256 validBefore,
            bytes32 nonce,
            bytes memory signature
        ) = abi.decode(
                data,
                (bytes32, address, uint256, uint256, uint256, bytes32, bytes)
            );

        escrow.authorizePayment(
            agentId,
            to,
            amount,
            validAfter,
            validBefore,
            nonce,
            signature
        );

        emit PaymentAuthorizationProcessed(agentId, nonce);
    }

    /**
     * @dev Decodes governance action and forwards to GovernanceGate.
     *      Action types: 0 = propose, 1 = vote.
     */
    function _handleGovernanceAction(bytes memory data) internal {
        if (address(governanceGate) == address(0))
            revert GovernanceGateNotConfigured();

        (
            uint8 actionType,
            bytes32 descriptionHash,
            uint256 proposalId,
            bool support,
            uint256 nullifierHash,
            address actor
        ) = abi.decode(data, (uint8, bytes32, uint256, bool, uint256, address));

        if (actionType == 0) {
            governanceGate.proposeAttested(
                descriptionHash,
                nullifierHash,
                actor
            );
        } else {
            governanceGate.voteAttested(
                proposalId,
                support,
                nullifierHash,
                actor
            );
        }

        emit GovernanceActionProcessed(actionType, nullifierHash);
    }

    /// @notice Update SentinelActions address. Owner-only.
    function setSentinel(address _sentinel) external onlyOwner {
        sentinel = ISentinelActions(_sentinel);
    }

    /// @notice Update ComplianceVault address. Owner-only.
    function setVault(address _vault) external onlyOwner {
        vault = IComplianceVault(_vault);
    }

    /// @notice Update PaymentEscrow address. Owner-only.
    function setEscrow(address _escrow) external onlyOwner {
        escrow = IPaymentEscrow(_escrow);
    }

    /// @notice Update GovernanceGate address. Owner-only.
    function setGovernanceGate(address _governanceGate) external onlyOwner {
        governanceGate = IGovernanceGate(_governanceGate);
    }
}
