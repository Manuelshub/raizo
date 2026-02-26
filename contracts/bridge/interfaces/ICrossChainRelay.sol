// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ISentinelActions} from "../../core/interfaces/ISentinelActions.sol";

/**
 * @title ICrossChainRelay
 * @notice Interface for CCIP-aware relay contracts facilitating cross-chain
 *         alert propagation and protective actions.
 */
interface ICrossChainRelay {
    enum MessageType {
        ALERT_PROPAGATE,
        ACTION_EXECUTE,
        CONFIG_SYNC,
        HEARTBEAT,
        INCIDENT_REPORT
    }

    struct CrossChainMessage {
        MessageType messageType;
        bytes32 reportId;
        bytes32 agentId;
        uint64 sourceChainSelector;
        uint64 destChainSelector;
        address targetProtocol;
        ISentinelActions.ActionType actionType;
        ISentinelActions.Severity severity;
        uint16 confidenceScore;
        uint256 timestamp;
        bytes payload;
        bytes donAttestation;
    }

    // ─── Errors ───
    error UnauthorizedSourceChain(uint64 sourceChainSelector);
    error UnauthorizedSourceSender(address sourceSender);
    error InvalidMessageType();
    error MessageAlreadyProcessed(bytes32 reportId);
    error TransferFailed();
    error AccessDenied(address caller, bytes32 role);

    // ─── Actions ───

    /**
     * @notice Send alert/action to another chain.
     * @param destChainSelector The CCIP chain selector for the destination.
     * @param reportId The unique identifier of the originating threat report.
     * @param actionType The type of protective action.
     * @param targetProtocol The address of the protocol to act upon on the target chain.
     * @param payload Additional action-specific data (unstructured).
     * @return messageId The CCIP message identifier.
     */
    function sendAlert(
        uint64 destChainSelector,
        bytes32 reportId,
        ISentinelActions.ActionType actionType,
        address targetProtocol,
        bytes calldata payload
    ) external returns (bytes32 messageId);

    /**
     * @notice Checks if a source chain is whitelisted.
     */
    function isSourceChainWhitelisted(
        uint64 chainSelector
    ) external view returns (bool);

    /**
     * @notice Checks if a source sender on a specific chain is whitelisted.
     */
    function isSourceSenderWhitelisted(
        uint64 chainSelector,
        address sender
    ) external view returns (bool);

    // ─── Events ───
    event AlertSent(
        bytes32 indexed messageId,
        uint64 indexed destChainSelector,
        bytes32 indexed reportId
    );
    event AlertReceived(
        bytes32 indexed messageId,
        uint64 indexed sourceChainSelector,
        bytes32 indexed reportId
    );
    event AlertExecuted(
        bytes32 indexed messageId,
        address indexed targetProtocol,
        ISentinelActions.ActionType actionType
    );
    event SourceChainWhitelisted(uint64 indexed chainSelector, bool allowed);
    event SourceSenderWhitelisted(
        uint64 indexed chainSelector,
        address indexed sender,
        bool allowed
    );
}
