// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ICrossChainRelay} from "./interfaces/ICrossChainRelay.sol";
import {ISentinelActions} from "../core/interfaces/ISentinelActions.sol";
import {IRaizoCore} from "../core/interfaces/IRaizoCore.sol";
import {
    Initializable
} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {
    UUPSUpgradeable
} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {
    AccessControlUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {
    Client,
    IRouterClient,
    IAny2EVMMessageReceiver
} from "../test/MockCCIP.sol"; // Using mocks for now

/**
 * @title CrossChainRelay
 * @notice Skeletal implementation for TDD Red Phase.
 */
contract CrossChainRelay is
    ICrossChainRelay,
    IAny2EVMMessageReceiver,
    Initializable,
    AccessControlUpgradeable,
    UUPSUpgradeable
{
    // --- State Variables ---
    IRouterClient public router;
    ISentinelActions public sentinel;
    IRaizoCore public raizoCore;

    mapping(uint64 => bool) private _whitelistedSourceChains;
    mapping(uint64 => mapping(address => bool))
        private _whitelistedSourceSenders;
    mapping(bytes32 => bool) private _processedReports;

    // (Events and Errors are inherited from ICrossChainRelay)

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the CrossChainRelay contract.
     * @param _router The CCIP Router address.
     * @param _sentinel The local SentinelActions executor.
     * @param _raizoCore The local RaizoCore registry.
     */
    function initialize(
        address _router,
        address _sentinel,
        address _raizoCore
    ) public initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();

        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);

        router = IRouterClient(_router);
        sentinel = ISentinelActions(_sentinel);
        raizoCore = IRaizoCore(_raizoCore);
    }

    /**
     * @inheritdoc ICrossChainRelay
     */
    function sendAlert(
        uint64 destChainSelector,
        bytes32 reportId,
        ISentinelActions.ActionType actionType,
        address targetProtocol,
        bytes calldata payload
    ) external override returns (bytes32 messageId) {
        // Fetch report data from local SentinelActions
        ISentinelActions.ThreatReport[] memory activeActions = sentinel
            .getActiveActions(targetProtocol);
        ISentinelActions.ThreatReport memory report;
        bool found = false;
        for (uint i = 0; i < activeActions.length; i++) {
            if (activeActions[i].reportId == reportId) {
                report = activeActions[i];
                found = true;
                break;
            }
        }

        // Use default values if report not found (e.g. specialized ALERT only)
        if (!found) {
            report.agentId = bytes32(0);
            report.severity = ISentinelActions.Severity.LOW;
            report.confidenceScore = 0;
            report.donSignatures = "0x";
        }

        ICrossChainRelay.CrossChainMessage memory msgData = ICrossChainRelay
            .CrossChainMessage({
                messageType: ICrossChainRelay.MessageType.ACTION_EXECUTE,
                reportId: reportId,
                agentId: report.agentId,
                sourceChainSelector: uint64(block.chainid), // Simplified for mock
                destChainSelector: destChainSelector,
                targetProtocol: targetProtocol,
                actionType: actionType,
                severity: report.severity,
                confidenceScore: uint16(report.confidenceScore),
                timestamp: block.timestamp,
                payload: payload,
                donAttestation: report.donSignatures
            });

        bytes memory data = abi.encode(msgData);

        Client.EVM2AnyMessage memory evm2AnyMessage = Client.EVM2AnyMessage({
            receiver: abi.encode(address(this)), // Assuming Spoke has relay at same address or whitelisted
            data: data,
            tokenAmounts: new Client.EVMTokenAmount[](0),
            extraArgs: "",
            feeToken: address(0) // Native payment for now
        });

        uint256 fee = router.getFee(destChainSelector, evm2AnyMessage);
        messageId = router.ccipSend{value: fee}(
            destChainSelector,
            evm2AnyMessage
        );

        emit AlertSent(messageId, destChainSelector, reportId);
    }

    /**
     * @inheritdoc IAny2EVMMessageReceiver
     */
    function ccipReceive(
        Client.Any2EVMMessage calldata message
    ) external override {
        // 1. Validate Source
        if (!_whitelistedSourceChains[message.sourceChainSelector]) {
            revert UnauthorizedSourceChain(message.sourceChainSelector);
        }

        address sender = abi.decode(message.sender, (address));
        if (!_whitelistedSourceSenders[message.sourceChainSelector][sender]) {
            revert UnauthorizedSourceSender(sender);
        }

        // 2. Decode Message
        ICrossChainRelay.CrossChainMessage memory msgData = abi.decode(
            message.data,
            (ICrossChainRelay.CrossChainMessage)
        );
        if (
            msgData.messageType != ICrossChainRelay.MessageType.ACTION_EXECUTE
        ) {
            revert InvalidMessageType();
        }

        // 3. Prevent Duplicates
        if (_processedReports[msgData.reportId]) {
            revert MessageAlreadyProcessed(msgData.reportId);
        }

        // 4. Execute Action via local Sentinel
        ISentinelActions.ThreatReport memory report = ISentinelActions
            .ThreatReport({
                reportId: msgData.reportId,
                agentId: msgData.agentId,
                exists: true,
                targetProtocol: msgData.targetProtocol,
                action: msgData.actionType,
                severity: msgData.severity,
                confidenceScore: msgData.confidenceScore,
                evidenceHash: abi.encodePacked("CCIP-Relayed"),
                timestamp: msgData.timestamp,
                donSignatures: msgData.donAttestation
            });

        _processedReports[msgData.reportId] = true;
        sentinel.executeAction(report);

        emit AlertReceived(
            message.messageId,
            message.sourceChainSelector,
            msgData.reportId
        );
        emit AlertExecuted(
            message.messageId,
            msgData.targetProtocol,
            msgData.actionType
        );
    }

    // --- Admin Functions ---

    /**
     * @notice Whitelists a source chain for receiving messages.
     * @param chainSelector The chain selector of the source chain.
     * @param allowed True to whitelist, false to unwhitelist.
     */
    function whitelistSourceChain(uint64 chainSelector, bool allowed) external {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert AccessDenied(msg.sender, DEFAULT_ADMIN_ROLE);
        }
        _whitelistedSourceChains[chainSelector] = allowed;
        emit SourceChainWhitelisted(chainSelector, allowed);
    }

    /**
     * @notice Whitelists a source sender on a specific source chain.
     * @param chainSelector The chain selector of the source chain.
     * @param sender The address of the sender to whitelist.
     * @param allowed True to whitelist, false to unwhitelist.
     */
    function whitelistSourceSender(
        uint64 chainSelector,
        address sender,
        bool allowed
    ) external {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert AccessDenied(msg.sender, DEFAULT_ADMIN_ROLE);
        }
        _whitelistedSourceSenders[chainSelector][sender] = allowed;
        emit SourceSenderWhitelisted(chainSelector, sender, allowed);
    }

    /**
     * @inheritdoc ICrossChainRelay
     */
    function isSourceChainWhitelisted(
        uint64 chainSelector
    ) external view override returns (bool) {
        return _whitelistedSourceChains[chainSelector];
    }

    /**
     * @inheritdoc ICrossChainRelay
     */
    function isSourceSenderWhitelisted(
        uint64 chainSelector,
        address sender
    ) external view override returns (bool) {
        return _whitelistedSourceSenders[chainSelector][sender];
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    uint256[50] private __gap;
}
