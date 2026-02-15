// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./interfaces/IRaizoCore.sol";

/**
 * @title RaizoCore
 * @notice Central registry for the Raizo protocol sentinel system.
 *         Manages monitored protocols, agent configurations, and global
 *         sentinel parameters (confidence threshold, epoch duration).
 */
contract RaizoCore is IRaizoCore, AccessControl {

    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    uint16 private constant DEFAULT_CONFIDENCE_THRESHOLD = 8500; // 85%
    uint256 private constant DEFAULT_EPOCH_DURATION = 1 days;

    /// @dev protocol address → config
    mapping(address => ProtocolConfig) private _protocols;

    /// @dev enumerable list of active protocol addresses
    address[] private _protocolList;

    /// @dev agent ID → config
    mapping(bytes32 => AgentConfig) private _agents;

    /// @dev minimum confidence score (basis points) for sentinel actions
    uint16 private _confidenceThreshold;

    /// @dev action budget reset period (seconds)
    uint256 private _epochDuration;


    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _confidenceThreshold = DEFAULT_CONFIDENCE_THRESHOLD;
        _epochDuration = DEFAULT_EPOCH_DURATION;
    }


    modifier onlyAdminOrGovernance() {
        if (
            !hasRole(DEFAULT_ADMIN_ROLE, msg.sender) &&
            !hasRole(GOVERNANCE_ROLE, msg.sender)
        ) {
            revert AccessControlUnauthorizedAccount(
                msg.sender,
                GOVERNANCE_ROLE
            );
        }
        _;
    }

    /// @inheritdoc IRaizoCore
    function registerProtocol(
        address protocol,
        uint16 chainId,
        uint8 riskTier
    ) external override onlyAdminOrGovernance {
        if (protocol == address(0)) revert ZeroAddress();
        if (riskTier == 0 || riskTier > 4) revert InvalidRiskTier(riskTier);
        if (_protocols[protocol].isActive)
            revert ProtocolAlreadyRegistered(protocol);

        _protocols[protocol] = ProtocolConfig({
            protocolAddress: protocol,
            chainId: chainId,
            riskTier: riskTier,
            isActive: true,
            registeredAt: block.timestamp
        });

        _protocolList.push(protocol);

        emit ProtocolRegistered(protocol, chainId, riskTier);
    }

    /// @inheritdoc IRaizoCore
    function deregisterProtocol(
        address protocol
    ) external override onlyAdminOrGovernance {
        if (!_protocols[protocol].isActive)
            revert ProtocolNotRegistered(protocol);

        _protocols[protocol].isActive = false;

        // Remove from the active list (swap-and-pop)
        uint256 len = _protocolList.length;
        for (uint256 i = 0; i < len; i++) {
            if (_protocolList[i] == protocol) {
                _protocolList[i] = _protocolList[len - 1];
                _protocolList.pop();
                break;
            }
        }

        emit ProtocolDeregistered(protocol);
    }

    /// @inheritdoc IRaizoCore
    function updateRiskTier(
        address protocol,
        uint8 newTier
    ) external override onlyAdminOrGovernance {
        if (!_protocols[protocol].isActive)
            revert ProtocolNotRegistered(protocol);
        if (newTier == 0 || newTier > 4) revert InvalidRiskTier(newTier);

        uint8 oldTier = _protocols[protocol].riskTier;
        _protocols[protocol].riskTier = newTier;

        emit RiskTierUpdated(protocol, oldTier, newTier);
    }

    /// @inheritdoc IRaizoCore
    function getProtocol(
        address protocol
    ) external view override returns (ProtocolConfig memory) {
        return _protocols[protocol];
    }

    /// @inheritdoc IRaizoCore
    function getAllProtocols()
        external
        view
        override
        returns (ProtocolConfig[] memory)
    {
        uint256 len = _protocolList.length;
        ProtocolConfig[] memory result = new ProtocolConfig[](len);
        for (uint256 i = 0; i < len; i++) {
            result[i] = _protocols[_protocolList[i]];
        }
        return result;
    }

    /// @inheritdoc IRaizoCore
    function getProtocolCount() external view override returns (uint256) {
        return _protocolList.length;
    }

    /// @inheritdoc IRaizoCore
    function registerAgent(
        bytes32 agentId,
        address paymentWallet,
        uint256 dailyBudget,
        uint256 actionBudget
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (paymentWallet == address(0)) revert ZeroAddress();
        if (_agents[agentId].isActive) revert AgentAlreadyRegistered(agentId);

        _agents[agentId] = AgentConfig({
            agentId: agentId,
            paymentWallet: paymentWallet,
            dailyBudgetUSDC: dailyBudget,
            actionBudgetPerEpoch: actionBudget,
            isActive: true
        });

        emit AgentRegistered(agentId, paymentWallet);
    }

    /// @inheritdoc IRaizoCore
    function deregisterAgent(
        bytes32 agentId
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!_agents[agentId].isActive) revert AgentNotRegistered(agentId);

        _agents[agentId].isActive = false;

        emit AgentDeregistered(agentId);
    }

    /// @inheritdoc IRaizoCore
    function getAgent(
        bytes32 agentId
    ) external view override returns (AgentConfig memory) {
        return _agents[agentId];
    }

    /// @inheritdoc IRaizoCore
    function setConfidenceThreshold(
        uint16 threshold
    ) external override onlyAdminOrGovernance {
        if (threshold > 10000) revert InvalidThreshold(threshold);

        uint16 oldThreshold = _confidenceThreshold;
        _confidenceThreshold = threshold;

        emit ConfidenceThresholdUpdated(oldThreshold, threshold);
    }

    /// @inheritdoc IRaizoCore
    function setEpochDuration(
        uint256 duration
    ) external override onlyAdminOrGovernance {
        if (duration == 0) revert InvalidEpochDuration(duration);

        uint256 oldDuration = _epochDuration;
        _epochDuration = duration;

        emit EpochDurationUpdated(oldDuration, duration);
    }

    /// @inheritdoc IRaizoCore
    function getConfidenceThreshold() external view override returns (uint16) {
        return _confidenceThreshold;
    }

    /// @inheritdoc IRaizoCore
    function getEpochDuration() external view override returns (uint256) {
        return _epochDuration;
    }
}
