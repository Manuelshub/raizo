// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./interfaces/IRaizoCore.sol";

/**
 * @title RaizoCore
 * @notice Central registry that maps monitored protocols, manages agent registrations, and stores global configuration.
 * @dev Implementation follows UUPS upgradeable pattern. Stores the source-of-truth for protected assets.
 */
contract RaizoCore is
    Initializable,
    IRaizoCore,
    AccessControlUpgradeable,
    UUPSUpgradeable
{
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    uint16 private constant DEFAULT_CONFIDENCE_THRESHOLD = 8500; // 85%
    uint256 private constant DEFAULT_EPOCH_DURATION = 1 days;

    mapping(address => ProtocolConfig) private _protocols;
    address[] private _protocolList;
    mapping(bytes32 => AgentConfig) private _agents;
    uint16 private _confidenceThreshold;
    uint256 private _epochDuration;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the RaizoCore contract.
     */
    function initialize() public initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _confidenceThreshold = DEFAULT_CONFIDENCE_THRESHOLD;
        _epochDuration = DEFAULT_EPOCH_DURATION;
    }

    /**
     * @inheritdoc UUPSUpgradeable
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    modifier onlyAdminOrGovernance() {
        if (
            !hasRole(DEFAULT_ADMIN_ROLE, msg.sender) &&
            !hasRole(GOVERNANCE_ROLE, msg.sender)
        ) {
            revert CallerNotAdminOrGovernance(msg.sender);
        }
        _;
    }

    /**
     * @notice Registers a new protocol for Raizo monitoring.
     * @param protocol Target protocol contract address.
     * @param chainId Chain selector identifier (CCIP format).
     * @param riskTier Protocol risk profile (1-4).
     */
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

    /**
     * @inheritdoc IRaizoCore
     */
    function deregisterProtocol(
        address protocol
    ) external override onlyAdminOrGovernance {
        if (!_protocols[protocol].isActive)
            revert ProtocolNotRegistered(protocol);

        _protocols[protocol].isActive = false;
        for (uint256 i = 0; i < _protocolList.length; i++) {
            if (_protocolList[i] == protocol) {
                _protocolList[i] = _protocolList[_protocolList.length - 1];
                _protocolList.pop();
                break;
            }
        }
        emit ProtocolDeregistered(protocol);
    }

    /**
     * @inheritdoc IRaizoCore
     */
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

    /**
     * @inheritdoc IRaizoCore
     */
    function getProtocol(
        address protocol
    ) external view override returns (ProtocolConfig memory) {
        return _protocols[protocol];
    }

    /**
     * @inheritdoc IRaizoCore
     */
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

    /**
     * @notice Registers a protective agent in the system.
     * @param agentId Unique CRE workflow identifier.
     * @param paymentWallet Account used for x402 payment settlements.
     * @param dailyBudget Maximum allowed expenditure per 24h (USDC 6 decimals).
     */
    function registerAgent(
        bytes32 agentId,
        address paymentWallet,
        uint256 dailyBudget
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (paymentWallet == address(0)) revert ZeroAddress();
        if (_agents[agentId].isActive) revert AgentAlreadyRegistered(agentId);

        _agents[agentId] = AgentConfig({
            agentId: agentId,
            paymentWallet: paymentWallet,
            dailyBudgetUSDC: dailyBudget,
            actionBudgetPerEpoch: 10, // Default value as not in registerAgent params
            isActive: true
        });
        emit AgentRegistered(agentId, paymentWallet);
    }

    /**
     * @inheritdoc IRaizoCore
     */
    function deregisterAgent(
        bytes32 agentId
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!_agents[agentId].isActive) revert AgentNotRegistered(agentId);
        _agents[agentId].isActive = false;
        emit AgentDeregistered(agentId);
    }

    /**
     * @inheritdoc IRaizoCore
     */
    function getAgent(
        bytes32 agentId
    ) external view override returns (AgentConfig memory) {
        return _agents[agentId];
    }

    /**
     * @notice Updates the confidence threshold for protective actions.
     * @param threshold New threshold in basis points (e.g., 9000 = 90%).
     */
    function setConfidenceThreshold(
        uint16 threshold
    ) external override onlyRole(GOVERNANCE_ROLE) {
        if (threshold > 10000) revert InvalidThreshold(threshold);
        _confidenceThreshold = threshold;
        emit ConfigUpdated("confidenceThreshold", threshold);
    }

    /**
     * @inheritdoc IRaizoCore
     */
    function setEpochDuration(
        uint256 duration
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (duration == 0) revert InvalidEpochDuration(duration);
        _epochDuration = duration;
        emit ConfigUpdated("epochDuration", duration);
    }

    /**
     * @inheritdoc IRaizoCore
     */
    function getConfidenceThreshold() external view override returns (uint16) {
        return _confidenceThreshold;
    }

    /**
     * @inheritdoc IRaizoCore
     */
    function getEpochDuration() external view override returns (uint256) {
        return _epochDuration;
    }

    uint256[50] private __gap;
}
