// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IRaizoCore
 * @notice Interface for the Raizo protocol registry — manages monitored protocols,
 *         agent configurations, and global sentinel parameters.
 */
interface IRaizoCore {

    struct ProtocolConfig {
        address protocolAddress;
        uint16 chainId;
        uint8 riskTier; // 1=low, 2=medium, 3=high, 4=critical
        bool isActive;
        uint256 registeredAt;
    }

    struct AgentConfig {
        bytes32 agentId;
        address paymentWallet;
        uint256 dailyBudgetUSDC; // 6 decimals
        uint256 actionBudgetPerEpoch;
        bool isActive;
    }


    error ProtocolAlreadyRegistered(address protocol);
    error ProtocolNotRegistered(address protocol);
    error AgentAlreadyRegistered(bytes32 agentId);
    error AgentNotRegistered(bytes32 agentId);
    error InvalidRiskTier(uint8 tier);
    error InvalidThreshold(uint16 threshold);
    error InvalidEpochDuration(uint256 duration);
    error ZeroAddress();


    event ProtocolRegistered(
        address indexed protocol,
        uint16 chainId,
        uint8 riskTier
    );
    event ProtocolDeregistered(address indexed protocol);
    event RiskTierUpdated(
        address indexed protocol,
        uint8 oldTier,
        uint8 newTier
    );
    event AgentRegistered(bytes32 indexed agentId, address paymentWallet);
    event AgentDeregistered(bytes32 indexed agentId);
    event ConfidenceThresholdUpdated(uint16 oldThreshold, uint16 newThreshold);
    event EpochDurationUpdated(uint256 oldDuration, uint256 newDuration);

    function registerProtocol(
        address protocol,
        uint16 chainId,
        uint8 riskTier
    ) external;
    function deregisterProtocol(address protocol) external;
    function updateRiskTier(address protocol, uint8 newTier) external;
    function getProtocol(
        address protocol
    ) external view returns (ProtocolConfig memory);
    function getAllProtocols() external view returns (ProtocolConfig[] memory);
    function getProtocolCount() external view returns (uint256);

    function registerAgent(
        bytes32 agentId,
        address paymentWallet,
        uint256 dailyBudget,
        uint256 actionBudget
    ) external;
    function deregisterAgent(bytes32 agentId) external;
    function getAgent(
        bytes32 agentId
    ) external view returns (AgentConfig memory);
    
    function setConfidenceThreshold(uint16 threshold) external;
    function setEpochDuration(uint256 duration) external;
    function getConfidenceThreshold() external view returns (uint16);
    function getEpochDuration() external view returns (uint256);
}
