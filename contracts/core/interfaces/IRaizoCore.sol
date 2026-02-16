// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IRaizoCore
 * @notice Interface for the Raizo protocol registry — manages monitored protocols,
 *         agent configurations, and global sentinel parameters.
 */
interface IRaizoCore {
    // ─── Structs ───
    struct ProtocolConfig {
        address protocolAddress; // Target protocol contract
        uint16 chainId; // Chain selector (CCIP format)
        uint8 riskTier; // 1=low, 2=medium, 3=high, 4=critical
        bool isActive;
        uint256 registeredAt;
    }

    struct AgentConfig {
        bytes32 agentId; // CRE workflow identifier
        address paymentWallet; // x402 escrow address
        uint256 dailyBudgetUSDC; // Max daily spend (6 decimals)
        uint256 actionBudgetPerEpoch; // Max protective actions per epoch
        bool isActive;
    }

    // ─── Errors ───
    error ProtocolAlreadyRegistered(address protocol);
    error ProtocolNotRegistered(address protocol);
    error AgentAlreadyRegistered(bytes32 agentId);
    error AgentNotRegistered(bytes32 agentId);
    error InvalidRiskTier(uint8 tier);
    error InvalidThreshold(uint16 threshold);
    error InvalidEpochDuration(uint256 duration);
    error ZeroAddress();
    error CallerNotAdminOrGovernance(address caller);
    error AccessDenied(address caller, bytes32 role);

    // ─── Events ───
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
    event ConfigUpdated(string key, uint256 value);

    // ─── Protocol Management ───
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

    // ─── Agent Management ───
    function registerAgent(
        bytes32 agentId,
        address paymentWallet,
        uint256 dailyBudget
    ) external;
    function deregisterAgent(bytes32 agentId) external;
    function getAgent(
        bytes32 agentId
    ) external view returns (AgentConfig memory);

    // ─── Configuration ───
    function setConfidenceThreshold(uint16 threshold) external; // basis points (e.g., 8500 = 85%)
    function setEpochDuration(uint256 duration) external;
    function getConfidenceThreshold() external view returns (uint16);
    function getEpochDuration() external view returns (uint256);
}
