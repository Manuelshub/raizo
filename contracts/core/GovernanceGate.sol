// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "./interfaces/IGovernanceGate.sol";

/**
 * @title GovernanceGate
 * @notice Minimal governance module with admin-only configuration setters and emergency pause control.
 * @dev Implementation follows UUPS upgradeable pattern.
 *      Configuration parameters are set by admin and can be updated on-the-fly for demo flexibility.
 */
contract GovernanceGate is
    Initializable,
    IGovernanceGate,
    AccessControlUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    /// @notice Role for emergency pause actions.
    bytes32 public constant EMERGENCY_PAUSER_ROLE =
        keccak256("EMERGENCY_PAUSER_ROLE");

    IGovernanceGate.Config public config;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the GovernanceGate contract.
     * @param _admin The admin address for configuration management.
     * @param _confidenceThreshold Initial confidence threshold (e.g., 8500 = 85%).
     */
    function initialize(
        address _admin,
        uint16 _confidenceThreshold
    ) public initializer {
        __AccessControl_init();
        __Pausable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(EMERGENCY_PAUSER_ROLE, _admin);

        config = Config({
            confidenceThreshold: _confidenceThreshold,
            emergencyPauseDelay: 0
        });
    }

    /**
     * @inheritdoc UUPSUpgradeable
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    // ─── Admin Configuration Setters ────────────────────────────────────

    /**
     * @notice Update the confidence threshold for threat detection.
     * @param newThreshold New threshold (e.g., 8500 = 85%).
     */
    function setConfidenceThreshold(
        uint16 newThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newThreshold > 10000) revert InvalidThreshold(newThreshold);
        config.confidenceThreshold = newThreshold;
        emit ConfigUpdated("confidenceThreshold", newThreshold);
    }

    /**
     * @notice Update the emergency pause delay.
     * @param newDelay New delay in blocks.
     */
    function setEmergencyPauseDelay(
        uint256 newDelay
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        config.emergencyPauseDelay = newDelay;
        emit ConfigUpdated("emergencyPauseDelay", newDelay);
    }

    // ─── Emergency Controls ─────────────────────────────────────────────

    /**
     * @notice Trigger emergency pause of all sentinel actions.
     */
    function emergencyPause() external onlyRole(EMERGENCY_PAUSER_ROLE) {
        _pause();
        emit EmergencyPauseTriggered(msg.sender);
    }

    /**
     * @notice Lift the emergency pause (admin only).
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
        emit PauseLifted(msg.sender);
    }

    /**
     * @notice Check if the system is paused.
     */
    function isPaused() external view returns (bool) {
        return paused();
    }

    // ─── Config Getters ────────────────────────────────────────────────

    /**
     * @notice Get the current confidence threshold.
     */
    function getConfidenceThreshold() external view returns (uint16) {
        return config.confidenceThreshold;
    }

    /**
     * @notice Get the current emergency pause delay.
     */
    function getEmergencyPauseDelay() external view returns (uint256) {
        return config.emergencyPauseDelay;
    }

    /**
     * @notice Get the full configuration.
     */
    function getConfig() external view returns (IGovernanceGate.Config memory) {
        return config;
    }

    uint256[50] private __gap;
}
