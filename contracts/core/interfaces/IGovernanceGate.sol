// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/**
 * @title IGovernanceGate
 * @notice Minimal governance module with admin-only configuration and emergency pause controls.
 */
interface IGovernanceGate {
    struct Config {
        uint16 confidenceThreshold; // e.g., 8500 = 85%
        uint256 emergencyPauseDelay; // Blocks before pause takes effect
    }

    // ─── Errors ───
    error InvalidThreshold(uint16 threshold);

    // ─── Admin Configuration ───

    /**
     * @notice Update the confidence threshold for threat detection.
     */
    function setConfidenceThreshold(uint16 newThreshold) external;

    /**
     * @notice Update the emergency pause delay.
     */
    function setEmergencyPauseDelay(uint256 newDelay) external;

    // ─── Emergency Controls ───

    /**
     * @notice Trigger emergency pause of all sentinel actions.
     */
    function emergencyPause() external;

    /**
     * @notice Lift the emergency pause (admin only).
     */
    function unpause() external;

    /**
     * @notice Check if the system is paused.
     */
    function isPaused() external view returns (bool);

    // ─── Config Getters ───

    /**
     * @notice Get the current confidence threshold.
     */
    function getConfidenceThreshold() external view returns (uint16);

    /**
     * @notice Get the current emergency pause delay.
     */
    function getEmergencyPauseDelay() external view returns (uint256);

    /**
     * @notice Get the full configuration.
     */
    function getConfig() external view returns (Config memory);

    // ─── Events ───
    event ConfigUpdated(string paramName, uint256 newValue);
    event EmergencyPauseTriggered(address indexed pauser);
    event PauseLifted(address indexed unpauser);
}
