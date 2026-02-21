// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockUpgradeTarget
 * @notice Minimal mock that accepts upgradeToAndCall for testing TimelockUpgradeController.
 */
contract MockUpgradeTarget {
    address public implementation;

    event UpgradePerformed(address newImplementation);

    function upgradeToAndCall(
        address newImplementation,
        bytes memory /* data */
    ) external {
        implementation = newImplementation;
        emit UpgradePerformed(newImplementation);
    }
}
