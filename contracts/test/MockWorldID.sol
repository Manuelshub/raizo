// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../core/interfaces/IWorldID.sol";

/**
 * @title MockWorldID
 * @notice Simplified World ID simulation for unit testing.
 * @dev Reverts with InvalidProof if the proof[0] is 0xDEADBEEF, otherwise passes.
 */
contract MockWorldID is IWorldID {
    error InvalidProof();

    function verifyProof(
        uint256, // root
        uint256, // groupId
        uint256, // signalHash
        uint256, // nullifierHash
        uint256, // externalNullifierHash
        uint256[8] calldata proof
    ) external pure override {
        // Simple magic value check to simulate failure
        if (proof[0] == 0xDEADBEEF) {
            revert InvalidProof();
        }
    }
}
