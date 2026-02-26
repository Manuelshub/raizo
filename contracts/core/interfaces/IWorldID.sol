// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/**
 * @title IWorldID
 * @notice Interface for the World ID verification Hub.
 * @dev This is a simplified interface based on the World ID Semaphore pattern.
 */
interface IWorldID {
    /**
     * @notice Verifies a World ID proof.
     * @param root The Merkle root of the World ID identity tree.
     * @param groupId The group ID (ignored for now, usually 1).
     * @param signalHash A hash of the signal being verified (e.g., proposer address).
     * @param nullifierHash The nullifier hash to prevent double-voting/signing.
     * @param externalNullifierHash A unique identifier for the action being performed.
     * @param proof The 8-element Groth16 ZK proof.
     */
    function verifyProof(
        uint256 root,
        uint256 groupId,
        uint256 signalHash,
        uint256 nullifierHash,
        uint256 externalNullifierHash,
        uint256[8] calldata proof
    ) external;
}
