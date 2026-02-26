// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/**
 * @title IGovernanceGate
 * @notice Sybil-resistant governance module that requires World ID proof-of-humanness
 *         for voting on sentinel configuration changes.
 */
interface IGovernanceGate {
    struct Proposal {
        uint256 proposalId;
        bytes32 descriptionHash;
        address proposer;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 startBlock;
        uint256 endBlock;
        bool executed;
    }

    // ─── Errors ───
    error ProposalAlreadyExecuted(uint256 proposalId);
    error ProposalNotActive(uint256 proposalId);
    error ProposalExpired(uint256 proposalId);
    error ProposalNotPassed(uint256 proposalId);
    error DoubleVoting(uint256 nullifierHash);
    error InvalidProof();

    // ─── Actions ───

    /**
     * @notice Submit a proposal (requires World ID verification)
     * @param descriptionHash Hash of the proposal text/details.
     * @param root World ID Merkle root.
     * @param nullifierHash Prevents double-voting/proposing.
     * @param proof Groth16 ZK proof.
     * @return proposalId Unique identifier for the proposal.
     */
    function propose(
        bytes32 descriptionHash,
        uint256 root,
        uint256 nullifierHash,
        uint256[8] calldata proof
    ) external returns (uint256 proposalId);

    /**
     * @notice Cast a vote (requires World ID verification)
     * @param proposalId The ID of the proposal to vote on.
     * @param support Whether to support (true) or oppose (false) the proposal.
     * @param root World ID Merkle root.
     * @param nullifierHash Prevents double-voting.
     * @param proof Groth16 ZK proof.
     */
    function vote(
        uint256 proposalId,
        bool support,
        uint256 root,
        uint256 nullifierHash,
        uint256[8] calldata proof
    ) external;

    /**
     * @notice Execute a passed proposal
     * @param proposalId The ID of the proposal to execute.
     */
    function execute(uint256 proposalId) external;

    // ─── State ───

    function getProposal(
        uint256 proposalId
    ) external view returns (Proposal memory);

    // ─── Events ───
    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        bytes32 descriptionHash
    );
    event VoteCast(
        uint256 indexed proposalId,
        address indexed voter,
        bool support
    );
    event ProposalExecuted(uint256 indexed proposalId);
}
