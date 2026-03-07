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

    /// @notice Stores a user-submitted IDKit proof awaiting CRE off-chain verification.
    struct PendingRequest {
        address requester;
        bytes32 descriptionHash;
        bytes idkitResponse; // Raw IDKit JSON response (forwarded to World ID Verify API)
        bool processed;
        uint256 submittedBlock;
    }

    // ─── Errors ───
    error ProposalAlreadyExecuted(uint256 proposalId);
    error ProposalNotActive(uint256 proposalId);
    error ProposalExpired(uint256 proposalId);
    error ProposalNotPassed(uint256 proposalId);
    error DoubleVoting(uint256 nullifierHash);
    error InvalidProof();
    error GovernanceNotConfigured();
    error RequestAlreadyProcessed(uint256 requestId);
    error InvalidIdkitResponse();

    // ─── Actions (Direct On-Chain Verification) ───

    /**
     * @notice Submit a proposal (requires on-chain World ID verification).
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
     * @notice Cast a vote (requires on-chain World ID verification).
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

    // ─── Proof Queue (User → On-Chain → CRE Off-Chain Verification) ───

    /**
     * @notice Submit an IDKit proof for off-chain verification by the CRE DON.
     * @dev The raw IDKit response JSON is stored on-chain. The CRE workflow reads
     *      it, forwards it to POST /api/v4/verify/{rp_id}, and writes the result
     *      back via proposeAttested/voteAttested.
     * @param idkitResponse The raw IDKit JSON response bytes (proof, nullifier, merkle_root, etc.).
     * @param descriptionHash Hash of the proposal text/details.
     * @return requestId The unique identifier for the pending request.
     */
    function submitProofRequest(
        bytes calldata idkitResponse,
        bytes32 descriptionHash
    ) external returns (uint256 requestId);

    /**
     * @notice Read a pending proof request.
     * @param requestId The ID of the pending request.
     * @return The pending request data.
     */
    function getPendingRequest(
        uint256 requestId
    ) external view returns (PendingRequest memory);

    /**
     * @notice Number of pending proof requests.
     */
    function pendingRequestCount() external view returns (uint256);

    // ─── Actions (CRE DON-Attested — Off-Chain Verification) ───

    /**
     * @notice Submit a proposal with a DON-attested World ID proof.
     * @dev Called by RaizoConsumer after the CRE workflow verified the proof
     *      off-chain via World ID API. Requires ATTESTER_ROLE.
     * @param descriptionHash Hash of the proposal text/details.
     * @param nullifierHash Prevents double-proposing (sybil resistance).
     * @param proposer The address of the human who submitted the proof.
     * @return proposalId Unique identifier for the proposal.
     */
    function proposeAttested(
        bytes32 descriptionHash,
        uint256 nullifierHash,
        address proposer
    ) external returns (uint256 proposalId);

    /**
     * @notice Cast a vote with a DON-attested World ID proof.
     * @dev Called by RaizoConsumer after the CRE workflow verified the proof
     *      off-chain via World ID API. Requires ATTESTER_ROLE.
     * @param proposalId The ID of the proposal to vote on.
     * @param support Whether to support (true) or oppose (false) the proposal.
     * @param nullifierHash Prevents double-voting (sybil resistance).
     * @param voter The address of the human who submitted the proof.
     */
    function voteAttested(
        uint256 proposalId,
        bool support,
        uint256 nullifierHash,
        address voter
    ) external;

    /**
     * @notice Execute a passed proposal.
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
    event VerificationRequested(
        uint256 indexed requestId,
        address indexed requester,
        bytes32 descriptionHash
    );
}
