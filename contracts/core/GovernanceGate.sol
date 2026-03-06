// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./interfaces/IGovernanceGate.sol";
import "./interfaces/IWorldID.sol";

/**
 * @title GovernanceGate
 * @notice Sybil-resistant governance module leveraging World ID for proof-of-humanness.
 * @dev Implementation follows UUPS upgradeable pattern.
 */
contract GovernanceGate is
    Initializable,
    IGovernanceGate,
    AccessControlUpgradeable,
    UUPSUpgradeable
{
    /// @notice Role for CRE DON-attested governance actions (e.g., RaizoConsumer).
    bytes32 public constant ATTESTER_ROLE = keccak256("ATTESTER_ROLE");

    IWorldID public worldId;
    uint256 public proposalCount;

    mapping(uint256 => Proposal) private _proposals;
    mapping(uint256 => bool) private _nullifierHashes;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the GovernanceGate contract.
     * @param _worldId The address of the World ID verification Hub.
     */
    function initialize(address _worldId) public initializer {
        __AccessControl_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        worldId = IWorldID(_worldId);
    }

    /**
     * @inheritdoc UUPSUpgradeable
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    // ─── Direct On-Chain Verification ───────────────────────────────────

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
    ) external override returns (uint256 proposalId) {
        if (_nullifierHashes[nullifierHash]) revert DoubleVoting(nullifierHash);

        worldId.verifyProof(
            root,
            1, // groupId
            uint256(keccak256(abi.encodePacked(msg.sender))) >> 8,
            nullifierHash,
            uint256(keccak256(abi.encodePacked("proposal-registration"))) >> 8,
            proof
        );

        _nullifierHashes[nullifierHash] = true;

        proposalId = _createProposal(descriptionHash, msg.sender);
    }

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
    ) external override {
        _validateVotePreConditions(proposalId, nullifierHash);

        worldId.verifyProof(
            root,
            1,
            uint256(keccak256(abi.encodePacked(msg.sender))) >> 8,
            nullifierHash,
            uint256(
                keccak256(abi.encodePacked(address(this), "vote", proposalId))
            ) >> 8,
            proof
        );

        _nullifierHashes[nullifierHash] = true;
        _castVote(proposalId, support, msg.sender);
    }

    // ─── CRE DON-Attested (Off-Chain Verification) ─────────────────────

    /**
     * @notice Submit a proposal with a DON-attested World ID proof.
     * @dev The CRE workflow verified the proof off-chain via World ID API.
     *      DON 2/3 consensus + KeystoneForwarder signature provides the
     *      trust anchor. Nullifier uniqueness is enforced on-chain.
     * @param descriptionHash Hash of the proposal text/details.
     * @param nullifierHash Prevents double-proposing (sybil resistance).
     * @param proposer The address of the human who submitted the proof.
     * @return proposalId Unique identifier for the proposal.
     */
    function proposeAttested(
        bytes32 descriptionHash,
        uint256 nullifierHash,
        address proposer
    ) external override onlyRole(ATTESTER_ROLE) returns (uint256 proposalId) {
        if (_nullifierHashes[nullifierHash]) revert DoubleVoting(nullifierHash);

        _nullifierHashes[nullifierHash] = true;

        proposalId = _createProposal(descriptionHash, proposer);
    }

    /**
     * @notice Cast a vote with a DON-attested World ID proof.
     * @dev The CRE workflow verified the proof off-chain via World ID API.
     *      DON 2/3 consensus + KeystoneForwarder signature provides the
     *      trust anchor. Nullifier uniqueness is enforced on-chain.
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
    ) external override onlyRole(ATTESTER_ROLE) {
        _validateVotePreConditions(proposalId, nullifierHash);

        _nullifierHashes[nullifierHash] = true;
        _castVote(proposalId, support, voter);
    }

    // ─── Shared Logic ───────────────────────────────────────────────────

    /**
     * @notice Execute a passed proposal.
     * @param proposalId The ID of the proposal to execute.
     */
    function execute(uint256 proposalId) external override {
        Proposal storage proposal = _proposals[proposalId];
        if (proposal.executed) revert ProposalAlreadyExecuted(proposalId);
        if (block.number <= proposal.endBlock)
            revert ProposalNotActive(proposalId);
        if (proposal.forVotes <= proposal.againstVotes)
            revert ProposalNotPassed(proposalId);

        proposal.executed = true;
        emit ProposalExecuted(proposalId);
    }

    /// @inheritdoc IGovernanceGate
    function getProposal(
        uint256 proposalId
    ) external view override returns (Proposal memory) {
        return _proposals[proposalId];
    }

    // ─── Internal Helpers ───────────────────────────────────────────────

    /**
     * @dev Creates a new proposal and emits the ProposalCreated event.
     */
    function _createProposal(
        bytes32 descriptionHash,
        address proposer
    ) internal returns (uint256 proposalId) {
        proposalId = proposalCount++;
        _proposals[proposalId] = Proposal({
            proposalId: proposalId,
            descriptionHash: descriptionHash,
            proposer: proposer,
            forVotes: 0,
            againstVotes: 0,
            startBlock: block.number,
            endBlock: block.number + 7200, // ~1 day
            executed: false
        });

        emit ProposalCreated(proposalId, proposer, descriptionHash);
    }

    /**
     * @dev Validates vote pre-conditions: active, not executed, no double-vote.
     */
    function _validateVotePreConditions(
        uint256 proposalId,
        uint256 nullifierHash
    ) internal view {
        Proposal storage proposal = _proposals[proposalId];
        if (block.number > proposal.endBlock)
            revert ProposalExpired(proposalId);
        if (proposal.executed) revert ProposalAlreadyExecuted(proposalId);
        if (_nullifierHashes[nullifierHash]) revert DoubleVoting(nullifierHash);
    }

    /**
     * @dev Records a vote and emits the VoteCast event.
     */
    function _castVote(
        uint256 proposalId,
        bool support,
        address voter
    ) internal {
        Proposal storage proposal = _proposals[proposalId];
        if (support) {
            proposal.forVotes++;
        } else {
            proposal.againstVotes++;
        }

        emit VoteCast(proposalId, voter, support);
    }

    uint256[50] private __gap;
}
