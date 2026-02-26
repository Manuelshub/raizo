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
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        worldId = IWorldID(_worldId);
    }

    /**
     * @inheritdoc UUPSUpgradeable
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /**
     * @notice Submit a proposal (requires World ID verification).
     * @dev Verification signal is the proposer's address. Proposing prevents
     *      further proposals/votes from the same person on the SAME proposal scope
     *      if nullifiers are reused improperly.
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

        // Verification signal is the proposer's address
        worldId.verifyProof(
            root,
            1, // groupId
            uint256(keccak256(abi.encodePacked(msg.sender))) >> 8,
            nullifierHash,
            uint256(keccak256(abi.encodePacked("proposal-registration"))) >> 8,
            proof
        );

        _nullifierHashes[nullifierHash] = true;

        proposalId = proposalCount++;
        _proposals[proposalId] = Proposal({
            proposalId: proposalId,
            descriptionHash: descriptionHash,
            proposer: msg.sender,
            forVotes: 0,
            againstVotes: 0,
            startBlock: block.number,
            endBlock: block.number + 7200, // ~1 day
            executed: false
        });

        emit ProposalCreated(proposalId, msg.sender, descriptionHash);
    }

    /**
     * @notice Cast a vote (requires World ID verification).
     * @dev Nullifier is tracked per individual human to prevent double voting.
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
        Proposal storage proposal = _proposals[proposalId];
        if (block.number > proposal.endBlock)
            revert ProposalExpired(proposalId);
        if (proposal.executed) revert ProposalAlreadyExecuted(proposalId);
        if (_nullifierHashes[nullifierHash]) revert DoubleVoting(nullifierHash);

        // Action ID scoping for voting prevents double-voting across proposals
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

        if (support) {
            proposal.forVotes++;
        } else {
            proposal.againstVotes++;
        }

        emit VoteCast(proposalId, msg.sender, support);
    }

    /**
     * @notice Execute a passed proposal.
     * @dev Reverts if proposal is active, executed, or failed.
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

    /**
     * @inheritdoc IGovernanceGate
     */
    function getProposal(
        uint256 proposalId
    ) external view override returns (Proposal memory) {
        return _proposals[proposalId];
    }

    uint256[50] private __gap;
}
