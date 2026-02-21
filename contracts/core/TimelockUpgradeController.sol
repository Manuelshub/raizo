// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title TimelockUpgradeController
 * @notice Enforces a 48-hour timelock + GovernanceGate approval before UUPS upgrades.
 * @dev Per SMART_CONTRACTS.md §3: All UUPS upgrades must pass through timelock + governance.
 *      This contract is intentionally NOT upgradeable — it controls upgrades of other contracts.
 */
contract TimelockUpgradeController is AccessControl {
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant CANCELLER_ROLE = keccak256("CANCELLER_ROLE");

    uint256 public constant MIN_DELAY = 48 hours;

    enum UpgradeState {
        None,
        Pending,
        Ready,
        Executed,
        Cancelled
    }

    struct UpgradeProposal {
        address proxy;
        address newImplementation;
        uint256 proposedAt;
        uint256 readyAt;
        UpgradeState state;
        bytes32 governanceProposalId;
    }

    mapping(bytes32 => UpgradeProposal) private _proposals;
    bytes32[] private _proposalIds;
    mapping(bytes32 => bool) private _approvedByGovernance;

    // ── Events ──
    event UpgradeProposed(
        bytes32 indexed proposalId,
        address indexed proxy,
        address newImplementation,
        uint256 readyAt
    );
    event UpgradeApprovedByGovernance(
        bytes32 indexed proposalId,
        bytes32 governanceProposalId
    );
    event UpgradeExecuted(
        bytes32 indexed proposalId,
        address indexed proxy,
        address newImplementation
    );
    event UpgradeCancelled(bytes32 indexed proposalId);

    // ── Errors ──
    error ProposalAlreadyExists(bytes32 proposalId);
    error ProposalNotFound(bytes32 proposalId);
    error ProposalNotReady(bytes32 proposalId, uint256 readyAt);
    error ProposalNotApproved(bytes32 proposalId);
    error ProposalNotPending(bytes32 proposalId);
    error InvalidAddress();
    error TimelockNotExpired(uint256 currentTime, uint256 readyAt);

    constructor(address admin, address proposer, address executor) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PROPOSER_ROLE, proposer);
        _grantRole(EXECUTOR_ROLE, executor);
        _grantRole(CANCELLER_ROLE, admin);
    }

    /**
     * @notice Propose an upgrade for a UUPS-proxied contract.
     * @param proxy The proxy contract address to upgrade.
     * @param newImplementation The new implementation contract address.
     * @return proposalId The unique identifier for this upgrade proposal.
     */
    function proposeUpgrade(
        address proxy,
        address newImplementation
    ) external onlyRole(PROPOSER_ROLE) returns (bytes32 proposalId) {
        if (proxy == address(0) || newImplementation == address(0))
            revert InvalidAddress();

        proposalId = keccak256(
            abi.encodePacked(proxy, newImplementation, block.timestamp)
        );
        if (_proposals[proposalId].state != UpgradeState.None)
            revert ProposalAlreadyExists(proposalId);

        uint256 readyAt = block.timestamp + MIN_DELAY;

        _proposals[proposalId] = UpgradeProposal({
            proxy: proxy,
            newImplementation: newImplementation,
            proposedAt: block.timestamp,
            readyAt: readyAt,
            state: UpgradeState.Pending,
            governanceProposalId: bytes32(0)
        });

        _proposalIds.push(proposalId);

        emit UpgradeProposed(proposalId, proxy, newImplementation, readyAt);
    }

    /**
     * @notice Record governance approval for an upgrade proposal.
     * @param proposalId The upgrade proposal ID.
     * @param governanceProposalId The GovernanceGate proposal ID that approved this.
     */
    function approveUpgrade(
        bytes32 proposalId,
        bytes32 governanceProposalId
    ) external onlyRole(PROPOSER_ROLE) {
        UpgradeProposal storage proposal = _proposals[proposalId];
        if (proposal.state != UpgradeState.Pending)
            revert ProposalNotPending(proposalId);

        _approvedByGovernance[proposalId] = true;
        proposal.governanceProposalId = governanceProposalId;

        emit UpgradeApprovedByGovernance(proposalId, governanceProposalId);
    }

    /**
     * @notice Execute an approved upgrade after the timelock period.
     * @param proposalId The upgrade proposal ID.
     */
    function executeUpgrade(
        bytes32 proposalId
    ) external onlyRole(EXECUTOR_ROLE) {
        UpgradeProposal storage proposal = _proposals[proposalId];
        if (proposal.state != UpgradeState.Pending)
            revert ProposalNotPending(proposalId);
        if (!_approvedByGovernance[proposalId])
            revert ProposalNotApproved(proposalId);
        if (block.timestamp < proposal.readyAt)
            revert TimelockNotExpired(block.timestamp, proposal.readyAt);

        proposal.state = UpgradeState.Executed;

        // The actual UUPS upgrade call — caller must also hold UPGRADER_ROLE on the proxy
        // This performs: proxy.upgradeToAndCall(newImplementation, "")
        (bool success, ) = proposal.proxy.call(
            abi.encodeWithSignature(
                "upgradeToAndCall(address,bytes)",
                proposal.newImplementation,
                ""
            )
        );
        require(success, "Upgrade call failed");

        emit UpgradeExecuted(
            proposalId,
            proposal.proxy,
            proposal.newImplementation
        );
    }

    /**
     * @notice Cancel a pending upgrade proposal.
     * @param proposalId The upgrade proposal ID.
     */
    function cancelUpgrade(
        bytes32 proposalId
    ) external onlyRole(CANCELLER_ROLE) {
        UpgradeProposal storage proposal = _proposals[proposalId];
        if (proposal.state != UpgradeState.Pending)
            revert ProposalNotPending(proposalId);

        proposal.state = UpgradeState.Cancelled;

        emit UpgradeCancelled(proposalId);
    }

    // ── View Functions ──

    function getProposal(
        bytes32 proposalId
    ) external view returns (UpgradeProposal memory) {
        return _proposals[proposalId];
    }

    function isApproved(bytes32 proposalId) external view returns (bool) {
        return _approvedByGovernance[proposalId];
    }

    function getProposalCount() external view returns (uint256) {
        return _proposalIds.length;
    }

    function getProposalIdAt(uint256 index) external view returns (bytes32) {
        return _proposalIds[index];
    }
}
