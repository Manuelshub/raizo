// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title TelemetryCache
 * @notice On-chain key-value store for per-protocol TVL snapshots.
 * @dev CRE workflows are stateless — this contract provides persistence across
 *      cron ticks so the Threat Sentinel can compute TVL deltas (e.g. delta24h).
 *      Intentionally NOT upgradeable: simple append/overwrite storage with no
 *      governance-sensitive state.
 */
contract TelemetryCache is AccessControl {
    bytes32 public constant RECORDER_ROLE = keccak256("RECORDER_ROLE");

    struct TvlSnapshot {
        uint256 tvl;
        uint256 timestamp;
    }

    mapping(address => TvlSnapshot) private _snapshots;

    // --- Errors ---
    error ZeroAddress();

    // --- Events ---
    event SnapshotRecorded(address indexed protocol, uint256 tvl);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @notice Records a TVL snapshot for a monitored protocol.
     * @dev Overwrites the previous snapshot. The calling workflow must read
     *      the previous value BEFORE writing to compute deltas.
     * @param protocol Address of the monitored protocol contract.
     * @param tvl Current total value locked (e.g. totalSupply result).
     */
    function recordSnapshot(
        address protocol,
        uint256 tvl
    ) external onlyRole(RECORDER_ROLE) {
        if (protocol == address(0)) revert ZeroAddress();

        _snapshots[protocol] = TvlSnapshot({
            tvl: tvl,
            timestamp: block.timestamp
        });

        emit SnapshotRecorded(protocol, tvl);
    }

    /**
     * @notice Returns the latest TVL snapshot for a protocol.
     * @dev Returns a zeroed struct if no snapshot has been recorded.
     * @param protocol Address of the monitored protocol contract.
     * @return snapshot The stored TVL and timestamp.
     */
    function getSnapshot(
        address protocol
    ) external view returns (TvlSnapshot memory) {
        return _snapshots[protocol];
    }
}
