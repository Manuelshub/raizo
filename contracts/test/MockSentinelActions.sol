// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ISentinelActions} from "../core/interfaces/ISentinelActions.sol";

contract MockSentinelActions is ISentinelActions {
    mapping(address => bool) public paused;

    function executeAction(ThreatReport calldata report) external {
        if (report.action == ActionType.PAUSE) {
            paused[report.targetProtocol] = true;
        }
    }

    function executeEmergencyPause(address protocol) external {}

    function liftAction(bytes32 reportId) external {}

    function getActiveActions(
        address protocol
    ) external view returns (ThreatReport[] memory) {
        return new ThreatReport[](0);
    }

    function isProtocolPaused(address protocol) external view returns (bool) {
        return paused[protocol];
    }

    function getActionCount(bytes32 agentId) external view returns (uint256) {
        return 0;
    }
}
