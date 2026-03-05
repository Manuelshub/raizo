// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IReceiver
 * @notice Standard interface for contracts that receive CRE workflow reports
 *         via the Chainlink KeystoneForwarder.
 * @dev Implementations must support this interface through ERC165.
 *      See: https://docs.chain.link/cre/guides/workflow/using-evm-client/onchain-write/building-consumer-contracts
 */
interface IReceiver is IERC165 {
    /**
     * @notice Handles incoming Keystone reports.
     * @dev If this function call reverts, it can be retried with a higher gas limit.
     *      The receiver is responsible for discarding stale reports.
     * @param metadata Report metadata (abi.encodePacked: bytes32 workflowId, bytes10 workflowName, address workflowOwner).
     * @param report Workflow report payload (ABI-encoded).
     */
    function onReport(bytes calldata metadata, bytes calldata report) external;
}
