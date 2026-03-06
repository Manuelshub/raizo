// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    Client
} from "@chainlink/contracts-ccip/src/v0.8/ccip/libraries/Client.sol";
import {
    IRouterClient
} from "@chainlink/contracts-ccip/src/v0.8/ccip/interfaces/IRouterClient.sol";
import {
    IAny2EVMMessageReceiver
} from "@chainlink/contracts-ccip/src/v0.8/ccip/interfaces/IAny2EVMMessageReceiver.sol";

/**
 * @title MockCCIPRouter
 * @notice Mock CCIP Router for local/unit testing. Uses real Chainlink types for compatibility.
 */
contract MockCCIPRouter is IRouterClient {
    function isChainSupported(uint64) external pure returns (bool) {
        return true;
    }

    function getFee(
        uint64,
        Client.EVM2AnyMessage memory
    ) external pure returns (uint256) {
        return 0;
    }

    function ccipSend(
        uint64,
        Client.EVM2AnyMessage calldata
    ) external payable returns (bytes32) {
        return keccak256(abi.encodePacked(block.timestamp));
    }

    /**
     * @notice Helper to simulate receiving a message from another chain.
     */
    function simulateReceive(
        address receiver,
        Client.Any2EVMMessage calldata message
    ) external {
        IAny2EVMMessageReceiver(receiver).ccipReceive(message);
    }
}
