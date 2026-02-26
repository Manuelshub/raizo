// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/**
 * @title MockCCIP
 * @notice Minimal CCIP interfaces and library for testing.
 */
library Client {
    struct EVMTokenAmount {
        address token;
        uint256 amount;
    }

    struct Any2EVMMessage {
        bytes32 messageId;
        uint64 sourceChainSelector;
        bytes sender;
        bytes data;
        EVMTokenAmount[] destTokenAmounts;
    }

    struct EVM2AnyMessage {
        bytes receiver;
        bytes data;
        EVMTokenAmount[] tokenAmounts;
        address feeToken;
        bytes extraArgs;
    }
}

interface IRouterClient {
    function getFee(
        uint64 destinationChainSelector,
        Client.EVM2AnyMessage memory message
    ) external view returns (uint256 fee);

    function ccipSend(
        uint64 destinationChainSelector,
        Client.EVM2AnyMessage calldata message
    ) external payable returns (bytes32);
}

interface IAny2EVMMessageReceiver {
    function ccipReceive(Client.Any2EVMMessage calldata message) external;
}

contract MockCCIPRouter is IRouterClient {
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
