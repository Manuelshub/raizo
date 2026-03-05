// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IReceiver} from "./IReceiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title ReceiverTemplate
 * @notice Abstract base for CRE consumer contracts.
 *         Validates that only the trusted Chainlink KeystoneForwarder can deliver reports.
 * @dev Subclasses implement _processReport() with their business logic.
 *      See: https://docs.chain.link/cre/guides/workflow/using-evm-client/onchain-write/building-consumer-contracts
 */
abstract contract ReceiverTemplate is IReceiver, Ownable {
    address private s_forwarderAddress;

    error InvalidForwarderAddress();
    error InvalidSender(address sender, address expected);

    event ForwarderAddressUpdated(
        address indexed previousForwarder,
        address indexed newForwarder
    );

    /**
     * @param _forwarderAddress Trusted Chainlink Forwarder address. Cannot be address(0).
     */
    constructor(address _forwarderAddress) Ownable(msg.sender) {
        if (_forwarderAddress == address(0)) {
            revert InvalidForwarderAddress();
        }
        s_forwarderAddress = _forwarderAddress;
        emit ForwarderAddressUpdated(address(0), _forwarderAddress);
    }

    /// @notice Returns the configured forwarder address.
    function getForwarderAddress() external view returns (address) {
        return s_forwarderAddress;
    }

    /// @inheritdoc IReceiver
    function onReport(bytes calldata, bytes calldata report) external override {
        if (
            s_forwarderAddress != address(0) && msg.sender != s_forwarderAddress
        ) {
            revert InvalidSender(msg.sender, s_forwarderAddress);
        }
        _processReport(report);
    }

    /// @notice Updates the forwarder address. Owner-only.
    function setForwarderAddress(address _forwarder) external onlyOwner {
        address prev = s_forwarderAddress;
        s_forwarderAddress = _forwarder;
        emit ForwarderAddressUpdated(prev, _forwarder);
    }

    /// @notice Implement with business logic for processing decoded report data.
    function _processReport(bytes calldata report) internal virtual;

    /// @inheritdoc IERC165
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override returns (bool) {
        return
            interfaceId == type(IReceiver).interfaceId ||
            interfaceId == type(IERC165).interfaceId;
    }
}
