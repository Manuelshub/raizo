// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./interfaces/IComplianceVault.sol";

/**
 * @title ComplianceVault
 * @notice Immutable, append-only on-chain store for compliance report hashes.
 * @dev Implementation follows the master specification for L1 audit anchoring.
 *      This contract is intentionally NOT upgradeable to ensure audit integrity.
 */
contract ComplianceVault is IComplianceVault, AccessControl {
    bytes32 public constant ANCHOR_ROLE = keccak256("ANCHOR_ROLE");

    mapping(bytes32 => ComplianceRecord) private _reports;
    bytes32[] private _reportHashes;

    // Indexing for retrieval
    mapping(uint8 => bytes32[]) private _reportsByType;
    mapping(uint16 => bytes32[]) private _reportsByChain;

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @inheritdoc IComplianceVault
     */
    function storeReport(
        bytes32 reportHash,
        bytes32 agentId,
        uint8 reportType,
        uint16 chainId,
        string calldata reportURI
    ) external override {
        if (
            !hasRole(ANCHOR_ROLE, msg.sender) &&
            !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)
        ) {
            revert UnauthorizedAnchor(msg.sender);
        }
        if (reportHash == bytes32(0)) revert ZeroAddress(); // Using as generic invalid hash
        if (_reports[reportHash].reportHash != bytes32(0)) {
            revert ReportAlreadyExists(reportHash);
        }
        if (reportType == 0 || reportType > 5) {
            revert InvalidReportType(reportType);
        }

        ComplianceRecord memory record = ComplianceRecord({
            reportHash: reportHash,
            agentId: agentId,
            reportType: reportType,
            timestamp: block.timestamp,
            chainId: chainId,
            reportURI: reportURI
        });

        _reports[reportHash] = record;
        _reportHashes.push(reportHash);
        _reportsByType[reportType].push(reportHash);
        _reportsByChain[chainId].push(reportHash);

        emit ReportStored(reportHash, agentId, reportType, chainId);
    }

    /**
     * @inheritdoc IComplianceVault
     */
    function getReport(
        bytes32 reportHash
    ) external view override returns (ComplianceRecord memory) {
        ComplianceRecord memory record = _reports[reportHash];
        if (record.reportHash == bytes32(0)) {
            revert ReportNotFound(reportHash);
        }
        return record;
    }

    /**
     * @inheritdoc IComplianceVault
     */
    function getReportsByType(
        uint8 reportType
    ) external view override returns (ComplianceRecord[] memory) {
        bytes32[] memory hashes = _reportsByType[reportType];
        ComplianceRecord[] memory result = new ComplianceRecord[](
            hashes.length
        );
        for (uint256 i = 0; i < hashes.length; i++) {
            result[i] = _reports[hashes[i]];
        }
        return result;
    }

    /**
     * @inheritdoc IComplianceVault
     */
    function getReportsByChain(
        uint16 chainId
    ) external view override returns (ComplianceRecord[] memory) {
        bytes32[] memory hashes = _reportsByChain[chainId];
        ComplianceRecord[] memory result = new ComplianceRecord[](
            hashes.length
        );
        for (uint256 i = 0; i < hashes.length; i++) {
            result[i] = _reports[hashes[i]];
        }
        return result;
    }

    /**
     * @inheritdoc IComplianceVault
     */
    function getReportCount() external view override returns (uint256) {
        return _reportHashes.length;
    }
}
