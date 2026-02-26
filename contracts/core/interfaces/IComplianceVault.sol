// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/**
 * @title IComplianceVault
 * @notice Interface for the append-only on-chain compliance audit store.
 */
interface IComplianceVault {
    struct ComplianceRecord {
        bytes32 reportHash; // keccak256 of full report
        bytes32 agentId; // Which agent generated it
        uint8 reportType; // 1=AML, 2=KYC, 3=ESG, 4=MiCA, 5=Custom
        uint256 timestamp; // When anchored
        uint16 chainId; // Which chain the report covers
        string reportURI; // Encrypted URI to full report (Confidential Compute result)
    }

    // --- Errors ---
    error ReportAlreadyExists(bytes32 reportHash);
    error ReportNotFound(bytes32 reportHash);
    error UnauthorizedAnchor(address caller);
    error InvalidReportType(uint8 reportType);
    error ZeroAddress();

    /**
     * @notice Anchors a new compliance report to the vault.
     * @param reportHash The keccak256 hash of the full report content.
     * @param agentId The ID of the agent that performed the assessment.
     * @param reportType The framework category (1=AML, 2=MiCA, etc.).
     * @param chainId The chain selector covering the telemetry.
     * @param reportURI The location of the encrypted blob.
     */
    function storeReport(
        bytes32 reportHash,
        bytes32 agentId,
        uint8 reportType,
        uint16 chainId,
        string calldata reportURI
    ) external;

    /**
     * @notice Retrieves a specific compliance record by its hash.
     * @param reportHash The unique hash anchor.
     * @return The ComplianceRecord struct.
     */
    function getReport(
        bytes32 reportHash
    ) external view returns (ComplianceRecord memory);

    /**
     * @notice Returns all reports of a specific type.
     * @param reportType The category to filter by (e.g., 4=MiCA).
     * @return An array of ComplianceRecord objects.
     */
    function getReportsByType(
        uint8 reportType
    ) external view returns (ComplianceRecord[] memory);

    /**
     * @notice Returns all reports covering a specific chain.
     * @param chainId The chain selector to filter by.
     * @return An array of ComplianceRecord objects.
     */
    function getReportsByChain(
        uint16 chainId
    ) external view returns (ComplianceRecord[] memory);

    /**
     * @notice Returns the total number of anchored reports.
     * @return The count of all reports stored.
     */
    function getReportCount() external view returns (uint256);

    /**
     * @notice Emitted when a new compliance report is successfully anchored.
     */
    event ReportStored(
        bytes32 indexed reportHash,
        bytes32 indexed agentId,
        uint8 reportType,
        uint16 chainId
    );
}
