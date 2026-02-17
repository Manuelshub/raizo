// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IPaymentEscrow
 * @notice Interface for agent funding and payment authorizations (x402).
 */
interface IPaymentEscrow {
    struct AgentWallet {
        bytes32 agentId;
        uint256 balance; // USDC balance (6 decimals)
        uint256 dailySpent; // Spent in current period
        uint256 lastResetTimestamp; // Last reset of daily limit
    }

    // ─── Errors ───
    error InsufficientBalance(
        bytes32 agentId,
        uint256 available,
        uint256 required
    );
    error DailyLimitExceeded(bytes32 agentId, uint256 limit, uint256 attempted);
    error InvalidSignature();
    error SignatureExpired();
    error NonceAlreadyUsed(bytes32 nonce);
    error AgentNotActive(bytes32 agentId);
    error TransferFailed();
    error AccessDenied(address caller, bytes32 role);

    // ─── Events ───
    event Deposited(
        bytes32 indexed agentId,
        address indexed provider,
        uint256 amount
    );
    event Withdrawn(
        bytes32 indexed agentId,
        address indexed receiver,
        uint256 amount
    );
    event PaymentAuthorized(
        bytes32 indexed agentId,
        address indexed to,
        uint256 amount,
        bytes32 nonce
    );
    event DailyLimitReset(bytes32 indexed agentId);

    // ─── Actions ───

    /**
     * @notice Deposit funds for an agent.
     * @param agentId The ID of the agent to fund.
     * @param amount The amount of USDC to deposit (6 decimals).
     */
    function deposit(bytes32 agentId, uint256 amount) external;

    /**
     * @notice Withdraw funds for an agent (restricted to authorized roles).
     * @param agentId The ID of the agent.
     * @param amount The amount to withdraw.
     * @param to The recipient address.
     */
    function withdraw(bytes32 agentId, uint256 amount, address to) external;

    /**
     * @notice Agent authorizes a payment via off-chain signature (EIP-3009 compatible logic).
     * @param agentId The ID of the agent.
     * @param to Recipient of the payment.
     * @param amount Amount to pay (6 decimals).
     * @param validAfter Timestamp after which the signature is valid.
     * @param validBefore Timestamp before which the signature is valid.
     * @param nonce Unique nonce for this authorization.
     * @param signature The EIP-712 signature from the agent's payment wallet.
     */
    function authorizePayment(
        bytes32 agentId,
        address to,
        uint256 amount,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external;

    // ─── State ───

    function getWallet(
        bytes32 agentId
    ) external view returns (AgentWallet memory);
    function getDailyRemaining(bytes32 agentId) external view returns (uint256);
}
