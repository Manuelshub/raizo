// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./interfaces/IPaymentEscrow.sol";
import "./interfaces/IRaizoCore.sol";

/**
 * @title PaymentEscrow
 * @notice Holds USDC for agents and executes authorized micro-payments.
 *         Follows EIP-3009 compatible authorization logic and enforces daily budgets.
 */
contract PaymentEscrow is
    Initializable,
    IPaymentEscrow,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    using SafeERC20 for IERC20;

    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");

    IRaizoCore public raizoCore;
    IERC20 public usdc;

    mapping(bytes32 => AgentWallet) private _wallets;
    mapping(bytes32 => bool) private _usedNonces;

    // EIP-712 constants
    bytes32 public constant DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
    bytes32 public constant AUTHORIZE_PAYMENT_TYPEHASH =
        keccak256(
            "AuthorizePayment(bytes32 agentId,address to,uint256 amount,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
        );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the PaymentEscrow contract.
     * @param _raizoCore The address of the RaizoCore registry.
     * @param _usdc The address of the USDC token.
     */
    function initialize(address _raizoCore, address _usdc) public initializer {
        __AccessControl_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(WITHDRAWER_ROLE, msg.sender);

        raizoCore = IRaizoCore(_raizoCore);
        usdc = IERC20(_usdc);
    }

    /**
     * @inheritdoc UUPSUpgradeable
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /**
     * @inheritdoc IPaymentEscrow
     */
    function deposit(
        bytes32 agentId,
        uint256 amount
    ) external override nonReentrant {
        // Verify agent exists in RaizoCore
        IRaizoCore.AgentConfig memory config = raizoCore.getAgent(agentId);
        if (config.agentId == bytes32(0))
            revert IRaizoCore.AgentNotRegistered(agentId);

        _wallets[agentId].agentId = agentId;
        _wallets[agentId].balance += amount;

        usdc.safeTransferFrom(msg.sender, address(this), amount);

        emit Deposited(agentId, msg.sender, amount);
    }

    /**
     * @inheritdoc IPaymentEscrow
     */
    function withdraw(
        bytes32 agentId,
        uint256 amount,
        address to
    ) external override nonReentrant {
        if (!hasRole(WITHDRAWER_ROLE, msg.sender)) {
            revert AccessDenied(msg.sender, WITHDRAWER_ROLE);
        }
        if (_wallets[agentId].balance < amount) {
            revert InsufficientBalance(
                agentId,
                _wallets[agentId].balance,
                amount
            );
        }

        _wallets[agentId].balance -= amount;
        usdc.safeTransfer(to, amount);

        emit Withdrawn(agentId, to, amount);
    }

    /**
     * @inheritdoc IPaymentEscrow
     */
    function authorizePayment(
        bytes32 agentId,
        address to,
        uint256 amount,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external override nonReentrant {
        if (block.timestamp <= validAfter || block.timestamp >= validBefore) {
            revert SignatureExpired();
        }
        if (_usedNonces[nonce]) revert NonceAlreadyUsed(nonce);

        IRaizoCore.AgentConfig memory config = raizoCore.getAgent(agentId);
        if (!config.isActive) revert AgentNotActive(agentId);

        // Verify EIP-712 Signature
        bytes32 structHash = keccak256(
            abi.encode(
                AUTHORIZE_PAYMENT_TYPEHASH,
                agentId,
                to,
                amount,
                validAfter,
                validBefore,
                nonce
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, signature);

        if (signer != config.paymentWallet) revert InvalidSignature();

        // Enforce Daily Limit
        _enforceDailyLimit(agentId, amount, config.dailyBudgetUSDC);

        // Check Balance
        if (_wallets[agentId].balance < amount) {
            revert InsufficientBalance(
                agentId,
                _wallets[agentId].balance,
                amount
            );
        }

        // State Update
        _usedNonces[nonce] = true;
        _wallets[agentId].balance -= amount;
        _wallets[agentId].dailySpent += amount;

        usdc.safeTransfer(to, amount);

        emit PaymentAuthorized(agentId, to, amount, nonce);
    }

    /**
     * @inheritdoc IPaymentEscrow
     */
    function getWallet(
        bytes32 agentId
    ) external view override returns (AgentWallet memory) {
        return _wallets[agentId];
    }

    /**
     * @inheritdoc IPaymentEscrow
     */
    function getDailyRemaining(
        bytes32 agentId
    ) external view override returns (uint256) {
        IRaizoCore.AgentConfig memory config = raizoCore.getAgent(agentId);
        uint256 currentPeriod = block.timestamp / 86400;

        uint256 spent = _wallets[agentId].dailySpent;
        if (_wallets[agentId].lastResetTimestamp / 86400 < currentPeriod) {
            spent = 0;
        }

        if (spent >= config.dailyBudgetUSDC) return 0;
        return config.dailyBudgetUSDC - spent;
    }

    /**
     * @dev Enforces the daily budget limit for an agent.
     */
    function _enforceDailyLimit(
        bytes32 agentId,
        uint256 amount,
        uint256 limit
    ) internal {
        uint256 currentPeriod = block.timestamp / 86400;

        if (_wallets[agentId].lastResetTimestamp / 86400 < currentPeriod) {
            _wallets[agentId].dailySpent = 0;
            _wallets[agentId].lastResetTimestamp = block.timestamp;
            emit DailyLimitReset(agentId);
        }

        if (_wallets[agentId].dailySpent + amount > limit) {
            revert DailyLimitExceeded(
                agentId,
                limit,
                _wallets[agentId].dailySpent + amount
            );
        }
    }

    /**
     * @dev Computes the EIP-712 domain separator.
     */
    function _domainSeparatorV4() internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    DOMAIN_TYPEHASH,
                    keccak256(bytes("PaymentEscrow")),
                    keccak256(bytes("1")),
                    block.chainid,
                    address(this)
                )
            );
    }

    /**
     * @dev Hashes the struct for EIP-712.
     */
    function _hashTypedDataV4(
        bytes32 structHash
    ) internal view returns (bytes32) {
        return ECDSA.toTypedDataHash(_domainSeparatorV4(), structHash);
    }

    uint256[48] private __gap;
}
