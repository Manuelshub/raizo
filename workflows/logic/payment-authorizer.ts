/**
 * @file payment-authorizer.ts
 * @notice x402 Payment Authorization — EIP-712 signing for PaymentEscrow.
 *
 * Spec References:
 *   ARCHITECTURE.md §3.3     — x402 Payment Flow (agent self-funding)
 *   SMART_CONTRACTS.md §2.6  — PaymentEscrow.authorizePayment EIP-712
 *   SECURITY.md §4.3         — Nonce management and replay prevention
 *
 * Architecture:
 *   - Constructs EIP-712 typed data matching PaymentEscrow's AUTHORIZE_PAYMENT_TYPEHASH
 *   - Signs with agent wallet (EOA) for on-chain verification
 *   - Generates cryptographically random nonces per payment
 *   - Domain separator matches: name="PaymentEscrow", version="1"
 */

import { ethers, TypedDataDomain, TypedDataField } from "ethers";

/** Any ethers signer that supports signTypedData (Wallet, HDNodeWallet, etc.) */
interface TypedDataSigner {
    signTypedData(
        domain: TypedDataDomain,
        types: Record<string, TypedDataField[]>,
        value: Record<string, any>,
    ): Promise<string>;
}

export interface PaymentAuthorizerConfig {
    escrowAddress: string;
    chainId: bigint | number;
}

export interface PaymentParams {
    agentId: string;       // bytes32
    to: string;            // address
    amount: bigint;        // uint256
    validAfter: bigint;    // uint256
    validBefore: bigint;   // uint256
    nonce: string;         // bytes32 (hex string)
}

const PAYMENT_TYPES: Record<string, TypedDataField[]> = {
    AuthorizePayment: [
        { name: "agentId", type: "bytes32" },
        { name: "to", type: "address" },
        { name: "amount", type: "uint256" },
        { name: "validAfter", type: "uint256" },
        { name: "validBefore", type: "uint256" },
        { name: "nonce", type: "bytes32" },
    ],
};

export class PaymentAuthorizer {
    private domain: TypedDataDomain;

    constructor(config: PaymentAuthorizerConfig) {
        this.domain = {
            name: "PaymentEscrow",
            version: "1",
            chainId: Number(config.chainId),
            verifyingContract: config.escrowAddress,
        };
    }

    /**
     * Signs an EIP-712 payment authorization with the agent wallet.
     * The returned signature can be passed to PaymentEscrow.authorizePayment().
     */
    async signPayment(wallet: TypedDataSigner, params: PaymentParams): Promise<string> {
        const value = {
            agentId: params.agentId,
            to: params.to,
            amount: params.amount,
            validAfter: params.validAfter,
            validBefore: params.validBefore,
            nonce: params.nonce,
        };

        return wallet.signTypedData(this.domain, PAYMENT_TYPES, value);
    }

    /**
     * Generates a cryptographically random bytes32 nonce.
     */
    generateNonce(): string {
        return ethers.hexlify(ethers.randomBytes(32));
    }
}
