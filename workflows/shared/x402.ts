import { type Runtime } from "@chainlink/cre-sdk";
import {
  keccak256,
  stringToHex,
  encodeAbiParameters,
  parseAbiParameters,
} from "viem";

/**
 * EIP-712 / EIP-3009 AuthorizePayment utility for x402 economic settlement.
 */

export interface AuthorizePayment {
  agentId: `0x${string}`;
  to: `0x${string}`;
  amount: bigint;
  validAfter: bigint;
  validBefore: bigint;
  nonce: `0x${string}`;
}

export const AUTHORIZE_PAYMENT_TYPES = {
  AuthorizePayment: [
    { name: "agentId", type: "bytes32" },
    { name: "to", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

/**
 * Generates a mock x402 payment authorization for the demo.
 * In a production CRE environment, this would use a real TEE-protected key.
 */
export const generatePaymentAuthorization = (
  runtime: Runtime<any>,
  agentId: `0x${string}`,
  operatorAddress: `0x${string}`,
  amount: bigint,
): AuthorizePayment => {
  const now = Math.floor(runtime.now().getTime() / 1000);

  // Deterministic nonce for the demo block
  const nonce = keccak256(stringToHex(`nonce-${now}-${agentId}`));

  return {
    agentId,
    to: operatorAddress,
    amount,
    validAfter: BigInt(now - 60), // Valid 1 min ago
    validBefore: BigInt(now + 3600), // Valid for 1 hour
    nonce: nonce as `0x${string}`,
  };
};

/**
 * Formats the payment for logging consistency in the demo.
 */
export const formatPaymentLog = (payment: AuthorizePayment): string => {
  return `[x402] Authorized ${payment.amount} (Mock USDC) to ${
    payment.to
  } (nonce: ${payment.nonce.slice(0, 10)}...)`;
};
