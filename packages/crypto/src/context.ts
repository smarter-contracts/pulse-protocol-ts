import { pulseHashString } from './hash.js';

/**
 * Builds the domain-separation context string for a given (chainId, contractAddress, consentNumber) tuple.
 * Mirrors pulse-protocol-go/crypto/internal/context.ContextString.
 */
export function contextString(
  chainId: number,
  contractAddress: string,
  consentNumber: number,
): string {
  return `|pulse|ctx|v1|chain=${chainId}|contract=${contractAddress}|consentNumber=${consentNumber}`;
}

/**
 * Computes a Keccak-256 hash of the context string.
 * Mirrors pulse-protocol-go/crypto/internal/context.ContextHash.
 */
export function contextHash(
  chainId: number,
  contractAddress: string,
  consentNumber: number,
): Uint8Array {
  return pulseHashString(contextString(chainId, contractAddress, consentNumber));
}
