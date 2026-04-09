import { keccak_256 } from '@noble/hashes/sha3';

/**
 * Computes a Keccak-256 hash of the provided byte array.
 * Mirrors pulse-protocol-go/crypto/internal/hash.PulseHashBytes.
 */
export function pulseHashBytes(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}

/**
 * Computes a Keccak-256 hash of the provided string (UTF-8 encoded).
 * Mirrors pulse-protocol-go/crypto/internal/hash.PulseHashString.
 */
export function pulseHashString(data: string): Uint8Array {
  return keccak_256(new TextEncoder().encode(data));
}

/** Encodes a byte array as a lowercase hex string. */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Decodes a lowercase hex string to a byte array. */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`Invalid hex string length: ${hex.length}`);
  }
  const result = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    result[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return result;
}
