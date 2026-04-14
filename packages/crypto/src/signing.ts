import { secp256k1 } from '@noble/curves/secp256k1';
import { pulseHashBytes } from './hash.js';

/**
 * Parses a hex-encoded contract address (with or without 0x prefix) to 20 bytes.
 */
function parseContractAddress(addr: string): Uint8Array {
  const raw = addr.startsWith('0x') || addr.startsWith('0X') ? addr.slice(2) : addr;
  // Ethereum addresses are 20 bytes (40 hex chars), but the field may be shorter in tests
  const padded = raw.padStart(40, '0');
  const bytes = new Uint8Array(20);
  for (let i = 0; i < 20; i++) {
    bytes[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Packs a contract address and one or more CID strings into a single byte array.
 * Mirrors pulse-protocol-go/crypto.packMessage.
 *
 * Format: contractAddress (20 bytes) || CID1 (ASCII bytes) [|| CID2 (ASCII bytes)]
 */
function packMessage(contractAddress: Uint8Array, ...cids: string[]): Uint8Array {
  const parts: Uint8Array[] = [contractAddress];
  for (const cid of cids) {
    parts.push(new TextEncoder().encode(cid));
  }
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    buf.set(p, offset);
    offset += p.length;
  }
  return buf;
}

/**
 * Builds the message hash: Keccak256(contractAddress || cid1 [|| cid2]).
 * Mirrors pulse-protocol-go/crypto.buildMessage.
 */
function buildMessage(contractAddressStr: string, ...cids: string[]): Uint8Array {
  const addr = parseContractAddress(contractAddressStr);
  const packed = packMessage(addr, ...cids);
  return pulseHashBytes(packed);
}

/**
 * Ethereum EIP-191 text hash: Keccak256("\x19Ethereum Signed Message:\n32" || messageHash).
 * Mirrors ethereum/accounts.TextHash.
 */
function ethereumTextHash(messageHash: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode('\x19Ethereum Signed Message:\n32');
  const combined = new Uint8Array(prefix.length + messageHash.length);
  combined.set(prefix);
  combined.set(messageHash, prefix.length);
  return pulseHashBytes(combined);
}

/**
 * Signs a consent request using EIP-191.
 * Mirrors pulse-protocol-go/crypto.SignConsent.
 *
 * @param privateKeyBytes - 32-byte secp256k1 private key
 * @param contractAddress - Hex-encoded Ethereum contract address
 * @param cid - Consent CID string
 * @returns 65-byte signature (r || s || v) where v is 27 or 28
 */
export function signConsent(
  privateKeyBytes: Uint8Array,
  contractAddress: string,
  cid: string,
): Uint8Array {
  return signRequest(privateKeyBytes, contractAddress, cid);
}

/**
 * Signs a revoke request using EIP-191.
 * Mirrors pulse-protocol-go/crypto.SignRevoke.
 *
 * @param privateKeyBytes - 32-byte secp256k1 private key
 * @param contractAddress - Hex-encoded Ethereum contract address
 * @param cid - Consent CID string
 * @param rcid - Revoke CID string
 * @returns 65-byte signature (r || s || v) where v is 27 or 28
 */
export function signRevoke(
  privateKeyBytes: Uint8Array,
  contractAddress: string,
  cid: string,
  rcid: string,
): Uint8Array {
  return signRequest(privateKeyBytes, contractAddress, cid, rcid);
}

function signRequest(
  privateKeyBytes: Uint8Array,
  contractAddress: string,
  ...cids: string[]
): Uint8Array {
  const msgHash = buildMessage(contractAddress, ...cids);
  const signingHash = ethereumTextHash(msgHash);
  // go-ethereum's crypto.Sign uses the secp256k1 library which enforces low-S normalisation.
  const sig = secp256k1.sign(signingHash, privateKeyBytes);
  // Encode as r || s || v (65 bytes), v = recoveryBit + 27
  const compact = sig.toCompactRawBytes(); // 64 bytes: r (32) || s (32)
  const result = new Uint8Array(65);
  result.set(compact, 0);
  result[64] = sig.recovery + 27;
  return result;
}

/**
 * Recovers the Ethereum address from a consent signature.
 * Mirrors pulse-protocol-go/crypto.GetConsentAddress.
 *
 * @param signature - 65-byte EIP-191 signature (r || s || v where v is 27 or 28)
 * @returns 20-byte Ethereum address
 */
export function getConsentAddress(
  signature: Uint8Array,
  contractAddress: string,
  cid: string,
): Uint8Array {
  return getSigningAddress(signature, contractAddress, cid);
}

/**
 * Recovers the Ethereum address from a revoke signature.
 * Mirrors pulse-protocol-go/crypto.GetRevokeAddress.
 */
export function getRevokeAddress(
  signature: Uint8Array,
  contractAddress: string,
  cid: string,
  rcid: string,
): Uint8Array {
  return getSigningAddress(signature, contractAddress, cid, rcid);
}

function getSigningAddress(
  signature: Uint8Array,
  contractAddress: string,
  ...cids: string[]
): Uint8Array {
  const msgHash = buildMessage(contractAddress, ...cids);
  const signingHash = ethereumTextHash(msgHash);

  if (signature.length !== 65) throw new Error('Signature must be 65 bytes');
  const sig = new Uint8Array(signature);
  // Convert v from EIP-191 format (27/28) to internal format (0/1)
  const v = sig[64]!;
  if (v === 27 || v === 28) {
    sig[64] = v - 27;
  }
  const recovery = sig[64]!;

  const ecSig = secp256k1.Signature.fromCompact(sig.slice(0, 64)).addRecoveryBit(recovery);
  const pubKey = ecSig.recoverPublicKey(signingHash);

  // Ethereum address = Keccak256(uncompressed pubkey without 0x04 prefix)[12:]
  const uncompressed = pubKey.toRawBytes(false); // 65 bytes (0x04 prefix + 64-byte coords)
  const hash = pulseHashBytes(uncompressed.slice(1)); // hash only the 64-byte coordinates
  return hash.slice(12); // last 20 bytes
}

// Export internals for testing
export { buildMessage, ethereumTextHash, packMessage, parseContractAddress };
