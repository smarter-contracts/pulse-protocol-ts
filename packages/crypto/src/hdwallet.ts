import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import type { PulsePurpose } from '@pulse-protocol/types';
import { HDKey } from '@scure/bip32';
import { contextHash } from './context.js';
import { pulseHashBytes, toHex } from './hash.js';
import { pulseHkdfPqSeed } from './hkdf.js';

/**
 * Pulse Protocol HD path prefix — hardened index 4410704 (0x434D50).
 * Full path: m/4410704'/otherParty/chainId/consentNumber/purpose
 */
const PULSE_PATH_PREFIX = 0x80434d50; // hardened 4410704

/**
 * Builds a BIP-32 derivation path string.
 * Mirrors pulse-protocol-go/crypto.newpulseHDPath.
 */
export function pulsePath(
  otherParty: number,
  chainId: number,
  consentNumber: number,
  purpose: PulsePurpose,
): string {
  return (
    `m/${PULSE_PATH_PREFIX & ~0x80000000}'/` +
    `${otherParty}/${chainId}/${consentNumber}/${purpose}`
  );
}

/**
 * Derives an HD wallet node from a master key along the Pulse path.
 */
export function deriveNode(
  masterKey: HDKey,
  otherParty: number,
  chainId: number,
  consentNumber: number,
  purpose: PulsePurpose,
): HDKey {
  // Hardened index for the Pulse prefix
  return masterKey
    .deriveChild(PULSE_PATH_PREFIX)
    .deriveChild(otherParty)
    .deriveChild(chainId)
    .deriveChild(consentNumber)
    .deriveChild(purpose);
}

/**
 * Derives the compressed secp256k1 public key at the given Pulse HD path.
 * Mirrors pulse-protocol-go/crypto.DerivePublicKeyFromParent.
 */
export function derivePublicKey(
  masterKey: HDKey,
  otherParty: number,
  chainId: number,
  consentNumber: number,
  purpose: PulsePurpose,
): Uint8Array {
  const node = deriveNode(masterKey, otherParty, chainId, consentNumber, purpose);
  if (!node.publicKey) throw new Error('Failed to derive public key');
  return node.publicKey;
}

/**
 * Derives the private key bytes at the given Pulse HD path.
 */
export function derivePrivateKey(
  masterKey: HDKey,
  otherParty: number,
  chainId: number,
  consentNumber: number,
  purpose: PulsePurpose,
): Uint8Array {
  const node = deriveNode(masterKey, otherParty, chainId, consentNumber, purpose);
  if (!node.privateKey) throw new Error('Failed to derive private key');
  return node.privateKey;
}

/**
 * Derives an ML-KEM-768 key pair for post-quantum encryption.
 * The private key bytes from the HD node are used as HKDF input material
 * to deterministically generate a 64-byte seed for ml_kem768.keygen.
 * Mirrors pulse-protocol-go/crypto.DerivePQKeyPair.
 */
export function derivePqKeyPair(
  masterKey: HDKey,
  otherParty: number,
  consentNumber: number,
  chainId: number,
  purpose: PulsePurpose.PQDeriveConsent | PulsePurpose.PQDeriveRevoke,
): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const node = deriveNode(masterKey, otherParty, chainId, consentNumber, purpose);
  if (!node.privateKey || !node.publicKey) throw new Error('Failed to derive PQ node key');

  const ctx = contextHash(chainId, '', consentNumber); // contractAddress is "" in seed derivation (Go uses the param)
  const seed = pulseHkdfPqSeed(node.privateKey, node.publicKey, String(otherParty), ctx);
  return ml_kem768.keygen(seed);
}

/**
 * Computes the Keccak-256 fingerprint of an ML-KEM-768 public key.
 * Mirrors the pqPubKeyFingerprint helper in pulse-protocol-go.
 */
export function pqKeyFingerprint(publicKey: Uint8Array): Uint8Array {
  return pulseHashBytes(publicKey);
}

/** Creates a master HD key from a 16-byte seed (or any length seed). */
export function masterKeyFromSeed(seed: Uint8Array): HDKey {
  return HDKey.fromMasterSeed(seed);
}

export { toHex };
