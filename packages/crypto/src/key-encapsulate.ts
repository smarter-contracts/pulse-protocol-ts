import { randomBytes } from '@noble/hashes/utils';
import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import {
  type PulsePQEncryptionKey,
  type PulsePQEncryptionResult,
  PulsePurpose,
} from '@pulse-protocol/types';
import { contextHash } from './context.js';
import { pulseHashBytes, toHex } from './hash.js';
import { pulseHkdfKyber } from './hkdf.js';
import {
  AES_KEY_SIZE,
  AES_NONCE_SIZE,
  pulseOpen,
  pulseSeal,
  pulseSealWithNewKey,
} from './symmetric.js';

export const PQ_DATA_CIPHER_SUITE = 'rng+aes-gcm-256';
export const PQ_KEY_CIPHER_SUITE = 'kyber768+hkdf-keccak256+aes-gcm-256';

/**
 * Encrypts plaintext for multiple ML-KEM-768 recipients.
 * Mirrors pulse-protocol-go/crypto/internal/key_encapsulate.EncryptPQ.
 *
 * Two-layer design:
 *   - Outer: random AES-256-GCM key encrypts the plaintext (rng+aes-gcm-256)
 *   - Inner: for each recipient, Kyber encapsulation wraps the data key
 *
 * @param plaintext - Data to encrypt
 * @param contractAddress - Hex contract address
 * @param recipientPublicKeys - ML-KEM-768 public keys (1184 bytes each)
 * @param purpose - Encryption purpose (SymmetricConsent, SymmetricRevoke, etc.)
 * @param chainId - Blockchain chain ID
 * @param consentNumber - Consent number
 */
export function encryptPq(
  plaintext: Uint8Array,
  contractAddress: string,
  recipientPublicKeys: Uint8Array[],
  purpose: PulsePurpose,
  chainId: number,
  consentNumber: number,
): PulsePQEncryptionResult {
  const ctx = contextHash(chainId, contractAddress, consentNumber);

  // Outer layer: encrypt plaintext with a random AES key
  // We need a combined recipient hash — use Keccak256 of all fingerprints concatenated
  const fingerprints = recipientPublicKeys.map((pk) => pulseHashBytes(pk));
  const recipientHash = pulseHashBytes(concatenate(...fingerprints));

  const {
    ciphertext: sealedData,
    aesKey,
    nonce: dataNonce,
  } = pulseSealWithNewKey(plaintext, purpose, PQ_DATA_CIPHER_SUITE, recipientHash, ctx);

  // Inner layer: for each recipient, encapsulate the data key
  const keyPacket = new Uint8Array(AES_KEY_SIZE + AES_NONCE_SIZE);
  keyPacket.set(aesKey, 0);
  keyPacket.set(dataNonce, AES_KEY_SIZE);

  const keys: PulsePQEncryptionKey[] = recipientPublicKeys.map((pubKey) => {
    const fingerprint = pulseHashBytes(pubKey);
    const { cipherText: encapsulatedKey, sharedSecret } = ml_kem768.encapsulate(pubKey);

    const { key: wrapKey, nonce: wrapNonce } = pulseHkdfKyber(
      sharedSecret,
      encapsulatedKey,
      fingerprint,
      ctx,
    );
    const encapsulatedDataKey = pulseSeal(
      keyPacket,
      wrapKey,
      wrapNonce,
      PulsePurpose.SymmetricKeyWrap,
      PQ_KEY_CIPHER_SUITE,
      fingerprint,
      ctx,
      pulseHashBytes(encapsulatedKey),
    );

    return {
      keyFingerPrint: fingerprint,
      encapsulatedKeyKey: encapsulatedKey,
      encapsulatedDataKey,
    };
  });

  return { sealedData, keys };
}

/**
 * Decrypts a PQ-encrypted ciphertext using the recipient's ML-KEM-768 private key.
 * Mirrors pulse-protocol-go/crypto/internal/key_encapsulate.DecryptPQ.
 */
export function decryptPq(
  result: PulsePQEncryptionResult,
  contractAddress: string,
  myPrivateKey: Uint8Array,
  myPublicKey: Uint8Array,
  purpose: PulsePurpose,
  chainId: number,
  consentNumber: number,
): Uint8Array {
  const ctx = contextHash(chainId, contractAddress, consentNumber);
  const myFingerprint = pulseHashBytes(myPublicKey);
  const myFingerprintHex = toHex(myFingerprint);

  // Find the key entry for this recipient
  const keyEntry = result.keys.find((k) => toHex(k.keyFingerPrint) === myFingerprintHex);
  if (!keyEntry) {
    throw new Error('No key entry found for this recipient');
  }

  // Decapsulate to recover the shared secret
  const sharedSecret = ml_kem768.decapsulate(keyEntry.encapsulatedKeyKey, myPrivateKey);

  // Derive the key-wrapping AES key
  const { key: wrapKey, nonce: wrapNonce } = pulseHkdfKyber(
    sharedSecret,
    keyEntry.encapsulatedKeyKey,
    myFingerprint,
    ctx,
  );

  // Unwrap the data key + nonce
  const keyPacket = pulseOpen(
    keyEntry.encapsulatedDataKey,
    wrapKey,
    wrapNonce,
    PulsePurpose.SymmetricKeyWrap,
    PQ_KEY_CIPHER_SUITE,
    myFingerprint,
    ctx,
    pulseHashBytes(keyEntry.encapsulatedKeyKey),
  );

  const dataAesKey = keyPacket.slice(0, AES_KEY_SIZE);
  const dataNonce = keyPacket.slice(AES_KEY_SIZE, AES_KEY_SIZE + AES_NONCE_SIZE);

  // Compute the recipient hash (same as encryption)
  const allFingerprints = result.keys.map((k) => k.keyFingerPrint);
  const recipientHash = pulseHashBytes(concatenate(...allFingerprints));
  const transcriptHash = pulseHashBytes(dataNonce);

  return pulseOpen(
    result.sealedData,
    dataAesKey,
    dataNonce,
    purpose,
    PQ_DATA_CIPHER_SUITE,
    recipientHash,
    ctx,
    transcriptHash,
  );
}

function concatenate(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}
