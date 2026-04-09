import { extract, expand } from '@noble/hashes/hkdf'
import { keccak_256 } from '@noble/hashes/sha3'
import { pulseHashBytes, pulseHashString, toHex } from './hash.js'

const AES_KEY_SIZE = 32
const AES_NONCE_SIZE = 12
const ML_KEM_SEED_SIZE = 64

type HkdfMode = 'ECDH' | 'Kyber' | 'PQSeed'

function getSettings(mode: HkdfMode): {
  func: string
  parentAlgo: string
  purpose: string
  suite: string
} {
  switch (mode) {
    case 'Kyber':
      return { func: 'kdf', parentAlgo: 'kyber768', purpose: 'keywrap-aes', suite: 'kyber768+hkdf-keccak256' }
    case 'PQSeed':
      return { func: 'seed', parentAlgo: 'kyber768', purpose: 'kyber-keygen', suite: 'kyber768+hkdf-keccak256' }
    default: // ECDH
      return { func: 'kdf', parentAlgo: 'secp256k1', purpose: 'aead:channel:', suite: 'ecdh-secp256k1+hkdf-keccak256' }
  }
}

function createSaltString(func_: string, parentAlgo: string, transcript: Uint8Array): string {
  return `|pulse|${func_}|v1|salt|${parentAlgo}|${toHex(transcript)}|`
}

function createSalt(func_: string, parentAlgo: string, transcript: Uint8Array): Uint8Array {
  return pulseHashString(createSaltString(func_, parentAlgo, transcript))
}

function createInfo(
  func_: string,
  purpose: string,
  suffix: string,
  suite: string,
  recipientIdStr: string,
  context: Uint8Array
): Uint8Array {
  const contextHash = pulseHashBytes(context)
  const str = `|pulse|${func_}|v1|${purpose}${suffix}|${suite}|rid=${recipientIdStr}|ctx=${toHex(contextHash)}|`
  return new TextEncoder().encode(str)
}

function pulseExtract(ikm: Uint8Array, func_: string, parentAlgo: string, transcript: Uint8Array): Uint8Array {
  const salt = createSalt(func_, parentAlgo, transcript)
  return extract(keccak_256, ikm, salt)
}

function pulseHkdfImpl(
  ikm: Uint8Array,
  func_: string,
  parentAlgo: string,
  transcript: Uint8Array,
  purpose: string,
  suite: string,
  recipientIdStr: string,
  context: Uint8Array,
  outputLength: number,
  output2Length: number
): [Uint8Array, Uint8Array | null] {
  const prk = pulseExtract(ikm, func_, parentAlgo, transcript)

  const suffix = output2Length > 0 ? 'key' : ''
  const info1 = createInfo(func_, purpose, suffix, suite, recipientIdStr, context)
  const output1 = expand(keccak_256, prk, info1, outputLength)

  if (output2Length === 0) {
    return [output1, null]
  }

  const infoNonce = createInfo(func_, purpose, 'nonce', suite, recipientIdStr, context)
  const output2 = expand(keccak_256, prk, infoNonce, output2Length)

  return [output1, output2]
}

/**
 * Derives a 32-byte AES key and 12-byte nonce from an ECDH shared secret.
 * Mirrors pulse-protocol-go/crypto/internal/hkdf.PulseHKDFECDH.
 *
 * @param sharedSecret - X coordinate of the ECDH shared point (32 bytes)
 * @param transcript - Keccak-256 hash of sorted compressed public keys
 * @param recipientId - Empty for ECDH (two-party)
 * @param context - Context hash (chainId, contract, consentNumber)
 */
export function pulseHkdfEcdh(
  sharedSecret: Uint8Array,
  transcript: Uint8Array,
  recipientId: Uint8Array | null,
  context: Uint8Array
): { key: Uint8Array; nonce: Uint8Array } {
  const { func, parentAlgo, purpose, suite } = getSettings('ECDH')
  const recipientIdStr = recipientId ? toHex(recipientId) : ''
  const [key, nonce] = pulseHkdfImpl(sharedSecret, func, parentAlgo, transcript, purpose, suite, recipientIdStr, context, AES_KEY_SIZE, AES_NONCE_SIZE)
  return { key, nonce: nonce! }
}

/**
 * Derives a 32-byte AES key and 12-byte nonce from a Kyber shared secret.
 * Mirrors pulse-protocol-go/crypto/internal/hkdf.PulseHKDFKyber.
 *
 * @param sharedSecret - ML-KEM decapsulated shared secret (32 bytes)
 * @param transcript - ML-KEM ciphertext (encapsulated key)
 * @param recipientId - Keccak-256 fingerprint of the recipient's ML-KEM public key
 * @param context - Context hash
 */
export function pulseHkdfKyber(
  sharedSecret: Uint8Array,
  transcript: Uint8Array,
  recipientId: Uint8Array,
  context: Uint8Array
): { key: Uint8Array; nonce: Uint8Array } {
  const { func, parentAlgo, purpose, suite } = getSettings('Kyber')
  const [key, nonce] = pulseHkdfImpl(sharedSecret, func, parentAlgo, transcript, purpose, suite, toHex(recipientId), context, AES_KEY_SIZE, AES_NONCE_SIZE)
  return { key, nonce: nonce! }
}

/**
 * Derives a 64-byte seed for ML-KEM-768 key pair generation from an HD wallet node key.
 * Mirrors pulse-protocol-go/crypto/internal/hkdf.PulseHKDFPQSeed.
 *
 * @param nodeKey - BIP-32 node private key bytes (32 bytes)
 * @param transcript - Compressed secp256k1 public key of the HD node (33 bytes)
 * @param recipientIdStr - Other party number as decimal string (e.g. "3")
 * @param context - Context hash
 */
export function pulseHkdfPqSeed(
  nodeKey: Uint8Array,
  transcript: Uint8Array,
  recipientIdStr: string,
  context: Uint8Array
): Uint8Array {
  const { func, parentAlgo, purpose, suite } = getSettings('PQSeed')
  const [seed] = pulseHkdfImpl(nodeKey, func, parentAlgo, transcript, purpose, suite, recipientIdStr, context, ML_KEM_SEED_SIZE, 0)
  return seed
}

// Export internals for testing
export { createSaltString, createSalt, createInfo, pulseExtract, toHex as _toHex }
