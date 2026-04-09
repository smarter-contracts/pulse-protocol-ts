import { secp256k1 } from '@noble/curves/secp256k1'
import { PulsePurpose, PulseECEncryptionResult } from '@pulse-protocol/types'
import { pulseHashString, toHex } from './hash.js'
import { pulseHkdfEcdh } from './hkdf.js'
import { contextHash } from './context.js'
import { pulseSeal, pulseOpen } from './symmetric.js'

export const ECDH_CIPHER_SUITE = 'ecdh-secp256k1+hkdf-keccak256+aes-gcm-256'

/**
 * Generates the transcript hash for ECDH key exchange.
 * Keys are sorted lexicographically (hex) to ensure symmetry.
 * Mirrors pulse-protocol-go/crypto/internal/key_exchange.generateTranscriptHash.
 */
export function generateTranscriptHash(pubKey1Compressed: Uint8Array, pubKey2Compressed: Uint8Array): Uint8Array {
  const hex1 = toHex(pubKey1Compressed)
  const hex2 = toHex(pubKey2Compressed)
  const [a, b] = [hex1, hex2].sort()
  const transcript = `|pulse|group|v1|${a}|${b}|${ECDH_CIPHER_SUITE}|`
  return pulseHashString(transcript)
}

/**
 * Performs ECDH encryption using secp256k1.
 * Mirrors pulse-protocol-go/crypto/internal/key_exchange.EncryptECDH.
 *
 * @param plaintext - Data to encrypt
 * @param contractAddress - Hex Ethereum contract address
 * @param myPrivateKey - 32-byte private key of the encrypting party
 * @param otherPublicKey - 33-byte compressed public key of the other party
 * @param purpose - Encryption purpose
 * @param chainId - Blockchain chain ID
 * @param consentNumber - Consent number
 */
export function encryptEcdh(
  plaintext: Uint8Array,
  contractAddress: string,
  myPrivateKey: Uint8Array,
  otherPublicKey: Uint8Array,
  purpose: PulsePurpose,
  chainId: number,
  consentNumber: number
): PulseECEncryptionResult {
  const myPublicKey = secp256k1.getPublicKey(myPrivateKey, true)

  const ctx = contextHash(chainId, contractAddress, consentNumber)
  const transcriptHash = generateTranscriptHash(myPublicKey, otherPublicKey)
  const { key, nonce } = generateAesKey(myPrivateKey, otherPublicKey, transcriptHash, ctx)

  const ciphertext = pulseSeal(plaintext, key, nonce, purpose, ECDH_CIPHER_SUITE, new Uint8Array(0), ctx, transcriptHash)

  return {
    sealedData: ciphertext,
    key1: myPublicKey,
    key2: otherPublicKey,
  }
}

/**
 * Decrypts an ECDH-encrypted ciphertext.
 * Mirrors pulse-protocol-go/crypto/internal/key_exchange.DecryptEC.
 */
export function decryptEc(
  result: PulseECEncryptionResult,
  contractAddress: string,
  myPrivateKey: Uint8Array,
  purpose: PulsePurpose,
  chainId: number,
  consentNumber: number
): Uint8Array {
  const myPublicKey = secp256k1.getPublicKey(myPrivateKey, true)
  const myHex = toHex(myPublicKey)

  let otherPublicKey: Uint8Array
  if (toHex(result.key1) === myHex) {
    otherPublicKey = result.key2
  } else if (toHex(result.key2) === myHex) {
    otherPublicKey = result.key1
  } else {
    throw new Error('No matching public key found in encryption result')
  }

  // Use key1/key2 from the result for the transcript (same as encryption)
  const transcriptHash = generateTranscriptHash(result.key1, result.key2)
  const ctx = contextHash(chainId, contractAddress, consentNumber)
  const { key, nonce } = generateAesKey(myPrivateKey, otherPublicKey, transcriptHash, ctx)

  return pulseOpen(result.sealedData, key, nonce, purpose, ECDH_CIPHER_SUITE, new Uint8Array(0), ctx, transcriptHash)
}

/**
 * Derives AES key and nonce from an ECDH shared secret.
 * The shared secret is the X coordinate of the ECDH shared point.
 */
function generateAesKey(
  myPrivateKey: Uint8Array,
  otherPublicKey: Uint8Array,
  transcriptHash: Uint8Array,
  ctx: Uint8Array
): { key: Uint8Array; nonce: Uint8Array } {
  // getSharedSecret returns compressed point (33 bytes); X coordinate is bytes [1..32]
  const sharedPoint = secp256k1.getSharedSecret(myPrivateKey, otherPublicKey, true)
  const sharedSecret = sharedPoint.slice(1) // X coordinate, 32 bytes
  return pulseHkdfEcdh(sharedSecret, transcriptHash, null, ctx)
}
