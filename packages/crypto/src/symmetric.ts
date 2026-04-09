import { gcm } from '@noble/ciphers/aes'
import { randomBytes } from '@noble/hashes/utils'
import { PulsePurpose, purposeString } from '@pulse-protocol/types'
import { pulseHashBytes, toHex } from './hash.js'

export const AES_KEY_SIZE = 32
export const AES_NONCE_SIZE = 12

function buildAad(
  purpose: PulsePurpose,
  cipherSuite: string,
  recipientHash: Uint8Array,
  nonce: Uint8Array,
  contextHash: Uint8Array,
  transcriptHash: Uint8Array
): Uint8Array {
  const str = `|pulse|${purposeString(purpose)}|v1|${cipherSuite}|rid=${toHex(recipientHash)}|ctx=${toHex(contextHash)}|th=${toHex(transcriptHash)}|nonce=${toHex(nonce)}|`
  return new TextEncoder().encode(str)
}

/**
 * Seals plaintext using AES-256-GCM with purpose-bound AAD.
 * Mirrors pulse-protocol-go/crypto/internal/symmetric.PulseSeal.
 */
export function pulseSeal(
  plaintext: Uint8Array,
  aesKey: Uint8Array,
  nonce: Uint8Array,
  purpose: PulsePurpose,
  cipherSuite: string,
  recipientHash: Uint8Array,
  contextHash: Uint8Array,
  transcriptHash: Uint8Array
): Uint8Array {
  const aad = buildAad(purpose, cipherSuite, recipientHash, nonce, contextHash, transcriptHash)
  const cipher = gcm(aesKey, nonce, aad)
  return cipher.encrypt(plaintext)
}

/**
 * Opens an AES-256-GCM sealed ciphertext.
 * Mirrors pulse-protocol-go/crypto/internal/symmetric.PulseOpen.
 */
export function pulseOpen(
  ciphertext: Uint8Array,
  aesKey: Uint8Array,
  nonce: Uint8Array,
  purpose: PulsePurpose,
  cipherSuite: string,
  recipient: Uint8Array,
  contextHash: Uint8Array,
  transcriptHash: Uint8Array
): Uint8Array {
  const aad = buildAad(purpose, cipherSuite, recipient, nonce, contextHash, transcriptHash)
  const cipher = gcm(aesKey, nonce, aad)
  return cipher.decrypt(ciphertext)
}

/**
 * Generates a new random AES key and nonce, then seals the plaintext.
 * The transcript hash is Keccak256(nonce).
 * Mirrors pulse-protocol-go/crypto/internal/symmetric.PulseSealWithNewKey.
 */
export function pulseSealWithNewKey(
  plaintext: Uint8Array,
  purpose: PulsePurpose,
  cipherSuite: string,
  recipientHash: Uint8Array,
  contextHash: Uint8Array,
  entropy?: Uint8Array
): { ciphertext: Uint8Array; aesKey: Uint8Array; nonce: Uint8Array } {
  const aesKey = entropy?.slice(0, AES_KEY_SIZE) ?? randomBytes(AES_KEY_SIZE)
  const nonce = entropy?.slice(AES_KEY_SIZE, AES_KEY_SIZE + AES_NONCE_SIZE) ?? randomBytes(AES_NONCE_SIZE)
  const transcriptHash = pulseHashBytes(nonce)
  const ciphertext = pulseSeal(plaintext, aesKey, nonce, purpose, cipherSuite, recipientHash, contextHash, transcriptHash)
  return { ciphertext, aesKey, nonce }
}

// Export buildAad for testing
export { buildAad }
