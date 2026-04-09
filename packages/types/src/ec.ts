/**
 * Result of an EC (ECDH secp256k1) encryption operation.
 * Mirrors types.PulseECEncryptionResult in pulse-protocol-go.
 */
export interface PulseECEncryptionResult {
  /** Encrypted payload (AES-256-GCM ciphertext + tag) */
  sealedData: Uint8Array
  /** Compressed secp256k1 public key of the encrypting party (33 bytes) */
  key1: Uint8Array
  /** Compressed secp256k1 public key of the other party (33 bytes) */
  key2: Uint8Array
}

/**
 * EC revoke structure — EC encryption result plus a reference to the original consent CID.
 */
export interface RevokeStructureEC {
  sealedData: Uint8Array
  key1: Uint8Array
  key2: Uint8Array
  /** CID string of the consent record being revoked */
  grant: string
}
