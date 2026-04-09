/**
 * Per-recipient key material for ML-KEM-768 (post-quantum) encryption.
 * Mirrors types.PulsePQEncryptionKey in pulse-protocol-go.
 */
export interface PulsePQEncryptionKey {
  /** Keccak-256 fingerprint of the recipient's ML-KEM-768 public key (32 bytes) */
  keyFingerPrint: Uint8Array
  /** ML-KEM-768 encapsulated key (1088 bytes) */
  encapsulatedKeyKey: Uint8Array
  /** AES-wrapped data key sealed for this recipient */
  encapsulatedDataKey: Uint8Array
}

/**
 * Result of a post-quantum (ML-KEM-768) multi-party encryption operation.
 * Mirrors types.PulsePQEncryptionResult in pulse-protocol-go.
 */
export interface PulsePQEncryptionResult {
  /** Encrypted payload (AES-256-GCM ciphertext + tag) */
  sealedData: Uint8Array
  /** Per-recipient key material */
  keys: PulsePQEncryptionKey[]
}

/**
 * PQ revoke structure — PQ encryption result plus a grant reference CID.
 */
export interface RevokeStructurePQ {
  sealedData: Uint8Array
  keys: PulsePQEncryptionKey[]
  grant: string
}
