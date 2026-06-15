/**
 * Result of an EC (ECDH secp256k1) encryption operation.
 * Mirrors types.PulseECEncryptionResult in pulse-protocol-go.
 */
export interface PulseECEncryptionResult {
  /** Encrypted payload (AES-256-GCM ciphertext + tag) */
  sealedData: Uint8Array;
  /** Compressed secp256k1 public key of the encrypting party (33 bytes) */
  key1: Uint8Array;
  /** Compressed secp256k1 public key of the other party (33 bytes) */
  key2: Uint8Array;
}

/**
 * EC revoke structure — EC encryption result plus a reference to the original consent CID.
 */
export interface RevokeStructureEC {
  sealedData: Uint8Array;
  key1: Uint8Array;
  key2: Uint8Array;
  /** CID string of the consent record being revoked */
  grant: string;
}

/**
 * Polymorphic consent payload — holds either EC (key1+key2) or PQ (keys) encryption results.
 * Mirrors types.PulseConsentPayload in pulse-protocol-go.
 *
 * EC form:  sealedData + key1 + key2
 * PQ form:  sealedData + keys
 */
export interface PulseConsentPayload {
  sealedData: Uint8Array;
  key1?: Uint8Array;
  key2?: Uint8Array;
  keys?: import('./pq.js').PulsePQEncryptionKey[];
}

/**
 * Polymorphic revoke payload — holds either EC (key1+key2) or PQ (keys) encryption results
 * plus a reference to the original consent CID.
 * Mirrors types.PulseRevokePayload in pulse-protocol-go.
 *
 * EC form:  sealedData + grantRef + key1 + key2
 * PQ form:  sealedData + grantRef + keys
 */
export interface PulseRevokePayload {
  sealedData: Uint8Array;
  /** CID of the original consent record being revoked */
  grantRef: string;
  key1?: Uint8Array;
  key2?: Uint8Array;
  keys?: import('./pq.js').PulsePQEncryptionKey[];
}
