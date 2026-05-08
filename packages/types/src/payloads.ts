/**
 * Unencrypted consent payload types for the Pulse Protocol.
 *
 * All payloads carry a type discriminator ("t") and version ("v") in their
 * CBOR encoding. Any party that can decrypt a consent record can read those
 * fields before deserialising the rest.
 */

/**
 * Audit metadata captured at the moment a consent or revocation was given.
 *
 * The NotaryBlock is encrypted using ECDH between the grantor's purpose-2 key
 * and the Mid-Tier notary public key, so only Mid-Tier can decrypt it. The
 * encrypted bytes are embedded in the consent record before the outer
 * participant encryption is applied.
 */
export interface NotaryBlock {
  /** Unix timestamp (seconds) at which the consent was given. */
  timestamp: number;
  /** IP address of the client at the time of consent. */
  ipAddress: string;
  /** User-agent string of the client at the time of consent. */
  userAgent: string;
  /** Optional geographic location hint (e.g. country code). */
  location: string;
}

/**
 * Unencrypted payload for a Feed Permission consent.
 *
 * Grants an external feed service permission to write data into a specific
 * container in the grantor's Solid pod. The pod container path is constrained
 * to "pulse/feeds/{feedType}/" to ensure external services can only write to
 * designated feed containers.
 */
export interface FeedPermissionPayload {
  /** Sequential consent number within this wallet/counterparty pair. */
  consentNo: number;
  /** Wallet identifier of the signing wallet. */
  walletId: string;
  /** WebID of the grantor (Solid pod owner). */
  grantorWebId: string;
  /** DID of the counterparty being granted permission. */
  counterpartyDid: string;
  /** Feed type identifier (e.g. "open-banking", "health"). */
  feedType: string;
  /** Target Solid pod container path — must be "pulse/feeds/{feedType}/". */
  podContainerPath: string;
  /** Set of permission strings granted (e.g. ["read", "write"]). */
  permissions: string[];
  /** Data categories covered by this consent (e.g. ["transaction-history"]). */
  dataCategories: string[];
  /** Unix timestamp (seconds) at which this consent was issued. */
  issuedAt: number;
  /** Unix timestamp (seconds) at which this consent expires; 0 = no expiry. */
  expiresAt: number;
  /** DAG-CBOR NotaryBlock encrypted for Mid-Tier's notary key. */
  encryptedNotary: Uint8Array;
  /** 33-byte compressed secp256k1 public key used to encrypt the notary block (grantor ephemeral). */
  notaryKey1: Uint8Array;
  /** 33-byte compressed secp256k1 public key used to encrypt the notary block (Mid-Tier notary). */
  notaryKey2: Uint8Array;
}
