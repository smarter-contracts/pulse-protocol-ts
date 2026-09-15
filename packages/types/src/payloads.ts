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
 * Wire versions of the feed-permission payload.
 *
 * Version 1 constrained the pod container path to "pulse/feeds/{feedType}/" and
 * had no data description. Version 2 generalises the container path to any region
 * under "pulse/" and adds the human-readable dataDescription field. Version 3
 * adds previousCid, the link from a regranted permission to the one it
 * supersedes, and policyVersions, the policy/T&C versions in force when consent
 * was granted. All versions deserialise into the same interface; the marshaller
 * picks the lowest version that can represent the payload, so records produced
 * by v1 and v2 callers keep their bytes (and therefore their CIDs) unchanged.
 *
 * Mirrors pulse-protocol-go/types/payloads/feedpermission.VersionV1/V2/V3.
 */
export const FEED_PERMISSION_VERSION_V1 = 1;
export const FEED_PERMISSION_VERSION_V2 = 2;
export const FEED_PERMISSION_VERSION_V3 = 3;

/**
 * Pairs a policy/T&C document type with the content-addressed reference to
 * the version in force when the payload was constructed. `documentHash` is
 * the pulse-policy-registry manifest reference (a CIDv1 string) — named
 * `documentHash` rather than `cid` because the registry persists documents
 * in Postgres, not IPFS.
 */
export interface PolicyVersionRef {
  docType: string;
  documentHash: string;
}

/**
 * Wire versions of the feed-revocation payload.
 *
 * Version 1 was the only version for the whole of this payload's history: a
 * fixed eight-entry map with no optional fields. Version 2 adds the custody
 * mark. As with feed-permission, the marshaller picks the lowest version able to
 * represent the payload, so an unmarked revocation keeps its original bytes and
 * therefore its CID.
 *
 * Mirrors pulse-protocol-go/types/payloads/feedrevocation.VersionV1/V2.
 */
export const FEED_REVOCATION_VERSION_V1 = 1;
export const FEED_REVOCATION_VERSION_V2 = 2;

/**
 * Which signing regime produced a consent record.
 *
 * The mark travels inside the DAG-CBOR payload, so it is covered by the record's
 * CID and by the EIP-191 signature over that CID: it is immutable once signed. It
 * is also inside the encrypted envelope, so only a party holding the record key
 * can read it — not an arbitrary third party resolving the CID.
 *
 * The mark is operator-asserted: the same wallet key signs in both regimes, so
 * the signature alone cannot prove which regime produced a record. What makes it
 * meaningful is the escrow plane's independent audit trail, which an
 * escrow-signed record falsely marked "holder" would contradict. See the VRS
 * escrow-custody design, Decision 4.
 *
 * Mirrors pulse-protocol-go/types/payloads.CustodyEscrow/CustodyHolder.
 */
export const CUSTODY_ESCROW = 'escrow';
export const CUSTODY_HOLDER = 'holder';

/**
 * The custody enum. Deliberately extensible: a future client-held-key mode is
 * added as a new member without any structural change to the payloads.
 */
export type Custody = typeof CUSTODY_ESCROW | typeof CUSTODY_HOLDER;

/**
 * Whether `s` is a recognised custody value.
 *
 * `undefined` and the empty string are deliberately NOT valid. Absence of the
 * mark is a distinct third state — "unmarked" — meaning a legacy or pre-VRS
 * record that predates custody marking, and it must never be read as
 * CUSTODY_HOLDER. Callers decoding untrusted bytes use this to reject an
 * explicit but unrecognised value, which is malformed or tampered input rather
 * than a legacy record.
 *
 * Mirrors pulse-protocol-go/types/payloads.ValidCustody.
 */
export function isValidCustody(s: unknown): s is Custody {
  return s === CUSTODY_ESCROW || s === CUSTODY_HOLDER;
}

/**
 * Unencrypted payload by which a grantor authorises an inbound data feed to
 * write into their own Solid pod.
 *
 * The counterparty is an upstream feed provider — a KYC or verifiable-credential
 * issuer, a Companies House director list, a vulnerable-person record service,
 * and so on. The grantor is the pod owner. The payload therefore describes a
 * write permission granted *into* the grantor's pod, scoped to:
 *
 *  - the grantor's pod only (grantorWebId),
 *  - one named feed provider only (counterpartyDid, feedType),
 *  - one container region under "pulse/" (podContainerPath),
 *  - the listed access modes (permissions),
 *  - optionally a time window (issuedAt, expiresAt).
 *
 * Scope questions ("may this feed write to this path?") are answered by `covers`.
 * Liveness questions (expiry, on-chain revocation) belong to the enforcing service.
 *
 * Mirrors pulse-protocol-go/types/payloads/feedpermission.FeedPermissionPayload.
 */
export interface FeedPermissionPayload {
  /** Sequential consent number within this wallet/counterparty pair. */
  consentNo: number;
  /** Wallet identifier of the signing wallet. */
  walletId: string;
  /** WebID of the grantor (Solid pod owner). */
  grantorWebId: string;
  /** DID of the feed provider being granted permission. */
  counterpartyDid: string;
  /** Feed type identifier (e.g. "open-banking", "verified-identity"). */
  feedType: string;
  /**
   * Pod-relative container the feed provider may write to. At v1 this was always
   * "pulse/feeds/{feedType}/"; at v2 it may be any container region under
   * "pulse/" (e.g. "pulse/credentials/identity/").
   */
  podContainerPath: string;
  /** Access modes granted; vocabulary is {"read", "write", "append"} — see `covers`. */
  permissions: string[];
  /** Machine-readable data category codes (e.g. ["transaction-history"]). */
  dataCategories: string[];
  /**
   * Human-readable description of the data this feed will write, shown to the
   * grantor when they authorise it (e.g. "Verified Identity Credential").
   * Added at v2; optional — omitted when empty.
   */
  dataDescription?: string;
  /**
   * CID of the feed permission this one supersedes, set when this grant is the
   * regrant half of a variation (revoke + regrant composite). A private,
   * backward-pointing link: only a party able to decrypt the record ever sees
   * it. Added at v3; optional — omitted when empty.
   */
  previousCid?: string;
  /**
   * Which signing regime produced this consent. Added at v3.
   *
   * Optional AT THE CODEC: an unset value is omitted from the wire, and a record
   * without the key decodes back to `undefined`. That state is "unmarked" — a
   * legacy or pre-VRS record — and must never be read as CUSTODY_HOLDER. The VRS
   * profile's requirement that producers always set an explicit value is a
   * product-policy constraint enforced at the signing call site, not something
   * this shared library imposes on every caller: a non-VRS grant has no
   * escrow/holder distinction to record.
   *
   * An explicit but unrecognised value is rejected by both marshalFeedPermission
   * and unmarshalFeedPermission.
   */
  custody?: Custody;
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
  /**
   * Grantor's extended public key at m/4410704'/{slot}, included when the sender
   * wishes the recipient to store it for future per-consent key derivation.
   * Optional — omitted when empty.
   */
  grantorXpub?: string;
  /**
   * Policy/T&C document versions in force when this consent was granted
   * (SOW §2.3), one entry per document type. Added at v3 alongside
   * previousCid and custody; optional — omitted when empty.
   */
  policyVersions?: PolicyVersionRef[];
}
