# Changelog — @pulse-protocol/ipfs

## 0.2.0

### Minor Changes

- c2ce626: Add `NotaryBlock` and `FeedPermissionPayload` types with DAG-CBOR marshallers

  **`@pulse-protocol/types`**

  - New `NotaryBlock` interface: metadata captured at consent time (timestamp, IP address, user-agent, location). Encrypted for Mid-Tier using ECDH with the grantor's purpose-2 key.
  - New `FeedPermissionPayload` interface: the 13-field unencrypted consent payload granting a counterparty write access to a specific Solid pod feed container. Embedded in the outer EC-encrypted consent record.

  **`@pulse-protocol/ipfs`**

  - `marshalNotaryBlock` / `unmarshalNotaryBlock`: DAG-CBOR encode/decode for `NotaryBlock`. Produces a 6-field map `{"t":"notary","v":1,"ts":<int>,"ip":<str>,"ua":<str>,"loc":<str>}` with keys in canonical order.
  - `marshalFeedPermission` / `unmarshalFeedPermission`: DAG-CBOR encode/decode for `FeedPermissionPayload`. Produces a 15-field map with keys in DAG-CBOR canonical order (length ascending, then lexicographic).

  Wire format is byte-identical to the Go implementation in `pulse-protocol-go/ipfs`.

- 9552264: Add polymorphic consent and revoke payload types with DAG-CBOR marshallers

  **`@pulse-protocol/types`**

  - New `PulseConsentPayload` interface — polymorphic consent content type. EC form carries `sealedData`, `key1`, `key2`; PQ form carries `sealedData`, `keys`. Mirrors `types.PulseConsentPayload` in `pulse-protocol-go`.
  - New `PulseRevokePayload` interface — polymorphic revoke content type. Same EC/PQ split plus `grantRef` (CID of the original consent being revoked). Mirrors `types.PulseRevokePayload` in `pulse-protocol-go`.

  **`@pulse-protocol/ipfs`**

  - `marshalConsent` / `unmarshalConsent` — DAG-CBOR encode/decode for `PulseConsentPayload`. Dispatches to EC or PQ path based on whether `keys` is populated. Mirrors `ipfs.MarshalConsent` / `ipfs.UnmarshalConsent` in `pulse-protocol-go`.
  - `marshalRevoke` / `unmarshalRevoke` — DAG-CBOR encode/decode for `PulseRevokePayload`. EC form produces `{"t":"rev-ec","v":1,...}`; PQ form delegates to the existing `marshalRevokePq`. Mirrors `ipfs.MarshalRevoke` / `ipfs.UnmarshalRevoke` in `pulse-protocol-go`.

  Wire format is byte-identical to the Go implementation.

### Patch Changes

- Updated dependencies [9552264]
- Updated dependencies [c2ce626]
- Updated dependencies [9552264]
  - @pulse-protocol/types@0.2.0

## [0.1.0] - 2026-04-09

### Added

- CIDv1 computation: `getCid` (DAG-CBOR codec, SHA2-256 multihash)
- V2 EC record CBOR encode/decode: `marshalConsentEc`, `unmarshalConsentEc`, `marshalRevokeEc`, `unmarshalRevokeEc`
- V2 PQ record CBOR encode/decode: `marshalConsentPq`, `unmarshalConsentPq`, `marshalRevokePq`, `unmarshalRevokePq`
- V1 EC record CBOR encode/decode: `marshalV1ConsentEc`, `unmarshalV1ConsentEc`, `marshalV1RevokeEc`, `unmarshalV1RevokeEc`
- V1 PQ record CBOR encode/decode: `marshalV1ConsentPq`, `unmarshalV1ConsentPq`, `marshalV1RevokePq`, `unmarshalV1RevokePq`
