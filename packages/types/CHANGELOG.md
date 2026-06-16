# Changelog — @pulse-protocol/types

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

- 9552264: Add dual ESM+CJS output to `crypto` and `types` packages

  Both packages now publish a CommonJS bundle (`.cjs`) alongside the existing ES module output, and expose it via the `require` condition in `exports`. The `main` field points to the CJS bundle for legacy consumers.

  No API changes — the published functions and types are identical.

## [0.1.0] - 2026-04-09

### Added

- `PulsePurpose` enum and `purposeString` helper
- `PulseECEncryptionResult` and `RevokeStructureEC` interfaces
- `PulsePQEncryptionKey` and `PulsePQEncryptionResult` interfaces
- `RevokeStructurePQ` interface
- V1 legacy record interfaces: `ConsentStructureV1`, `RevokeStructureV1`, `ConsentStructureMultiV1`, `RevokeStructureMultiV1`
