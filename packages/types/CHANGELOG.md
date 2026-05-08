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

## [0.1.0] - 2026-04-09

### Added

- `PulsePurpose` enum and `purposeString` helper
- `PulseECEncryptionResult` and `RevokeStructureEC` interfaces
- `PulsePQEncryptionKey` and `PulsePQEncryptionResult` interfaces
- `RevokeStructurePQ` interface
- V1 legacy record interfaces: `ConsentStructureV1`, `RevokeStructureV1`, `ConsentStructureMultiV1`, `RevokeStructureMultiV1`
