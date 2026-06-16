---
"@pulse-protocol/types": minor
"@pulse-protocol/ipfs": minor
---

Add polymorphic consent and revoke payload types with DAG-CBOR marshallers

**`@pulse-protocol/types`**

- New `PulseConsentPayload` interface — polymorphic consent content type. EC form carries `sealedData`, `key1`, `key2`; PQ form carries `sealedData`, `keys`. Mirrors `types.PulseConsentPayload` in `pulse-protocol-go`.
- New `PulseRevokePayload` interface — polymorphic revoke content type. Same EC/PQ split plus `grantRef` (CID of the original consent being revoked). Mirrors `types.PulseRevokePayload` in `pulse-protocol-go`.

**`@pulse-protocol/ipfs`**

- `marshalConsent` / `unmarshalConsent` — DAG-CBOR encode/decode for `PulseConsentPayload`. Dispatches to EC or PQ path based on whether `keys` is populated. Mirrors `ipfs.MarshalConsent` / `ipfs.UnmarshalConsent` in `pulse-protocol-go`.
- `marshalRevoke` / `unmarshalRevoke` — DAG-CBOR encode/decode for `PulseRevokePayload`. EC form produces `{"t":"rev-ec","v":1,...}`; PQ form delegates to the existing `marshalRevokePq`. Mirrors `ipfs.MarshalRevoke` / `ipfs.UnmarshalRevoke` in `pulse-protocol-go`.

Wire format is byte-identical to the Go implementation.
