---
"@pulse-protocol/types": minor
"@pulse-protocol/ipfs": minor
"@pulse-protocol/consent": minor
---

Add the optional `custody` signing-regime mark to the consent payloads

**`@pulse-protocol/types`**

- `CUSTODY_ESCROW` / `CUSTODY_HOLDER`, the `Custody` type, and `isValidCustody` — the signing-regime enum. Mirrors `payloads.CustodyEscrow`/`CustodyHolder`/`ValidCustody` in `pulse-protocol-go`. `isValidCustody` deliberately rejects `undefined` and the empty string: absence of the mark is a third state, "unmarked", meaning a legacy or pre-VRS record, and must never be read as `CUSTODY_HOLDER`.
- `FeedPermissionPayload.custody` — which signing regime produced the consent. A further optional feature *of* wire version 3 alongside `previousCid` and `policyVersions`, so a v3 payload may carry any combination of them, or none.
- `FEED_REVOCATION_VERSION_V1` / `FEED_REVOCATION_VERSION_V2` — added for parity with Go, where feed-revocation gains its first wire-version bump to carry the mark. There is no feed-revocation codec in `@pulse-protocol/ipfs` to extend.

**`@pulse-protocol/ipfs`**

- `feedPermissionWireVersion`'s v3 branch becomes `previousCid || custody || policyVersions?.length`, a disjunction rather than a single test, so a further v3 feature composes by appending a clause rather than by bumping the version again.
- `marshalFeedPermission` emits the optional `"cu"` key when `custody` is set — two characters, sorting between `"cn"` and `"dc"` — and refuses to encode an explicit but unrecognised value rather than minting a signed, CID-bound record no conforming decoder will accept.
- `unmarshalFeedPermission` rejects `"cu"` on a record declaring a version below 3 (mirroring the `"dd"`-below-v2 and `"pcid"`-below-v3 rules), rejects an unrecognised value, and errors on a present-but-non-string `"cu"` at every version. Absence stays valid and reads as unmarked.

Payloads without a `custody` are unchanged, so existing v1, v2 and v3 (`previousCid`-only) records keep their exact bytes and CIDs.

**`@pulse-protocol/consent`**

- `LINKAGE_KIND_REAFFIRM` — names the composite that upgrades an escrow-signed grant to a holder-signed one. A value-only declaration; the encoding that carries it is separate work.

Wire format is byte-identical to the Go implementation, pinned by matched known-answer tests in both languages.
