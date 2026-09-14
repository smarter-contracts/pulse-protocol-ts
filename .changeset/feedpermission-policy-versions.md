---
"@pulse-protocol/types": minor
"@pulse-protocol/ipfs": minor
---

Add the optional `policyVersions` feed-permission field and wire version 3

**`@pulse-protocol/types`**

- `FeedPermissionPayload.policyVersions` — optional list of `{ docType, documentHash }` in-force policy/T&C document versions anchored to the grant (SOW §2.3, issue #672). Mirrors `feedpermission.FeedPermissionPayload.PolicyVersions` in `pulse-protocol-go`.
- `FEED_PERMISSION_VERSION_V3` is required to express `policyVersions` (shared with `previousCid`).

**`@pulse-protocol/ipfs`**

- `marshalFeedPermission` emits the optional `"pv"` key, sorted by `docType`, when `policyVersions` is non-empty, and `feedPermissionWireVersion` then returns 3 — taking precedence over the v2 features it may compose with. Payloads without `policyVersions` are unchanged, so existing v1 and v2 records keep their exact bytes and CIDs.
- `unmarshalFeedPermission` accepts version 3 and rejects a lower-version record carrying a non-empty `"pv"`, mirroring the existing `"dd"`-below-v2 and `"pcid"`-below-v3 rules. Each entry's `documentHash` must parse as a well-formed CID, and `docType` may not repeat within the list.

Wire format is byte-identical to the Go implementation, pinned by matched known-answer tests in both languages.
