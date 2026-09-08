---
"@pulse-protocol/types": minor
"@pulse-protocol/ipfs": minor
---

Add the optional `previousCid` feed-permission field and wire version 3

**`@pulse-protocol/types`**

- `FeedPermissionPayload.previousCid` — optional CID of the permission this one supersedes, set when a grant is the regrant half of a variation (revoke + regrant composite). Mirrors `feedpermission.FeedPermissionPayload.PreviousCid` in `pulse-protocol-go`.
- New `FEED_PERMISSION_VERSION_V3` constant — the wire version required to express `previousCid`.

**`@pulse-protocol/ipfs`**

- `marshalFeedPermission` emits the optional `"pcid"` key when `previousCid` is set, and `feedPermissionWireVersion` then returns 3 — taking precedence over the v2 features it may compose with. Payloads without a `previousCid` are unchanged, so existing v1 and v2 records keep their exact bytes and CIDs.
- `unmarshalFeedPermission` accepts version 3 and rejects a lower-version record carrying a non-empty `"pcid"`, mirroring the existing `"dd"`-below-v2 rule. A present-but-non-string `"pcid"` is an error at every version.

Wire format is byte-identical to the Go implementation, pinned by matched known-answer tests in both languages.
