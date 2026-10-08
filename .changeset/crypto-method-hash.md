---
"@pulse-protocol/crypto": minor
---

Add `computeMethodHash(sub, iss)`, the canonical keyslot locator

- Returns lowercase-hex Keccak-256(utf8(sub) || utf8(iss)) — the legacy `{methodHash}.enc` keyslot filename and the `methodHash` recorded on a v2 password slot. Exported from the package index and from the `@pulse-protocol/crypto/keyslot` subpath (which keyslot consumers already use, and which avoids loading the ESM-only post-quantum dependency the root entry carries).
- The inputs are concatenated with no separator, so `computeMethodHash('ab', 'c') === computeMethodHash('a', 'bc')` by design; this matches every keyslot already written to a pod.

Byte-identical to `MethodHash` in `pulse-protocol-go/crypto`, pinned by matched known-answer tests in both languages.
