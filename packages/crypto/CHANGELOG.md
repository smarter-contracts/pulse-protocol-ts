# Changelog — @pulse-protocol/crypto

## Unreleased

### Added

- Escrow (type-5) keyslot — `SLOT_TYPE_ESCROW`, `encodeV2EscrowSlot`, `decodeEscrowParams` and
  the `EscrowParams` type (an alias of `OracleParams`, as the two slot types share one params
  encoding). An escrow slot lets a wallet be opened while its registrant is absent, under the
  escrow plane's audited controls. Its wire format is deliberately identical to the oracle
  (type-4) slot — `[2B keyIdLen BE][keyId UTF-8][wrappedSlotKey 60B]` — a new type byte over the
  same param layout, not a new encoding; the codec is shared so the two cannot drift apart.
  Byte-identical to `pulse-protocol-go/crypto`, with mirrored known-answer vectors.

  The type byte is legibility, not enforcement: which plane may open a slot is decided by the
  key class of the keyId in the escrow/oracle keyring, never by a byte in an attacker-supplied
  blob.

- Local unwrap of a type-5 blob refuses with `escrow keyslot must be opened via the escrow
  plane`, distinctly from the generic `unsupported keyslot slot type` and from the oracle
  refusal. As with every other v2 error the refusal still falls through to the legacy decode
  attempt, and the message is carried into the combined error.

### Changed

- The oracle keyslot's header builder and params codec are now parametrised over the slot-type
  byte and shared with the escrow slot. No change to the type-4 wire format.

### Fixed

- `encodeV2OracleSlot` (and `encodeV2EscrowSlot`) now reject a params block that does not fit the
  header's 2-byte `paramLen` field: `2 + len(keyId) + len(wrappedSlotKey)` must be `<=
  MAX_V2_PARAM_LEN`. Bounding only the keyId left a band — 65474..65535 bytes, with a 60-byte
  wrappedSlotKey — where each field fitted individually but their total did not, and
  `DataView.setUint16` wrote the length modulo 2^16 without complaint, producing a blob whose
  declared `paramLen` disagreed with its real length and which no reader could parse. The bound
  is derived from the actual total rather than hardcoded, so it stays correct for any future
  wrappedSlotKey size. Only previously-corrupt output is now rejected, so no valid blob is
  affected.
- Length checks in the shared encoder measure UTF-8 bytes rather than UTF-16 code units, matching
  Go — the previous check undercounted every non-ASCII keyId.

## 0.1.1

### Patch Changes

- 9552264: Add dual ESM+CJS output to `crypto` and `types` packages

  Both packages now publish a CommonJS bundle (`.cjs`) alongside the existing ES module output, and expose it via the `require` condition in `exports`. The `main` field points to the CJS bundle for legacy consumers.

  No API changes — the published functions and types are identical.

- Updated dependencies [9552264]
- Updated dependencies [c2ce626]
- Updated dependencies [9552264]
  - @pulse-protocol/types@0.2.0

## [0.1.0] - 2026-04-09

### Added

- Keccak-256 hashing: `pulseHashBytes`, `pulseHashString`, `toHex`, `fromHex`
- Context hash: `contextString`, `contextHash`
- AES-256-GCM: `pulseSeal`, `pulseOpen`, `pulseSealWithNewKey`
- HKDF-Keccak-256: `pulseHkdfEcdh`, `pulseHkdfKyber`, `pulseHkdfPqSeed`
- HD wallet: `masterKeyFromSeed`, `pulsePath`, `deriveNode`, `derivePublicKey`, `derivePrivateKey`, `derivePqKeyPair`, `pqKeyFingerprint`
- ECDH encryption: `encryptEcdh`, `decryptEc`, `generateTranscriptHash`
- ML-KEM-768 PQ encryption: `encryptPq`, `decryptPq`
- EIP-191 signing: `signConsent`, `signRevoke`, `getConsentAddress`, `getRevokeAddress`

All functions produce byte-identical output to `pulse-protocol-go` v1.1.0 (NIST ML-KEM-768 / FIPS 203).
