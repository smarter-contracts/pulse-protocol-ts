# Changelog — @pulse-protocol/crypto

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
