# Changelog — @pulse-protocol/crypto

## 0.1.1

### Patch Changes

- Updated dependencies [c2ce626]
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
