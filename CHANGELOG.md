# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-09

### Added

- `@pulse-protocol/types` — shared type definitions (enums, EC/PQ encryption result interfaces, V1 consent/revoke record shapes)
- `@pulse-protocol/crypto` — full cryptographic primitive set:
  - Keccak-256 hashing (`pulseHashBytes`, `pulseHashString`)
  - HKDF-Keccak-256 key derivation — EC (`pulseHkdfEcdh`), PQ (`pulseHkdfKyber`), and seed (`pulseHkdfPqSeed`) variants
  - AES-256-GCM authenticated encryption (`pulseSeal`, `pulseOpen`, `pulseSealWithNewKey`)
  - secp256k1 HD wallet derivation from BIP39/BIP32 master key (`derivePublicKey`, `derivePrivateKey`, `derivePqKeyPair`)
  - NIST ML-KEM-768 (FIPS 203) post-quantum multi-party encryption (`encryptPq`, `decryptPq`)
  - ECDH secp256k1 encryption (`encryptEcdh`, `decryptEc`)
  - EIP-191 signing and address recovery (`signConsent`, `signRevoke`, `getConsentAddress`, `getRevokeAddress`)
  - Contract/consent context hash (`contextString`, `contextHash`)
- `@pulse-protocol/ipfs` — DAG-CBOR serialisation and CIDv1 computation:
  - V1 EC and PQ consent/revoke record encode/decode (`marshalV1ConsentEc`, `marshalV1RevokePq`, …)
  - V2 EC and PQ consent/revoke record encode/decode (`marshalConsentEc`, `marshalConsentPq`, …)
  - CIDv1 (DAG-CBOR + SHA2-256) computation (`getCid`)
- `@pulse-protocol/consent` — `ConsentStore` interface for persistence backends

All known-value tests produce byte-identical output to `pulse-protocol-go` v1.1.0.
