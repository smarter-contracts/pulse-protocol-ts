# @pulse-protocol/types

Shared TypeScript types for the Pulse Protocol — enums, encryption result interfaces, and consent/revoke record shapes. All types mirror the corresponding Go structs in [`pulse-protocol-go`](https://github.com/smarter-contracts/pulse-protocol-go).

## Installation

```sh
pnpm add @pulse-protocol/types
```

## API

### `PulsePurpose`

Identifies the intended use of a derived key or encryption operation. Used as domain-separation input in HKDF and AES-GCM AAD.

```ts
import { PulsePurpose, purposeString } from '@pulse-protocol/types'

PulsePurpose.EncryptConsentStructure  // 3
PulsePurpose.PQDeriveConsent          // 9
PulsePurpose.PQDeriveRevoke           // 10

purposeString(PulsePurpose.EncryptConsentStructure)
// → 'encrypt-consent-structure'
```

| Value | Constant | Description |
|---|---|---|
| 1 | `SignTx` | Transaction signing |
| 2 | `EncryptConsentNotaryBlock` | EC notary block encryption |
| 3 | `EncryptConsentStructure` | EC/PQ consent structure encryption |
| 4 | `EncryptRevokeNotaryBlock` | EC notary revoke block encryption |
| 5 | `EncryptRevokeStructure` | EC/PQ revoke structure encryption |
| 6 | `SymmetricConsent` | Symmetric consent encryption |
| 7 | `SymmetricRevoke` | Symmetric revoke encryption |
| 8 | `SymmetricUpdate` | Symmetric update encryption |
| 9 | `PQDeriveConsent` | ML-KEM-768 consent key derivation |
| 10 | `PQDeriveRevoke` | ML-KEM-768 revoke key derivation |
| 255 | `SymmetricKeyWrap` | Symmetric key wrapping |

### EC types

```ts
interface PulseECEncryptionResult {
  sealedData: Uint8Array  // AES-256-GCM ciphertext + tag
  key1: Uint8Array        // compressed secp256k1 public key of encrypting party (33 bytes)
  key2: Uint8Array        // compressed secp256k1 public key of recipient (33 bytes)
}

interface RevokeStructureEC extends PulseECEncryptionResult {
  grant: string           // CID of the consent record being revoked
}
```

### PQ types

```ts
interface PulsePQEncryptionKey {
  keyFingerPrint: Uint8Array       // Keccak-256 of recipient's ML-KEM-768 public key (32 bytes)
  encapsulatedKeyKey: Uint8Array   // ML-KEM-768 ciphertext (1088 bytes)
  encapsulatedDataKey: Uint8Array  // AES-wrapped data key for this recipient
}

interface PulsePQEncryptionResult {
  sealedData: Uint8Array           // AES-256-GCM ciphertext + tag
  keys: PulsePQEncryptionKey[]     // one entry per recipient
}

interface RevokeStructurePQ extends PulsePQEncryptionResult {
  grant: string                    // CID of the consent record being revoked
}
```

### V1 record types (legacy format)

```ts
interface ConsentStructureV1    { consent: string; key1: string; key2: string }
interface RevokeStructureV1     { revoke: string; key1: string; key2: string; grantRef: string }
interface ConsentStructureMultiV1 { consent: string; keys: string[] }
interface RevokeStructureMultiV1  { revoke: string; keys: string[]; grantRef: string }
```
