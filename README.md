# pulse-protocol-ts

TypeScript implementation of the Pulse Protocol cryptographic library, mirroring [`pulse-protocol-go/crypto`](https://github.com/smarter-contracts/pulse-protocol-go).

Provides HD wallet derivation, ECDH and post-quantum (NIST ML-KEM-768) encryption, EIP-191 signing, and DAG-CBOR serialisation for consent records — with byte-identical output to the Go reference implementation.

## Packages

| Package | Description |
|---|---|
| [`@pulse-protocol/types`](./packages/types) | Shared type definitions — enums, encryption results, consent/revoke record shapes |
| [`@pulse-protocol/crypto`](./packages/crypto) | Cryptographic primitives — hashing, HD wallet, ECDH, ML-KEM-768, EIP-191, AES-GCM |
| [`@pulse-protocol/ipfs`](./packages/ipfs) | DAG-CBOR serialisation and CIDv1 computation for consent records |
| [`@pulse-protocol/consent`](./packages/consent) | `ConsentStore` interface for persistence backends |

## Requirements

- Node.js ≥ 18
- pnpm ≥ 9

## Installation

Each package is published independently to npm:

```sh
pnpm add @pulse-protocol/crypto @pulse-protocol/ipfs @pulse-protocol/types
```

## Quick start

```ts
import { masterKeyFromSeed, derivePqKeyPair, encryptPq, decryptPq } from '@pulse-protocol/crypto'
import { PulsePurpose } from '@pulse-protocol/types'

// Derive ML-KEM-768 key pairs from an HD wallet seed
const masterKey = masterKeyFromSeed(seed)
const alice = derivePqKeyPair(masterKey, bobPartyId, consentNumber, chainId, PulsePurpose.PQDeriveConsent)
const bob   = derivePqKeyPair(masterKey, alicePartyId, consentNumber, chainId, PulsePurpose.PQDeriveConsent)

// Encrypt for multiple recipients
const encrypted = encryptPq(
  plaintext,
  contractAddress,
  [alice.publicKey, bob.publicKey],
  PulsePurpose.EncryptConsentStructure,
  chainId,
  consentNumber,
)

// Any recipient can decrypt with their private key
const plaintext = decryptPq(encrypted, contractAddress, bob.secretKey, bob.publicKey,
  PulsePurpose.EncryptConsentStructure, chainId, consentNumber)
```

See the individual package READMEs for full API documentation.

## Cross-language compatibility

Key fingerprints, ciphertext structure, and CBOR encoding are byte-identical between this library and `pulse-protocol-go`. Both use NIST ML-KEM-768 (FIPS 203) for post-quantum key encapsulation.

## Development

```sh
pnpm install          # install all workspace dependencies
pnpm build            # build all packages (tsup)
pnpm test             # run all tests (vitest via Turborepo)
```

### Running tests for a single package

```sh
cd packages/crypto
pnpm test
```

## Licence

Private — © Smarter Contracts Ltd
