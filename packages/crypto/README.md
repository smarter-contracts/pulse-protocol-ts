# @pulse-protocol/crypto

TypeScript cryptographic primitives for the Pulse Protocol. Mirrors [`pulse-protocol-go/crypto`](https://github.com/smarter-contracts/pulse-protocol-go) with byte-identical output.

## Installation

```sh
pnpm add @pulse-protocol/crypto @pulse-protocol/types
```

## API

### Hashing

```ts
import { pulseHashBytes, pulseHashString, toHex, fromHex } from '@pulse-protocol/crypto'

const hash = pulseHashBytes(new TextEncoder().encode('hello'))  // Keccak-256, Uint8Array
const hex  = toHex(hash)
const back = fromHex(hex)

pulseHashString('hello')  // convenience — UTF-8 encodes then hashes
```

---

### HD Wallet derivation

Derives secp256k1 and ML-KEM-768 key pairs from a BIP32 master key using Pulse-specific derivation paths.

```ts
import { masterKeyFromSeed, derivePublicKey, derivePrivateKey, derivePqKeyPair, pqKeyFingerprint } from '@pulse-protocol/crypto'
import { PulsePurpose } from '@pulse-protocol/types'

const masterKey = masterKeyFromSeed(seed)  // HDKey from 16–64 byte seed

// secp256k1 keys
const pubKey  = derivePublicKey(masterKey, otherPartyId, chainId, consentNumber, PulsePurpose.SignTx)
const privKey = derivePrivateKey(masterKey, otherPartyId, chainId, consentNumber, PulsePurpose.SignTx)

// ML-KEM-768 post-quantum key pair (64-byte seed → 1184-byte pubKey, 2400-byte secretKey)
const { publicKey, secretKey } = derivePqKeyPair(
  masterKey, otherPartyId, consentNumber, chainId, PulsePurpose.PQDeriveConsent
)

// Keccak-256 fingerprint of an ML-KEM-768 public key (32 bytes)
const fp = pqKeyFingerprint(publicKey)
```

Derivation path format: `m/44'/60'/<purpose>'/<chainId>'/<otherParty>'/<consentNumber>'`

---

### ECDH encryption (two-party, secp256k1)

```ts
import { encryptEcdh, decryptEc } from '@pulse-protocol/crypto'
import { PulsePurpose } from '@pulse-protocol/types'

const encrypted = encryptEcdh(
  plaintext,
  contractAddress,   // hex Ethereum address, e.g. '0xabc...'
  myPrivateKey,      // 32-byte secp256k1 private key
  otherPublicKey,    // 33-byte compressed secp256k1 public key
  PulsePurpose.EncryptConsentStructure,
  chainId,
  consentNumber,
)
// encrypted: PulseECEncryptionResult { sealedData, key1, key2 }

const plaintext = decryptEc(encrypted, contractAddress, myPrivateKey,
  PulsePurpose.EncryptConsentStructure, chainId, consentNumber)
```

---

### Post-quantum encryption (multi-party, ML-KEM-768)

Encrypts for one or more recipients. Each recipient can decrypt independently with their private key.

```ts
import { encryptPq, decryptPq } from '@pulse-protocol/crypto'
import { PulsePurpose } from '@pulse-protocol/types'

const encrypted = encryptPq(
  plaintext,
  contractAddress,
  [alicePublicKey, bobPublicKey],   // ML-KEM-768 public keys (1184 bytes each)
  PulsePurpose.EncryptConsentStructure,
  chainId,
  consentNumber,
)
// encrypted: PulsePQEncryptionResult { sealedData, keys: [ {keyFingerPrint, ...}, ... ] }

const plaintext = decryptPq(
  encrypted,
  contractAddress,
  bobSecretKey,    // ML-KEM-768 private key (2400 bytes)
  bobPublicKey,    // ML-KEM-768 public key (1184 bytes)
  PulsePurpose.EncryptConsentStructure,
  chainId,
  consentNumber,
)
```

---

### EIP-191 signing

Signs and recovers Ethereum addresses using EIP-191 (`"\x19Ethereum Signed Message:\n32"`).

```ts
import { signConsent, signRevoke, getConsentAddress, getRevokeAddress } from '@pulse-protocol/crypto'

// Sign
const sig = signConsent(privateKeyBytes, contractAddress, cid)
// sig: Uint8Array (65 bytes) — r(32) || s(32) || v(1), v = 27 or 28

const sig = signRevoke(privateKeyBytes, contractAddress, cid, rcid)

// Recover address
const addr = getConsentAddress(sig, contractAddress, cid)  // 20-byte Uint8Array
const addr = getRevokeAddress(sig, contractAddress, cid, rcid)
```

---

### Context hash

Domain-separation hash binding a (chainId, contractAddress, consentNumber) tuple. Used as AAD in all encryption operations.

```ts
import { contextString, contextHash } from '@pulse-protocol/crypto'

contextString(1, '0x0102...', 2)
// → '|pulse|ctx|v1|chain=1|contract=0x0102...|consentNumber=2'

contextHash(1, '0x0102...', 2)  // Keccak-256 of the above, Uint8Array (32 bytes)
```

---

### AES-256-GCM (low-level)

```ts
import { pulseSeal, pulseOpen, pulseSealWithNewKey, AES_KEY_SIZE, AES_NONCE_SIZE } from '@pulse-protocol/crypto'

// Generate a new key + nonce and seal
const { ciphertext, aesKey, nonce } = pulseSealWithNewKey(
  plaintext, purpose, cipherSuite, recipientHash, contextHash
)

// Seal with an existing key/nonce
const ciphertext = pulseSeal(plaintext, aesKey, nonce, purpose, cipherSuite,
  recipientHash, contextHash, transcriptHash)

// Open
const plaintext = pulseOpen(ciphertext, aesKey, nonce, purpose, cipherSuite,
  recipientHash, contextHash, transcriptHash)
```

---

### HKDF-Keccak-256 (low-level)

```ts
import { pulseHkdfEcdh, pulseHkdfKyber, pulseHkdfPqSeed } from '@pulse-protocol/crypto'

// ECDH key derivation
const { key, nonce } = pulseHkdfEcdh(sharedSecret, transcriptHash, null, contextHash)

// ML-KEM key derivation
const { key, nonce } = pulseHkdfKyber(sharedSecret, encapsulatedKey, fingerprint, contextHash)

// ML-KEM seed derivation (HD wallet → ML-KEM seed)
const seed64 = pulseHkdfPqSeed(nodePrivKey, nodePubKey, otherPartyStr, contextHash)
```
