# @pulse-protocol/ipfs

DAG-CBOR serialisation and CIDv1 computation for Pulse Protocol consent records. Mirrors [`pulse-protocol-go/ipfs`](https://github.com/smarter-contracts/pulse-protocol-go) with byte-identical output.

## Installation

```sh
pnpm add @pulse-protocol/ipfs @pulse-protocol/types
```

## API

### CID computation

```ts
import { getCid } from '@pulse-protocol/ipfs'

const cbor = marshalConsentPq(result)
const cid  = await getCid(cbor)
// → 'bafyreia...'  (CIDv1, DAG-CBOR codec, SHA2-256 multihash)
```

---

### V2 EC consent/revoke records

The V2 format uses a CBOR map with a type discriminator (`"ec"`) and version field.

```ts
import { marshalConsentEc, unmarshalConsentEc, marshalRevokeEc, unmarshalRevokeEc } from '@pulse-protocol/ipfs'
import type { PulseECEncryptionResult, RevokeStructureEC } from '@pulse-protocol/types'

// Consent
const bytes  = marshalConsentEc(encryptionResult)  // PulseECEncryptionResult → Uint8Array
const result = unmarshalConsentEc(bytes)            // Uint8Array → PulseECEncryptionResult

// Revoke
const bytes  = marshalRevokeEc(revokeResult)   // RevokeStructureEC → Uint8Array
const result = unmarshalRevokeEc(bytes)         // Uint8Array → RevokeStructureEC
```

---

### V2 PQ consent/revoke records

The V2 format uses a CBOR map with a type discriminator (`"pq"`) and version field.

```ts
import { marshalConsentPq, unmarshalConsentPq, marshalRevokePq, unmarshalRevokePq } from '@pulse-protocol/ipfs'
import type { PulsePQEncryptionResult, RevokeStructurePQ } from '@pulse-protocol/types'

// Consent
const bytes  = marshalConsentPq(encryptionResult)   // PulsePQEncryptionResult → Uint8Array
const result = unmarshalConsentPq(bytes)             // Uint8Array → PulsePQEncryptionResult

// Revoke
const bytes  = marshalRevokePq(revokeResult)    // RevokeStructurePQ → Uint8Array
const result = unmarshalRevokePq(bytes)          // Uint8Array → RevokeStructurePQ
```

---

### V1 EC consent/revoke records (legacy format)

V1 records store CID strings rather than raw bytes.

```ts
import {
  marshalV1ConsentEc, unmarshalV1ConsentEc,
  marshalV1RevokeEc, unmarshalV1RevokeEc,
  marshalV1ConsentPq, unmarshalV1ConsentPq,
  marshalV1RevokePq, unmarshalV1RevokePq,
} from '@pulse-protocol/ipfs'
import type { ConsentStructureV1, RevokeStructureV1, ConsentStructureMultiV1, RevokeStructureMultiV1 } from '@pulse-protocol/types'

const bytes = marshalV1ConsentEc({ consent: cid1, key1: cid2, key2: cid3 })
const rec   = unmarshalV1ConsentEc(bytes)

const bytes = marshalV1RevokePq({ revoke: cid, keys: [cid1, cid2], grantRef: grantCid })
const rec   = unmarshalV1RevokePq(bytes)
```

---

## CBOR format notes

- All records use DAG-CBOR encoding (deterministic, sorted map keys)
- Map keys are sorted by byte-length first, then lexicographically (DAG-CBOR canonical order)
- Binary values (`sealedData`, keys, fingerprints) are encoded as CBOR byte strings
- String values (CIDs, type discriminators) are encoded as CBOR text strings
- The V2 format includes a `"at"` (algorithm type) and `"v"` (version) field to allow future evolution
