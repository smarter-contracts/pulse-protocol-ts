# @pulse-protocol/consent

Consent record persistence interface and helpers for the Pulse Protocol.

## Installation

```sh
pnpm add @pulse-protocol/consent @pulse-protocol/types
```

## API

### `ConsentStore`

Interface for a consent/revoke record persistence backend. Implement this to plug in any storage layer (IPFS, Solid Pod, database, etc.).

```ts
import type { ConsentStore } from '@pulse-protocol/consent'

interface ConsentStore {
  putConsent(cid: string, data: Uint8Array): Promise<void>
  getConsent(cid: string): Promise<Uint8Array | null>
  putRevoke(cid: string, data: Uint8Array): Promise<void>
  getRevoke(cid: string): Promise<Uint8Array | null>
}
```

### Example — in-memory implementation

```ts
import type { ConsentStore } from '@pulse-protocol/consent'

class MemoryStore implements ConsentStore {
  private consents = new Map<string, Uint8Array>()
  private revokes  = new Map<string, Uint8Array>()

  async putConsent(cid: string, data: Uint8Array) { this.consents.set(cid, data) }
  async getConsent(cid: string) { return this.consents.get(cid) ?? null }
  async putRevoke(cid: string, data: Uint8Array)  { this.revokes.set(cid, data) }
  async getRevoke(cid: string) { return this.revokes.get(cid) ?? null }
}
```
