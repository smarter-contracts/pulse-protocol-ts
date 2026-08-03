# @pulse-protocol/registry

Grantee service registry for the Pulse Protocol — binds a grantee counterparty DID to the service identifier authenticated at the API boundary.

Mirrors `pulse-protocol-go/registry` (`ServiceRegistry`, `MemoryServiceRegistry`).

## Installation

```sh
pnpm add @pulse-protocol/registry
```

## Why it exists

A consent payload names its grantee by DID (`counterpartyDid`). The service that later presents that consent authenticates under a mutable service identifier. The registry lets an enforcing service answer *"is this authenticated caller the grantee this consent was granted to?"* without the immutable consent record having to name a mutable identity.

## API

```ts
import { MemoryServiceRegistry, BindingNotFoundError } from '@pulse-protocol/registry';
import type { ServiceBinding, ServiceRegistry } from '@pulse-protocol/registry';

interface ServiceBinding {
  counterpartyDid: string;
  serviceId: string;
  status: 'active' | 'suspended';
  updatedAt: number;
}

interface ServiceRegistry {
  resolveDid(did: string): Promise<ServiceBinding>;
  resolveServiceId(serviceId: string): Promise<ServiceBinding>;
  register(binding: ServiceBinding): Promise<void>; // upsert
}
```

- `register` is an upsert keyed on `counterpartyDid`, so a provider can **rotate** its service identifier without the grantor re-consenting; the superseded identifier stops resolving immediately.
- Registering a service identifier already bound to a *different* counterparty is refused — one identifier resolving to two counterparties would let one grantee act under another's consents.
- Suspended bindings are **returned**, not hidden, so callers can distinguish "suspended" from "never registered".
- `updatedAt` is caller-supplied metadata; the registry does not order updates by it.

The Go interface is synchronous; this one returns promises so implementations backed by real storage are possible, matching `@pulse-protocol/consent`'s `ConsentStore`.

## Example

```ts
const registry = new MemoryServiceRegistry();

await registry.register({
  counterpartyDid: 'did:web:vc.example.com',
  serviceId: 'svc-vc-issuer-1',
  status: 'active',
  updatedAt: Math.floor(Date.now() / 1000),
});

const binding = await registry.resolveDid('did:web:vc.example.com');
```
