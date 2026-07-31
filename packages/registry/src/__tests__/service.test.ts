/**
 * Tests for the grantee service registry.
 *
 * Mirrors pulse-protocol-go/registry/service_test.go — keep the two suites in sync.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { BindingNotFoundError, type ServiceBinding } from '../service.js';
import { MemoryServiceRegistry } from '../service-memory.js';

const DID_A = 'did:web:vc.example.com';
const DID_B = 'did:web:companies-house.example.com';
const SERVICE_A = 'svc-vc-issuer-1';
const SERVICE_B = 'svc-vc-issuer-2';

function activeBinding(did: string, serviceId: string): ServiceBinding {
  return {
    counterpartyDid: did,
    serviceId,
    status: 'active',
    updatedAt: 1_700_000_000,
  };
}

describe('MemoryServiceRegistry', () => {
  let registry: MemoryServiceRegistry;

  beforeEach(() => {
    registry = new MemoryServiceRegistry();
  });

  // ── Resolution ──────────────────────────────────────────────────────────────

  it('resolves a binding in both directions', async () => {
    await registry.register(activeBinding(DID_A, SERVICE_A));

    const byDid = await registry.resolveDid(DID_A);
    expect(byDid.serviceId).toBe(SERVICE_A);
    expect(byDid.status).toBe('active');
    expect(byDid.updatedAt).toBe(1_700_000_000);

    const byService = await registry.resolveServiceId(SERVICE_A);
    expect(byService.counterpartyDid).toBe(DID_A);
    expect(byService).toEqual(byDid);
  });

  it('reports unknown identifiers as not found', async () => {
    await expect(registry.resolveDid('did:web:unknown.example.com')).rejects.toThrow(
      BindingNotFoundError,
    );
    await expect(registry.resolveServiceId('svc-unknown')).rejects.toThrow(BindingNotFoundError);
  });

  it('rejects empty identifiers', async () => {
    await registry.register(activeBinding(DID_A, SERVICE_A));
    await expect(registry.resolveDid('')).rejects.toThrow('must not be empty');
    await expect(registry.resolveServiceId('')).rejects.toThrow('must not be empty');
  });

  // ── Registration and rotation ───────────────────────────────────────────────

  it('rotates the service identifier for a counterparty', async () => {
    await registry.register(activeBinding(DID_A, SERVICE_A));
    await registry.register({ ...activeBinding(DID_A, SERVICE_B), updatedAt: 1_700_000_100 });

    const byDid = await registry.resolveDid(DID_A);
    expect(byDid.serviceId).toBe(SERVICE_B);
    expect(byDid.updatedAt).toBe(1_700_000_100);

    const byService = await registry.resolveServiceId(SERVICE_B);
    expect(byService.counterpartyDid).toBe(DID_A);

    // The superseded service identifier must no longer resolve.
    await expect(registry.resolveServiceId(SERVICE_A)).rejects.toThrow(BindingNotFoundError);
  });

  it('returns a suspended binding rather than hiding it', async () => {
    await registry.register(activeBinding(DID_A, SERVICE_A));
    await registry.register({ ...activeBinding(DID_A, SERVICE_A), status: 'suspended' });

    expect((await registry.resolveDid(DID_A)).status).toBe('suspended');
    expect((await registry.resolveServiceId(SERVICE_A)).status).toBe('suspended');
  });

  it('refuses a service identifier already bound to another counterparty', async () => {
    await registry.register(activeBinding(DID_A, SERVICE_A));

    await expect(registry.register(activeBinding(DID_B, SERVICE_A))).rejects.toThrow(
      'already bound',
    );

    // The original binding is untouched.
    expect((await registry.resolveServiceId(SERVICE_A)).counterpartyDid).toBe(DID_A);
    await expect(registry.resolveDid(DID_B)).rejects.toThrow(BindingNotFoundError);
  });

  // ── Validation ──────────────────────────────────────────────────────────────

  it.each([
    ['empty counterparty DID', { counterpartyDid: '', serviceId: SERVICE_A, status: 'active' }],
    ['empty service ID', { counterpartyDid: DID_A, serviceId: '', status: 'active' }],
    ['empty status', { counterpartyDid: DID_A, serviceId: SERVICE_A, status: '' }],
    ['unknown status', { counterpartyDid: DID_A, serviceId: SERVICE_A, status: 'revoked' }],
  ])('rejects a binding with an %s', async (_name, binding) => {
    await expect(
      registry.register({ ...(binding as ServiceBinding), updatedAt: 0 }),
    ).rejects.toThrow();
  });

  it('does not mutate anything when a registration is rejected', async () => {
    await registry.register(activeBinding(DID_A, SERVICE_A));

    // Cast through unknown: an invalid status is exactly what a JavaScript caller
    // (or a decoded JSON document) can hand us, and the registry must refuse it.
    const bad = {
      ...activeBinding(DID_A, SERVICE_B),
      status: 'revoked',
    } as unknown as ServiceBinding;
    await expect(registry.register(bad)).rejects.toThrow();

    expect((await registry.resolveDid(DID_A)).serviceId).toBe(SERVICE_A);
    expect((await registry.resolveServiceId(SERVICE_A)).counterpartyDid).toBe(DID_A);
  });

  it('stores a copy so later mutation of the caller’s object cannot change the registry', async () => {
    const binding = activeBinding(DID_A, SERVICE_A);
    await registry.register(binding);
    binding.status = 'suspended';

    expect((await registry.resolveDid(DID_A)).status).toBe('active');
  });

  // ── Concurrency ─────────────────────────────────────────────────────────────

  it('handles interleaved registrations and lookups', async () => {
    await registry.register(activeBinding(DID_A, SERVICE_A));

    await Promise.all(
      Array.from({ length: 50 }, (_, i) => {
        switch (i % 3) {
          case 0:
            return registry.register({ ...activeBinding(DID_A, SERVICE_A), updatedAt: i });
          case 1:
            return registry.resolveDid(DID_A);
          default:
            return registry.resolveServiceId(SERVICE_A);
        }
      }),
    );

    expect((await registry.resolveDid(DID_A)).serviceId).toBe(SERVICE_A);
  });
});
