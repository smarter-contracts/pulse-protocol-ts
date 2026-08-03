/**
 * In-memory reference implementation of ServiceRegistry.
 *
 * Mirrors pulse-protocol-go/registry/service_memory.go.
 */

import {
  BINDING_STATUSES,
  BindingNotFoundError,
  type ServiceBinding,
  type ServiceRegistry,
} from './service.js';

/**
 * A thread-safe-by-construction in-memory ServiceRegistry: JavaScript runs the
 * synchronous body of each method to completion, so no interleaving is possible.
 * Intended for testing and development; production deployments should use a
 * persistent backend.
 */
export class MemoryServiceRegistry implements ServiceRegistry {
  private readonly byDid = new Map<string, ServiceBinding>();
  private readonly byServiceId = new Map<string, ServiceBinding>();

  /**
   * Stores a binding, replacing any existing binding for the same counterparty DID
   * and retiring the service identifier it previously used.
   *
   * The binding is validated in full before anything is written, so a rejected
   * registration leaves the registry exactly as it was. A copy is stored, so later
   * mutation of the caller's object cannot change what the registry resolves.
   */
  async register(binding: ServiceBinding): Promise<void> {
    if (!binding.counterpartyDid) throw new Error('counterparty DID must not be empty');
    if (!binding.serviceId) throw new Error('service ID must not be empty');
    if (!BINDING_STATUSES.includes(binding.status)) {
      throw new Error(`unknown binding status "${binding.status}"`);
    }

    // A service identifier must never resolve to two counterparties: that would let
    // one grantee act under another grantee's consents.
    const existing = this.byServiceId.get(binding.serviceId);
    if (existing && existing.counterpartyDid !== binding.counterpartyDid) {
      throw new Error(
        `service ID "${binding.serviceId}" is already bound to counterparty "${existing.counterpartyDid}"`,
      );
    }

    // Rotation: drop the identifier this counterparty used before, so it stops
    // resolving the moment the new one is registered.
    const previous = this.byDid.get(binding.counterpartyDid);
    if (previous && previous.serviceId !== binding.serviceId) {
      this.byServiceId.delete(previous.serviceId);
    }

    const stored: ServiceBinding = { ...binding };
    this.byDid.set(stored.counterpartyDid, stored);
    this.byServiceId.set(stored.serviceId, stored);
  }

  /** Returns the binding for a counterparty DID. */
  async resolveDid(did: string): Promise<ServiceBinding> {
    if (!did) throw new Error('counterparty DID must not be empty');
    const binding = this.byDid.get(did);
    if (!binding) throw new BindingNotFoundError(did);
    return { ...binding };
  }

  /** Returns the binding for a service identifier. */
  async resolveServiceId(serviceId: string): Promise<ServiceBinding> {
    if (!serviceId) throw new Error('service ID must not be empty');
    const binding = this.byServiceId.get(serviceId);
    if (!binding) throw new BindingNotFoundError(serviceId);
    return { ...binding };
  }
}
