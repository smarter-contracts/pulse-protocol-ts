/**
 * Grantee service registry.
 *
 * Mirrors pulse-protocol-go/registry/service.go. The Go interface is synchronous;
 * this one returns promises because a TypeScript implementation backed by real
 * storage cannot block, matching the convention already used by
 * `@pulse-protocol/consent`'s ConsentStore.
 */

/** Whether a bound grantee service may currently act. */
export type BindingStatus = 'active' | 'suspended';

/** The statuses a binding may hold. */
export const BINDING_STATUSES: readonly BindingStatus[] = ['active', 'suspended'];

/**
 * Ties a grantee counterparty DID — the DID that appears as `counterpartyDid` in
 * a consent payload — to the identifier of the service authenticated at the API
 * boundary.
 *
 * It exists so an enforcing service can answer "is this authenticated caller the
 * grantee this consent was granted to?" without the consent record having to name
 * a mutable service identity. The binding may be rotated (a provider re-issues its
 * service credential) without the grantor re-consenting.
 */
export interface ServiceBinding {
  /** The grantee DID as it appears in consent payloads. */
  counterpartyDid: string;
  /** Identifies the service as authenticated at the API boundary. */
  serviceId: string;
  /** Whether the binding is currently active. */
  status: BindingStatus;
  /**
   * Unix timestamp (seconds) at which this binding was last written. Caller-supplied
   * metadata: the registry stores it but does not order updates by it, so callers
   * that need rollback protection must enforce monotonicity themselves.
   */
  updatedAt: number;
}

/** Thrown when no binding exists for the given DID or service identifier. */
export class BindingNotFoundError extends Error {
  constructor(identifier: string) {
    super(`service binding not found: ${identifier}`);
    this.name = 'BindingNotFoundError';
  }
}

/**
 * Resolves the binding between grantee counterparty DIDs and the service
 * identifiers presented at the API boundary.
 *
 * Deliberately separate from the Go `OtherPartyRegistry`, which allocates HD wallet
 * derivation numbers and has nothing to do with authorisation.
 */
export interface ServiceRegistry {
  /**
   * Returns the binding for a counterparty DID, rejecting with BindingNotFoundError
   * if the DID has no binding. A suspended binding is returned with its status
   * intact; deciding what to do with it is the caller's responsibility.
   */
  resolveDid(did: string): Promise<ServiceBinding>;

  /**
   * Returns the binding for a service identifier, rejecting with
   * BindingNotFoundError if the identifier has no binding.
   */
  resolveServiceId(serviceId: string): Promise<ServiceBinding>;

  /**
   * Stores a binding, replacing any existing binding for the same counterparty DID
   * — this is how a service identifier is rotated without the grantor re-consenting.
   * Registering a service identifier that is already bound to a different
   * counterparty must fail: one identifier resolving to two counterparties would let
   * one grantee act under another's consents.
   */
  register(binding: ServiceBinding): Promise<void>;
}
