/**
 * ConsentStore is the interface for storing and retrieving consent records.
 * Mirrors pulse-protocol-go/types.ConsentStore.
 */
export interface ConsentStore {
  /** Stores a consent record by CID. */
  putConsent(cid: string, data: Uint8Array): Promise<void>
  /** Retrieves a consent record by CID. */
  getConsent(cid: string): Promise<Uint8Array | null>
  /** Stores a revoke record by CID. */
  putRevoke(cid: string, data: Uint8Array): Promise<void>
  /** Retrieves a revoke record by CID. */
  getRevoke(cid: string): Promise<Uint8Array | null>
}
