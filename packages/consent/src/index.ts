/**
 * Names the relationship between the two halves of a revoke+regrant composite —
 * why the successor replaces the predecessor, as distinct from the pointers that
 * record merely that it does.
 *
 * LINKAGE_KIND_REAFFIRM marks a composite that upgrades an escrow-signed grant to
 * a holder-signed one: the same permission, re-given by the registrant themselves
 * after they have actually reviewed it during the claim journey. Custody folding
 * depends on the distinction — a reaffirmed grant is presented as one permission
 * whose custody is now "holder" but with its history intact, never as a flat
 * "holder" that erases the escrow period.
 *
 * Introduced by #783 as a VALUE ONLY; the composite encoding that carries it is
 * #670's remit and nothing reads this constant yet.
 *
 * Mirrors pulse-protocol-go/consent.LinkageKindReaffirm.
 */
export const LINKAGE_KIND_REAFFIRM = 'reaffirm';

/** The linkage-kind enum. Extended as further composite kinds are defined. */
export type LinkageKind = typeof LINKAGE_KIND_REAFFIRM;

/**
 * ConsentStore is the interface for storing and retrieving consent records.
 * Mirrors pulse-protocol-go/types.ConsentStore.
 */
export interface ConsentStore {
  /** Stores a consent record by CID. */
  putConsent(cid: string, data: Uint8Array): Promise<void>;
  /** Retrieves a consent record by CID. */
  getConsent(cid: string): Promise<Uint8Array | null>;
  /** Stores a revoke record by CID. */
  putRevoke(cid: string, data: Uint8Array): Promise<void>;
  /** Retrieves a revoke record by CID. */
  getRevoke(cid: string): Promise<Uint8Array | null>;
}
