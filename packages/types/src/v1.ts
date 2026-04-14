/**
 * V1 (legacy) wire types used for on-disk consent records encoded as DAG-CBOR.
 * Values are base64-encoded strings (as stored in the original mid-tier format).
 * Mirrors types/v1/ in pulse-protocol-go.
 */

/** V1 EC (two-party) consent record. */
export interface ConsentStructureV1 {
  consent: string;
  key1: string;
  key2: string;
}

/** V1 EC (two-party) revoke record. */
export interface RevokeStructureV1 {
  revoke: string;
  key1: string;
  key2: string;
  grantRef: string;
}

/** V1 PQ (multi-party) consent record. */
export interface ConsentStructureMultiV1 {
  consent: string;
  keys: string[];
}

/** V1 PQ (multi-party) revoke record. */
export interface RevokeStructureMultiV1 {
  revoke: string;
  keys: string[];
  grantRef: string;
}
