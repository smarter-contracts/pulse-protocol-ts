import { decode, encode } from '@ipld/dag-cbor';
import type {
  ConsentStructureMultiV1,
  ConsentStructureV1,
  RevokeStructureMultiV1,
  RevokeStructureV1,
} from '@pulse-protocol/types';

/**
 * Encodes a V1 EC consent record as DAG-CBOR.
 * Map keys in DAG-CBOR canonical order (length, then lexicographic):
 *   key1(4), key2(4), consent(7)
 *
 * Important: DAG-CBOR encodes all string values as text strings, not byte strings.
 * This preserves the original on-disk format from the mid-tier service.
 * Mirrors pulse-protocol-go/ipfs.MarshalV1ConsentEC.
 */
export function marshalV1ConsentEc(c: ConsentStructureV1): Uint8Array {
  return encode({ key1: c.key1, key2: c.key2, consent: c.consent });
}

/**
 * Decodes a V1 EC consent DAG-CBOR block.
 */
export function unmarshalV1ConsentEc(block: Uint8Array): ConsentStructureV1 {
  const obj = decode(block) as Record<string, unknown>;
  if ('t' in obj) throw new Error('Block has a type discriminator; expected a V1 record');
  return {
    consent: obj.consent as string,
    key1: obj.key1 as string,
    key2: obj.key2 as string,
  };
}

/**
 * Encodes a V1 EC revoke record as DAG-CBOR.
 * Map keys in canonical order: key1(4), key2(4), revoke(6), grant_ref(9)
 * Mirrors pulse-protocol-go/ipfs.MarshalV1RevokeEC.
 */
export function marshalV1RevokeEc(r: RevokeStructureV1): Uint8Array {
  return encode({ key1: r.key1, key2: r.key2, revoke: r.revoke, grant_ref: r.grantRef });
}

/**
 * Decodes a V1 EC revoke DAG-CBOR block.
 */
export function unmarshalV1RevokeEc(block: Uint8Array): RevokeStructureV1 {
  const obj = decode(block) as Record<string, unknown>;
  if ('t' in obj) throw new Error('Block has a type discriminator; expected a V1 record');
  return {
    revoke: obj.revoke as string,
    key1: obj.key1 as string,
    key2: obj.key2 as string,
    grantRef: obj.grant_ref as string,
  };
}

/**
 * Encodes a V1 PQ consent record as DAG-CBOR.
 * Map keys in canonical order: keys(4), consent(7)
 *
 * Note: The Go implementation writes keys in insertion order (consent, keys) but
 * DAG-CBOR canonicalisation always produces length-first order, so the final
 * encoding has keys(4) before consent(7). The known-CID canary verifies this.
 * Mirrors pulse-protocol-go/ipfs.MarshalV1ConsentPQ.
 */
export function marshalV1ConsentPq(c: ConsentStructureMultiV1): Uint8Array {
  return encode({ consent: c.consent, keys: c.keys });
}

/**
 * Decodes a V1 PQ consent DAG-CBOR block.
 */
export function unmarshalV1ConsentPq(block: Uint8Array): ConsentStructureMultiV1 {
  const obj = decode(block) as Record<string, unknown>;
  if ('t' in obj) throw new Error('Block has a type discriminator; expected a V1 record');
  return {
    consent: obj.consent as string,
    keys: obj.keys as string[],
  };
}

/**
 * Encodes a V1 PQ revoke record as DAG-CBOR.
 * Map keys in canonical order (by length, then lexicographic):
 *   keys(4), revoke(6), grant_ref(9)
 * Mirrors pulse-protocol-go/ipfs.MarshalV1RevokePQ.
 */
export function marshalV1RevokePq(r: RevokeStructureMultiV1): Uint8Array {
  return encode({ revoke: r.revoke, keys: r.keys, grant_ref: r.grantRef });
}

/**
 * Decodes a V1 PQ revoke DAG-CBOR block.
 */
export function unmarshalV1RevokePq(block: Uint8Array): RevokeStructureMultiV1 {
  const obj = decode(block) as Record<string, unknown>;
  if ('t' in obj) throw new Error('Block has a type discriminator; expected a V1 record');
  return {
    revoke: obj.revoke as string,
    keys: obj.keys as string[],
    grantRef: obj.grant_ref as string,
  };
}
