import { decode, encode } from '@ipld/dag-cbor';
import type { PulseConsentPayload, PulseRevokePayload } from '@pulse-protocol/types';
import { marshalConsentEc, unmarshalConsentEc } from './cbor-ec.js';
import {
  marshalConsentPq,
  marshalRevokePq,
  unmarshalConsentPq,
  unmarshalRevokePq,
} from './cbor-pq.js';

/**
 * Encodes a PulseConsentPayload to its V2 DAG-CBOR representation.
 * Dispatches to EC or PQ encoding based on whether keys is populated.
 * Mirrors pulse-protocol-go/ipfs.MarshalConsent.
 */
export function marshalConsent(p: PulseConsentPayload): Uint8Array {
  if (p.keys && p.keys.length > 0) {
    return marshalConsentPq({ sealedData: p.sealedData, keys: p.keys });
  }
  if (!p.key1 || !p.key2) {
    throw new Error('EC consent payload requires key1 and key2');
  }
  return marshalConsentEc({ sealedData: p.sealedData, key1: p.key1, key2: p.key2 });
}

/**
 * Decodes a V2 DAG-CBOR block into a PulseConsentPayload.
 * Dispatches by "t" field: ec or pq.
 * Mirrors pulse-protocol-go/ipfs.UnmarshalConsent.
 */
export function unmarshalConsent(block: Uint8Array): PulseConsentPayload {
  const obj = decode(block) as Record<string, unknown>;
  if (obj.t === 'ec') {
    const ec = unmarshalConsentEc(block);
    return { sealedData: ec.sealedData, key1: ec.key1, key2: ec.key2 };
  }
  if (obj.t === 'pq') {
    const pq = unmarshalConsentPq(block);
    return { sealedData: pq.sealedData, keys: pq.keys };
  }
  throw new Error(
    `Block does not match any known V2 consent structure: unexpected type "${obj.t}"`,
  );
}

/**
 * Encodes a PulseRevokePayload to its V2 DAG-CBOR representation.
 * Map for EC: {"t":"rev-ec","v":1,"sd":<bytes>,"k1":<bytes>,"k2":<bytes>,"gr":<string>}
 * Map for PQ: {"t":"rev-pq","v":1,"sd":<bytes>,"keys":[...],"gr":<string>}
 * Mirrors pulse-protocol-go/ipfs.MarshalRevoke.
 */
export function marshalRevoke(p: PulseRevokePayload): Uint8Array {
  if (p.keys && p.keys.length > 0) {
    return marshalRevokePq({
      sealedData: p.sealedData,
      keys: p.keys,
      grant: p.grantRef,
    });
  }
  if (!p.key1 || !p.key2) {
    throw new Error('EC revoke payload requires key1 and key2');
  }
  return encode({
    t: 'rev-ec',
    v: 1,
    sd: p.sealedData,
    k1: p.key1,
    k2: p.key2,
    gr: p.grantRef,
  });
}

/**
 * Decodes a V2 DAG-CBOR block into a PulseRevokePayload.
 * Dispatches by "t" field: rev-ec or rev-pq.
 * Mirrors pulse-protocol-go/ipfs.UnmarshalRevoke.
 */
export function unmarshalRevoke(block: Uint8Array): PulseRevokePayload {
  const obj = decode(block) as Record<string, unknown>;
  if (obj.t === 'rev-ec') {
    if (obj.v !== 1) throw new Error(`Unexpected rev-ec version: ${obj.v}`);
    return {
      sealedData: obj.sd as Uint8Array,
      key1: obj.k1 as Uint8Array,
      key2: obj.k2 as Uint8Array,
      grantRef: obj.gr as string,
    };
  }
  if (obj.t === 'rev-pq') {
    const pq = unmarshalRevokePq(block);
    return { sealedData: pq.sealedData, keys: pq.keys, grantRef: pq.grant };
  }
  throw new Error(`Block does not match any known V2 revoke structure: unexpected type "${obj.t}"`);
}
