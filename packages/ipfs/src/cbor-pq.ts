import { decode, encode } from '@ipld/dag-cbor';
import {
  PulsePQEncryptionKey,
  type PulsePQEncryptionResult,
  type RevokeStructurePQ,
} from '@pulse-protocol/types';

/**
 * Encodes a V2 PQ consent record as DAG-CBOR.
 * Map: {"t":"pq","v":1,"sd":<bytes>,"keys":[{"fp":<bytes32>,"ekk":<bytes>,"edk":<bytes>},...]}
 * Mirrors pulse-protocol-go/ipfs.MarshalConsentPQ.
 */
export function marshalConsentPq(r: PulsePQEncryptionResult): Uint8Array {
  return encode({
    t: 'pq',
    v: 1,
    sd: r.sealedData,
    keys: r.keys.map((k) => ({
      fp: k.keyFingerPrint,
      ekk: k.encapsulatedKeyKey,
      edk: k.encapsulatedDataKey,
    })),
  });
}

/**
 * Decodes a V2 PQ consent DAG-CBOR block.
 */
export function unmarshalConsentPq(block: Uint8Array): PulsePQEncryptionResult {
  const obj = decode(block) as Record<string, unknown>;
  if (obj['t'] !== 'pq') throw new Error(`Unexpected type: ${obj['t']}`);
  if (obj['v'] !== 1) throw new Error(`Unexpected version: ${obj['v']}`);
  const keys = (obj['keys'] as Array<Record<string, unknown>>).map((k) => ({
    keyFingerPrint: k['fp'] as Uint8Array,
    encapsulatedKeyKey: k['ekk'] as Uint8Array,
    encapsulatedDataKey: k['edk'] as Uint8Array,
  }));
  return {
    sealedData: obj['sd'] as Uint8Array,
    keys,
  };
}

/**
 * Encodes a V2 PQ revoke record as DAG-CBOR.
 */
export function marshalRevokePq(r: RevokeStructurePQ): Uint8Array {
  return encode({
    t: 'rev-pq',
    v: 1,
    sd: r.sealedData,
    keys: r.keys.map((k) => ({
      fp: k.keyFingerPrint,
      ekk: k.encapsulatedKeyKey,
      edk: k.encapsulatedDataKey,
    })),
    gr: r.grant,
  });
}

/**
 * Decodes a V2 PQ revoke DAG-CBOR block.
 */
export function unmarshalRevokePq(block: Uint8Array): RevokeStructurePQ {
  const obj = decode(block) as Record<string, unknown>;
  if (obj['t'] !== 'rev-pq') throw new Error(`Unexpected type: ${obj['t']}`);
  if (obj['v'] !== 1) throw new Error(`Unexpected version: ${obj['v']}`);
  const keys = (obj['keys'] as Array<Record<string, unknown>>).map((k) => ({
    keyFingerPrint: k['fp'] as Uint8Array,
    encapsulatedKeyKey: k['ekk'] as Uint8Array,
    encapsulatedDataKey: k['edk'] as Uint8Array,
  }));
  return {
    sealedData: obj['sd'] as Uint8Array,
    keys,
    grant: obj['gr'] as string,
  };
}
