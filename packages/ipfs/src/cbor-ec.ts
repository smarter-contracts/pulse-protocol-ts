import { decode, encode } from '@ipld/dag-cbor';
import type { PulseECEncryptionResult, RevokeStructureEC } from '@pulse-protocol/types';

/**
 * Encodes a V2 EC consent record as DAG-CBOR.
 * Map: {"t":"ec","v":1,"sd":<bytes>,"k1":<bytes>,"k2":<bytes>}
 * Keys are sorted by DAG-CBOR canonical rules (length then lexicographic):
 *   t(1), v(1), k1(2), k2(2), sd(2)
 * Mirrors pulse-protocol-go/ipfs.MarshalConsentEC.
 */
export function marshalConsentEc(r: PulseECEncryptionResult): Uint8Array {
  return encode({
    t: 'ec',
    v: 1,
    sd: r.sealedData,
    k1: r.key1,
    k2: r.key2,
  });
}

/**
 * Decodes a V2 EC consent DAG-CBOR block.
 * Mirrors pulse-protocol-go/ipfs.UnmarshalConsentEC.
 */
export function unmarshalConsentEc(block: Uint8Array): PulseECEncryptionResult {
  const obj = decode(block) as Record<string, unknown>;
  if (obj.t !== 'ec') throw new Error(`Unexpected type: ${obj.t}`);
  if (obj.v !== 1) throw new Error(`Unexpected version: ${obj.v}`);
  return {
    sealedData: obj.sd as Uint8Array,
    key1: obj.k1 as Uint8Array,
    key2: obj.k2 as Uint8Array,
  };
}

/**
 * Encodes a V2 EC revoke record as DAG-CBOR.
 * Map: {"t":"rev-ec","v":1,"sd":<bytes>,"k1":<bytes>,"k2":<bytes>,"gr":<string>}
 * Mirrors pulse-protocol-go/ipfs.MarshalRevokeEC.
 */
export function marshalRevokeEc(r: RevokeStructureEC): Uint8Array {
  return encode({
    t: 'rev-ec',
    v: 1,
    sd: r.sealedData,
    k1: r.key1,
    k2: r.key2,
    gr: r.grant,
  });
}

/**
 * Decodes a V2 EC revoke DAG-CBOR block.
 */
export function unmarshalRevokeEc(block: Uint8Array): RevokeStructureEC {
  const obj = decode(block) as Record<string, unknown>;
  if (obj.t !== 'rev-ec') throw new Error(`Unexpected type: ${obj.t}`);
  if (obj.v !== 1) throw new Error(`Unexpected version: ${obj.v}`);
  return {
    sealedData: obj.sd as Uint8Array,
    key1: obj.k1 as Uint8Array,
    key2: obj.k2 as Uint8Array,
    grant: obj.gr as string,
  };
}
