import { decode, encode } from '@ipld/dag-cbor';
import type { NotaryBlock } from '@pulse-protocol/types';

/**
 * Encodes a NotaryBlock as DAG-CBOR.
 * Map: {"t":"notary","v":1,"ts":<int>,"ip":<string>,"ua":<string>,"loc":<string>}
 * Keys in DAG-CBOR canonical order (length asc, then lexicographic):
 *   t(1), v(1), ip(2), ts(2), ua(2), loc(3)
 * Mirrors pulse-protocol-go/ipfs.MarshalNotaryBlock.
 */
export function marshalNotaryBlock(n: NotaryBlock): Uint8Array {
  return encode({
    t: 'notary',
    v: 1,
    ts: n.timestamp,
    ip: n.ipAddress,
    ua: n.userAgent,
    loc: n.location,
  });
}

/**
 * Decodes a DAG-CBOR block into a NotaryBlock.
 * Mirrors pulse-protocol-go/ipfs.UnmarshalNotaryBlock.
 */
export function unmarshalNotaryBlock(block: Uint8Array): NotaryBlock {
  const obj = decode(block) as Record<string, unknown>;
  if (obj['t'] !== 'notary') throw new Error(`Unexpected type: ${obj['t']}`);
  if (obj['v'] !== 1) throw new Error(`Unexpected version: ${obj['v']}`);
  return {
    timestamp: obj['ts'] as number,
    ipAddress: obj['ip'] as string,
    userAgent: obj['ua'] as string,
    location: obj['loc'] as string,
  };
}
