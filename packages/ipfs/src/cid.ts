import { CID } from 'multiformats/cid'
import { sha256 } from 'multiformats/hashes/sha2'
import * as dagCbor from '@ipld/dag-cbor'

/**
 * Computes a CIDv1 with DAG-CBOR codec and SHA2-256 multihash for a CBOR block.
 * Mirrors pulse-protocol-go/ipfs.GetCid.
 */
export async function getCid(block: Uint8Array): Promise<string> {
  const hash = await sha256.digest(block)
  const cid = CID.createV1(dagCbor.code, hash)
  return cid.toString()
}
