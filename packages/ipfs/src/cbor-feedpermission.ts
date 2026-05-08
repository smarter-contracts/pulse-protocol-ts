import { decode, encode } from '@ipld/dag-cbor';
import type { FeedPermissionPayload } from '@pulse-protocol/types';

/**
 * Encodes a FeedPermissionPayload as DAG-CBOR.
 * Map with 15 fields — keys in DAG-CBOR canonical order (length asc, then lexicographic):
 *   t(1), v(1), cn(2), dc(2), en(2), ft(2), pm(2),
 *   cpd(3), exp(3), iat(3), nk1(3), nk2(3), pcp(3), wid(3), gwid(4)
 * Mirrors pulse-protocol-go/ipfs.MarshalFeedPermission.
 */
export function marshalFeedPermission(p: FeedPermissionPayload): Uint8Array {
  return encode({
    t: 'feed-permission',
    v: 1,
    cn: p.consentNo,
    dc: p.dataCategories,
    en: p.encryptedNotary,
    ft: p.feedType,
    pm: p.permissions,
    cpd: p.counterpartyDid,
    exp: p.expiresAt,
    iat: p.issuedAt,
    nk1: p.notaryKey1,
    nk2: p.notaryKey2,
    pcp: p.podContainerPath,
    wid: p.walletId,
    gwid: p.grantorWebId,
  });
}

/**
 * Decodes a DAG-CBOR block into a FeedPermissionPayload.
 * Mirrors pulse-protocol-go/ipfs.UnmarshalFeedPermission.
 */
export function unmarshalFeedPermission(block: Uint8Array): FeedPermissionPayload {
  const obj = decode(block) as Record<string, unknown>;
  if (obj.t !== 'feed-permission') throw new Error(`Unexpected type: ${obj.t}`);
  if (obj.v !== 1) throw new Error(`Unexpected version: ${obj.v}`);
  return {
    consentNo: obj.cn as number,
    walletId: obj.wid as string,
    grantorWebId: obj.gwid as string,
    counterpartyDid: obj.cpd as string,
    feedType: obj.ft as string,
    podContainerPath: obj.pcp as string,
    permissions: obj.pm as string[],
    dataCategories: obj.dc as string[],
    issuedAt: obj.iat as number,
    expiresAt: obj.exp as number,
    encryptedNotary: obj.en as Uint8Array,
    notaryKey1: obj.nk1 as Uint8Array,
    notaryKey2: obj.nk2 as Uint8Array,
  };
}
