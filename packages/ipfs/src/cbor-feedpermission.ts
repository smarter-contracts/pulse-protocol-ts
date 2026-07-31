import { decode, encode } from '@ipld/dag-cbor';
import {
  FEED_PERMISSION_VERSION_V1,
  FEED_PERMISSION_VERSION_V2,
  type FeedPermissionPayload,
} from '@pulse-protocol/types';

/**
 * Returns the lowest wire version able to represent the payload.
 *
 * v2 is required when the payload uses a v2-only feature: a dataDescription, or a
 * pod container path outside the v1 "pulse/feeds/{feedType}/" shape. Everything
 * else stays at v1 so that records produced by existing callers keep their exact
 * bytes — and therefore their CIDs — unchanged. An unset container path expresses
 * no v2 feature and is treated as legacy.
 *
 * Mirrors pulse-protocol-go/ipfs.feedPermissionWireVersion.
 */
function feedPermissionWireVersion(p: FeedPermissionPayload): number {
  if (p.dataDescription) return FEED_PERMISSION_VERSION_V2;
  if (p.podContainerPath && p.podContainerPath !== `pulse/feeds/${p.feedType}/`) {
    return FEED_PERMISSION_VERSION_V2;
  }
  return FEED_PERMISSION_VERSION_V1;
}

/**
 * Encodes a FeedPermissionPayload as DAG-CBOR.
 *
 * Map with 15 mandatory fields plus the optional "dd" (dataDescription, v2 only)
 * and "gx" (grantorXpub) fields when non-empty — keys in DAG-CBOR canonical order
 * (length asc, then lexicographic):
 *   t(1), v(1), cn(2), dc(2), dd(2)?, en(2), ft(2), gx(2)?, pm(2),
 *   cpd(3), exp(3), iat(3), nk1(3), nk2(3), pcp(3), wid(3), gwid(4)
 *
 * Mirrors pulse-protocol-go/ipfs.MarshalFeedPermission.
 */
export function marshalFeedPermission(p: FeedPermissionPayload): Uint8Array {
  const version = feedPermissionWireVersion(p);
  const block: Record<string, unknown> = {
    t: 'feed-permission',
    v: version,
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
  };
  if (version >= FEED_PERMISSION_VERSION_V2 && p.dataDescription) {
    block.dd = p.dataDescription;
  }
  if (p.grantorXpub) {
    block.gx = p.grantorXpub;
  }
  return encode(block);
}

/**
 * Decodes a DAG-CBOR block into a FeedPermissionPayload.
 *
 * Both wire versions are accepted: v1 records carry no "dd" field, and v2 records
 * may carry it. Any other version is rejected, as is a v1 record carrying the
 * v2-only "dd" field and any record whose "dd" is present but not a string.
 *
 * Mirrors pulse-protocol-go/ipfs.UnmarshalFeedPermission.
 */
export function unmarshalFeedPermission(block: Uint8Array): FeedPermissionPayload {
  const obj = decode(block) as Record<string, unknown>;
  if (obj.t !== 'feed-permission') throw new Error(`Unexpected type: ${obj.t}`);
  const version = obj.v;
  if (version !== FEED_PERMISSION_VERSION_V1 && version !== FEED_PERMISSION_VERSION_V2) {
    throw new Error(`Unexpected version: ${version}`);
  }
  // "dd" is optional and v2-only. Mirrors Go's ipfs.OptString followed by the
  // version rule: an absent key reads as the empty string, a present-but-non-string
  // value is an error at every version, and only a non-empty value is treated as
  // the v2-only feature a v1 record may not carry.
  //
  // The type check cannot be skipped in favour of a truthiness test. CBOR is an
  // untrusted input here, and `obj.dd` is whatever the block author put there —
  // an unchecked cast would let `dd: 7` land in `dataDescription: string`, and let
  // falsy values such as `dd: 0` slip past the v1 guard that Go rejects outright.
  let dd = '';
  if (Object.hasOwn(obj, 'dd')) {
    if (typeof obj.dd !== 'string') {
      throw new Error(`dd: expected string, got ${obj.dd === null ? 'null' : typeof obj.dd}`);
    }
    dd = obj.dd;
  }
  if (dd !== '' && version < FEED_PERMISSION_VERSION_V2) {
    throw new Error(`dd is not valid in feed-permission version ${version}`);
  }
  const payload: FeedPermissionPayload = {
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
  if (dd) payload.dataDescription = dd;
  const gx = obj.gx as string | undefined;
  if (gx) payload.grantorXpub = gx;
  return payload;
}
