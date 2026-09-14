import { decode, encode } from '@ipld/dag-cbor';
import {
  FEED_PERMISSION_VERSION_V1,
  FEED_PERMISSION_VERSION_V2,
  FEED_PERMISSION_VERSION_V3,
  type FeedPermissionPayload,
} from '@pulse-protocol/types';
import { CID } from 'multiformats/cid';

/**
 * Returns the lowest wire version able to represent the payload.
 *
 * v3 is required when the payload carries a previousCid or policyVersions — these
 * cannot be expressed below v3, so they are checked first and outrank the v2
 * features they may compose with.
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
  if (p.previousCid || (p.policyVersions && p.policyVersions.length > 0)) {
    return FEED_PERMISSION_VERSION_V3;
  }
  if (p.dataDescription) return FEED_PERMISSION_VERSION_V2;
  if (p.podContainerPath && p.podContainerPath !== `pulse/feeds/${p.feedType}/`) {
    return FEED_PERMISSION_VERSION_V2;
  }
  return FEED_PERMISSION_VERSION_V1;
}

/**
 * Encodes a FeedPermissionPayload as DAG-CBOR.
 *
 * Map with 15 mandatory fields plus the optional "dd" (dataDescription, v2 only),
 * "gx" (grantorXpub), "pcid" (previousCid, v3 only) and "pv" (policyVersions, v3 only)
 * fields when non-empty — keys in DAG-CBOR canonical order (length asc, then lexicographic):
 *   t(1), v(1), cn(2), dc(2), dd(2)?, en(2), ft(2), gx(2)?, pm(2), pv(2)?,
 *   cpd(3), exp(3), iat(3), nk1(3), nk2(3), pcp(3), wid(3), gwid(4), pcid(4)?
 *
 * The object literal below is built in declaration order; @ipld/dag-cbor sorts
 * the keys canonically on encode, so only the list above records the wire order.
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
  if (version >= FEED_PERMISSION_VERSION_V3 && p.policyVersions && p.policyVersions.length > 0) {
    const sorted = [...p.policyVersions].sort((a, b) =>
      a.docType < b.docType ? -1 : a.docType > b.docType ? 1 : 0,
    );
    block.pv = sorted.map((v) => ({ dh: v.documentHash, dt: v.docType }));
  }
  if (version >= FEED_PERMISSION_VERSION_V3 && p.previousCid) {
    block.pcid = p.previousCid;
  }
  return encode(block);
}

/**
 * Decodes a DAG-CBOR block into a FeedPermissionPayload.
 *
 * All three wire versions are accepted: v1 records carry neither "dd" nor "pcid",
 * v2 records may carry "dd", and v3 records may carry both. Any other version is
 * rejected, as is a record carrying a field its version cannot express ("dd"
 * below v2, "pcid" below v3) and any record whose "dd" or "pcid" is present but
 * not a string.
 *
 * Mirrors pulse-protocol-go/ipfs.UnmarshalFeedPermission.
 */
export function unmarshalFeedPermission(block: Uint8Array): FeedPermissionPayload {
  const obj = decode(block) as Record<string, unknown>;
  if (obj.t !== 'feed-permission') throw new Error(`Unexpected type: ${obj.t}`);
  const version = obj.v;
  if (
    version !== FEED_PERMISSION_VERSION_V1 &&
    version !== FEED_PERMISSION_VERSION_V2 &&
    version !== FEED_PERMISSION_VERSION_V3
  ) {
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
  // "pcid" is optional and v3-only, and is checked exactly as "dd" is above: an
  // absent key reads as the empty string, a present-but-non-string value is an
  // error at every version, and only a non-empty value is treated as the v3-only
  // feature a lower-version record may not carry.
  let pcid = '';
  if (Object.hasOwn(obj, 'pcid')) {
    if (typeof obj.pcid !== 'string') {
      throw new Error(`pcid: expected string, got ${obj.pcid === null ? 'null' : typeof obj.pcid}`);
    }
    pcid = obj.pcid;
  }
  if (pcid !== '' && version < FEED_PERMISSION_VERSION_V3) {
    throw new Error(`pcid is not valid in feed-permission version ${version}`);
  }
  // "pv" is optional and v3-only, exactly as "pcid" is above.
  let pv: { docType: string; documentHash: string }[] | undefined;
  if (Object.hasOwn(obj, 'pv')) {
    const raw = obj.pv;
    if (!Array.isArray(raw)) {
      throw new Error(`pv: expected array, got ${typeof raw}`);
    }
    const seen = new Set<string>();
    pv = raw.map((entry) => {
      if (typeof entry !== 'object' || entry === null) {
        throw new Error('pv: entry is not an object');
      }
      const e = entry as Record<string, unknown>;
      if (typeof e.dh !== 'string') throw new Error(`dh: expected string, got ${typeof e.dh}`);
      if (typeof e.dt !== 'string') throw new Error(`dt: expected string, got ${typeof e.dt}`);
      try {
        CID.parse(e.dh);
      } catch {
        throw new Error(`dh: ${e.dh} is not a well-formed CID`);
      }
      if (seen.has(e.dt)) throw new Error(`duplicate docType ${e.dt} in pv`);
      seen.add(e.dt);
      return { docType: e.dt, documentHash: e.dh };
    });
  }
  if (pv && pv.length > 0 && version < FEED_PERMISSION_VERSION_V3) {
    throw new Error(`pv is not valid in feed-permission version ${version}`);
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
  if (pcid) payload.previousCid = pcid;
  if (pv && pv.length > 0) payload.policyVersions = pv;
  const gx = obj.gx as string | undefined;
  if (gx) payload.grantorXpub = gx;
  return payload;
}
