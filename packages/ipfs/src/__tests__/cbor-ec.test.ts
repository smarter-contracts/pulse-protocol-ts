/**
 * Known-value tests for V2 EC CBOR marshal/unmarshal.
 * Mirrors pulse-protocol-go/ipfs/cbor_ec_test.go.
 *
 * Key invariant: marshalRevokeEc includes the GrantRef (`gr` field) in the
 * CBOR map, so it produces a different CID than marshalConsentEc for the
 * same underlying EC encryption result.  This distinction is what the
 * mid-tier verifies when checking a revoke signature.
 */

import { describe, expect, it } from 'vitest';
import {
  marshalConsentEc,
  marshalRevokeEc,
  unmarshalConsentEc,
  unmarshalRevokeEc,
} from '../cbor-ec.js';
import { getCid } from '../cid.js';

// Fixed canary inputs — small deterministic byte arrays for stable CID pinning.
const sd = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
const k1 = new Uint8Array([0x0a, 0x0b, 0x0c]);
const k2 = new Uint8Array([0x14, 0x15, 0x16]);
const grant = 'bafyreiabnu633o7opc26xejbewl22zsuhao4kjoeuayzhfep3h2nzfir6i';

describe('V2 EC CBOR — marshalConsentEc / marshalRevokeEc', () => {
  it('marshalConsentEc round-trips through unmarshalConsentEc', () => {
    const block = marshalConsentEc({ sealedData: sd, key1: k1, key2: k2 });
    const decoded = unmarshalConsentEc(block);
    expect(decoded.sealedData).toEqual(sd);
    expect(decoded.key1).toEqual(k1);
    expect(decoded.key2).toEqual(k2);
  });

  it('marshalRevokeEc round-trips through unmarshalRevokeEc', () => {
    const block = marshalRevokeEc({ sealedData: sd, key1: k1, key2: k2, grant });
    const decoded = unmarshalRevokeEc(block);
    expect(decoded.sealedData).toEqual(sd);
    expect(decoded.key1).toEqual(k1);
    expect(decoded.key2).toEqual(k2);
    expect(decoded.grant).toBe(grant);
  });

  it('marshalConsentEc produces known CID', async () => {
    const block = marshalConsentEc({ sealedData: sd, key1: k1, key2: k2 });
    const cid = await getCid(block);
    expect(cid).toBe('bafyreiex6aeefdbq6byjdbdyi75yw467up4f3m5nxftrsikkuok4omjsba');
  });

  it('marshalRevokeEc produces known CID (different from consent CID)', async () => {
    const block = marshalRevokeEc({ sealedData: sd, key1: k1, key2: k2, grant });
    const cid = await getCid(block);
    expect(cid).toBe('bafyreielxqcnj4lpg26uquziqhy6wiiv6ulsfl6xeiehas7dbv2puwdek4');
  });

  it('marshalRevokeEc CID differs from marshalConsentEc CID for same data', async () => {
    const consentBlock = marshalConsentEc({ sealedData: sd, key1: k1, key2: k2 });
    const revokeBlock = marshalRevokeEc({ sealedData: sd, key1: k1, key2: k2, grant });
    const consentCid = await getCid(consentBlock);
    const revokeCid = await getCid(revokeBlock);
    // The GrantRef field in the revoke CBOR changes the hash — this is the
    // invariant that the mid-tier relies on when verifying revoke signatures.
    expect(revokeCid).not.toBe(consentCid);
  });
});
