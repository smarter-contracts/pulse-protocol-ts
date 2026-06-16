/**
 * Known-value tests for V2 PQ CBOR marshal/unmarshal.
 * Mirrors the EC tests in cbor-ec.test.ts.
 *
 * Key invariant: marshalRevokePq includes the GrantRef (`gr` field) in the
 * CBOR map, so it produces a different CID than marshalConsentPq for the
 * same underlying PQ encryption result.
 */

import { describe, expect, it } from 'vitest';
import {
  marshalConsentPq,
  marshalRevokePq,
  unmarshalConsentPq,
  unmarshalRevokePq,
} from '../cbor-pq.js';
import { getCid } from '../cid.js';

// Fixed canary inputs.
const sd = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
const fp1 = new Uint8Array(32).fill(0xaa);
const ekk1 = new Uint8Array([0x10, 0x11, 0x12]);
const edk1 = new Uint8Array([0x20, 0x21, 0x22]);
const fp2 = new Uint8Array(32).fill(0xbb);
const ekk2 = new Uint8Array([0x30, 0x31, 0x32]);
const edk2 = new Uint8Array([0x40, 0x41, 0x42]);
const grant = 'bafyreiabnu633o7opc26xejbewl22zsuhao4kjoeuayzhfep3h2nzfir6i';

const keys = [
  { keyFingerPrint: fp1, encapsulatedKeyKey: ekk1, encapsulatedDataKey: edk1 },
  { keyFingerPrint: fp2, encapsulatedKeyKey: ekk2, encapsulatedDataKey: edk2 },
];

describe('V2 PQ CBOR — marshalConsentPq / marshalRevokePq', () => {
  it('marshalConsentPq round-trips through unmarshalConsentPq', () => {
    const block = marshalConsentPq({ sealedData: sd, keys });
    const decoded = unmarshalConsentPq(block);
    expect(decoded.sealedData).toEqual(sd);
    expect(decoded.keys).toHaveLength(2);
    expect(decoded.keys[0]!.keyFingerPrint).toEqual(fp1);
    expect(decoded.keys[1]!.keyFingerPrint).toEqual(fp2);
  });

  it('marshalRevokePq round-trips through unmarshalRevokePq', () => {
    const block = marshalRevokePq({ sealedData: sd, keys, grant });
    const decoded = unmarshalRevokePq(block);
    expect(decoded.sealedData).toEqual(sd);
    expect(decoded.keys).toHaveLength(2);
    expect(decoded.grant).toBe(grant);
  });

  it('marshalConsentPq produces known CID', async () => {
    const block = marshalConsentPq({ sealedData: sd, keys });
    const cid = await getCid(block);
    expect(cid).toBe('bafyreiejxhcor2mbbhfvmvsat2gspfucjetnfvwkkxj43srchio7urisne');
  });

  it('marshalRevokePq produces known CID (different from consent CID)', async () => {
    const block = marshalRevokePq({ sealedData: sd, keys, grant });
    const cid = await getCid(block);
    expect(cid).toBe('bafyreih7sciihau4nq2ad3giqqjan6q7xcjvsn6vydhk42dhghn3wbmlni');
  });

  it('marshalRevokePq CID differs from marshalConsentPq CID for same data', async () => {
    const consentBlock = marshalConsentPq({ sealedData: sd, keys });
    const revokeBlock = marshalRevokePq({ sealedData: sd, keys, grant });
    const consentCid = await getCid(consentBlock);
    const revokeCid = await getCid(revokeBlock);
    expect(revokeCid).not.toBe(consentCid);
  });
});
