/**
 * Known-value tests for the polymorphic marshalRevoke / marshalConsent functions.
 *
 * The CID constants below match the Go implementation's cbor_payload_test.go
 * tests exactly, proving byte-identical DAG-CBOR output between TypeScript and Go.
 *
 * Canary inputs — must be kept in sync with pulse-protocol-go/ipfs/cbor_payload_test.go:
 *   payloadTestSealedData = []byte{0x01, 0x02, 0x03, 0x04, 0x05}
 *   payloadTestKey1       = []byte{0x02, 0x10, 0x20, 0x30, 0x40}
 *   payloadTestKey2       = []byte{0x03, 0x50, 0x60, 0x70, 0x80}
 *   payloadTestGrantRef   = "bafyreidknownvalue001"
 *   payloadTestPQKey      = {fp:[1..32], ekk:[0xAA,0xBB,0xCC], edk:[0x11,0x22,0x33]}
 */

import { describe, expect, it } from 'vitest';
import { marshalConsent, marshalRevoke } from '../cbor-request.js';
import { getCid } from '../cid.js';

const sd = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
const k1 = new Uint8Array([0x02, 0x10, 0x20, 0x30, 0x40]);
const k2 = new Uint8Array([0x03, 0x50, 0x60, 0x70, 0x80]);
const grantRef = 'bafyreidknownvalue001';

const pqKeyFp = new Uint8Array(32);
for (let i = 0; i < 32; i++) pqKeyFp[i] = i + 1;
const pqKey = {
  keyFingerPrint: pqKeyFp,
  encapsulatedKeyKey: new Uint8Array([0xaa, 0xbb, 0xcc]),
  encapsulatedDataKey: new Uint8Array([0x11, 0x22, 0x33]),
};

describe('marshalRevoke — EC', () => {
  it('produces a known CID byte-identical to the Go implementation', async () => {
    const want = 'bafyreihjqdlyrcq6pwf3befiag6mvws6p4oftvl4uzktv4rorcgtsngkv4';
    const cbor = marshalRevoke({ sealedData: sd, key1: k1, key2: k2, grantRef });
    const got = await getCid(cbor);
    expect(got).toBe(want);
  });
});

describe('marshalRevoke — PQ', () => {
  it('produces a known CID byte-identical to the Go implementation', async () => {
    const want = 'bafyreiglc3gmrbrn4hm7tjlqne5ebbfkwh6qwgda2gnfqoctp5zls5lgny';
    const cbor = marshalRevoke({ sealedData: sd, keys: [pqKey], grantRef });
    const got = await getCid(cbor);
    expect(got).toBe(want);
  });
});

describe('marshalConsent — EC', () => {
  it('produces a known CID byte-identical to the Go implementation', async () => {
    const want = 'bafyreibycrajtid4jjzm3w2s6myfqbxtkf4tstwwbh6s2clnzym3ax4zam';
    const cbor = marshalConsent({ sealedData: sd, key1: k1, key2: k2 });
    const got = await getCid(cbor);
    expect(got).toBe(want);
  });
});

describe('marshalConsent — PQ', () => {
  it('produces a known CID byte-identical to the Go implementation', async () => {
    const want = 'bafyreidt4lws7mpguyvvnr6adc5dpiyjyeqtymvpbcy3chieni332bqbwe';
    const cbor = marshalConsent({ sealedData: sd, keys: [pqKey] });
    const got = await getCid(cbor);
    expect(got).toBe(want);
  });
});
