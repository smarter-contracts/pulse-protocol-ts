import { describe, expect, it } from 'vitest';
import { getCid } from '../cid.js';

describe('getCid — known values (mirrors pulse-protocol-go/ipfs/cid_test.go)', () => {
  it('hello world', async () => {
    const cid = await getCid(new TextEncoder().encode('hello world'));
    expect(cid).toBe('bafyreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e');
  });

  it('CBOR text "a" (0x61 0x61)', async () => {
    const cid = await getCid(new Uint8Array([0x61, 0x61]));
    expect(cid).toBe('bafyreiewdnw5h3pdzohmxkwl22g6aqgnpdvs5vmiseymz22mjeti5jgvay');
  });

  it('empty block', async () => {
    const cid = await getCid(new Uint8Array(0));
    expect(cid).toBe('bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku');
  });

  it('known block from send_test_consent.js (V1 mid-tier test)', async () => {
    const block = new Uint8Array([
      163, 100, 107, 101, 121, 49, 106, 75, 69, 89, 49, 114, 97, 110, 100, 111, 109, 100, 107, 101,
      121, 50, 106, 75, 69, 89, 50, 114, 97, 110, 100, 111, 109, 103, 99, 111, 110, 115, 101, 110,
      116, 120, 42, 67, 79, 78, 83, 69, 78, 84, 95, 82, 69, 86, 84, 69, 83, 84, 49, 49, 55, 54, 57,
      48, 49, 49, 51, 49, 53, 52, 53, 56, 49, 55, 54, 57, 48, 49, 49, 51, 49, 53, 52, 53, 56,
    ]);
    const cid = await getCid(block);
    expect(cid).toBe('bafyreid2bvcka3iw7ag2lwxy7jvpd3wil4vj4ftmhyehty3b6ypbfge3pu');
  });
});
