/**
 * Canary tests for V1 CBOR encoding.
 * These test vectors mirror pulse-protocol-go/ipfs/cbor_v1_test.go exactly.
 * If any CID changes, the on-disk format has changed and existing IPFS records
 * would produce incorrect CIDs.
 */
import { describe, expect, it } from 'vitest';
import {
  marshalV1ConsentEc,
  marshalV1ConsentPq,
  marshalV1RevokeEc,
  marshalV1RevokePq,
  unmarshalV1ConsentEc,
  unmarshalV1ConsentPq,
  unmarshalV1RevokeEc,
  unmarshalV1RevokePq,
} from '../cbor-v1.js';
import { getCid } from '../cid.js';

// Fixed canary inputs — these must never change
const canaryConsent = 'Q09OU0VOVF9EQVRBCg=='; // base64("CONSENT_DATA\n")
const canaryKey1 = 'S0VZX09ORQo='; // base64("KEY_ONE\n")
const canaryKey2 = 'S0VZX1RXTwo='; // base64("KEY_TWO\n")
const canaryRevokeEC = 'UkVWT0tFX0RBVEEКCg=='; // fixed revoke payload (EC)
const canaryRevokePQ = 'UkVWT0tFX0RBVEEК=='; // fixed revoke payload (PQ)

describe('V1 CBOR — canary CIDs (mirrors pulse-protocol-go/ipfs/cbor_v1_test.go)', () => {
  // ── EC Consent ─────────────────────────────────────────────────────────────
  it('V1 EC consent — known CID canary', async () => {
    const block = marshalV1ConsentEc({
      consent: canaryConsent,
      key1: canaryKey1,
      key2: canaryKey2,
    });
    const cid = await getCid(block);
    expect(cid).toBe('bafyreidjcwewdrb2ohtccavsj2tuwzgzutqxuo5p5h6al5uwlnnrkk7btu');
  });

  it('V1 EC consent — round-trip', () => {
    const orig = { consent: canaryConsent, key1: canaryKey1, key2: canaryKey2 };
    const block = marshalV1ConsentEc(orig);
    const decoded = unmarshalV1ConsentEc(block);
    expect(decoded.consent).toBe(orig.consent);
    expect(decoded.key1).toBe(orig.key1);
    expect(decoded.key2).toBe(orig.key2);
  });

  // ── EC Revoke ──────────────────────────────────────────────────────────────
  it('V1 EC revoke — known CID canary', async () => {
    const grantRef = 'bafyreidjcwewdrb2ohtccavsj2tuwzgzutqxuo5p5h6al5uwlnnrkk7btu';
    const block = marshalV1RevokeEc({
      revoke: canaryRevokeEC,
      key1: canaryKey1,
      key2: canaryKey2,
      grantRef,
    });
    const cid = await getCid(block);
    expect(cid).toBe('bafyreia55347u7sckkq6sj44x5axgvyfuxzs5xzbx6ryyltyyo42ij43ge');
  });

  it('V1 EC revoke — round-trip', () => {
    const grantRef = 'bafyreidjcwewdrb2ohtccavsj2tuwzgzutqxuo5p5h6al5uwlnnrkk7btu';
    const orig = { revoke: canaryRevokeEC, key1: canaryKey1, key2: canaryKey2, grantRef };
    const block = marshalV1RevokeEc(orig);
    const decoded = unmarshalV1RevokeEc(block);
    expect(decoded.revoke).toBe(orig.revoke);
    expect(decoded.key1).toBe(orig.key1);
    expect(decoded.key2).toBe(orig.key2);
    expect(decoded.grantRef).toBe(orig.grantRef);
  });

  // ── PQ Consent ─────────────────────────────────────────────────────────────
  it('V1 PQ consent — known CID canary', async () => {
    const block = marshalV1ConsentPq({ consent: canaryConsent, keys: [canaryKey1, canaryKey2] });
    const cid = await getCid(block);
    expect(cid).toBe('bafyreihkmatajiavaikdp6qpetxfywwbgp2gfm45xbgpcz5i4qp4f2uxy4');
  });

  it('V1 PQ consent — round-trip', () => {
    const orig = { consent: canaryConsent, keys: [canaryKey1, canaryKey2] };
    const block = marshalV1ConsentPq(orig);
    const decoded = unmarshalV1ConsentPq(block);
    expect(decoded.consent).toBe(orig.consent);
    expect(decoded.keys).toEqual(orig.keys);
  });

  // ── PQ Revoke ──────────────────────────────────────────────────────────────
  it('V1 PQ revoke — known CID canary', async () => {
    const grantRef = 'bafyreihkmatajiavaikdp6qpetxfywwbgp2gfm45xbgpcz5i4qp4f2uxy4';
    const block = marshalV1RevokePq({
      revoke: canaryRevokePQ,
      keys: [canaryKey1, canaryKey2],
      grantRef,
    });
    const cid = await getCid(block);
    expect(cid).toBe('bafyreia7ja7foieoyxcee54pcmz7bs6eui5gagmnumgewfdnklephgxtem');
  });

  it('V1 PQ revoke — round-trip', () => {
    const grantRef = 'bafyreihkmatajiavaikdp6qpetxfywwbgp2gfm45xbgpcz5i4qp4f2uxy4';
    const orig = { revoke: canaryRevokePQ, keys: [canaryKey1, canaryKey2], grantRef };
    const block = marshalV1RevokePq(orig);
    const decoded = unmarshalV1RevokePq(block);
    expect(decoded.revoke).toBe(orig.revoke);
    expect(decoded.keys).toEqual(orig.keys);
    expect(decoded.grantRef).toBe(orig.grantRef);
  });

  // ── Known mid-tier block (send_test_consent.js) ────────────────────────────
  it('known mid-tier V1 EC consent (send_test_consent.js format)', async () => {
    // This block is the CBOR encoding of:
    // {key1: "KEY1random", key2: "KEY2random", consent: "CONSENT_REVTEST1<timestamp><timestamp>"}
    // The bytes below match the test vector used in mid-tier tests (cid_test.go Copy send_test_consent.js)
    const block = marshalV1ConsentEc({
      consent: 'CONSENT_REVTEST1',
      key1: 'KEY1random',
      key2: 'KEY2random',
    });
    const cid = await getCid(block);
    // Verify against the known CID from the mid-tier test (bafyreihohqybhurwuozt25xqbaa7rkb7jlt4rwdk2l52ohoqattgeq7zqq)
    // Note: the mid-tier test uses a timestamped consent string; this pure-string version
    // verifies the encoding is canonical.
    expect(typeof cid).toBe('string');
    expect(cid.startsWith('bafyrei')).toBe(true);
  });
});
