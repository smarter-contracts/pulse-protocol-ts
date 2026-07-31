import { decode } from '@ipld/dag-cbor';
import type { FeedPermissionPayload, NotaryBlock } from '@pulse-protocol/types';
import { describe, expect, it } from 'vitest';
import { marshalFeedPermission, unmarshalFeedPermission } from '../cbor-feedpermission.js';
import { marshalNotaryBlock } from '../cbor-notary.js';

/** Reads the raw CBOR map of a marshalled block, for version/key assertions. */
function rawMap(block: Uint8Array): Record<string, unknown> {
  return decode(block) as Record<string, unknown>;
}

const nk1 = new Uint8Array(33);
nk1[0] = 0x02;
const nk2 = new Uint8Array(33);
nk2[0] = 0x03;

const sample: FeedPermissionPayload = {
  consentNo: 42,
  walletId: 'wlt-abc123',
  grantorWebId: 'https://pod.example/alice/profile/card#me',
  counterpartyDid: 'did:web:feeds.example.com',
  feedType: 'open-banking',
  podContainerPath: 'pulse/feeds/open-banking/',
  permissions: ['read', 'write'],
  dataCategories: ['transaction-history', 'account-balance'],
  issuedAt: 1_700_000_000,
  expiresAt: 1_730_000_000,
  encryptedNotary: new Uint8Array([1, 2, 3, 4]),
  notaryKey1: nk1,
  notaryKey2: nk2,
};

const notarySample: NotaryBlock = {
  timestamp: 1_700_000_000,
  ipAddress: '127.0.0.1',
  userAgent: 'test',
  location: 'GB',
};

describe('FeedPermissionPayload CBOR', () => {
  it('round-trips a full FeedPermissionPayload', () => {
    const block = marshalFeedPermission(sample);
    const got = unmarshalFeedPermission(block);

    expect(got.consentNo).toBe(sample.consentNo);
    expect(got.walletId).toBe(sample.walletId);
    expect(got.grantorWebId).toBe(sample.grantorWebId);
    expect(got.counterpartyDid).toBe(sample.counterpartyDid);
    expect(got.feedType).toBe(sample.feedType);
    expect(got.podContainerPath).toBe(sample.podContainerPath);
    expect(got.permissions).toEqual(sample.permissions);
    expect(got.dataCategories).toEqual(sample.dataCategories);
    expect(got.issuedAt).toBe(sample.issuedAt);
    expect(got.expiresAt).toBe(sample.expiresAt);
    expect(got.encryptedNotary).toEqual(sample.encryptedNotary);
    expect(got.notaryKey1).toEqual(sample.notaryKey1);
    expect(got.notaryKey2).toEqual(sample.notaryKey2);
  });

  it('round-trips with empty permission and category lists', () => {
    const sparse: FeedPermissionPayload = {
      ...sample,
      permissions: [],
      dataCategories: [],
      expiresAt: 0,
    };
    const block = marshalFeedPermission(sparse);
    const got = unmarshalFeedPermission(block);
    expect(got.expiresAt).toBe(0);
    expect(got.permissions).toEqual([]);
    expect(got.dataCategories).toEqual([]);
  });

  it('produces non-empty bytes', () => {
    expect(marshalFeedPermission(sample).length).toBeGreaterThan(0);
  });

  it('rejects a block encoded as a different type', () => {
    const bad = marshalNotaryBlock(notarySample);
    expect(() => unmarshalFeedPermission(bad)).toThrow('Unexpected type');
  });

  it('round-trips the optional grantorXpub field', () => {
    const withXpub: FeedPermissionPayload = {
      ...sample,
      grantorXpub: 'xpub661MyMwAqRbcGRandomTestXpubValue',
    };
    const got = unmarshalFeedPermission(marshalFeedPermission(withXpub));
    expect(got.grantorXpub).toBe(withXpub.grantorXpub);
  });

  it('omits grantorXpub when it is not set', () => {
    const got = unmarshalFeedPermission(marshalFeedPermission(sample));
    expect(got.grantorXpub).toBeUndefined();
  });
});

/**
 * Wire version 2 — the generalised inbound-feed permission.
 * Mirrors pulse-protocol-go/ipfs/cbor_feedpermission_v2_test.go.
 */
describe('FeedPermissionPayload CBOR — v2', () => {
  /** A verified-credential provider granted write access under pulse/credentials/. */
  const v2Sample: FeedPermissionPayload = {
    ...sample,
    feedType: 'verified-identity',
    podContainerPath: 'pulse/credentials/identity/',
    permissions: ['write'],
    dataCategories: ['identity-document'],
    dataDescription: 'Verified Identity Credential',
  };

  it('emits v1 for legacy-shaped payloads', () => {
    const raw = rawMap(marshalFeedPermission(sample));
    expect(raw.v).toBe(1);
    expect('dd' in raw).toBe(false);
  });

  it('emits v2 when a data description is present', () => {
    const raw = rawMap(marshalFeedPermission({ ...sample, dataDescription: 'Identity' }));
    expect(raw.v).toBe(2);
    expect(raw.dd).toBe('Identity');
  });

  it('emits v2 for a generalised container path', () => {
    const raw = rawMap(
      marshalFeedPermission({ ...sample, podContainerPath: 'pulse/credentials/identity/' }),
    );
    expect(raw.v).toBe(2);
    expect('dd' in raw).toBe(false);
  });

  it('keeps emitting v1 when the container path is unset', () => {
    const raw = rawMap(marshalFeedPermission({ ...sample, podContainerPath: '' }));
    expect(raw.v).toBe(1);
  });

  it('round-trips a v2 payload', () => {
    const got = unmarshalFeedPermission(marshalFeedPermission(v2Sample));
    expect(got.dataDescription).toBe(v2Sample.dataDescription);
    expect(got.podContainerPath).toBe(v2Sample.podContainerPath);
    expect(got.feedType).toBe(v2Sample.feedType);
    expect(got.permissions).toEqual(v2Sample.permissions);
    expect(got.grantorXpub).toBeUndefined();
  });

  it('round-trips a v2 payload carrying both optional fields', () => {
    const both: FeedPermissionPayload = {
      ...v2Sample,
      grantorXpub: 'xpub661MyMwAqRbcGRandomTestXpubValue',
    };
    const got = unmarshalFeedPermission(marshalFeedPermission(both));
    expect(got.grantorXpub).toBe(both.grantorXpub);
    expect(got.dataDescription).toBe(both.dataDescription);
  });

  it('round-trips a v2 payload without a data description', () => {
    const noDd: FeedPermissionPayload = { ...v2Sample, dataDescription: '' };
    const block = marshalFeedPermission(noDd);
    expect(rawMap(block).v).toBe(2);
    expect(unmarshalFeedPermission(block).dataDescription).toBeUndefined();
  });

  it('rejects an unknown wire version', () => {
    const block = marshalFeedPermission(v2Sample);
    // Rewrite the "v" value from 2 to 3 (single-byte unsigned ints in CBOR).
    const idx = block.findIndex(
      (b, i) => b === 0x61 && block[i + 1] === 0x76 && block[i + 2] === 0x02,
    );
    expect(idx).toBeGreaterThan(-1);
    const tampered = Uint8Array.from(block);
    tampered[idx + 2] = 0x03;
    expect(() => unmarshalFeedPermission(tampered)).toThrow('Unexpected version');
  });

  it('rejects a data description on a v1 record', () => {
    const block = marshalFeedPermission(v2Sample);
    const idx = block.findIndex(
      (b, i) => b === 0x61 && block[i + 1] === 0x76 && block[i + 2] === 0x02,
    );
    const tampered = Uint8Array.from(block);
    tampered[idx + 2] = 0x01;
    expect(() => unmarshalFeedPermission(tampered)).toThrow(
      'dd is not valid in feed-permission version 1',
    );
  });
});
