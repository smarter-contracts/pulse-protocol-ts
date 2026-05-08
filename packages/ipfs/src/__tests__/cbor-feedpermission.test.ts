import type { FeedPermissionPayload, NotaryBlock } from '@pulse-protocol/types';
import { describe, expect, it } from 'vitest';
import { marshalFeedPermission, unmarshalFeedPermission } from '../cbor-feedpermission.js';
import { marshalNotaryBlock } from '../cbor-notary.js';

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
});
