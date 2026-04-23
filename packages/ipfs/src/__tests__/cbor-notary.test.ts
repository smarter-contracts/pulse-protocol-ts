import { describe, expect, it } from 'vitest';
import { marshalNotaryBlock, unmarshalNotaryBlock } from '../cbor-notary.js';
import { marshalFeedPermission } from '../cbor-feedpermission.js';
import type { FeedPermissionPayload, NotaryBlock } from '@pulse-protocol/types';

const feedSample: FeedPermissionPayload = {
  consentNo: 1, walletId: 'w', grantorWebId: 'gw', counterpartyDid: 'cp',
  feedType: 'ft', podContainerPath: 'pulse/feeds/ft/', permissions: [], dataCategories: [],
  issuedAt: 0, expiresAt: 0, encryptedNotary: new Uint8Array(1),
  notaryKey1: new Uint8Array(33), notaryKey2: new Uint8Array(33),
};

describe('NotaryBlock CBOR', () => {
  const sample: NotaryBlock = {
    timestamp: 1_700_000_000,
    ipAddress: '203.0.113.42',
    userAgent: 'PulsePlus/1.0 (iOS 17.0)',
    location: 'GB',
  };

  it('round-trips a full NotaryBlock', () => {
    const block = marshalNotaryBlock(sample);
    const got = unmarshalNotaryBlock(block);
    expect(got.timestamp).toBe(sample.timestamp);
    expect(got.ipAddress).toBe(sample.ipAddress);
    expect(got.userAgent).toBe(sample.userAgent);
    expect(got.location).toBe(sample.location);
  });

  it('round-trips a NotaryBlock with empty optional fields', () => {
    const sparse: NotaryBlock = { timestamp: 1_700_000_001, ipAddress: '', userAgent: '', location: '' };
    const block = marshalNotaryBlock(sparse);
    const got = unmarshalNotaryBlock(block);
    expect(got.timestamp).toBe(sparse.timestamp);
    expect(got.ipAddress).toBe('');
    expect(got.location).toBe('');
  });

  it('produces non-empty bytes', () => {
    expect(marshalNotaryBlock(sample).length).toBeGreaterThan(0);
  });

  it('rejects a block encoded as a different type', () => {
    const bad = marshalFeedPermission(feedSample);
    expect(() => unmarshalNotaryBlock(bad)).toThrow('Unexpected type');
  });
});
