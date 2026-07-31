import { decode, encode } from '@ipld/dag-cbor';
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

  /**
   * "dd" type discipline.
   *
   * Mirrors pulse-protocol-go/ipfs/cbor_feedpermission_v2_test.go:
   *   - TestUnmarshalFeedPermission_RejectsNonStringDataDescriptionAtV2
   *   - TestUnmarshalFeedPermission_RejectsNonStringDataDescriptionAtV1
   *   - TestUnmarshalFeedPermission_AcceptsEmptyDataDescriptionAtV1
   *
   * Go reaches these outcomes via ipfs.OptString, which returns "" for an absent
   * key and an error for a present-but-non-string one. The TypeScript decoder
   * hands back whatever CBOR contained, so it must type-check "dd" explicitly or
   * a forged block could smuggle a non-string into `dataDescription: string`.
   */
  describe('dd type discipline', () => {
    /**
     * Forges a block carrying an arbitrary "dd" value at an arbitrary version —
     * something no marshaller would emit. Counterpart of the Go tests'
     * replaceValue helper; dag-cbor re-sorts the keys canonically on encode.
     */
    function forge(dd: unknown, version: number): Uint8Array {
      const raw = rawMap(marshalFeedPermission(v2Sample));
      raw.dd = dd;
      raw.v = version;
      return encode(raw);
    }

    // A non-string dd is refused on type grounds at every version, so it can
    // never reach the payload. Go: OptString's AsString error, wrapped as "dd: …".
    //
    // The falsy entries (0, false) are the ones a truthiness test waves through:
    // at v1 they slip past a `if (dd)` version guard entirely, so a v1 record can
    // carry a v2-only field undetected. They are not padding — they are the bug.
    const illTyped: Array<[string, unknown]> = [
      ['int', 7],
      ['zero', 0],
      ['bool', true],
      ['false', false],
      ['list', ['a']],
    ];

    for (const [name, dd] of illTyped) {
      it(`rejects a non-string data description at v2 (${name})`, () => {
        expect(() => unmarshalFeedPermission(forge(dd, 2))).toThrow(/dd/);
      });

      it(`rejects a non-string data description at v1 (${name})`, () => {
        expect(() => unmarshalFeedPermission(forge(dd, 1))).toThrow(/dd/);
      });
    }

    it('rejects a non-empty string data description at v1', () => {
      expect(() => unmarshalFeedPermission(forge('x', 1))).toThrow(
        'dd is not valid in feed-permission version 1',
      );
    });

    it('accepts an empty-string data description at v1', () => {
      // Go's OptString cannot tell an empty dd from an absent one, so its v1
      // rejection rule does not fire here. Matching that exactly matters more
      // than the rule reading tidily: a stricter TypeScript decoder would reject
      // blocks Go accepts, splitting the two implementations' view of validity.
      const got = unmarshalFeedPermission(forge('', 1));
      expect(got.dataDescription).toBeUndefined();
    });

    it('does not coerce a non-string dd into the payload', () => {
      // The failure mode being guarded: a silent blind cast would have produced
      // `dataDescription` holding a number, defeating its declared string type.
      let caught: unknown;
      try {
        unmarshalFeedPermission(forge(7, 2));
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(Error);
    });
  });
});
