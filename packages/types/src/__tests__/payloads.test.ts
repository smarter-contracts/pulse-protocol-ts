/**
 * Pins the wire constants and the custody validator for the consent payloads.
 *
 * These values are written into DAG-CBOR records and so into their CIDs; each
 * must equal its pulse-protocol-go counterpart exactly (Go is canon):
 *   - feedpermission.VersionV1/V2/V3, feedrevocation.VersionV1/V2
 *   - payloads.CustodyEscrow/CustodyHolder and payloads.ValidCustody
 *   - feedpermission.ActionRead/Write/Append
 *
 * Feed-permission encoding round-trips live with the codec in
 * packages/ipfs/src/__tests__/. There is no TS feed-revocation codec yet, so
 * the revocation versions are pinned here only.
 */

import { describe, expect, it } from 'vitest';
import {
  CUSTODY_ESCROW,
  CUSTODY_HOLDER,
  FEED_PERMISSION_VERSION_V1,
  FEED_PERMISSION_VERSION_V2,
  FEED_PERMISSION_VERSION_V3,
  FEED_REVOCATION_VERSION_V1,
  FEED_REVOCATION_VERSION_V2,
  isValidCustody,
} from '../payloads.js';
import { ACTION_APPEND, ACTION_READ, ACTION_WRITE } from '../scope.js';

describe('payload wire versions', () => {
  it('numbers feed-permission versions as Go does', () => {
    expect([
      FEED_PERMISSION_VERSION_V1,
      FEED_PERMISSION_VERSION_V2,
      FEED_PERMISSION_VERSION_V3,
    ]).toEqual([1, 2, 3]);
  });

  it('numbers feed-revocation versions as Go does', () => {
    expect([FEED_REVOCATION_VERSION_V1, FEED_REVOCATION_VERSION_V2]).toEqual([1, 2]);
  });
});

describe('custody marks', () => {
  it('spells the custody values exactly as Go does', () => {
    expect(CUSTODY_ESCROW).toBe('escrow');
    expect(CUSTODY_HOLDER).toBe('holder');
  });
});

describe('isValidCustody', () => {
  it.each([CUSTODY_ESCROW, CUSTODY_HOLDER])('accepts %s', (value) => {
    expect(isValidCustody(value)).toBe(true);
  });

  it.each([
    // Absence is "unmarked", a distinct legacy state — never a valid custody value.
    ['undefined', undefined],
    ['the empty string', ''],
    ['null', null],
    // Matching is exact, as in Go: no case-folding or trimming.
    ['a differently cased value', 'Holder'],
    ['a padded value', ' escrow'],
    ['an unknown mode', 'client'],
    ['a non-string', 1],
  ])('rejects %s', (_name, value) => {
    expect(isValidCustody(value)).toBe(false);
  });
});

describe('feed-permission access modes', () => {
  it('spells the access modes exactly as Go does', () => {
    expect([ACTION_READ, ACTION_WRITE, ACTION_APPEND]).toEqual(['read', 'write', 'append']);
  });
});
