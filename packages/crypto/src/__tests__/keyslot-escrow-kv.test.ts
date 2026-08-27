/**
 * Known-value tests for the escrow (type-5) keyslot.
 * Mirrors pulse-protocol-go/crypto/keyslot_escrow_kv_test.go.
 *
 * These vectors pin the exact byte layout of a v2 escrow keyslot blob. The
 * literal constants below MUST stay identical to the Go mirror so the two
 * implementations remain byte-identical.
 *
 * The escrow slot uses only AES-256-GCM (no Argon2id), so the blob is fully
 * deterministic from the fixed inputs below. The fixtures are deliberately
 * disjoint from the oracle (type-4) vector, so the pinned blob differs from the
 * oracle vector throughout rather than merely in its type byte.
 *
 * Fixed inputs:
 *   keyId           = "escrow-2026"
 *   wrappedSlotKey  = 12B nonce ++ 48B AES-256-GCM(slotKey, KEK)   (60 bytes)
 *                     1011..1a1b ++ 2021..4f
 *   outer nonce     = 505152535455565758595a5b
 *   Kw   (32B)      = 6061..7f
 *   slotKey (32B)   = 8081..9f
 */

import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../hash.js';
import {
  decodeEscrowParams,
  decodeV2Slot,
  encodeV2EscrowSlot,
  SLOT_TYPE_ESCROW,
  unwrapKeyslot,
  unwrapKw,
  WRAPPED_SLOT_KEY_SIZE,
  wrapKw,
} from '../keyslot.js';

// ── Fixed inputs (identical to keyslot_escrow_kv_test.go) ─────────────────────
const KEY_ID = 'escrow-2026';
const WRAPPED_SLOT_KEY = fromHex(
  '101112131415161718191a1b' +
    '202122232425262728292a2b2c2d2e2f' +
    '303132333435363738393a3b3c3d3e3f' +
    '404142434445464748494a4b4c4d4e4f',
);
const OUTER_NONCE = fromHex('505152535455565758595a5b');
const KW = fromHex('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f');
const SLOT_KEY = fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');

// ── Known value (identical to keyslot_escrow_kv_test.go) ──────────────────────
const ESCROW_V2_BLOB_HEX =
  'b002050049000b657363726f772d32303236' +
  '101112131415161718191a1b202122232425262728292a2b2c2d2e2f' +
  '303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f' +
  '505152535455565758595a5b' +
  'd2e4f426431c678106326140e3f3bef0360566b448529e5fdab2352aa9e3f856' +
  '7310c20cdbd0ce844986c7c8c4ddd254';

describe('Escrow keyslot — known values (mirrors pulse-protocol-go/crypto/keyslot_escrow_kv_test.go)', () => {
  it('wrappedSlotKey is the documented 60 bytes', () => {
    expect(WRAPPED_SLOT_KEY.length).toBe(WRAPPED_SLOT_KEY_SIZE);
  });

  it('full v2 escrow blob is byte-identical to the Go reference', () => {
    const ct = wrapKw(KW, SLOT_KEY, OUTER_NONCE);
    const blob = encodeV2EscrowSlot(KEY_ID, WRAPPED_SLOT_KEY, OUTER_NONCE, ct);
    expect(toHex(blob)).toBe(ESCROW_V2_BLOB_HEX);
  });

  it('decodeEscrowParams recovers keyId and wrappedSlotKey', () => {
    const params = decodeEscrowParams(fromHex(ESCROW_V2_BLOB_HEX));
    expect(params.keyId).toBe(KEY_ID);
    expect(toHex(params.wrappedSlotKey)).toBe(toHex(WRAPPED_SLOT_KEY));
  });

  it('given the slot key, unwrapKw recovers Kw from the outer body', () => {
    const decoded = decodeV2Slot(fromHex(ESCROW_V2_BLOB_HEX));
    if (decoded === null) {
      throw new Error('expected escrow blob to decode');
    }
    expect(decoded.slotType).toBe(SLOT_TYPE_ESCROW);
    const recovered = unwrapKw(decoded.ct, SLOT_KEY, decoded.nonce);
    expect(toHex(recovered)).toBe(toHex(KW));
  });

  it('an escrow slot is not locally unwrappable via unwrapKeyslot', () => {
    expect(() =>
      unwrapKeyslot(fromHex(ESCROW_V2_BLOB_HEX), {
        password: {
          sub: 'x',
          iss: 'y',
          walletId: 'z',
          secret: new TextEncoder().encode('s'),
        },
      }),
    ).toThrow(/escrow keyslot must be opened via the escrow plane/);
  });
});
