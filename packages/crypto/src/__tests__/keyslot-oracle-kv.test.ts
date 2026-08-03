/**
 * Known-value tests for the oracle (type-4) keyslot.
 * Mirrors pulse-protocol-go/crypto/keyslot_oracle_kv_test.go.
 *
 * These vectors pin the exact byte layout of a v2 oracle keyslot blob. The
 * literal constants below MUST stay identical to the Go mirror so the two
 * implementations remain byte-identical.
 *
 * The oracle slot uses only AES-256-GCM (no Argon2id), so the blob is fully
 * deterministic from the fixed inputs below.
 *
 * Fixed inputs:
 *   keyId           = "tier-30-2026"
 *   wrappedSlotKey  = 12B nonce ++ 48B AES-256-GCM(slotKey, KEK)   (60 bytes)
 *   outer nonce     = d0d1d2d3d4d5d6d7d8d9dadb
 *   Kw   (32B)      = 0102..20
 *   slotKey (32B)   = 2122..40
 */

import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../hash.js';
import {
  decodeOracleParams,
  decodeV2Slot,
  encodeV2OracleSlot,
  SLOT_TYPE_ORACLE,
  unwrapKeyslot,
  unwrapKw,
  WRAPPED_SLOT_KEY_SIZE,
  wrapKw,
} from '../keyslot.js';

// ── Fixed inputs (identical to keyslot_oracle_kv_test.go) ─────────────────────
const KEY_ID = 'tier-30-2026';
const WRAPPED_SLOT_KEY = fromHex(
  'b0b1b2b3b4b5b6b7b8b9babb' +
    'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
    'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' +
    'e0e1e2e3e4e5e6e7e8e9eaebecedeeef',
);
const OUTER_NONCE = fromHex('d0d1d2d3d4d5d6d7d8d9dadb');
const KW = fromHex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
const SLOT_KEY = fromHex('2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40');

// ── Known value (identical to keyslot_oracle_kv_test.go) ──────────────────────
const ORACLE_V2_BLOB_HEX =
  'b00204004a000c746965722d33302d32303236b0b1b2b3b4b5b6b7b8b9babbc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeefd0d1d2d3d4d5d6d7d8d9dadb0254d833e779a757cda16d14d15544157eec14d291798b73781b6ab35330b0ed4dec90175647bf639c06d16437823a99';

describe('Oracle keyslot — known values (mirrors pulse-protocol-go/crypto/keyslot_oracle_kv_test.go)', () => {
  it('wrappedSlotKey is the documented 60 bytes', () => {
    expect(WRAPPED_SLOT_KEY.length).toBe(WRAPPED_SLOT_KEY_SIZE);
  });

  it('full v2 oracle blob is byte-identical to the Go reference', () => {
    const ct = wrapKw(KW, SLOT_KEY, OUTER_NONCE);
    const blob = encodeV2OracleSlot(KEY_ID, WRAPPED_SLOT_KEY, OUTER_NONCE, ct);
    expect(toHex(blob)).toBe(ORACLE_V2_BLOB_HEX);
  });

  it('decodeOracleParams recovers keyId and wrappedSlotKey', () => {
    const params = decodeOracleParams(fromHex(ORACLE_V2_BLOB_HEX));
    expect(params.keyId).toBe(KEY_ID);
    expect(toHex(params.wrappedSlotKey)).toBe(toHex(WRAPPED_SLOT_KEY));
  });

  it('given the slot key, unwrapKw recovers Kw from the outer body', () => {
    const decoded = decodeV2Slot(fromHex(ORACLE_V2_BLOB_HEX));
    if (decoded === null) {
      throw new Error('expected oracle blob to decode');
    }
    expect(decoded.slotType).toBe(SLOT_TYPE_ORACLE);
    const recovered = unwrapKw(decoded.ct, SLOT_KEY, decoded.nonce);
    expect(toHex(recovered)).toBe(toHex(KW));
  });

  it('an oracle slot is not locally unwrappable via unwrapKeyslot', () => {
    expect(() =>
      unwrapKeyslot(fromHex(ORACLE_V2_BLOB_HEX), {
        password: {
          sub: 'x',
          iss: 'y',
          walletId: 'z',
          secret: new TextEncoder().encode('s'),
        },
      }),
    ).toThrow();
  });
});
