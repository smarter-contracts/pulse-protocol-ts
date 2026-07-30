/**
 * Known-value tests for the keyslot / envelope-encryption core.
 * Mirrors pulse-protocol-go/crypto/keyslot_kv_test.go.
 *
 * These vectors pin the exact byte layout of the v2 keyslot blob and the
 * password/legacy slot-key derivations. The literal constants below MUST stay
 * identical to the Go mirror so the two implementations remain byte-identical.
 *
 * All binary values are lowercase hex. Fast Argon2id parameters (m=256, t=1,
 * p=1) are used so the vectors run quickly; production callers use stronger
 * parameters, which are stored inline in the v2 blob.
 *
 * Fixed inputs:
 *   sub           = "alice"
 *   iss           = "https://kc.example/realms/pulse"
 *   walletId      = "a1b2c3d4"
 *   secret        = utf8("s3cret-device")          (password/PIN bytes)
 *   deviceSecret  = utf8("legacy-device-secret")   (legacy path)
 *   salt (16B)    = 00112233445566778899aabbccddeeff
 *   Kw   (32B)    = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
 *   nonce (12B)   = a0a1a2a3a4a5a6a7a8a9aaab
 *   argon params  = m=256, t=1, p=1
 */

import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../hash.js';
import {
  decodeV2Slot,
  deriveMethodKeyLegacy,
  deriveSlotKeyPassword,
  encodeV2PasswordSlot,
  SLOT_TYPE_PASSWORD,
  unwrapKeyslot,
  wrapKw,
} from '../keyslot.js';

// ── Fixed inputs (identical to keyslot_kv_test.go) ────────────────────────────
const SUB = 'alice';
const ISS = 'https://kc.example/realms/pulse';
const WALLET_ID = 'a1b2c3d4';
const SECRET = new TextEncoder().encode('s3cret-device');
const DEVICE_SECRET = new TextEncoder().encode('legacy-device-secret');

const SALT = fromHex('00112233445566778899aabbccddeeff');
const KW = fromHex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
const NONCE = fromHex('a0a1a2a3a4a5a6a7a8a9aaab');
const ARGON = { m: 256, t: 1, p: 1 };

// ── Known values (identical to keyslot_kv_test.go) ────────────────────────────
const PASSWORD_SLOT_KEY_HEX = 'e0a526a8299e7df426fabbeccbe3fa17ef482aba7f3fc0a231ff5a6f8d9b0247';
const V2_BLOB_HEX =
  'b00201001900112233445566778899aabbccddeeff000001000000000101a0a1a2a3a4a5a6a7a8a9aaab65bf91c7fa0f86398a4e61909ea42e20478f3a1a086e3d1636c53868700f30665c239f1fc76c3d75b6ea91a55820bca0';
const LEGACY_SLOT_KEY_HEX = 'ddb43fa7829150cb319f0a7bc489ae4885febf2b0ee370481744d98af8e6d439';
const LEGACY_BLOB_HEX =
  '00112233445566778899aabbccddeeffa0a1a2a3a4a5a6a7a8a9aaab5562f8f2f2578021a58374164a0109078064d8ea858cd0aa1753ac8dfae81af944764bda3015c8c646c56f8c3d3d853e';

describe('Keyslot — known values (mirrors pulse-protocol-go/crypto/keyslot_kv_test.go)', () => {
  it('password/argon2 slot key matches the Go reference', () => {
    const slotKey = deriveSlotKeyPassword(SUB, ISS, WALLET_ID, SECRET, SALT, ARGON);
    expect(toHex(slotKey)).toBe(PASSWORD_SLOT_KEY_HEX);
  });

  it('full v2 blob is byte-identical to the Go reference', () => {
    const slotKey = deriveSlotKeyPassword(SUB, ISS, WALLET_ID, SECRET, SALT, ARGON);
    const ct = wrapKw(KW, slotKey, NONCE);
    expect(ct.length).toBe(48);
    const blob = encodeV2PasswordSlot(SLOT_TYPE_PASSWORD, SALT, NONCE, ct, ARGON);
    expect(toHex(blob)).toBe(V2_BLOB_HEX);
  });

  it('decodes the v2 blob into its parts', () => {
    const decoded = decodeV2Slot(fromHex(V2_BLOB_HEX));
    if (decoded === null) {
      throw new Error('expected v2 blob to decode');
    }
    expect(decoded.slotType).toBe(SLOT_TYPE_PASSWORD);
    expect(toHex(decoded.nonce)).toBe(toHex(NONCE));
    expect(decoded.ct.length).toBe(48);
    expect(decoded.params.length).toBe(25);
  });

  it('unwrapKeyslot recovers Kw via the v2 password path', () => {
    const recovered = unwrapKeyslot(fromHex(V2_BLOB_HEX), {
      password: { sub: SUB, iss: ISS, walletId: WALLET_ID, secret: SECRET },
    });
    expect(toHex(recovered)).toBe(toHex(KW));
  });

  it('legacy slot key matches the Go reference', () => {
    const slotKey = deriveMethodKeyLegacy(SUB, ISS, DEVICE_SECRET, SALT, ARGON);
    expect(toHex(slotKey)).toBe(LEGACY_SLOT_KEY_HEX);
  });

  it('legacy blob is byte-identical to the Go reference', () => {
    const slotKey = deriveMethodKeyLegacy(SUB, ISS, DEVICE_SECRET, SALT, ARGON);
    const ct = wrapKw(KW, slotKey, NONCE);
    const blob = new Uint8Array([...SALT, ...NONCE, ...ct]);
    expect(toHex(blob)).toBe(LEGACY_BLOB_HEX);
  });

  it('unwrapKeyslot recovers Kw via the legacy path', () => {
    const recovered = unwrapKeyslot(fromHex(LEGACY_BLOB_HEX), {
      legacy: { sub: SUB, iss: ISS, deviceSecret: DEVICE_SECRET, params: ARGON },
    });
    expect(toHex(recovered)).toBe(toHex(KW));
  });
});
