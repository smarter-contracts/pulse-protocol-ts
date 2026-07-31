/**
 * Dispatch-robustness and header-authentication (AAD) tests for the keyslot
 * core. Mirrors pulse-protocol-go/crypto/keyslot_dispatch_test.go.
 *
 * These are behavioural tests (not cross-language known-answer vectors), but the
 * same scenarios and fixed inputs are used in both languages.
 */

import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../hash.js';
import {
  type ArgonParams,
  decodeV2Slot,
  deriveMethodKeyLegacy,
  deriveSlotKeyPassword,
  encodeV2PasswordSlot,
  KEYSLOT_MAGIC,
  MAX_ARGON_M,
  MAX_ARGON_P,
  MAX_ARGON_T,
  MIN_ARGON_M,
  MIN_ARGON_P,
  MIN_ARGON_T,
  SALT_SIZE,
  SLOT_TYPE_PASSWORD,
  unwrapKeyslot,
  wrapKw,
} from '../keyslot.js';

const ARGON = { m: 256, t: 1, p: 1 };
const SUB = 'alice';
const ISS = 'https://kc.example/realms/pulse';

/** Wrap kw under a legacy slot key and lay out [16B salt][12B nonce][48B ct]. */
function buildLegacyBlob(
  deviceSecret: Uint8Array,
  salt: Uint8Array,
  nonce: Uint8Array,
  kw: Uint8Array,
): Uint8Array {
  const slotKey = deriveMethodKeyLegacy(SUB, ISS, deviceSecret, salt, ARGON);
  const ct = wrapKw(kw, slotKey, nonce);
  return new Uint8Array([...salt, ...nonce, ...ct]);
}

describe('Keyslot dispatch — robustness and AAD (mirrors keyslot_dispatch_test.go)', () => {
  it('decodes a legacy blob whose salt starts with the v2 magic byte (0xB0)', () => {
    const deviceSecret = new TextEncoder().encode('legacy-device-secret');
    const kw = fromHex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
    const nonce = fromHex('a0a1a2a3a4a5a6a7a8a9aaab');
    // Deterministic salt whose first byte is the v2 magic 0xB0.
    const salt = fromHex('b0112233445566778899aabbccddeeff');
    expect(salt[0]).toBe(KEYSLOT_MAGIC);

    const blob = buildLegacyBlob(deviceSecret, salt, nonce, kw);
    expect(blob[0]).toBe(KEYSLOT_MAGIC);

    const recovered = unwrapKeyslot(blob, {
      legacy: { sub: SUB, iss: ISS, deviceSecret, params: ARGON },
    });
    expect(toHex(recovered)).toBe(toHex(kw));
  });

  it('decodes a legacy blob whose salt starts with magic AND version (0xB0 0x02)', () => {
    const deviceSecret = new TextEncoder().encode('legacy-device-secret');
    const kw = fromHex('1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30');
    const nonce = fromHex('b0b1b2b3b4b5b6b7b8b9babb');
    // magic + version both match, so v2 parsing does not bail at the version check.
    const salt = fromHex('b00201ff445566778899aabbccddeeff');

    const blob = buildLegacyBlob(deviceSecret, salt, nonce, kw);
    // Supply BOTH methods; the correct legacy result must still be returned.
    const recovered = unwrapKeyslot(blob, {
      password: {
        sub: SUB,
        iss: ISS,
        walletId: 'a1b2c3d4',
        secret: new TextEncoder().encode('s3cret-device'),
      },
      legacy: { sub: SUB, iss: ISS, deviceSecret, params: ARGON },
    });
    expect(toHex(recovered)).toBe(toHex(kw));
  });

  it('errors on a genuinely malformed blob (neither valid v2 nor legacy)', () => {
    const password = {
      sub: SUB,
      iss: ISS,
      walletId: 'w',
      secret: new TextEncoder().encode('s'),
    };
    const legacy = {
      sub: SUB,
      iss: ISS,
      deviceSecret: new TextEncoder().encode('d'),
      params: ARGON,
    };
    const malformed: Uint8Array[] = [
      new Uint8Array([KEYSLOT_MAGIC, 0xff]),
      new Uint8Array([0x00, 0x01, 0x02]),
      new Uint8Array([KEYSLOT_MAGIC, 0x02, SLOT_TYPE_PASSWORD, 0x00, 0x19, 0x00]),
      new Uint8Array([]),
    ];
    for (const blob of malformed) {
      expect(() => unwrapKeyslot(blob, { password, legacy })).toThrow();
    }
  });

  it('v2 header tampering (salt / argon param) fails authentication', () => {
    const secret = new TextEncoder().encode('s3cret-device');
    const salt = fromHex('00112233445566778899aabbccddeeff');
    const kw = fromHex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
    const nonce = fromHex('a0a1a2a3a4a5a6a7a8a9aaab');

    const slotKey = deriveSlotKeyPassword(SUB, ISS, 'a1b2c3d4', secret, salt, ARGON);
    const blob = encodeV2PasswordSlot(SLOT_TYPE_PASSWORD, kw, slotKey, salt, nonce, ARGON);
    const password = { sub: SUB, iss: ISS, walletId: 'a1b2c3d4', secret };

    // Untampered blob unwraps correctly.
    expect(toHex(unwrapKeyslot(blob, { password }))).toBe(toHex(kw));

    // Flip a salt byte (index 5, first salt byte).
    const tamperedSalt = new Uint8Array(blob);
    tamperedSalt[5] = (tamperedSalt[5] ?? 0) ^ 0x01;
    expect(() => unwrapKeyslot(tamperedSalt, { password })).toThrow();

    // Flip an argon 'm' param byte (index 5 + SALT_SIZE).
    const tamperedParam = new Uint8Array(blob);
    tamperedParam[5 + SALT_SIZE] = (tamperedParam[5 + SALT_SIZE] ?? 0) ^ 0x01;
    expect(() => unwrapKeyslot(tamperedParam, { password })).toThrow();
  });

  it('v2 AAD binds the header independently of the key (slotType flip)', async () => {
    const { gcm } = await import('@noble/ciphers/aes');
    const secret = new TextEncoder().encode('s3cret-device');
    const salt = fromHex('00112233445566778899aabbccddeeff');
    const kw = fromHex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
    const nonce = fromHex('a0a1a2a3a4a5a6a7a8a9aaab');

    const slotKey = deriveSlotKeyPassword(SUB, ISS, 'a1b2c3d4', secret, salt, ARGON);
    const blob = encodeV2PasswordSlot(SLOT_TYPE_PASSWORD, kw, slotKey, salt, nonce, ARGON);

    const decoded = decodeV2Slot(blob);
    if (decoded === null) {
      throw new Error('expected v2 blob to decode');
    }
    const realAad = blob.subarray(0, 5 + decoded.params.length);

    // Correct AAD opens.
    expect(toHex(gcm(slotKey, decoded.nonce, realAad).decrypt(decoded.ct))).toBe(toHex(kw));

    // Tamper only the slotType byte of the AAD (does not affect slotKey). Open
    // with the SAME correct key + nonce must fail purely because the AAD differs.
    const tamperedAad = new Uint8Array(realAad);
    tamperedAad[2] = (tamperedAad[2] ?? 0) ^ 0xff;
    expect(() => gcm(slotKey, decoded.nonce, tamperedAad).decrypt(decoded.ct)).toThrow();
  });

  /**
   * Overwrite the m/t/p bytes of an encoded v2 password blob in place. The
   * encoder rejects out-of-range parameters, so hostile blobs have to be forged
   * by patching the bytes of a validly-encoded one — exactly what an attacker
   * with write access to the stored blob can do.
   */
  function patchV2ArgonParams(blob: Uint8Array, argon: ArgonParams): Uint8Array {
    const patched = new Uint8Array(blob);
    const base = 5 + SALT_SIZE;
    const view = new DataView(patched.buffer, patched.byteOffset, patched.byteLength);
    view.setUint32(base, argon.m, false); // big-endian
    view.setUint32(base + 4, argon.t, false);
    patched[base + 8] = argon.p & 0xff;
    return patched;
  }

  /**
   * Regression test for the denial-of-service in the v2 password path: the
   * Argon2id parameters live in the blob header, which is the AEAD's additional
   * authenticated data, so they must be read — and the key derived — BEFORE the
   * tag can authenticate them. A single flipped byte in the big-endian 'm' field
   * turns m=256 KiB into ~16 GiB and the process dies out of memory.
   * Out-of-range parameters must be rejected at decode time, before any
   * derivation is attempted.
   */
  it('rejects out-of-range argon params in a v2 blob before deriving', () => {
    const secret = new TextEncoder().encode('s3cret-device');
    const salt = fromHex('00112233445566778899aabbccddeeff');
    const kw = fromHex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
    const nonce = fromHex('a0a1a2a3a4a5a6a7a8a9aaab');

    const slotKey = deriveSlotKeyPassword(SUB, ISS, 'a1b2c3d4', secret, salt, ARGON);
    const blob = encodeV2PasswordSlot(SLOT_TYPE_PASSWORD, kw, slotKey, salt, nonce, ARGON);
    const password = { sub: SUB, iss: ISS, walletId: 'a1b2c3d4', secret };

    // Untouched blob still unwraps.
    expect(toHex(unwrapKeyslot(blob, { password }))).toBe(toHex(kw));

    const hostile: Array<[string, ArgonParams]> = [
      // The exact CI out-of-memory case: flipping the MSB of m (blob byte 21)
      // turns 256 KiB into ~16 GiB.
      ['m flipped MSB (~16 GiB)', { ...ARGON, m: ARGON.m ^ (1 << 24) }],
      ['m just above cap', { ...ARGON, m: MAX_ARGON_M + 1 }],
      ['m at uint32 max', { ...ARGON, m: 0xffffffff }],
      ['m below minimum', { ...ARGON, m: MIN_ARGON_M - 1 }],
      ['m below 8*p', { ...ARGON, m: 8, p: 2 }],
      ['t zero', { ...ARGON, t: 0 }],
      ['t above cap', { ...ARGON, t: MAX_ARGON_T + 1 }],
      ['p zero', { ...ARGON, p: 0 }],
      ['p above cap', { ...ARGON, p: MAX_ARGON_P + 1 }],
    ];

    for (const [name, argon] of hostile) {
      const patched = patchV2ArgonParams(blob, argon);
      const start = Date.now();
      expect(() => unwrapKeyslot(patched, { password }), name).toThrow(
        /argon2 parameters out of range/,
      );
      // Rejection happens before derivation, so it must be near-instant.
      expect(Date.now() - start, name).toBeLessThan(2000);
    }
  });

  /**
   * Pin the production Argon2id parameters (pulse-user-proxy ARGON2_PARAMS) and
   * the bound edges as valid, so the DoS bounds can never be tightened into a
   * compatibility break.
   */
  it('accepts the production argon params and the bound edges', () => {
    const secret = new TextEncoder().encode('s3cret-device');
    const salt = fromHex('00112233445566778899aabbccddeeff');
    const kw = fromHex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
    const nonce = fromHex('a0a1a2a3a4a5a6a7a8a9aaab');
    const slotKey = deriveSlotKeyPassword(SUB, ISS, 'a1b2c3d4', secret, salt, ARGON);

    const accepted: ArgonParams[] = [
      { m: 65536, t: 3, p: 1 }, // production defaults
      ARGON, // fast test params
      { m: MIN_ARGON_M, t: MIN_ARGON_T, p: MIN_ARGON_P },
      { m: MAX_ARGON_M, t: MAX_ARGON_T, p: MAX_ARGON_P },
    ];
    for (const argon of accepted) {
      // Encoding never derives, so even the maximum params are cheap here; a
      // successful encode proves the shared bounds accept them.
      expect(() =>
        encodeV2PasswordSlot(SLOT_TYPE_PASSWORD, kw, slotKey, salt, nonce, argon),
      ).not.toThrow();
    }

    // Full round trip under the production parameters, proving the decoder
    // accepts what the service actually writes.
    const prod = { m: 65536, t: 3, p: 1 };
    const prodKey = deriveSlotKeyPassword(SUB, ISS, 'a1b2c3d4', secret, salt, prod);
    const prodBlob = encodeV2PasswordSlot(SLOT_TYPE_PASSWORD, kw, prodKey, salt, nonce, prod);
    const recovered = unwrapKeyslot(prodBlob, {
      password: { sub: SUB, iss: ISS, walletId: 'a1b2c3d4', secret },
    });
    expect(toHex(recovered)).toBe(toHex(kw));
  }, 30_000);
});
