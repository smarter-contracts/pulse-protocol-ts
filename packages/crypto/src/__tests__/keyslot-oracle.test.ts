/**
 * Bounds tests for the shared wrapped-slot-key codec, exercised through BOTH
 * slot types that use it: oracle (type-4) and escrow (type-5).
 *
 * Mirrors pulse-protocol-go/crypto/keyslot_oracle_test.go. The codec is written
 * once and parametrised over the type byte, so a bound that holds for one
 * encoder must hold identically for the other — these tests run the same table
 * against both rather than trusting that by inspection.
 */

import { describe, expect, it } from 'vitest';
import { fromHex } from '../hash.js';
import {
  decodeEscrowParams,
  decodeOracleParams,
  encodeV2EscrowSlot,
  encodeV2OracleSlot,
  MAX_V2_PARAM_LEN,
  type OracleParams,
  WRAPPED_SLOT_KEY_SIZE,
  wrapKw,
} from '../keyslot.js';

const WRAPPED_SLOT_KEY = fromHex(
  '101112131415161718191a1b' +
    '202122232425262728292a2b2c2d2e2f' +
    '303132333435363738393a3b3c3d3e3f' +
    '404142434445464748494a4b4c4d4e4f',
);
const OUTER_NONCE = fromHex('505152535455565758595a5b');
const KW = fromHex('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f');
const SLOT_KEY = fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');

const CT = wrapKw(KW, SLOT_KEY, OUTER_NONCE);

/**
 * The header's paramLen field is two bytes, so the whole params block —
 * [2B keyIdLen][keyId][wrappedSlotKey] — must fit in 0xffff bytes. The bound
 * that matters is therefore the TOTAL, not the keyId alone: with a 60-byte
 * wrappedSlotKey a keyId of 65474..65535 bytes is individually under 0xffff yet
 * pushes the total over it, and DataView.setUint16 silently writes the value
 * modulo 2^16 rather than failing.
 */
const KEYID_LEN_SIZE = 2;
const MAX_KEYID_BYTES = MAX_V2_PARAM_LEN - KEYID_LEN_SIZE - WRAPPED_SLOT_KEY_SIZE; // 65473

interface KeyIdSlotEncoder {
  name: string;
  encode: (
    keyId: string,
    wrappedSlotKey: Uint8Array,
    nonce: Uint8Array,
    ct: Uint8Array,
  ) => Uint8Array;
  decode: (blob: Uint8Array) => OracleParams;
}

const ENCODERS: KeyIdSlotEncoder[] = [
  { name: 'oracle', encode: encodeV2OracleSlot, decode: decodeOracleParams },
  { name: 'escrow', encode: encodeV2EscrowSlot, decode: decodeEscrowParams },
];

describe('Shared wrapped-slot-key codec bounds (mirrors pulse-protocol-go/crypto/keyslot_oracle_test.go)', () => {
  /**
   * A keyId at the exact boundary must encode AND decode. This is the test that
   * makes the encoders' documented promise — that a writer can never produce a
   * blob the matching reader refuses — an actually checked claim rather than an
   * assertion in a comment.
   */
  for (const enc of ENCODERS) {
    it(`${enc.name}: accepts the exact param-length boundary and round-trips`, () => {
      const keyId = 'k'.repeat(MAX_KEYID_BYTES);
      const blob = enc.encode(keyId, WRAPPED_SLOT_KEY, OUTER_NONCE, CT);
      const params = enc.decode(blob);
      expect(params.keyId).toBe(keyId);
      expect(params.wrappedSlotKey.length).toBe(WRAPPED_SLOT_KEY_SIZE);
    });

    /**
     * One byte past the boundary the params block no longer fits the 2-byte
     * paramLen field. The encoder must refuse, not emit a blob whose declared
     * paramLen has wrapped modulo 2^16 — such a blob is undecodable, so
     * producing it silently is strictly worse than an error.
     */
    it(`${enc.name}: rejects a params block that overflows the 2-byte paramLen`, () => {
      const cases: Array<[string, string]> = [
        // The regression case: individually under 0xffff, but the total wraps.
        ['one byte past the boundary', 'k'.repeat(MAX_KEYID_BYTES + 1)],
        ['top of the overflow band', 'k'.repeat(0xffff)],
        ['keyId alone exceeds the length prefix', 'k'.repeat(0x10000)],
        // Measured in UTF-8 bytes, not UTF-16 code units: 21825 * 3 = 65475
        // bytes, while .length is only 21825. A naive length check accepts this.
        ['multi-byte UTF-8 keyId over the boundary', '€'.repeat(21825)],
      ];
      for (const [name, keyId] of cases) {
        expect(() => enc.encode(keyId, WRAPPED_SLOT_KEY, OUTER_NONCE, CT), name).toThrow(
          /malformed v2 keyslot/,
        );
      }
    });

    /**
     * A multi-byte keyId that fits once measured in UTF-8 bytes must be accepted
     * and round-trip, so the bound cannot be "fixed" by over-tightening it.
     */
    it(`${enc.name}: accepts a multi-byte UTF-8 keyId within the bound`, () => {
      // 21824 * 3 = 65472 bytes; + 2 + 60 = 65534, one under the limit.
      const keyId = '€'.repeat(21824);
      const params = enc.decode(enc.encode(keyId, WRAPPED_SLOT_KEY, OUTER_NONCE, CT));
      expect(params.keyId).toBe(keyId);
    });
  }

  /**
   * The oracle encoder's basic input validation, mirroring the escrow encoder's.
   * It had no test of its own before the shared codec existed.
   */
  it('oracle: rejects malformed inputs', () => {
    expect(() => encodeV2OracleSlot('', WRAPPED_SLOT_KEY, OUTER_NONCE, CT)).toThrow();
    expect(() =>
      encodeV2OracleSlot('k'.repeat(0x10000), WRAPPED_SLOT_KEY, OUTER_NONCE, CT),
    ).toThrow();
    expect(() => encodeV2OracleSlot('tier-30-2026', new Uint8Array(0), OUTER_NONCE, CT)).toThrow();
    expect(() =>
      encodeV2OracleSlot('tier-30-2026', WRAPPED_SLOT_KEY, OUTER_NONCE.subarray(0, 11), CT),
    ).toThrow();
    expect(() =>
      encodeV2OracleSlot('tier-30-2026', WRAPPED_SLOT_KEY, OUTER_NONCE, new Uint8Array(0)),
    ).toThrow();
  });
});
