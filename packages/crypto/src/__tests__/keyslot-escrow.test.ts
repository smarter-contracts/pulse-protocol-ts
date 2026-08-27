/**
 * Behaviour tests for the escrow (type-5) keyslot: round-trip, the refusal of
 * any local unwrap, and the decode-time bounds on the params block.
 *
 * Mirrors pulse-protocol-go/crypto/keyslot_escrow_test.go. The escrow slot
 * deliberately reuses the oracle (type-4) wire shape under a new type byte, so
 * these tests also pin the "identical params, different type byte" relationship —
 * a future change that drifted the two encodings apart would break here rather
 * than silently in the field.
 */

import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../hash.js';
import {
  decodeEscrowParams,
  decodeOracleParams,
  decodeV2Slot,
  encodeV2EscrowSlot,
  encodeV2OracleSlot,
  KEYSLOT_MAGIC,
  KEYSLOT_VERSION,
  SLOT_TYPE_ESCROW,
  SLOT_TYPE_ORACLE,
  unwrapKeyslot,
  unwrapKw,
  WRAPPED_SLOT_KEY_SIZE,
  wrapKw,
} from '../keyslot.js';

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

// The oracle known value, so the two decoders can be shown to refuse each
// other's blobs. Identical to keyslot-oracle-kv.test.ts.
const ORACLE_V2_BLOB_HEX =
  'b00204004a000c746965722d33302d32303236b0b1b2b3b4b5b6b7b8b9babbc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeefd0d1d2d3d4d5d6d7d8d9dadb0254d833e779a757cda16d14d15544157eec14d291798b73781b6ab35330b0ed4dec90175647bf639c06d16437823a99';

const PASSWORD = {
  sub: 'x',
  iss: 'y',
  walletId: 'z',
  secret: new TextEncoder().encode('s'),
};

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * Assemble a v2 blob from an arbitrary params block, bypassing the encoders so
 * that malformed params can be presented to the decoders.
 */
function rawV2Blob(slotType: number, params: Uint8Array, nonce: Uint8Array, ct: Uint8Array) {
  const prefix = new Uint8Array(5);
  prefix[0] = KEYSLOT_MAGIC;
  prefix[1] = KEYSLOT_VERSION;
  prefix[2] = slotType;
  new DataView(prefix.buffer).setUint16(3, params.length, false);
  return concat(prefix, params, nonce, ct);
}

/**
 * Build a params block with a caller-chosen keyIdLen prefix, so tests can lie
 * about the length.
 */
function keyIdParams(keyIdLen: number, keyId: string, wrappedSlotKey: Uint8Array): Uint8Array {
  const keyIdBytes = new TextEncoder().encode(keyId);
  const prefix = new Uint8Array(2);
  new DataView(prefix.buffer).setUint16(0, keyIdLen, false);
  return concat(prefix, keyIdBytes, wrappedSlotKey);
}

function escrowBlob(): Uint8Array {
  const ct = wrapKw(KW, SLOT_KEY, OUTER_NONCE);
  return encodeV2EscrowSlot(KEY_ID, WRAPPED_SLOT_KEY, OUTER_NONCE, ct);
}

describe('Escrow keyslot (mirrors pulse-protocol-go/crypto/keyslot_escrow_test.go)', () => {
  it('round-trips keyId, wrappedSlotKey and Kw', () => {
    const blob = escrowBlob();

    const decoded = decodeV2Slot(blob);
    if (decoded === null) {
      throw new Error('expected escrow blob to decode');
    }
    expect(decoded.slotType).toBe(SLOT_TYPE_ESCROW);
    expect(toHex(decoded.nonce)).toBe(toHex(OUTER_NONCE));

    const params = decodeEscrowParams(blob);
    expect(params.keyId).toBe(KEY_ID);
    expect(toHex(params.wrappedSlotKey)).toBe(toHex(WRAPPED_SLOT_KEY));

    // The decoded wrappedSlotKey is a copy: mutating it must not touch the blob.
    // (The fixture's first byte is 0x10, so 0xff is a real change.)
    const before = toHex(blob);
    params.wrappedSlotKey.fill(0xff, 0, 1);
    expect(toHex(params.wrappedSlotKey)).not.toBe(toHex(WRAPPED_SLOT_KEY));
    expect(toHex(blob)).toBe(before);

    expect(toHex(unwrapKw(decoded.ct, SLOT_KEY, decoded.nonce))).toBe(toHex(KW));
  });

  /**
   * An escrow slot holds no locally derivable secret. unwrapKeyslot must say so
   * distinctly from "unsupported slot type" (which would suggest an unrecognised
   * format) and from the oracle refusal (which would send a caller to the wrong
   * plane).
   */
  it('refuses any local unwrap, distinctly from an unknown or oracle slot', () => {
    const blob = escrowBlob();

    expect(() => unwrapKeyslot(blob, { password: PASSWORD })).toThrow(
      /escrow keyslot must be opened via the escrow plane/,
    );
    expect(() => unwrapKeyslot(blob, { password: PASSWORD })).not.toThrow(
      /unsupported keyslot slot type/,
    );
    expect(() => unwrapKeyslot(blob, { password: PASSWORD })).not.toThrow(
      /must be unwrapped via the key oracle/,
    );

    // Same refusal when a legacy method is supplied: the legacy fallthrough must
    // not mask the cause.
    expect(() =>
      unwrapKeyslot(blob, {
        legacy: {
          sub: 'x',
          iss: 'y',
          deviceSecret: new TextEncoder().encode('s'),
          params: { m: 8, t: 1, p: 1 },
        },
      }),
    ).toThrow(/escrow keyslot must be opened via the escrow plane/);
  });

  /**
   * The escrow params are byte-for-byte the oracle params; only the type byte
   * differs. This is the deliberate design (spec: "same wire shape as type 4").
   */
  it('differs from an oracle blob only in the slot-type byte', () => {
    const ct = wrapKw(KW, SLOT_KEY, OUTER_NONCE);
    const escrow = encodeV2EscrowSlot(KEY_ID, WRAPPED_SLOT_KEY, OUTER_NONCE, ct);
    const oracle = encodeV2OracleSlot(KEY_ID, WRAPPED_SLOT_KEY, OUTER_NONCE, ct);

    expect(escrow.length).toBe(oracle.length);
    expect(escrow[2]).toBe(SLOT_TYPE_ESCROW);
    expect(oracle[2]).toBe(SLOT_TYPE_ORACLE);

    const escrowRest = Uint8Array.from(escrow);
    const oracleRest = Uint8Array.from(oracle);
    escrowRest[2] = 0;
    oracleRest[2] = 0;
    expect(toHex(escrowRest)).toBe(toHex(oracleRest));
  });

  /**
   * A type-5 blob is not an oracle slot and vice versa: each decoder must refuse
   * the other's type byte rather than silently accepting a slot governed by a
   * different plane.
   */
  it('each decoder refuses the other slot type', () => {
    expect(() => decodeOracleParams(escrowBlob())).toThrow(/not an oracle slot/);
    expect(() => decodeEscrowParams(fromHex(ORACLE_V2_BLOB_HEX))).toThrow(/not an escrow slot/);
  });

  it('encodeV2EscrowSlot rejects malformed inputs', () => {
    const ct = wrapKw(KW, SLOT_KEY, OUTER_NONCE);
    const oversized = concat(WRAPPED_SLOT_KEY, new Uint8Array(1));

    expect(() => encodeV2EscrowSlot('', WRAPPED_SLOT_KEY, OUTER_NONCE, ct)).toThrow();
    expect(() =>
      encodeV2EscrowSlot('k'.repeat(0x10000), WRAPPED_SLOT_KEY, OUTER_NONCE, ct),
    ).toThrow();
    expect(() => encodeV2EscrowSlot(KEY_ID, new Uint8Array(0), OUTER_NONCE, ct)).toThrow();
    expect(() =>
      encodeV2EscrowSlot(
        KEY_ID,
        WRAPPED_SLOT_KEY.subarray(0, WRAPPED_SLOT_KEY_SIZE - 1),
        OUTER_NONCE,
        ct,
      ),
    ).toThrow();
    expect(() => encodeV2EscrowSlot(KEY_ID, oversized, OUTER_NONCE, ct)).toThrow();
    expect(() =>
      encodeV2EscrowSlot(KEY_ID, WRAPPED_SLOT_KEY, OUTER_NONCE.subarray(0, 11), ct),
    ).toThrow();
    expect(() =>
      encodeV2EscrowSlot(KEY_ID, WRAPPED_SLOT_KEY, OUTER_NONCE, new Uint8Array(0)),
    ).toThrow();
  });

  /**
   * Decode-time bounds. The params block is attacker-controlled (it is read
   * before anything authenticates it), so every length must be validated before
   * use — the same discipline the password slot applies to its Argon2id
   * parameters.
   */
  it('decodeEscrowParams rejects malformed params', () => {
    const ct = new Uint8Array(48).fill(0xaa);
    const keyIdLen = new TextEncoder().encode(KEY_ID).length;

    const cases: Array<[string, Uint8Array]> = [
      ['empty params', new Uint8Array(0)],
      ['params shorter than the length prefix', new Uint8Array(1)],
      ['keyIdLen overruns the params block', keyIdParams(0xffff, KEY_ID, WRAPPED_SLOT_KEY)],
      ['keyIdLen one byte too large', keyIdParams(keyIdLen + 1, KEY_ID, WRAPPED_SLOT_KEY)],
      ['zero-length keyId', keyIdParams(0, '', WRAPPED_SLOT_KEY)],
      ['missing wrappedSlotKey', keyIdParams(keyIdLen, KEY_ID, new Uint8Array(0))],
      [
        'wrappedSlotKey one byte short',
        keyIdParams(keyIdLen, KEY_ID, WRAPPED_SLOT_KEY.subarray(0, WRAPPED_SLOT_KEY_SIZE - 1)),
      ],
      [
        'wrappedSlotKey one byte long',
        keyIdParams(keyIdLen, KEY_ID, concat(WRAPPED_SLOT_KEY, new Uint8Array(1))),
      ],
    ];

    for (const [name, params] of cases) {
      const blob = rawV2Blob(SLOT_TYPE_ESCROW, params, OUTER_NONCE, ct);
      expect(() => decodeEscrowParams(blob), name).toThrow(/malformed v2 keyslot/);
    }
  });

  /**
   * A malformed type-5 blob must still refuse locally rather than being mistaken
   * for a password slot; the refusal must not depend on the params parsing.
   */
  it('refuses local unwrap even when the params are malformed', () => {
    const ct = new Uint8Array(48).fill(0xaa);
    const blob = rawV2Blob(SLOT_TYPE_ESCROW, new Uint8Array([0xff, 0xff]), OUTER_NONCE, ct);
    expect(() => unwrapKeyslot(blob, { password: PASSWORD })).toThrow(
      /escrow keyslot must be opened via the escrow plane/,
    );
  });
});
