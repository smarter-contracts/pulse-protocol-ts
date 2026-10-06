/**
 * Equivalence tests for the asynchronous keyslot unwrap entry point.
 *
 * `unwrapKeyslot` derives the slot key on the calling thread. That is correct
 * but it is also, for a server, a stall: Argon2id is memory-hard by design, so
 * a Node process that unwraps a keyslot on its event loop answers nothing
 * meanwhile — which is how a wallet-init came to race a Kubernetes liveness
 * probe (mid-tier #1167).
 *
 * `unwrapKeyslotAsync` exists so a caller can put JUST the derivation somewhere
 * else — a worker thread, a thread pool, another process — while everything
 * that decides bytes stays exactly where it was. It is an ADDITION: the
 * synchronous entry point is unchanged, still exported, and still what the
 * known-answer vectors pin to pulse-protocol-go.
 *
 * The risk in having two entry points is that they drift, so these tests assert
 * the two agree — same plaintext, same refusals, same error text — across the
 * whole dispatch matrix, including the cases that exist precisely because they
 * are easy to get wrong: the 0xB0-prefixed legacy blob that must fall back, and
 * the out-of-range parameters that must be refused BEFORE any derivation runs.
 */

import { describe, expect, it, vi } from 'vitest';
import { fromHex, toHex } from '../hash.js';
import {
  type ArgonParams,
  type AsyncSlotKeyDeriver,
  deriveMethodKeyLegacy,
  deriveSlotKeyPassword,
  encodeV2EscrowSlot,
  encodeV2OracleSlot,
  encodeV2PasswordSlot,
  KEYSLOT_MAGIC,
  MAX_ARGON_M,
  SLOT_TYPE_PASSWORD,
  unwrapKeyslot,
  unwrapKeyslotAsync,
  WRAPPED_SLOT_KEY_SIZE,
  wrapKw,
} from '../keyslot.js';

const SUB = 'alice';
const ISS = 'https://kc.example/realms/pulse';
const WALLET_ID = 'a1b2c3d4';
const SECRET = new TextEncoder().encode('s3cret-device');
const DEVICE_SECRET = new TextEncoder().encode('legacy-device-secret');
const SALT = fromHex('00112233445566778899aabbccddeeff');
const KW = fromHex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
const NONCE = fromHex('a0a1a2a3a4a5a6a7a8a9aaab');
const ARGON: ArgonParams = { m: 256, t: 1, p: 1 };

/**
 * The deriver a real caller supplies: the same two library functions, reached
 * through a promise. A worker-thread caller substitutes the thread boundary
 * here and nothing else changes.
 */
const deriver: AsyncSlotKeyDeriver = {
  password: (sub, iss, walletId, secret, salt, params) =>
    Promise.resolve(deriveSlotKeyPassword(sub, iss, walletId, secret, salt, params)),
  legacy: (sub, iss, deviceSecret, salt, params) =>
    Promise.resolve(deriveMethodKeyLegacy(sub, iss, deviceSecret, salt, params)),
};

function spyingDeriver(): AsyncSlotKeyDeriver & {
  password: ReturnType<typeof vi.fn>;
  legacy: ReturnType<typeof vi.fn>;
} {
  return {
    password: vi.fn(deriver.password),
    legacy: vi.fn(deriver.legacy),
  } as never;
}

/** The arguments a spy was first called with, or a failure if it never was. */
function firstCall(spy: ReturnType<typeof vi.fn>): unknown[] {
  const call = spy.mock.calls.at(0);
  if (!call) throw new Error('the deriver was never called');
  return call;
}

function v2Blob(salt = SALT, params = ARGON): Uint8Array {
  const slotKey = deriveSlotKeyPassword(SUB, ISS, WALLET_ID, SECRET, salt, params);
  return encodeV2PasswordSlot(SLOT_TYPE_PASSWORD, KW, slotKey, salt, NONCE, params);
}

function legacyBlob(salt = SALT): Uint8Array {
  const slotKey = deriveMethodKeyLegacy(SUB, ISS, DEVICE_SECRET, salt, ARGON);
  const ct = wrapKw(KW, slotKey, NONCE);
  const out = new Uint8Array(salt.length + NONCE.length + ct.length);
  out.set(salt, 0);
  out.set(NONCE, salt.length);
  out.set(ct, salt.length + NONCE.length);
  return out;
}

const PASSWORD = { sub: SUB, iss: ISS, walletId: WALLET_ID, secret: SECRET };
const LEGACY = { sub: SUB, iss: ISS, deviceSecret: DEVICE_SECRET, params: ARGON };

/** Run both entry points over the same input and return what each produced. */
async function both(
  blob: Uint8Array,
  methods: Parameters<typeof unwrapKeyslot>[1],
): Promise<{ sync: string; async: string }> {
  const syncResult = ((): string => {
    try {
      return `ok:${toHex(unwrapKeyslot(blob, methods))}`;
    } catch (err) {
      return `err:${(err as Error).message}`;
    }
  })();

  const asyncResult = await (async (): Promise<string> => {
    try {
      return `ok:${toHex(await unwrapKeyslotAsync(blob, methods, deriver))}`;
    } catch (err) {
      return `err:${(err as Error).message}`;
    }
  })();

  return { sync: syncResult, async: asyncResult };
}

describe('unwrapKeyslotAsync agrees with unwrapKeyslot', () => {
  it('recovers Kw from a v2 password slot', async () => {
    const result = await both(v2Blob(), { password: PASSWORD });
    expect(result.async).toBe(result.sync);
    expect(result.async).toBe(`ok:${toHex(KW)}`);
  });

  it('recovers Kw from a legacy slot', async () => {
    const result = await both(legacyBlob(), { legacy: LEGACY });
    expect(result.async).toBe(result.sync);
    expect(result.async).toBe(`ok:${toHex(KW)}`);
  });

  it('falls back to the legacy decode for a legacy blob whose salt starts with 0xB0', async () => {
    // Roughly one legacy blob in 256 has a salt beginning with the v2 magic
    // byte. Misreading one as a malformed v2 blob would make it permanently
    // undecryptable, so BOTH entry points must attempt v2, fail, and fall back.
    const salt = new Uint8Array(SALT);
    salt[0] = KEYSLOT_MAGIC;
    const blob = legacyBlob(salt);
    expect(blob[0]).toBe(KEYSLOT_MAGIC);

    const result = await both(blob, { password: PASSWORD, legacy: { ...LEGACY } });
    expect(result.async).toBe(result.sync);
    expect(result.async).toBe(`ok:${toHex(KW)}`);
  });

  it('reports the same combined failure when both attempts fail', async () => {
    const wrong = { ...PASSWORD, secret: new TextEncoder().encode('wrong') };
    const result = await both(v2Blob(), { password: wrong, legacy: LEGACY });
    expect(result.async).toBe(result.sync);
    expect(result.async).toMatch(/^err:keyslot unwrap failed \(v2: .*; legacy: .*\)$/);
  });

  it('refuses the same way when no unlock method is supplied', async () => {
    const result = await both(v2Blob(), {});
    expect(result.async).toBe(result.sync);
    expect(result.async).toMatch(/^err:/);
  });

  it('refuses an oracle slot the same way', async () => {
    const blob = encodeV2OracleSlot(
      'oracle-key-1',
      new Uint8Array(WRAPPED_SLOT_KEY_SIZE).fill(7),
      NONCE,
      wrapKw(KW, KW, NONCE),
    );
    const result = await both(blob, { password: PASSWORD });
    expect(result.async).toBe(result.sync);
    expect(result.async).toMatch(/oracle/i);
  });

  it('refuses an escrow slot the same way', async () => {
    const blob = encodeV2EscrowSlot(
      'escrow-key-1',
      new Uint8Array(WRAPPED_SLOT_KEY_SIZE).fill(9),
      NONCE,
      wrapKw(KW, KW, NONCE),
    );
    const result = await both(blob, { password: PASSWORD });
    expect(result.async).toBe(result.sync);
    expect(result.async).toMatch(/escrow/i);
  });
});

describe('unwrapKeyslotAsync derives through the supplied deriver', () => {
  it('hands the deriver exactly the salt and parameters stored in the blob', async () => {
    const params: ArgonParams = { m: 512, t: 2, p: 1 };
    const spy = spyingDeriver();

    const kw = await unwrapKeyslotAsync(v2Blob(SALT, params), { password: PASSWORD }, spy);

    expect(toHex(kw)).toBe(toHex(KW));
    expect(spy.password).toHaveBeenCalledTimes(1);
    const [sub, iss, walletId, secret, salt, gotParams] = firstCall(spy.password);
    expect([sub, iss, walletId]).toEqual([SUB, ISS, WALLET_ID]);
    expect(toHex(secret as Uint8Array)).toBe(toHex(SECRET));
    expect(toHex(salt as Uint8Array)).toBe(toHex(SALT));
    expect(gotParams).toEqual(params);
    expect(spy.legacy).not.toHaveBeenCalled();
  });

  it('uses the legacy deriver, with the caller-supplied parameters, for a legacy blob', async () => {
    const spy = spyingDeriver();

    await unwrapKeyslotAsync(legacyBlob(), { legacy: LEGACY }, spy);

    expect(spy.legacy).toHaveBeenCalledTimes(1);
    expect(firstCall(spy.legacy)[4]).toEqual(ARGON);
    expect(spy.password).not.toHaveBeenCalled();
  });

  it('refuses out-of-range Argon2id parameters WITHOUT calling the deriver', async () => {
    // The parameters live in the blob's header and must be read before the AEAD
    // tag can vouch for them, so until the unwrap succeeds they are
    // attacker-supplied. A hostile `m` must cost a refusal, never a derivation
    // — the whole point of the bound is that the work is not done.
    const blob = v2Blob();
    // Overwrite the header's big-endian `m` field (offset 5 + 16 = 21) with a
    // value above the ceiling.
    const hostile = new Uint8Array(blob);
    new DataView(hostile.buffer, hostile.byteOffset, hostile.byteLength).setUint32(
      21,
      MAX_ARGON_M + 1,
      false,
    );

    const spy = spyingDeriver();
    await expect(unwrapKeyslotAsync(hostile, { password: PASSWORD }, spy)).rejects.toThrow();

    expect(spy.password).not.toHaveBeenCalled();
    expect(spy.legacy).not.toHaveBeenCalled();
  });
});
