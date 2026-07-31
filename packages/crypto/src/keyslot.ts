/**
 * Keyslot / envelope-encryption core.
 *
 * A keyslot wraps the 32-byte wallet key (Kw) under a per-unlock-method key so
 * that the same wallet can be unlocked by several independent authentication
 * methods (password/PIN, device key, WebAuthn PRF, a KMS oracle, ...). Each
 * method has its own keyslot; unlocking any one recovers Kw.
 *
 * Two on-disk encodings are supported:
 *
 *   - v2 (self-describing): a tagged blob that carries a slot type and the
 *     key-derivation parameters inline, so a reader can re-derive the slot key
 *     from the user's secret without any out-of-band configuration.
 *
 *         [1B magic=0xB0][1B version=0x02][1B slotType]
 *         [2B paramLen big-endian][paramLen bytes params]
 *         [12B nonce][ciphertext]
 *
 *     slotType 1 = password/argon2 (2=device-key, 3=webauthn-prf, 4=kms-oracle
 *     are reserved). type-1 params are 25 bytes:
 *
 *         [16B argon salt][4B m big-endian][4B t big-endian][1B p]
 *
 *     ciphertext = AES-256-GCM(plaintext=Kw, key=slotKey, nonce) -> 48 bytes
 *     (32 bytes ciphertext + 16 bytes GCM tag).
 *
 *   - legacy (back-compat, no magic byte): the original fixed layout
 *
 *         [16B salt][12B nonce][48B ciphertext]
 *
 *     Its slot key is derived by deriveMethodKeyLegacy, reproducing the existing
 *     deriveMethodKey formula used by pulse-user-proxy and pulsedrive. The
 *     Argon2id parameters are not stored in the blob, so a reader must supply
 *     them out of band.
 *
 * On read, dispatch is by the leading byte: a blob whose first byte is 0xB0 and
 * that parses as a valid v2 header takes the v2 path (dispatched by slotType);
 * anything else is treated as legacy.
 *
 * This module is the byte-identical mirror of
 * pulse-protocol-go/crypto/keyslot.go.
 */

import { gcm } from '@noble/ciphers/aes';
import { argon2id } from '@noble/hashes/argon2';
import { randomBytes } from '@noble/hashes/utils';

// ─── Constants ──────────────────────────────────────────────────────────────

/** Leading byte of a v2 keyslot blob. */
export const KEYSLOT_MAGIC = 0xb0;
/** Current keyslot format version. */
export const KEYSLOT_VERSION = 0x02;

/** Password / PIN slot: Argon2id-derived slot key. */
export const SLOT_TYPE_PASSWORD = 1;
/** Reserved slot types (not yet implemented). */
export const SLOT_TYPE_DEVICE_KEY = 2;
export const SLOT_TYPE_WEBAUTHN_PRF = 3;
export const SLOT_TYPE_KMS_ORACLE = 4;

const KW_SIZE = 32; // wallet key length
const SALT_SIZE = 16; // Argon2id salt length
const NONCE_SIZE = 12; // AES-256-GCM nonce length
const WRAP_SIZE = 48; // AES-256-GCM(Kw): 32 ciphertext + 16 tag
const PASSWORD_PARAM_LEN = SALT_SIZE + 4 + 4 + 1; // 25

/**
 * Argon2id parameter bounds enforced when decoding a v2 password keyslot.
 *
 * The parameters are stored in the blob header, and that header is the AEAD's
 * additional authenticated data — so they must be read, and the slot key
 * derived, BEFORE the authentication tag can vouch for them. A tampered or
 * hostile blob therefore dictates the cost of a derivation that has not yet been
 * authenticated: flipping the single most-significant byte of the big-endian 'm'
 * field turns 256 KiB into roughly 16 GiB, and the process dies with an
 * out-of-memory fault. Bounding the parameters at decode time, before any
 * derivation is attempted, closes that denial-of-service.
 *
 * The ceilings are generous enough to allow any plausible future hardening of
 * the production parameters (currently m=65536, t=3, p=1) while keeping the
 * worst case a bounded allocation. These values must stay identical to the Go
 * constants in pulse-protocol-go/crypto/keyslot.go.
 */
export const MIN_ARGON_M = 8; // Argon2 itself also requires m >= 8*p
export const MAX_ARGON_M = 2097152; // 2 GiB expressed in KiB
export const MIN_ARGON_T = 1;
export const MAX_ARGON_T = 64;
export const MIN_ARGON_P = 1;
export const MAX_ARGON_P = 16;

/** Argon2id parameters. */
export interface ArgonParams {
  m: number; // memory in KiB
  t: number; // iterations
  p: number; // parallelism
}

/** Unlock a password/argon2 slot. Argon parameters come from the v2 blob. */
export interface PasswordUnlock {
  sub: string;
  iss: string;
  walletId: string;
  secret: Uint8Array; // raw password/PIN bytes (device-secret bytes for the CLI)
}

/**
 * Unlock a legacy slot. Legacy blobs do not store the Argon2id parameters, so
 * the caller must supply the same params used when the blob was written.
 */
export interface LegacyUnlock {
  sub: string;
  iss: string;
  deviceSecret: Uint8Array;
  params: ArgonParams;
}

/** Decoded parts of a v2 keyslot blob. */
export interface DecodedV2Slot {
  slotType: number;
  params: Uint8Array;
  nonce: Uint8Array;
  ct: Uint8Array;
}

// ─── Kw generation and wrapping ─────────────────────────────────────────────

/** Generate a fresh random 32-byte wallet key. */
export function generateKw(): Uint8Array {
  return randomBytes(KW_SIZE);
}

/**
 * Encrypt Kw under slotKey with AES-256-GCM and the supplied nonce, returning
 * the 48-byte ciphertext+tag. No additional authenticated data is used, matching
 * the legacy keyslot scheme.
 */
export function wrapKw(kw: Uint8Array, slotKey: Uint8Array, nonce: Uint8Array): Uint8Array {
  if (kw.length !== KW_SIZE) {
    throw new Error(`Kw must be ${KW_SIZE} bytes, got ${kw.length}`);
  }
  if (nonce.length !== NONCE_SIZE) {
    throw new Error(`nonce must be ${NONCE_SIZE} bytes, got ${nonce.length}`);
  }
  return gcm(slotKey, nonce).encrypt(kw);
}

/** Decrypt a 48-byte wrapped Kw produced by wrapKw. */
export function unwrapKw(wrapped: Uint8Array, slotKey: Uint8Array, nonce: Uint8Array): Uint8Array {
  return gcm(slotKey, nonce).decrypt(wrapped);
}

// ─── Slot-key derivation ────────────────────────────────────────────────────

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * Derive a 32-byte password/argon2 slot key.
 *
 *   slotKey = Argon2id(utf8(sub) || utf8(iss) || utf8(walletId) || secret, salt, m, t, p, 32)
 *
 * The walletId binding ensures a slot key is scoped to a single wallet even when
 * the same identity and secret are reused across wallets.
 */
export function deriveSlotKeyPassword(
  sub: string,
  iss: string,
  walletId: string,
  secret: Uint8Array,
  salt: Uint8Array,
  params: ArgonParams,
): Uint8Array {
  const password = concatBytes(utf8(sub), utf8(iss), utf8(walletId), secret);
  return argon2id(password, salt, { ...params, dkLen: KW_SIZE });
}

/**
 * Reproduce the existing deriveMethodKey formula used by pulse-user-proxy
 * (src/lib/wallet.ts) and pulsedrive (internal/crypto/pod.go):
 *
 *   slotKey = Argon2id(utf8(sub) || utf8(iss) || deviceSecret, salt, m, t, p, 32)
 *
 * Note the absence of a walletId binding — this is the pre-v2 behaviour and must
 * not change.
 */
export function deriveMethodKeyLegacy(
  sub: string,
  iss: string,
  deviceSecret: Uint8Array,
  salt: Uint8Array,
  params: ArgonParams,
): Uint8Array {
  const password = concatBytes(utf8(sub), utf8(iss), deviceSecret);
  return argon2id(password, salt, { ...params, dkLen: KW_SIZE });
}

// ─── v2 blob encode / decode ────────────────────────────────────────────────

/**
 * Assemble the header portion of a v2 password/argon2 keyslot blob — everything
 * before the nonce:
 *
 *     [magic 0xB0][version 0x02][slotType][paramLen 2B BE][params]
 *
 * This header is used verbatim as the AES-GCM additional authenticated data, so
 * the same byte sequence is reproduced by both the encoder and the reader (which
 * slices it back out of the stored blob).
 */
function buildV2PasswordHeader(
  slotType: number,
  salt: Uint8Array,
  params: ArgonParams,
): Uint8Array {
  const paramBlock = new Uint8Array(PASSWORD_PARAM_LEN);
  paramBlock.set(salt.subarray(0, SALT_SIZE), 0);
  const paramView = new DataView(paramBlock.buffer, paramBlock.byteOffset, paramBlock.byteLength);
  paramView.setUint32(SALT_SIZE, params.m, false); // big-endian
  paramView.setUint32(SALT_SIZE + 4, params.t, false);
  paramBlock[SALT_SIZE + 8] = params.p & 0xff;

  const prefix = new Uint8Array(5);
  prefix[0] = KEYSLOT_MAGIC;
  prefix[1] = KEYSLOT_VERSION;
  prefix[2] = slotType & 0xff;
  new DataView(prefix.buffer).setUint16(3, paramBlock.length, false);

  return concatBytes(prefix, paramBlock);
}

/**
 * Seal Kw under slotKey and assemble a full v2 password/argon2 keyslot blob. The
 * header (magic..params) is bound into the ciphertext as AES-GCM additional
 * authenticated data, so slotType, params and salt cannot be swapped without
 * invalidating the authentication tag. Legacy blobs use no AAD and are
 * unaffected.
 */
export function encodeV2PasswordSlot(
  slotType: number,
  kw: Uint8Array,
  slotKey: Uint8Array,
  salt: Uint8Array,
  nonce: Uint8Array,
  params: ArgonParams,
): Uint8Array {
  if (kw.length !== KW_SIZE) {
    throw new Error(`Kw must be ${KW_SIZE} bytes, got ${kw.length}`);
  }
  if (nonce.length !== NONCE_SIZE) {
    throw new Error(`nonce must be ${NONCE_SIZE} bytes, got ${nonce.length}`);
  }
  // Same bounds as the decoder, so a writer can never produce a blob that the
  // reader will refuse. The encoded byte format is unchanged.
  validateArgonParams(params);
  const header = buildV2PasswordHeader(slotType, salt, params);
  const ct = gcm(slotKey, nonce, header).encrypt(kw);
  return concatBytes(header, nonce, ct);
}

/**
 * Parse a v2 keyslot blob into its slot type, raw params, nonce and ciphertext.
 * Validates the magic byte, version and length consistency; does not interpret
 * the params (that is slot-type specific).
 *
 * Returns `null` if the blob is not a v2 blob (wrong magic / too short). Throws
 * if the magic matches but the blob is malformed.
 */
export function decodeV2Slot(blob: Uint8Array): DecodedV2Slot | null {
  if (blob.length < 5 || blob[0] !== KEYSLOT_MAGIC) {
    return null;
  }
  const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const version = view.getUint8(1);
  if (version !== KEYSLOT_VERSION) {
    throw new Error(`malformed v2 keyslot: unexpected version 0x${version.toString(16)}`);
  }
  const slotType = view.getUint8(2);
  const paramLen = view.getUint16(3, false);
  if (blob.length < 5 + paramLen + NONCE_SIZE) {
    throw new Error(`malformed v2 keyslot: truncated (${blob.length} bytes)`);
  }
  const params = blob.subarray(5, 5 + paramLen);
  const nonce = blob.subarray(5 + paramLen, 5 + paramLen + NONCE_SIZE);
  const ct = blob.subarray(5 + paramLen + NONCE_SIZE);
  if (ct.length === 0) {
    throw new Error('malformed v2 keyslot: empty ciphertext');
  }
  return { slotType, params, nonce, ct };
}

/**
 * Bound the Argon2id cost parameters read out of a keyslot blob. See the
 * MIN_ARGON_M..MAX_ARGON_P block for why this must happen before any derivation:
 * the parameters are attacker-controllable until the AEAD tag has been checked,
 * and the tag cannot be checked without first deriving the key.
 */
function validateArgonParams({ m, t, p }: ArgonParams): void {
  // Decoded parameters are always integers; this rejects NaN and fractional
  // values from a JavaScript caller, which Go's uint32 typing rules out.
  if (!Number.isInteger(m) || !Number.isInteger(t) || !Number.isInteger(p)) {
    throw new Error(`argon2 parameters out of range: m=${m}, t=${t}, p=${p} must be integers`);
  }
  if (p < MIN_ARGON_P || p > MAX_ARGON_P) {
    throw new Error(
      `argon2 parameters out of range: p=${p} outside [${MIN_ARGON_P},${MAX_ARGON_P}]`,
    );
  }
  if (t < MIN_ARGON_T || t > MAX_ARGON_T) {
    throw new Error(
      `argon2 parameters out of range: t=${t} outside [${MIN_ARGON_T},${MAX_ARGON_T}]`,
    );
  }
  if (m < MIN_ARGON_M || m > MAX_ARGON_M) {
    throw new Error(
      `argon2 parameters out of range: m=${m} outside [${MIN_ARGON_M},${MAX_ARGON_M}]`,
    );
  }
  // Argon2 requires at least 8 KiB of memory per lane.
  if (m < 8 * p) {
    throw new Error(`argon2 parameters out of range: m=${m} is below the required 8*p=${8 * p}`);
  }
}

/**
 * Extract the salt and Argon2id parameters from a type-1 params block, rejecting
 * parameters outside the accepted bounds before the caller can feed them to a
 * derivation.
 */
function decodePasswordParams(params: Uint8Array): { salt: Uint8Array; argon: ArgonParams } {
  if (params.length !== PASSWORD_PARAM_LEN) {
    throw new Error(
      `malformed v2 keyslot: password params must be ${PASSWORD_PARAM_LEN} bytes, got ${params.length}`,
    );
  }
  const salt = params.subarray(0, SALT_SIZE);
  const view = new DataView(params.buffer, params.byteOffset, params.byteLength);
  const m = view.getUint32(SALT_SIZE, false);
  const t = view.getUint32(SALT_SIZE + 4, false);
  const p = view.getUint8(SALT_SIZE + 8);
  const argon = { m, t, p };
  validateArgonParams(argon);
  return { salt, argon };
}

// ─── Dispatch ───────────────────────────────────────────────────────────────

/**
 * Recover Kw from a keyslot blob, dispatching on the encoding.
 *
 * A blob whose first byte is 0xB0 is *attempted* as v2 first. Crucially, if the
 * v2 attempt fails for ANY reason — wrong version, inconsistent paramLen,
 * out-of-range Argon2id parameters, a failed authentication tag, or simply that
 * no v2 unlock method was supplied — the reader falls back to attempting the
 * legacy decode. This is required for
 * correctness: a genuine legacy blob whose random salt happens to start with
 * 0xB0 (roughly 1 in 256) would otherwise be misread as a malformed v2 blob and
 * become undecryptable. An error is surfaced only when BOTH the v2 and legacy
 * attempts fail.
 */
export function unwrapKeyslot(
  blob: Uint8Array,
  methods: { password?: PasswordUnlock; legacy?: LegacyUnlock },
): Uint8Array {
  let v2Error: unknown;
  if (blob.length > 0 && blob[0] === KEYSLOT_MAGIC) {
    try {
      return tryUnwrapV2(blob, methods.password);
    } catch (err) {
      v2Error = err; // fall through to the legacy attempt
    }
  }

  try {
    return unwrapLegacy(blob, methods.legacy);
  } catch (legacyError) {
    if (v2Error !== undefined) {
      throw new Error(
        `keyslot unwrap failed (v2: ${errMsg(v2Error)}; legacy: ${errMsg(legacyError)})`,
      );
    }
    throw legacyError;
  }
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Decode and unwrap a blob via the v2 path, reconstructing the header AAD. */
function tryUnwrapV2(blob: Uint8Array, password?: PasswordUnlock): Uint8Array {
  const decoded = decodeV2Slot(blob);
  if (!decoded) {
    throw new Error('not a v2 keyslot blob');
  }
  // The header (AAD) is everything before the nonce: 5 header bytes + params.
  const aad = blob.subarray(0, 5 + decoded.params.length);
  return unwrapV2(decoded, aad, password);
}

function unwrapV2(decoded: DecodedV2Slot, aad: Uint8Array, password?: PasswordUnlock): Uint8Array {
  switch (decoded.slotType) {
    case SLOT_TYPE_PASSWORD: {
      if (!password) {
        throw new Error('no matching unlock method supplied for keyslot');
      }
      const { salt, argon } = decodePasswordParams(decoded.params);
      const slotKey = deriveSlotKeyPassword(
        password.sub,
        password.iss,
        password.walletId,
        password.secret,
        salt,
        argon,
      );
      return gcm(slotKey, decoded.nonce, aad).decrypt(decoded.ct);
    }
    default:
      throw new Error(`unsupported keyslot slot type ${decoded.slotType}`);
  }
}

function unwrapLegacy(blob: Uint8Array, legacy?: LegacyUnlock): Uint8Array {
  if (!legacy) {
    throw new Error('no matching unlock method supplied for keyslot');
  }
  if (blob.length < SALT_SIZE + NONCE_SIZE + 1) {
    throw new Error(`malformed legacy keyslot blob: ${blob.length} bytes`);
  }
  const salt = blob.subarray(0, SALT_SIZE);
  const nonce = blob.subarray(SALT_SIZE, SALT_SIZE + NONCE_SIZE);
  const ct = blob.subarray(SALT_SIZE + NONCE_SIZE);
  const slotKey = deriveMethodKeyLegacy(
    legacy.sub,
    legacy.iss,
    legacy.deviceSecret,
    salt,
    legacy.params,
  );
  return gcm(slotKey, nonce).decrypt(ct);
}

// Export sizes for callers/tests.
export { KW_SIZE, NONCE_SIZE, PASSWORD_PARAM_LEN, SALT_SIZE, WRAP_SIZE };
