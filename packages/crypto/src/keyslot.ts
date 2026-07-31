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
/**
 * Acr-gated key-oracle slot (see the oracle helpers below). Its slot key is held
 * only by the pulse-keyslot-oracle service and is never derivable locally, so
 * this slot type has no local unwrap path.
 */
export const SLOT_TYPE_ORACLE = 4;

const KW_SIZE = 32; // wallet key length
const SALT_SIZE = 16; // Argon2id salt length
const NONCE_SIZE = 12; // AES-256-GCM nonce length
const WRAP_SIZE = 48; // AES-256-GCM(Kw): 32 ciphertext + 16 tag
const PASSWORD_PARAM_LEN = SALT_SIZE + 4 + 4 + 1; // 25
const ORACLE_KEYID_LEN_SIZE = 2; // [2B keyIdLen BE] prefix in oracle params
/** Length of a wrappedSlotKey: 12B nonce + 48B AES-256-GCM(slotKey, KEK). */
export const WRAPPED_SLOT_KEY_SIZE = NONCE_SIZE + WRAP_SIZE; // 60

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

/** Decoded contents of an oracle (type-4) keyslot's params. */
export interface OracleParams {
  /** Names the oracle master key and, via the oracle keyring, the minimum acr. */
  keyId: string;
  /** The oracle-wrapped slot key: 12B nonce ++ AES-256-GCM(slotKey, KEK). */
  wrappedSlotKey: Uint8Array;
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

/** Extract the salt and Argon2id parameters from a type-1 params block. */
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
  return { salt, argon: { m, t, p } };
}

// ─── Oracle (type-4) slot ─────────────────────────────────────────────────────

/**
 * Assemble the header of a v2 oracle keyslot blob — everything before the outer
 * nonce:
 *
 *     [magic 0xB0][version 0x02][slotType 0x04][paramLen 2B BE][params]
 *
 * with params = [2B keyIdLen BE][keyId UTF-8][wrappedSlotKey].
 */
function buildV2OracleHeader(keyId: string, wrappedSlotKey: Uint8Array): Uint8Array {
  const keyIdBytes = utf8(keyId);
  const paramBlock = new Uint8Array(
    ORACLE_KEYID_LEN_SIZE + keyIdBytes.length + wrappedSlotKey.length,
  );
  new DataView(paramBlock.buffer).setUint16(0, keyIdBytes.length, false); // big-endian
  paramBlock.set(keyIdBytes, ORACLE_KEYID_LEN_SIZE);
  paramBlock.set(wrappedSlotKey, ORACLE_KEYID_LEN_SIZE + keyIdBytes.length);

  const prefix = new Uint8Array(5);
  prefix[0] = KEYSLOT_MAGIC;
  prefix[1] = KEYSLOT_VERSION;
  prefix[2] = SLOT_TYPE_ORACLE;
  new DataView(prefix.buffer).setUint16(3, paramBlock.length, false);

  return concatBytes(prefix, paramBlock);
}

/**
 * Assemble a full v2 oracle keyslot blob from its parts.
 *
 * keyId and wrappedSlotKey populate the type-4 params. nonce and ct are the outer
 * envelope: ct MUST be AES-256-GCM(plaintext=Kw, key=slotKey, nonce) with NO
 * additional authenticated data — i.e. the output of wrapKw(kw, slotKey, nonce).
 * The oracle body is intentionally not header-bound (mirroring unwrapKw, which
 * takes no AAD): keyId and wrappedSlotKey are independently authenticated when
 * the oracle opens wrappedSlotKey under its KEK, and the outer body is
 * authenticated by its own GCM tag under slotKey.
 *
 * Byte-identical mirror of EncodeV2OracleSlot in
 * pulse-protocol-go/crypto/keyslot_oracle.go.
 */
export function encodeV2OracleSlot(
  keyId: string,
  wrappedSlotKey: Uint8Array,
  nonce: Uint8Array,
  ct: Uint8Array,
): Uint8Array {
  if (keyId.length === 0) {
    throw new Error('malformed v2 keyslot: empty oracle keyId');
  }
  if (wrappedSlotKey.length === 0) {
    throw new Error('malformed v2 keyslot: empty wrappedSlotKey');
  }
  if (nonce.length !== NONCE_SIZE) {
    throw new Error(`nonce must be ${NONCE_SIZE} bytes, got ${nonce.length}`);
  }
  if (ct.length === 0) {
    throw new Error('malformed v2 keyslot: empty ciphertext');
  }
  const header = buildV2OracleHeader(keyId, wrappedSlotKey);
  return concatBytes(header, nonce, ct);
}

/** Parse a type-4 params block into its keyId and wrappedSlotKey. */
function parseOracleParams(params: Uint8Array): OracleParams {
  if (params.length < ORACLE_KEYID_LEN_SIZE) {
    throw new Error(`malformed v2 keyslot: oracle params too short (${params.length} bytes)`);
  }
  const view = new DataView(params.buffer, params.byteOffset, params.byteLength);
  const keyIdLen = view.getUint16(0, false);
  if (params.length < ORACLE_KEYID_LEN_SIZE + keyIdLen) {
    throw new Error('malformed v2 keyslot: oracle keyId truncated');
  }
  const keyIdBytes = params.subarray(ORACLE_KEYID_LEN_SIZE, ORACLE_KEYID_LEN_SIZE + keyIdLen);
  const wrapped = params.subarray(ORACLE_KEYID_LEN_SIZE + keyIdLen);
  if (wrapped.length === 0) {
    throw new Error('malformed v2 keyslot: oracle params missing wrappedSlotKey');
  }
  return {
    keyId: new TextDecoder().decode(keyIdBytes),
    // Copy so callers cannot mutate the source blob through the result.
    wrappedSlotKey: wrapped.slice(),
  };
}

/**
 * Decode a v2 oracle keyslot blob and return the oracle coordinates a client
 * needs to obtain the slot key: the master-key id and the oracle-wrapped slot
 * key. It does NOT (and cannot) recover Kw — the slot key is held only by the
 * oracle. Once a client has obtained slotKey from the oracle it recovers Kw with
 * unwrapKw(ct, slotKey, nonce), where ct and nonce come from the same blob via
 * decodeV2Slot.
 *
 * Byte-identical mirror of DecodeOracleParams in
 * pulse-protocol-go/crypto/keyslot_oracle.go.
 */
export function decodeOracleParams(blob: Uint8Array): OracleParams {
  const decoded = decodeV2Slot(blob);
  if (!decoded) {
    throw new Error('not a v2 keyslot blob');
  }
  if (decoded.slotType !== SLOT_TYPE_ORACLE) {
    throw new Error(`unsupported keyslot slot type ${decoded.slotType}: not an oracle slot`);
  }
  return parseOracleParams(decoded.params);
}

// ─── Dispatch ───────────────────────────────────────────────────────────────

/**
 * Recover Kw from a keyslot blob, dispatching on the encoding.
 *
 * A blob whose first byte is 0xB0 is *attempted* as v2 first. Crucially, if the
 * v2 attempt fails for ANY reason — wrong version, inconsistent paramLen, a
 * failed authentication tag, or simply that no v2 unlock method was supplied —
 * the reader falls back to attempting the legacy decode. This is required for
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
    case SLOT_TYPE_ORACLE:
      // Oracle slots carry no local secret; the slot key lives only in the
      // oracle service. Recognise the slot type but refuse to unwrap locally.
      throw new Error('oracle keyslot must be unwrapped via the key oracle');
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
