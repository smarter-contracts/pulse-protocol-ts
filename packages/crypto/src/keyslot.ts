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
 *     slotType 1 = password/argon2, 4 = oracle and 5 = escrow (see the oracle
 *     and escrow helpers below); 2=device-key and 3=webauthn-prf are reserved.
 *     type-1 params are 25 bytes:
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
/**
 * Escrow slot (see the escrow helpers below): the same wire shape as the oracle
 * slot under a distinct type byte, opened only by the escrow plane under audited
 * controls. Like the oracle slot it carries no locally derivable secret, so it
 * too has no local unwrap path.
 *
 * The type byte is legibility, NOT enforcement. Which plane may open a slot is
 * decided by the key class of the keyId in the escrow/oracle keyring, never by
 * the slot-type byte in a blob — a blob is attacker-supplied data, and any
 * enforcement that read this byte would be trusting the wrong side of the wire.
 *
 * The type byte is not authenticated, and the confusion is symmetric. Neither
 * slot type binds its header into the body as AEAD additional data (both are
 * sealed by wrapKw, which takes no AAD), and the two share one params encoding —
 * so anyone who can write the stored blob can flip byte 2 in either direction: a
 * type-4 blob relabelled 5 is accepted by decodeEscrowParams, and a type-5 blob
 * relabelled 4 is accepted by decodeOracleParams, the outer body still opening
 * under its original slot key in both cases. This is inherited from the type-4
 * design, not introduced by the escrow slot; what the escrow slot adds is that
 * the forgeable byte now names a *plane*.
 */
export const SLOT_TYPE_ESCROW = 5;

const KW_SIZE = 32; // wallet key length
const SALT_SIZE = 16; // Argon2id salt length
const NONCE_SIZE = 12; // AES-256-GCM nonce length
const WRAP_SIZE = 48; // AES-256-GCM(Kw): 32 ciphertext + 16 tag
const PASSWORD_PARAM_LEN = SALT_SIZE + 4 + 4 + 1; // 25
const ORACLE_KEYID_LEN_SIZE = 2; // [2B keyIdLen BE] prefix in oracle/escrow params
/**
 * The largest params block a v2 header can describe: the header's paramLen field
 * is two bytes wide (see decodeV2Slot). Must stay identical to maxV2ParamLen in
 * pulse-protocol-go/crypto/keyslot_oracle.go.
 */
export const MAX_V2_PARAM_LEN = 0xffff;
/** Length of a wrappedSlotKey: 12B nonce + 48B AES-256-GCM(slotKey, KEK). */
export const WRAPPED_SLOT_KEY_SIZE = NONCE_SIZE + WRAP_SIZE; // 60

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

/** Decoded contents of an oracle (type-4) keyslot's params. */
export interface OracleParams {
  /** Names the oracle master key and, via the oracle keyring, the minimum acr. */
  keyId: string;
  /** The oracle-wrapped slot key: 12B nonce ++ AES-256-GCM(slotKey, KEK). */
  wrappedSlotKey: Uint8Array;
}

/**
 * Decoded contents of an escrow (type-5) keyslot's params.
 *
 * This is an alias of, not a copy of, OracleParams: the two slot types share one
 * params encoding, so a decoded type-4 and a decoded type-5 params block are the
 * same value and neither side needs a conversion. The separate name exists for
 * the same reason the separate type byte does — so call sites read as what they
 * are. Any *behavioural* difference between the planes belongs in the keyring's
 * key class, never in this type.
 */
export type EscrowParams = OracleParams;

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

// ─── Shared wrapped-slot-key codec ────────────────────────────────────────────
//
// The oracle (type-4) and escrow (type-5) slots share one params encoding:
//
//     [2B keyIdLen BE][keyId UTF-8][wrappedSlotKey]
//
// The two types differ only in the header's slot-type byte — deliberately so
// (see the escrow helpers below). The codec is therefore written once and
// parametrised over the type byte, rather than duplicated per slot type, so the
// two encodings cannot drift apart. slotName appears only in error messages.

/**
 * Assemble the header of a v2 wrapped-slot-key keyslot blob — everything before
 * the outer nonce:
 *
 *     [magic 0xB0][version 0x02][slotType][paramLen 2B BE][params]
 *
 * with params = [2B keyIdLen BE][keyId UTF-8][wrappedSlotKey].
 *
 * Callers must have validated the input lengths first (see
 * validateKeyIdSlotInputs); the 16-bit length fields below assume it.
 *
 * Byte-identical mirror of buildV2KeyIDHeader in
 * pulse-protocol-go/crypto/keyslot_oracle.go.
 */
function buildV2KeyIdHeader(
  slotType: number,
  keyId: string,
  wrappedSlotKey: Uint8Array,
): Uint8Array {
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
  prefix[2] = slotType;
  new DataView(prefix.buffer).setUint16(3, paramBlock.length, false);

  return concatBytes(prefix, paramBlock);
}

/**
 * Apply the checks common to both wrapped-slot-key slot types.
 *
 * The binding limit is the size of the WHOLE params block, not the keyId alone.
 * Both the keyIdLen prefix and the header's paramLen field are two bytes wide,
 * and DataView.setUint16 writes a value that does not fit modulo 2^16 rather
 * than failing — so bounding only the keyId leaves a band (65474..65535 bytes,
 * with a 60-byte wrappedSlotKey) where every individual field fits but their
 * total does not, and the encoder emits a blob whose declared paramLen disagrees
 * with its real length. No reader can parse such a blob, so producing one
 * silently is strictly worse than refusing. The bound is derived from the actual
 * total below rather than hardcoded as a keyId ceiling, so it stays correct if a
 * slot type ever carries a wrappedSlotKey of a different size.
 *
 * Lengths are measured in UTF-8 bytes exactly as Go measures them — not UTF-16
 * code units, which would undercount every non-ASCII keyId.
 */
function validateKeyIdSlotInputs(
  slotName: string,
  keyId: string,
  wrappedSlotKey: Uint8Array,
  nonce: Uint8Array,
  ct: Uint8Array,
): void {
  const keyIdBytes = utf8(keyId).length;
  if (keyIdBytes === 0) {
    throw new Error(`malformed v2 keyslot: empty ${slotName} keyId`);
  }
  if (wrappedSlotKey.length === 0) {
    throw new Error('malformed v2 keyslot: empty wrappedSlotKey');
  }
  const paramLen = ORACLE_KEYID_LEN_SIZE + keyIdBytes + wrappedSlotKey.length;
  if (paramLen > MAX_V2_PARAM_LEN) {
    throw new Error(
      `malformed v2 keyslot: ${slotName} params too long (${paramLen} bytes, max ${MAX_V2_PARAM_LEN}: ${keyIdBytes}-byte keyId + ${wrappedSlotKey.length}-byte wrappedSlotKey + ${ORACLE_KEYID_LEN_SIZE}-byte length prefix)`,
    );
  }
  if (nonce.length !== NONCE_SIZE) {
    throw new Error(`nonce must be ${NONCE_SIZE} bytes, got ${nonce.length}`);
  }
  if (ct.length === 0) {
    throw new Error('malformed v2 keyslot: empty ciphertext');
  }
}

/**
 * Assemble a full v2 wrapped-slot-key keyslot blob (oracle or escrow) from its
 * parts, after the shared input validation.
 */
function encodeV2KeyIdSlot(
  slotType: number,
  slotName: string,
  keyId: string,
  wrappedSlotKey: Uint8Array,
  nonce: Uint8Array,
  ct: Uint8Array,
): Uint8Array {
  validateKeyIdSlotInputs(slotName, keyId, wrappedSlotKey, nonce, ct);
  const header = buildV2KeyIdHeader(slotType, keyId, wrappedSlotKey);
  return concatBytes(header, nonce, ct);
}

/**
 * Parse a wrapped-slot-key params block into its keyId and wrappedSlotKey.
 *
 * The params block is read before anything has authenticated it, so every length
 * is validated against the block's actual size before it is used to slice — a
 * declared keyIdLen never drives an allocation. The returned wrappedSlotKey is a
 * copy, so callers cannot mutate the source blob through it.
 *
 * This is the permissive layer: it does not opine on how long a wrappedSlotKey
 * should be. Callers that require the canonical WRAPPED_SLOT_KEY_SIZE enforce it
 * on top (see decodeEscrowParams).
 */
function parseKeyIdParams(slotName: string, params: Uint8Array): OracleParams {
  if (params.length < ORACLE_KEYID_LEN_SIZE) {
    throw new Error(`malformed v2 keyslot: ${slotName} params too short (${params.length} bytes)`);
  }
  const view = new DataView(params.buffer, params.byteOffset, params.byteLength);
  const keyIdLen = view.getUint16(0, false);
  if (params.length < ORACLE_KEYID_LEN_SIZE + keyIdLen) {
    throw new Error(`malformed v2 keyslot: ${slotName} keyId truncated`);
  }
  const keyIdBytes = params.subarray(ORACLE_KEYID_LEN_SIZE, ORACLE_KEYID_LEN_SIZE + keyIdLen);
  const wrapped = params.subarray(ORACLE_KEYID_LEN_SIZE + keyIdLen);
  if (wrapped.length === 0) {
    throw new Error(`malformed v2 keyslot: ${slotName} params missing wrappedSlotKey`);
  }
  return {
    keyId: new TextDecoder().decode(keyIdBytes),
    // Copy so callers cannot mutate the source blob through the result.
    wrappedSlotKey: wrapped.slice(),
  };
}

// ─── Oracle (type-4) slot ─────────────────────────────────────────────────────

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
  return encodeV2KeyIdSlot(SLOT_TYPE_ORACLE, 'oracle', keyId, wrappedSlotKey, nonce, ct);
}

/**
 * Parse a type-4 params block into its keyId and wrappedSlotKey.
 *
 * Note that this does not require wrappedSlotKey to be exactly
 * WRAPPED_SLOT_KEY_SIZE. That leniency is the historical type-4 behaviour and is
 * kept deliberately: type-4 blobs are already deployed, and narrowing what an
 * existing decoder accepts is a compatibility change, not a bug fix. The oracle
 * service applies the exact-length check itself before it will open a
 * wrappedSlotKey. The escrow slot, having no deployed blobs, is strict from the
 * start.
 */
function parseOracleParams(params: Uint8Array): OracleParams {
  return parseKeyIdParams('oracle', params);
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

// ─── Escrow (type-5) slot ─────────────────────────────────────────────────────
//
// An escrow keyslot lets a wallet be opened while its registrant is absent — an
// auto-onboarded wallet has to be able to sign before anyone has claimed it.
// Like the oracle slot its slot key is never held by the client and never on
// disk; unlike the oracle slot it is released by the escrow plane, under a
// service credential and an audited, purpose-bound request rather than a live
// user authentication.
//
// The wire format is deliberately identical to the oracle (type-4) slot — a new
// type byte over the same param layout, not a new encoding — so the codec above
// is shared and the two cannot drift apart. The distinct type byte exists for
// legibility (manifest scans, tooling, the client-facing audit story), never for
// enforcement; see SLOT_TYPE_ESCROW and
// docs/superpowers/specs/2026-08-12-vrs-escrow-custody-design.md ("Two planes").
//
// Byte-identical mirror of pulse-protocol-go/crypto/keyslot_escrow.go.

/**
 * Hold the escrow slot's exact-length rule in one place, so the encoder and the
 * decoder can never disagree about it.
 */
function validateEscrowWrappedSlotKey(wrappedSlotKey: Uint8Array): void {
  if (wrappedSlotKey.length !== WRAPPED_SLOT_KEY_SIZE) {
    throw new Error(
      `malformed v2 keyslot: escrow wrappedSlotKey must be ${WRAPPED_SLOT_KEY_SIZE} bytes, got ${wrappedSlotKey.length}`,
    );
  }
}

/**
 * Assemble a full v2 escrow keyslot blob from its parts.
 *
 * keyId and wrappedSlotKey populate the type-5 params. nonce and ct are the outer
 * envelope: ct MUST be AES-256-GCM(plaintext=Kw, key=slotKey, nonce) with NO
 * additional authenticated data — i.e. the output of wrapKw(kw, slotKey, nonce).
 *
 * wrappedSlotKey must be exactly WRAPPED_SLOT_KEY_SIZE bytes, and the params
 * block as a whole must fit the header's 2-byte paramLen field (see
 * validateKeyIdSlotInputs). Both are the same bounds decodeEscrowParams applies,
 * so every blob this encoder returns decodes — a property asserted in
 * __tests__/keyslot-oracle.test.ts rather than only claimed here.
 *
 * Byte-identical mirror of EncodeV2EscrowSlot in
 * pulse-protocol-go/crypto/keyslot_escrow.go.
 */
export function encodeV2EscrowSlot(
  keyId: string,
  wrappedSlotKey: Uint8Array,
  nonce: Uint8Array,
  ct: Uint8Array,
): Uint8Array {
  validateEscrowWrappedSlotKey(wrappedSlotKey);
  return encodeV2KeyIdSlot(SLOT_TYPE_ESCROW, 'escrow', keyId, wrappedSlotKey, nonce, ct);
}

/**
 * Decode a v2 escrow keyslot blob and return the escrow coordinates a caller
 * needs to obtain the slot key: the master-key id and the escrow-wrapped slot
 * key. It does NOT (and cannot) recover Kw — the slot key is released only by
 * the escrow plane. Once a caller has obtained slotKey it recovers Kw with
 * unwrapKw(ct, slotKey, nonce), where ct and nonce come from the same blob via
 * decodeV2Slot.
 *
 * The params block is attacker-controlled — it is parsed before anything
 * authenticates it — so it is validated exactly rather than leniently: a
 * wrappedSlotKey of any length other than WRAPPED_SLOT_KEY_SIZE, or an empty
 * keyId, is rejected here rather than passed on to the escrow plane. Nothing has
 * ever written a type-5 blob of another shape, so being strict from the start
 * costs no compatibility.
 *
 * Byte-identical mirror of DecodeEscrowParams in
 * pulse-protocol-go/crypto/keyslot_escrow.go.
 */
export function decodeEscrowParams(blob: Uint8Array): EscrowParams {
  const decoded = decodeV2Slot(blob);
  if (!decoded) {
    throw new Error('not a v2 keyslot blob');
  }
  if (decoded.slotType !== SLOT_TYPE_ESCROW) {
    throw new Error(`unsupported keyslot slot type ${decoded.slotType}: not an escrow slot`);
  }
  const params = parseKeyIdParams('escrow', decoded.params);
  if (params.keyId.length === 0) {
    throw new Error('malformed v2 keyslot: empty escrow keyId');
  }
  validateEscrowWrappedSlotKey(params.wrappedSlotKey);
  return params;
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
    case SLOT_TYPE_ORACLE:
      // Oracle slots carry no local secret; the slot key lives only in the
      // oracle service. Recognise the slot type but refuse to unwrap locally.
      throw new Error('oracle keyslot must be unwrapped via the key oracle');
    case SLOT_TYPE_ESCROW:
      // Escrow slots carry no local secret either; the slot key is released only
      // by the escrow plane. Recognise the slot type but refuse to unwrap
      // locally.
      //
      // As with every other v2 error this still lets unwrapKeyslot fall through
      // to the legacy attempt — required for correctness, since a genuine legacy
      // blob's random salt can start with 0xB0 — but the message is carried into
      // the combined error, so a caller can still tell an escrow slot from an
      // unrecognised one. Deliberately distinct from the oracle refusal: the two
      // slot types are opened by different planes holding different key classes.
      throw new Error('escrow keyslot must be opened via the escrow plane');
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
