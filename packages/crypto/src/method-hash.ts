import { pulseHashBytes, toHex } from './hash.js';

/**
 * Returns the keyslot locator for an OIDC identity:
 *
 *   lowercase-hex Keccak-256(utf8(sub) || utf8(iss))
 *
 * Mirrors pulse-protocol-go/crypto.MethodHash (Go is canon) and is pinned by
 * the same known-answer vectors.
 *
 * It is the filename of the legacy `{methodHash}.enc` keyslot and the
 * `methodHash` recorded against a password slot in a v2 wallet manifest, and
 * it is derivable from token claims alone (no device secret), so callers can
 * locate a keyslot before deriving any key. It is a locator, not a secret and
 * not an authenticator: it must never be relied upon to prove who the caller
 * is.
 *
 * The inputs are concatenated with no separator or length prefix, so the
 * sub/iss boundary is not hashed: `computeMethodHash('ab', 'c') ===
 * computeMethodHash('a', 'bc')` by design. This is the established on-pod
 * scheme; changing it would orphan every existing keyslot.
 *
 * Strings are UTF-8 encoded with `TextEncoder`, so byte-identity with Go holds
 * for well-formed strings (any lone UTF-16 surrogate would be replaced with
 * U+FFFD). JSON-decoded token claims are always well-formed.
 */
export function computeMethodHash(sub: string, iss: string): string {
  const encoder = new TextEncoder();
  const subBytes = encoder.encode(sub);
  const issBytes = encoder.encode(iss);
  const combined = new Uint8Array(subBytes.length + issBytes.length);
  combined.set(subBytes, 0);
  combined.set(issBytes, subBytes.length);
  return toHex(pulseHashBytes(combined));
}
