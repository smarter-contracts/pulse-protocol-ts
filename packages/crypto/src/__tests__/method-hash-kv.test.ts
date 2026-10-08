/**
 * Known-answer tests (KAT) for computeMethodHash.
 * Mirrors pulse-protocol-go/crypto/methodhash_test.go.
 *
 *   computeMethodHash(sub, iss) = lowercase-hex Keccak-256(utf8(sub) || utf8(iss))
 *
 * The literal vectors below MUST stay identical to the Go mirror so the two
 * implementations remain byte-identical. The non-ASCII vector mixes raw
 * precomposed (NFC) UTF-8 literals with an escaped 4-byte emoji; take care
 * that no editor or Unicode normalisation step alters the raw characters, as
 * that would silently change the bytes under test.
 *
 * Provenance: every expected value was computed independently from both
 * pre-existing implementations (pulsedrive's Go ComputeMethodHash and
 * pulse-user-proxy's computeMethodHash) before this canonical function
 * existed, and the two agreed. Keccak-256("") and Keccak-256("abc") are also
 * well-known published values.
 */

import { describe, expect, it } from 'vitest';
import * as indexExports from '../index.js';
import * as keyslotExports from '../keyslot.js';
import { computeMethodHash } from '../method-hash.js';

const vectors: ReadonlyArray<{ name: string; sub: string; iss: string; want: string }> = [
  {
    name: 'normal OIDC identity',
    sub: 'alice',
    iss: 'https://kc.example/realms/pulse',
    want: 'ce6353a0699ea132b50a04551887a87bff043b6dfb811001f73b7938c544ab49',
  },
  {
    name: 'empty sub',
    sub: '',
    iss: 'https://kc.example/realms/pulse',
    want: 'c45ea4937d58745385b1b6a1e99cb71fe5e52c95cfe82001c29d74e4baf89cda',
  },
  {
    name: 'empty iss',
    sub: 'alice',
    iss: '',
    want: '9c0257114eb9399a2985f8e75dad7600c5d89fe3824ffa99ec1c3eb8bf3b0501',
  },
  {
    // Keccak-256 of the empty input — a well-known published value.
    name: 'empty sub and iss',
    sub: '',
    iss: '',
    want: 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
  },
  {
    // Two-byte, three-byte and four-byte UTF-8 sequences; U+1F511 is a
    // surrogate pair in UTF-16, so this exercises the UTF-16 to UTF-8 step.
    name: 'non-ASCII UTF-8',
    sub: 'zöë-東京-\u{1F511}',
    iss: 'https://ïdp.example/réalm',
    want: '3d0ee652d45d71cd0c3cc6288265dc4bc9486df5821a180e4ddc298c27c92781',
  },
  {
    // Keccak-256("abc") — a well-known published value.
    name: 'boundary ambiguity: ab + c',
    sub: 'ab',
    iss: 'c',
    want: '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
  },
  {
    // Deliberately EQUAL to "ab + c": the encoding is a plain concatenation
    // with no length prefix or separator, so the sub/iss boundary is not part
    // of the hash. This is the established on-pod keyslot filename scheme and
    // must not be "fixed" here — changing it would orphan existing keyslots.
    name: 'boundary ambiguity: a + bc',
    sub: 'a',
    iss: 'bc',
    want: '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
  },
];

describe('computeMethodHash — known answers (mirrors pulse-protocol-go/crypto MethodHash)', () => {
  for (const v of vectors) {
    it(v.name, () => {
      expect(computeMethodHash(v.sub, v.iss)).toBe(v.want);
    });
  }

  it('hashes only the concatenation sub||iss, not the boundary', () => {
    expect(computeMethodHash('ab', 'c')).toBe(computeMethodHash('a', 'bc'));
  });

  it('returns 64 lowercase hex characters', () => {
    expect(computeMethodHash('alice', 'https://kc.example/realms/pulse')).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is exported from the package index', () => {
    expect(indexExports.computeMethodHash).toBe(computeMethodHash);
  });

  it('is exported from the keyslot subpath entry', () => {
    // `@pulse-protocol/crypto/keyslot` is the entry consumers such as
    // pulse-user-proxy already use for keyslot primitives; it avoids pulling in
    // the ESM-only post-quantum dependency that the root entry carries.
    expect(keyslotExports.computeMethodHash).toBe(computeMethodHash);
  });
});
