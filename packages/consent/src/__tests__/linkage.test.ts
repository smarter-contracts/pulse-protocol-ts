import { describe, expect, expectTypeOf, it } from 'vitest';
import { LINKAGE_KIND_REAFFIRM, type LinkageKind } from '../index.js';

/**
 * Pins the wire value of the reaffirm linkage kind, and its equality with the Go
 * constant consent.LinkageKindReaffirm. The composite encoding that carries it is
 * #670's work — this is a value-only declaration, so pinning the string is what
 * stops the two libraries from disagreeing about its spelling.
 */
describe('linkage kinds', () => {
  it('spells reaffirm exactly as the Go constant does', () => {
    expect(LINKAGE_KIND_REAFFIRM).toBe('reaffirm');
  });

  it('admits only the kinds Go defines', () => {
    // Go's consent.LinkageKind has exactly one member today. Widening this union
    // without a matching Go constant would let TS emit a kind Go cannot read.
    // Checked by `pnpm typecheck`; a no-op at runtime.
    expectTypeOf<LinkageKind>().toEqualTypeOf<'reaffirm'>();
  });
});
