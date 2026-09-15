import { describe, expect, it } from 'vitest';
import { LINKAGE_KIND_REAFFIRM } from '../index.js';

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
});
