import { describe, expect, it } from 'vitest';
import { pulseHashBytes, pulseHashString, toHex } from '../hash.js';

describe('PulseHash — known values (mirrors pulse-protocol-go/crypto/internal/hash)', () => {
  it('hash of empty byte slice', () => {
    expect(toHex(pulseHashBytes(new Uint8Array(0)))).toBe(
      'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
    );
  });

  it('hash of single zero byte', () => {
    expect(toHex(pulseHashBytes(new Uint8Array([0x00])))).toBe(
      'bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a',
    );
  });

  it('hash of "pulse"', () => {
    expect(toHex(pulseHashBytes(new TextEncoder().encode('pulse')))).toBe(
      '6db1f6525ccc1966e3fc8c06df53e9935e2404e341e61b7bf45d002e1eee6cf9',
    );
  });

  it('PulseHashString("") matches PulseHashBytes(empty)', () => {
    expect(toHex(pulseHashString(''))).toBe(
      'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
    );
  });

  it('PulseHashString("pulse") matches PulseHashBytes("pulse")', () => {
    expect(toHex(pulseHashString('pulse'))).toBe(
      '6db1f6525ccc1966e3fc8c06df53e9935e2404e341e61b7bf45d002e1eee6cf9',
    );
  });

  it('is deterministic', () => {
    const input = new TextEncoder().encode('deterministic test');
    const h1 = toHex(pulseHashBytes(input));
    const h2 = toHex(pulseHashBytes(input));
    expect(h1).toBe(h2);
  });
});
