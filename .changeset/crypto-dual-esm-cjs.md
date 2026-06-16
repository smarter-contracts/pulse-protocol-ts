---
"@pulse-protocol/crypto": patch
"@pulse-protocol/types": patch
---

Add dual ESM+CJS output to `crypto` and `types` packages

Both packages now publish a CommonJS bundle (`.cjs`) alongside the existing ES module output, and expose it via the `require` condition in `exports`. The `main` field points to the CJS bundle for legacy consumers.

No API changes — the published functions and types are identical.
