---
"@pulse-protocol/crypto": minor
---

Add an asynchronous keyslot unwrap entry point, and export the Argon2id parameter bounds check

Argon2id is memory-hard by design, so on a server `unwrapKeyslot` stops the event loop for the whole derivation and the process answers nothing meanwhile — including its own health check. That is what got a `pulse-user-proxy` pod killed by a Kubernetes liveness probe mid-`POST /wallet/init` (mid-tier #1167). These two additions let a caller move the derivation, and only the derivation, somewhere else.

**Added**

- `unwrapKeyslotAsync(blob, methods, derive)` — `unwrapKeyslot` with the slot-key derivation delegated to the caller. Every byte-level decision stays in this library: which slot type, the Argon2id parameter bounds, the reconstructed header AAD, the AEAD open, the legacy fallback that keeps a legacy blob whose random salt starts with `0xB0` decryptable, and the combined error text. The parameters are bounded *before* a derivation is scheduled, so a hostile `m` costs a refusal rather than the work.
- `AsyncSlotKeyDeriver` — the derivation hook. Its two members mirror `deriveSlotKeyPassword` and `deriveMethodKeyLegacy` argument for argument, so the obvious implementation forwards to them and a server implementation forwards to them on a worker thread. They must return those functions' bytes exactly; nothing downstream re-checks a slot key, and one wrong byte is simply an authentication-tag failure with no diagnosis.
- `validateArgonParams(params)` — already applied by the encoder and the decoder, now exported so a caller that schedules the derivation elsewhere can apply the *same* bounds before committing resources, instead of keeping a second copy of the limits that is free to drift from the ones the decoder enforces.

**Unchanged**

`unwrapKeyslot` and every other existing export keep their signatures and their output. Internally the two entry points are now four lines each over one shared `UnwrapPlan`, differing only in whether the derivation is awaited. No encoding, parameter, salt handling or derived key changes, nothing in `pulse-protocol-go` changes, and the known-answer vectors are untouched — `__tests__/keyslot-async.test.ts` additionally asserts the two entry points agree (same plaintext, same refusals, same error text) across the whole dispatch matrix.
