# CLAUDE.md — pulse-protocol-ts

This is the **canonical working copy** of the Pulse Protocol TypeScript cryptographic library. It
is part of the `mid-tier` repository.

The standalone `~/sc_code/pulse-protocol-ts/` repo is a legacy downstream publish target only.
Edit here, not there.

## pnpm workspace structure

This directory is a self-contained pnpm workspace (`pnpm-workspace.yaml` → `packages/*`):

| Package directory | Published name | Purpose |
|-------------------|---------------|---------|
| `packages/types/` | `@pulse-protocol/types` | Shared type definitions, enums, encryption result shapes |
| `packages/crypto/` | `@pulse-protocol/crypto` | HD wallet, ECDH, ML-KEM-768, EIP-191, AES-GCM |
| `packages/ipfs/` | `@pulse-protocol/ipfs` | DAG-CBOR serialisation and CIDv1 computation |
| `packages/consent/` | `@pulse-protocol/consent` | `ConsentStore` interface for persistence backends |

## Common commands

```bash
# From pulse-protocol-ts/ root
pnpm install

pnpm build        # Build all packages
pnpm test         # Run all tests
pnpm test:watch   # Watch mode
pnpm typecheck    # Type-check all packages

pnpm lint         # Biome lint
pnpm lint:fix
pnpm format       # Biome format

pnpm docs         # Generate TypeDoc API docs
pnpm clean        # Remove build artefacts
```

## Byte-identical output requirement

All cryptographic operations must produce **byte-identical output** to the Go reference
implementation in `../pulse-protocol-go/`. If you change serialisation, encryption, or hashing
logic here, the Go implementation must be updated to match, and tests in both must verify identical
output.

## Cryptographic details

- **ML-KEM-768** — post-quantum key encapsulation; uses `@noble/post-quantum`
- **secp256k1 ECDH** — key agreement in HD wallet / consent key derivation
- **EIP-191** — Ethereum-compatible `personal_sign`
- **AES-GCM** — symmetric encryption of consent payloads
- **BIP32 / BIP39** — HD wallet derivation from mnemonics
- **DAG-CBOR + CIDv1** — IPFS content addressing for consent records

## Tooling

- **Biome** for lint and format (not ESLint/Prettier)
- Tests alongside source in `__tests__/` directories or `*.test.ts` files
- Build output in `dist/` per package
