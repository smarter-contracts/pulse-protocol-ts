// Type shim for the `@pulse-protocol/crypto/keyslot` subpath export.
//
// The package's `exports` map routes `@pulse-protocol/crypto/keyslot` to
// `dist/keyslot.{js,cjs}` at runtime, but TypeScript's classic ("node10")
// module resolution — used by consumers such as pulse-user-proxy — does not
// read the `exports` field. This root-level declaration file is where classic
// resolution looks for `@pulse-protocol/crypto/keyslot`, and it simply
// re-exports the built keyslot type declarations.
export * from './dist/keyslot';
