/**
 * PulsePurpose identifies the intended use of a derived key or encryption operation.
 * Values mirror pulse-protocol-go/crypto/purposes/purpose.go.
 */
export enum PulsePurpose {
  SignTx = 1,
  EncryptConsentNotaryBlock = 2,
  EncryptConsentStructure = 3,
  EncryptRevokeNotaryBlock = 4,
  EncryptRevokeStructure = 5,
  SymmetricConsent = 6,
  SymmetricRevoke = 7,
  SymmetricUpdate = 8,
  PQDeriveConsent = 9,
  PQDeriveRevoke = 10,
  SymmetricKeyWrap = 255,
}

/**
 * Returns the AAD purpose string for a given PulsePurpose.
 * Mirrors PulsePurpose.String() in the Go reference implementation.
 */
export function purposeString(p: PulsePurpose): string {
  switch (p) {
    case PulsePurpose.SignTx:
      return 'signtx'
    case PulsePurpose.EncryptConsentNotaryBlock:
      return 'encrypt-consent-notary-block'
    case PulsePurpose.EncryptConsentStructure:
      return 'consent'
    case PulsePurpose.EncryptRevokeNotaryBlock:
      return 'encrypt-revoke-notary-block'
    case PulsePurpose.EncryptRevokeStructure:
      return 'revoke'
    case PulsePurpose.PQDeriveConsent:
      return 'pq-derive-consent'
    case PulsePurpose.PQDeriveRevoke:
      return 'pq-derive-revoke'
    case PulsePurpose.SymmetricConsent:
      return 'consent'
    case PulsePurpose.SymmetricRevoke:
      return 'revoke'
    case PulsePurpose.SymmetricUpdate:
      return 'update'
    case PulsePurpose.SymmetricKeyWrap:
      return 'keywrap'
    default:
      return `unknown-${p}`
  }
}
