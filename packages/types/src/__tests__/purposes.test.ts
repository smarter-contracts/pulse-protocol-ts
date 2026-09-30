/**
 * Pins the PulsePurpose numeric values and their AAD strings.
 *
 * Both are wire-significant: the number is a BIP32 path component and the string
 * is bound into AES-GCM additional data, so a drift from Go would make records
 * produced by one library undecryptable by the other.
 *
 * Mirrors pulse-protocol-go/crypto/purposes/purpose_test.go — keep the tables in sync.
 */

import { describe, expect, it } from 'vitest';
import { PulsePurpose, purposeString } from '../purposes.js';

describe('PulsePurpose values', () => {
  it.each([
    ['SignTx', PulsePurpose.SignTx, 1],
    ['EncryptConsentNotaryBlock', PulsePurpose.EncryptConsentNotaryBlock, 2],
    ['EncryptConsentStructure', PulsePurpose.EncryptConsentStructure, 3],
    ['EncryptRevokeNotaryBlock', PulsePurpose.EncryptRevokeNotaryBlock, 4],
    ['EncryptRevokeStructure', PulsePurpose.EncryptRevokeStructure, 5],
    ['SymmetricConsent', PulsePurpose.SymmetricConsent, 6],
    ['SymmetricRevoke', PulsePurpose.SymmetricRevoke, 7],
    ['SymmetricUpdate', PulsePurpose.SymmetricUpdate, 8],
    ['PQDeriveConsent', PulsePurpose.PQDeriveConsent, 9],
    ['PQDeriveRevoke', PulsePurpose.PQDeriveRevoke, 10],
    ['SymmetricKeyWrap', PulsePurpose.SymmetricKeyWrap, 255],
  ])('%s is %d', (_name, purpose, want) => {
    expect(purpose).toBe(want);
  });
});

describe('purposeString', () => {
  it.each([
    [PulsePurpose.SignTx, 'signtx'],
    [PulsePurpose.EncryptConsentNotaryBlock, 'encrypt-consent-notary-block'],
    [PulsePurpose.EncryptConsentStructure, 'consent'],
    [PulsePurpose.EncryptRevokeNotaryBlock, 'encrypt-revoke-notary-block'],
    [PulsePurpose.EncryptRevokeStructure, 'revoke'],
    [PulsePurpose.PQDeriveConsent, 'pq-derive-consent'],
    [PulsePurpose.PQDeriveRevoke, 'pq-derive-revoke'],
    [PulsePurpose.SymmetricConsent, 'consent'],
    [PulsePurpose.SymmetricRevoke, 'revoke'],
    [PulsePurpose.SymmetricUpdate, 'update'],
    [PulsePurpose.SymmetricKeyWrap, 'keywrap'],
  ])('purpose %d is %s', (purpose, want) => {
    expect(purposeString(purpose)).toBe(want);
  });

  it('shares an AAD string between the HD and symmetric consent/revoke purposes', () => {
    // Go maps both families to the same label; the AAD must match across them.
    expect(purposeString(PulsePurpose.EncryptConsentStructure)).toBe(
      purposeString(PulsePurpose.SymmetricConsent),
    );
    expect(purposeString(PulsePurpose.EncryptRevokeStructure)).toBe(
      purposeString(PulsePurpose.SymmetricRevoke),
    );
  });

  it.each([
    // 0 is Go's PulseNoSymmetricPurpose, which has no label and no TS enum member.
    [0, 'unknown-0'],
    [999, 'unknown-999'],
  ])('labels unrecognised purpose %d as %s, as Go does', (purpose, want) => {
    expect(purposeString(purpose as PulsePurpose)).toBe(want);
  });
});
