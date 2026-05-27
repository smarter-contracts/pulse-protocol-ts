/**
 * Known-value tests for the NIST ML-KEM-768 HD wallet consent/revoke lifecycle.
 *
 * COMPATIBILITY NOTE — Kyber Round 3 vs NIST ML-KEM-768:
 *   The Go reference implementation (pulse-protocol-go) uses cloudflare/circl
 *   `kem/kyber/kyber768`, which implements CRYSTALS-Kyber Round 3 (pre-NIST).
 *   This TypeScript library uses @noble/post-quantum `ml_kem768`, which
 *   implements NIST ML-KEM-768 (FIPS 203, published August 2024).
 *
 *   The two algorithms differ in the internal K-PKE key generation step:
 *     Kyber R3:   SHA3-512(seed)        → (ρ, σ)
 *     NIST ML-KEM: SHA3-512(seed || K)  → (ρ, σ)  where K=3 for 768 variant
 *
 *   Consequently the ML-KEM-768 public-key fingerprints here DIFFER from
 *   those in pulse-protocol-go/crypto/hdwallet_pq_kv_test.go.
 *
 *   ACTION REQUIRED for cross-language PQ compatibility:
 *   Update pulse-protocol-go to use `circl/kem/mlkem/mlkem768` (NIST ML-KEM)
 *   instead of `circl/kem/kyber/kyber768` (Kyber Round 3).  After updating
 *   the Go known values must be regenerated.
 *
 *   All deterministic EC-based values (HD paths, secp256k1 node keys, notary
 *   sealed data) match the Go reference exactly; only the PQ fingerprints differ.
 *
 * Test parameters (same as EC KV test):
 *   Alice seed (BIP-32 Test Vector 1): 000102030405060708090a0b0c0d0e0f
 *   Bob seed:                          101112131415161718191a1b1c1d1e1f
 *   Notary private key:                aa01020304050607080910111213141516171819202122232425262728293031
 *   contractAddress: "0x0102030405060708091011121314"
 *   chainId:         1
 *   otherParty:      3
 *   consentNumber:   2
 *
 * PQ encryption is non-deterministic (random KEM), so only deterministic
 * derivations are pinned.  Encrypted output and CIDs are verified
 * functionally (round-trip) rather than by known value.
 */

import { PulsePurpose } from '@pulse-protocol/types';
import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../hash.js';
import {
  deriveNode,
  derivePqKeyPair,
  masterKeyFromSeed,
  pqKeyFingerprint,
  pulsePath,
} from '../hdwallet.js';

function h(hex: string): Uint8Array {
  return fromHex(hex);
}

// ── Fixed seeds (same as EC KV test) ────────────────────────────────────────
const aliceSeed = h('000102030405060708090a0b0c0d0e0f');
const bobSeed = h('101112131415161718191a1b1c1d1e1f');
const notarySeed = h('aa01020304050607080910111213141516171819202122232425262728293031');

const contractAddress = '0x0102030405060708091011121314';
const chainId = 1;
const otherParty = 3;
const consentNumber = 2;

describe('HD Wallet — NIST ML-KEM-768 known values', () => {
  describe('HD path format for PQ purposes', () => {
    it('PQ consent key path (purpose 9)', () => {
      expect(pulsePath(otherParty, chainId, consentNumber, PulsePurpose.PQDeriveConsent)).toBe(
        "m/4410704'/3/1/2/9",
      );
    });

    it('PQ revoke key path (purpose 10)', () => {
      expect(pulsePath(otherParty, chainId, consentNumber, PulsePurpose.PQDeriveRevoke)).toBe(
        "m/4410704'/3/1/2/10",
      );
    });
  });

  describe('PQ consent key derivation (purpose 9)', () => {
    it('Alice PQ consent node priv/pub keys', () => {
      const alice = masterKeyFromSeed(aliceSeed);
      const node = deriveNode(
        alice,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.PQDeriveConsent,
      );
      expect(toHex(node.privateKey!)).toBe(
        '7d3607e752508cf9e8e3188ef8db8890f5d7aac618865c9d4a52460f76d32a6b',
      );
      expect(toHex(node.publicKey!)).toBe(
        '02704fab5d7282c0e6719bcc762f2e45d481351741598483900b8e4c429d11e2b3',
      );
    });

    it('Bob PQ consent node priv/pub keys', () => {
      const bob = masterKeyFromSeed(bobSeed);
      const node = deriveNode(
        bob,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.PQDeriveConsent,
      );
      expect(toHex(node.privateKey!)).toBe(
        'af988f9d0ab2f603851d56d20bd0eb3749814dd44bfd2d5d638f900cee0be74b',
      );
      expect(toHex(node.publicKey!)).toBe(
        '03f7a0062f05bc7fc1f9187d80e22b72962195f198955a49ac0e2d86798ffb1db8',
      );
    });

    it('Alice ML-KEM-768 consent public key fingerprint', () => {
      const alice = masterKeyFromSeed(aliceSeed);
      const { publicKey } = derivePqKeyPair(
        alice,
        otherParty,
        consentNumber,
        chainId,
        PulsePurpose.PQDeriveConsent,
      );
      // NIST ML-KEM value — differs from Go Kyber R3: 031ca30b2f9ac61fe6649278258e94e3ec2ec918db0853d19de7579200d26da7
      expect(toHex(pqKeyFingerprint(publicKey))).toBe(
        '339dd3c75c1d9050c74a343b02babd5415bde0eace37a7d0ecc0682d750984d6',
      );
    });

    it('Bob ML-KEM-768 consent public key fingerprint', () => {
      const bob = masterKeyFromSeed(bobSeed);
      const { publicKey } = derivePqKeyPair(
        bob,
        otherParty,
        consentNumber,
        chainId,
        PulsePurpose.PQDeriveConsent,
      );
      // NIST ML-KEM value — differs from Go Kyber R3: 81cea2acf154fda8c30f29f799692b1b3fbb5f1ad9b17420cd48b0985082df45
      expect(toHex(pqKeyFingerprint(publicKey))).toBe(
        '83f0b64c4e38c3c8167f5286b9b079e926c91d15c140bc516bcd70b789e22331',
      );
    });
  });

  describe('PQ revoke key derivation (purpose 10)', () => {
    it('Alice PQ revoke node priv/pub keys', () => {
      const alice = masterKeyFromSeed(aliceSeed);
      const node = deriveNode(
        alice,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.PQDeriveRevoke,
      );
      expect(toHex(node.privateKey!)).toBe(
        '923b9ee0e2e2ef45d8c5b8f91ac02c4be9bf6982d71ab5751c928021abba52af',
      );
      expect(toHex(node.publicKey!)).toBe(
        '03f3bb3680cfaec89a75fd0e99e8a20737e40f644f6c3243a8f058fd92ecc53aa4',
      );
    });

    it('Bob PQ revoke node priv/pub keys', () => {
      const bob = masterKeyFromSeed(bobSeed);
      const node = deriveNode(bob, otherParty, chainId, consentNumber, PulsePurpose.PQDeriveRevoke);
      expect(toHex(node.privateKey!)).toBe(
        '8162d312cd9f751121b09ddd34b3d4f57ba056c73cd9c9d1c83367e3d4372be8',
      );
      expect(toHex(node.publicKey!)).toBe(
        '03f8998a3047c33e613107cfe9d68d142000c25e9e2efeb344ad4319eefb169545',
      );
    });

    it('Alice ML-KEM-768 revoke public key fingerprint', () => {
      const alice = masterKeyFromSeed(aliceSeed);
      const { publicKey } = derivePqKeyPair(
        alice,
        otherParty,
        consentNumber,
        chainId,
        PulsePurpose.PQDeriveRevoke,
      );
      // NIST ML-KEM value — differs from Go Kyber R3: d49540b0dcad70d8988ee1fd6818a33df881505dd79fa880a9a395af48260b20
      expect(toHex(pqKeyFingerprint(publicKey))).toBe(
        'bffe71771b9b84ccec7b2c9cb24ae736a128f25bffed5e197ad56c3c31ded1bc',
      );
    });

    it('Bob ML-KEM-768 revoke public key fingerprint', () => {
      const bob = masterKeyFromSeed(bobSeed);
      const { publicKey } = derivePqKeyPair(
        bob,
        otherParty,
        consentNumber,
        chainId,
        PulsePurpose.PQDeriveRevoke,
      );
      // NIST ML-KEM value — differs from Go Kyber R3: 5c9995e1dbc90b217fcd88b38fb313c3e2f754c376b4b9fd748d1df5ee996854
      expect(toHex(pqKeyFingerprint(publicKey))).toBe(
        '30a4275b6c98c1bd3e4f32db360d224e40cfae3b3ac62be10c1955215dda7512',
      );
    });
  });

  describe('Revoke notary EC encryption (purpose 4)', () => {
    it('revoke notary sealed data matches known value', async () => {
      const { encryptEcdh } = await import('../key-exchange.js');
      const { secp256k1 } = await import('@noble/curves/secp256k1');

      const alice = masterKeyFromSeed(aliceSeed);
      const aliceNode = deriveNode(
        alice,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptRevokeNotaryBlock,
      );
      const notaryPub = secp256k1.getPublicKey(notarySeed, true);

      const revokeNotaryData = new TextEncoder().encode('revoke notary block payload for kv test');
      const result = encryptEcdh(
        revokeNotaryData,
        contractAddress,
        aliceNode.privateKey!,
        notaryPub,
        PulsePurpose.EncryptRevokeNotaryBlock,
        chainId,
        consentNumber,
      );

      expect(toHex(result.sealedData)).toBe(
        'efbddc817f89c54b6cb47afa479bcb7516456053683414762ccc5dd0b44f86d6d9267668cdc9f6ced99973ad147285d41d72941b92bb3f',
      );
    });
  });

  describe('PQ consent encrypt/decrypt round-trip', () => {
    it('Alice encrypts with PQ keys for both parties, both can decrypt', async () => {
      const { encryptPq, decryptPq } = await import('../key-encapsulate.js');

      const alice = masterKeyFromSeed(aliceSeed);
      const bob = masterKeyFromSeed(bobSeed);

      const aliceKem = derivePqKeyPair(
        alice,
        otherParty,
        consentNumber,
        chainId,
        PulsePurpose.PQDeriveConsent,
      );
      const bobKem = derivePqKeyPair(
        bob,
        otherParty,
        consentNumber,
        chainId,
        PulsePurpose.PQDeriveConsent,
      );

      const plaintext = new TextEncoder().encode('pq consent payload for round-trip test');

      const result = encryptPq(
        plaintext,
        contractAddress,
        [aliceKem.publicKey, bobKem.publicKey],
        PulsePurpose.PQDeriveConsent,
        chainId,
        consentNumber,
      );

      expect(result.keys).toHaveLength(2);

      // Alice decrypts
      const decryptedAlice = decryptPq(
        result,
        contractAddress,
        aliceKem.secretKey,
        aliceKem.publicKey,
        PulsePurpose.PQDeriveConsent,
        chainId,
        consentNumber,
      );
      expect(decryptedAlice).toEqual(plaintext);

      // Bob decrypts
      const decryptedBob = decryptPq(
        result,
        contractAddress,
        bobKem.secretKey,
        bobKem.publicKey,
        PulsePurpose.PQDeriveConsent,
        chainId,
        consentNumber,
      );
      expect(decryptedBob).toEqual(plaintext);
    });

    it('Alice encrypts revoke with PQ keys, both can decrypt', async () => {
      const { encryptPq, decryptPq } = await import('../key-encapsulate.js');

      const alice = masterKeyFromSeed(aliceSeed);
      const bob = masterKeyFromSeed(bobSeed);

      const aliceKem = derivePqKeyPair(
        alice,
        otherParty,
        consentNumber,
        chainId,
        PulsePurpose.PQDeriveRevoke,
      );
      const bobKem = derivePqKeyPair(
        bob,
        otherParty,
        consentNumber,
        chainId,
        PulsePurpose.PQDeriveRevoke,
      );

      const plaintext = new TextEncoder().encode('pq revoke payload for round-trip test');

      const result = encryptPq(
        plaintext,
        contractAddress,
        [aliceKem.publicKey, bobKem.publicKey],
        PulsePurpose.PQDeriveRevoke,
        chainId,
        consentNumber,
      );

      expect(result.keys).toHaveLength(2);

      // Alice decrypts
      const decryptedAlice = decryptPq(
        result,
        contractAddress,
        aliceKem.secretKey,
        aliceKem.publicKey,
        PulsePurpose.PQDeriveRevoke,
        chainId,
        consentNumber,
      );
      expect(decryptedAlice).toEqual(plaintext);

      // Bob decrypts
      const decryptedBob = decryptPq(
        result,
        contractAddress,
        bobKem.secretKey,
        bobKem.publicKey,
        PulsePurpose.PQDeriveRevoke,
        chainId,
        consentNumber,
      );
      expect(decryptedBob).toEqual(plaintext);
    });
  });

  describe('PQ revoke signing (functional — CID non-deterministic due to ML-KEM randomness)', () => {
    it('revoke signature verifies against Alice signing address; wrong CID recovers different address', async () => {
      const { getCid, marshalConsentPq, marshalRevokePq } = await import('@pulse-protocol/ipfs');
      const { encryptPq } = await import('../key-encapsulate.js');
      const { signRevoke, getRevokeAddress } = await import('../signing.js');

      // Use the consent CID from the EC KV test as a fixed GrantRef, matching
      // how the mid-tier uses the original consent CID in the revoke structure.
      const fakeConsentCid = 'bafyreiabnu633o7opc26xejbewl22zsuhao4kjoeuayzhfep3h2nzfir6i';

      const alice = masterKeyFromSeed(aliceSeed);
      const bob = masterKeyFromSeed(bobSeed);

      const aliceKem = derivePqKeyPair(alice, otherParty, consentNumber, chainId, PulsePurpose.PQDeriveRevoke);
      const bobKem = derivePqKeyPair(bob, otherParty, consentNumber, chainId, PulsePurpose.PQDeriveRevoke);

      const pqResult = encryptPq(
        new TextEncoder().encode('revoke payload for PQ signing test'),
        contractAddress,
        [aliceKem.publicKey, bobKem.publicKey],
        PulsePurpose.PQDeriveRevoke,
        chainId,
        consentNumber,
      );

      // Correct CID: marshalRevokePq includes the GrantRef
      const correctCbor = marshalRevokePq({ ...pqResult, grant: fakeConsentCid });
      const correctRevokeCid = await getCid(correctCbor);

      // Wrong CID: marshalConsentPq omits the GrantRef (the pre-fix bug)
      const wrongCbor = marshalConsentPq(pqResult);
      const wrongRevokeCid = await getCid(wrongCbor);

      // Sanity: GrantRef must change the CBOR and therefore the CID
      expect(correctRevokeCid).not.toBe(wrongRevokeCid);

      // Alice signs over the correct CID using her deterministic secp256k1 key (purpose 1)
      const aliceSignNode = deriveNode(alice, otherParty, chainId, consentNumber, PulsePurpose.SignTx);
      const sig = signRevoke(aliceSignNode.privateKey!, contractAddress, fakeConsentCid, correctRevokeCid);

      // Address recovery against the correct CID must equal Alice's known signing address
      const recovered = getRevokeAddress(sig, contractAddress, fakeConsentCid, correctRevokeCid);
      expect(toHex(recovered)).toBe('1147b934b5c0fcabbaed2cf128a3db1eb71ef2c0');

      // Recovery against the wrong CID must NOT equal Alice's address — demonstrating
      // why a mid-tier that uses marshalRevoke (correct) rejects signatures made with
      // the wrong CID.
      const recoveredWrong = getRevokeAddress(sig, contractAddress, fakeConsentCid, wrongRevokeCid);
      expect(toHex(recoveredWrong)).not.toBe('1147b934b5c0fcabbaed2cf128a3db1eb71ef2c0');
    });
  });
});
