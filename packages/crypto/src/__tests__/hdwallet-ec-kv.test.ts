/**
 * Known-value tests for the EC HD wallet consent/revoke lifecycle.
 * Mirrors pulse-protocol-go/crypto/hdwallet_ec_kv_test.go.
 *
 * Test parameters:
 *   Alice seed (BIP-32 Test Vector 1): 000102030405060708090a0b0c0d0e0f
 *   Bob seed:                          101112131415161718191a1b1c1d1e1f
 *   Notary private key:                aa01020304050607080910111213141516171819202122232425262728293031
 *   contractAddress: "0x0102030405060708091011121314"
 *   chainId:         1
 *   otherParty:      3
 *   consentNumber:   2
 */

import { PulsePurpose } from '@pulse-protocol/types';
import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../hash.js';
import { deriveNode, masterKeyFromSeed, pulsePath } from '../hdwallet.js';

function h(hex: string): Uint8Array {
  return fromHex(hex);
}

// ── Fixed seeds ──────────────────────────────────────────────────────────────
const aliceSeed = h('000102030405060708090a0b0c0d0e0f');
const bobSeed = h('101112131415161718191a1b1c1d1e1f');
const notarySeed = h('aa01020304050607080910111213141516171819202122232425262728293031');

const contractAddress = '0x0102030405060708091011121314';
const chainId = 1;
const otherParty = 3;
const consentNumber = 2;

describe('HD Wallet — EC known values (mirrors pulse-protocol-go/crypto/hdwallet_ec_kv_test.go)', () => {
  it('HD path format', () => {
    expect(
      pulsePath(otherParty, chainId, consentNumber, PulsePurpose.EncryptConsentStructure),
    ).toBe("m/4410704'/3/1/2/3");
    expect(
      pulsePath(otherParty, chainId, consentNumber, PulsePurpose.EncryptConsentNotaryBlock),
    ).toBe("m/4410704'/3/1/2/2");
    expect(pulsePath(otherParty, chainId, consentNumber, PulsePurpose.SignTx)).toBe(
      "m/4410704'/3/1/2/1",
    );
  });

  it('Notary public key (standalone key, not from HD wallet)', async () => {
    const { secp256k1 } = await import('@noble/curves/secp256k1');
    const pub = secp256k1.getPublicKey(notarySeed, true);
    expect(toHex(pub)).toBe('02fade94180988b62103c7788bac14dd71819c92ad3c757ac5eb3477054970d805');
  });

  describe('Notary encryption path (purpose 2)', () => {
    it('Alice notary node priv/pub keys', () => {
      const alice = masterKeyFromSeed(aliceSeed);
      const node = deriveNode(
        alice,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptConsentNotaryBlock,
      );
      expect(toHex(node.privateKey!)).toBe(
        'de9ff0acd0e4774ec79ef72dd2e086b8e45e97214fed3cac5b7b352c94e8eeaa',
      );
      expect(toHex(node.publicKey!)).toBe(
        '03c502eb5c46c4c98b3b82f6a479800ca93a5c3ff82c48efef2825972f7189a188',
      );
    });
  });

  describe('Consent encryption path (purpose 3)', () => {
    it('Alice consent node priv/pub keys', () => {
      const alice = masterKeyFromSeed(aliceSeed);
      const node = deriveNode(
        alice,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptConsentStructure,
      );
      expect(toHex(node.privateKey!)).toBe(
        '61e1d6824a3faf93e939d06471854c887497d2a7e93bb3fbfe23ea643009682c',
      );
      expect(toHex(node.publicKey!)).toBe(
        '02759a7c74a13b454e94c4846d0ee14366d4f8716bd6bc1fce99507952e7220a2c',
      );
    });
  });

  describe('Revoke notary path (purpose 4)', () => {
    it('Alice revoke notary node priv/pub keys', () => {
      const alice = masterKeyFromSeed(aliceSeed);
      const node = deriveNode(
        alice,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptRevokeNotaryBlock,
      );
      expect(toHex(node.privateKey!)).toBe(
        'fc216eb1fe324fef31308b8550dbd2e31e627143334d7dec596c9dd685c594bb',
      );
      expect(toHex(node.publicKey!)).toBe(
        '03ca619266af8f2b255b5ab690815bf6786511c83b8368ff8be412f2ad46f86cf8',
      );
    });
  });

  describe('Revoke encryption path (purpose 5)', () => {
    it('Alice revoke node priv/pub keys', () => {
      const alice = masterKeyFromSeed(aliceSeed);
      const node = deriveNode(
        alice,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptRevokeStructure,
      );
      expect(toHex(node.privateKey!)).toBe(
        'e36c8f883748b24f1ce6c2202c0f9eea257b7d8e6ddb334130dd2878b7c74731',
      );
      expect(toHex(node.publicKey!)).toBe(
        '03ee864493c54357eefca45c3531d444650cc30dd1e15e82c990f069b11ad07993',
      );
    });
  });

  describe('Signing path (purpose 1)', () => {
    it('Alice signing key', () => {
      const alice = masterKeyFromSeed(aliceSeed);
      const node = deriveNode(alice, otherParty, chainId, consentNumber, PulsePurpose.SignTx);
      expect(toHex(node.privateKey!)).toBe(
        'abc5df3dacf1cfd8fb11cacf2a4b23688326dfb14f14f03bfd733057d89e3583',
      );
      expect(toHex(node.publicKey!)).toBe(
        '0238e67685c6addffef2ba3f18d37d6ae4411b38753adfa89cceed5767093e7f44',
      );
    });

    it('Bob signing key', () => {
      const bob = masterKeyFromSeed(bobSeed);
      const node = deriveNode(bob, otherParty, chainId, consentNumber, PulsePurpose.SignTx);
      expect(toHex(node.privateKey!)).toBe(
        '7619026ba76aa9b51a8480076296d8e92bea454ea40cadc49937964804e63cca',
      );
      expect(toHex(node.publicKey!)).toBe(
        '03fa4b3d0c976d2836cbf200e1b5f3935982b2a6bbd71b74b69d703cae5b9b6a40',
      );
    });
  });

  describe('EC consent encrypt/decrypt round-trip', () => {
    it('Alice encrypts with her key and Bob public key, both can decrypt', async () => {
      const { encryptEcdh, decryptEc } = await import('../key-exchange.js');
      const alice = masterKeyFromSeed(aliceSeed);
      const bob = masterKeyFromSeed(bobSeed);

      const aliceNode = deriveNode(
        alice,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptConsentStructure,
      );
      const bobNode = deriveNode(
        bob,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptConsentStructure,
      );

      const alicePriv = aliceNode.privateKey!;
      const bobPub = bobNode.publicKey!;
      const plaintext = new TextEncoder().encode('test consent payload');

      const result = encryptEcdh(
        plaintext,
        contractAddress,
        alicePriv,
        bobPub,
        PulsePurpose.EncryptConsentStructure,
        chainId,
        consentNumber,
      );

      // Alice decrypts
      const decryptedAlice = decryptEc(
        result,
        contractAddress,
        alicePriv,
        PulsePurpose.EncryptConsentStructure,
        chainId,
        consentNumber,
      );
      expect(decryptedAlice).toEqual(plaintext);

      // Bob decrypts
      const bobPriv = bobNode.privateKey!;
      const decryptedBob = decryptEc(
        result,
        contractAddress,
        bobPriv,
        PulsePurpose.EncryptConsentStructure,
        chainId,
        consentNumber,
      );
      expect(decryptedBob).toEqual(plaintext);
    });

    it('notary sealed data matches known value', async () => {
      const { encryptEcdh } = await import('../key-exchange.js');
      const { secp256k1 } = await import('@noble/curves/secp256k1');

      const alice = masterKeyFromSeed(aliceSeed);
      const aliceNode = deriveNode(
        alice,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptConsentNotaryBlock,
      );
      const notaryPub = secp256k1.getPublicKey(notarySeed, true);

      const notaryData = new TextEncoder().encode('notary block payload for kv test');
      const result = encryptEcdh(
        notaryData,
        contractAddress,
        aliceNode.privateKey!,
        notaryPub,
        PulsePurpose.EncryptConsentNotaryBlock,
        chainId,
        consentNumber,
      );

      // Verify the sealed data matches the Go reference
      expect(toHex(result.sealedData)).toBe(
        '5633c336c4f8c6dcda0399783b83daf472b1023b49f522746780cecec098284fc39b162fb912866008591f865bba8389',
      );
    });

    it('consent CID matches known value', async () => {
      const { getCid, marshalConsentEc } = await import('@pulse-protocol/ipfs');
      const { encryptEcdh } = await import('../key-exchange.js');
      const { secp256k1 } = await import('@noble/curves/secp256k1');

      const alice = masterKeyFromSeed(aliceSeed);
      const bob = masterKeyFromSeed(bobSeed);

      // Notary encryption
      const aliceNotaryNode = deriveNode(
        alice,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptConsentNotaryBlock,
      );
      const notaryPub = secp256k1.getPublicKey(notarySeed, true);
      const notaryData = new TextEncoder().encode('notary block payload for kv test');
      const notaryResult = encryptEcdh(
        notaryData,
        contractAddress,
        aliceNotaryNode.privateKey!,
        notaryPub,
        PulsePurpose.EncryptConsentNotaryBlock,
        chainId,
        consentNumber,
      );

      // Build consent plaintext
      const notaryCbor = marshalConsentEc(notaryResult);
      const consentPlaintext = new Uint8Array([
        ...notaryCbor,
        ...new TextEncoder().encode('|consent payload for kv test'),
      ]);

      // Consent encryption
      const aliceConsentNode = deriveNode(
        alice,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptConsentStructure,
      );
      const bobConsentNode = deriveNode(
        bob,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptConsentStructure,
      );
      const consentResult = encryptEcdh(
        consentPlaintext,
        contractAddress,
        aliceConsentNode.privateKey!,
        bobConsentNode.publicKey!,
        PulsePurpose.EncryptConsentStructure,
        chainId,
        consentNumber,
      );

      const cbor = marshalConsentEc(consentResult);
      const cid = await getCid(cbor);
      expect(cid).toBe('bafyreiabnu633o7opc26xejbewl22zsuhao4kjoeuayzhfep3h2nzfir6i');
    });

    it('revoke CID, signature and address match known values', async () => {
      const { getCid, marshalConsentEc, marshalRevokeEc } = await import('@pulse-protocol/ipfs');
      const { encryptEcdh } = await import('../key-exchange.js');
      const { signRevoke, getRevokeAddress } = await import('../signing.js');
      const { secp256k1 } = await import('@noble/curves/secp256k1');

      const alice = masterKeyFromSeed(aliceSeed);
      const bob = masterKeyFromSeed(bobSeed);
      const notaryPub = secp256k1.getPublicKey(notarySeed, true);

      // ── Reproduce consent CID (GrantRef for the revoke) ────────────────────
      const aliceNotaryNode = deriveNode(
        alice,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptConsentNotaryBlock,
      );
      const notaryResult = encryptEcdh(
        new TextEncoder().encode('notary block payload for kv test'),
        contractAddress,
        aliceNotaryNode.privateKey!,
        notaryPub,
        PulsePurpose.EncryptConsentNotaryBlock,
        chainId,
        consentNumber,
      );
      const notaryCbor = marshalConsentEc(notaryResult);
      const consentPlaintext = new Uint8Array([
        ...notaryCbor,
        ...new TextEncoder().encode('|consent payload for kv test'),
      ]);
      const aliceConsentNode = deriveNode(
        alice,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptConsentStructure,
      );
      const bobConsentNode = deriveNode(
        bob,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptConsentStructure,
      );
      const consentResult = encryptEcdh(
        consentPlaintext,
        contractAddress,
        aliceConsentNode.privateKey!,
        bobConsentNode.publicKey!,
        PulsePurpose.EncryptConsentStructure,
        chainId,
        consentNumber,
      );
      const consentCid = await getCid(marshalConsentEc(consentResult));

      // ── Step 8: Alice encrypts revoke notary (purpose 4) ───────────────────
      const aliceRevokeNotaryNode = deriveNode(
        alice,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptRevokeNotaryBlock,
      );
      const revokeNotaryResult = encryptEcdh(
        new TextEncoder().encode('revoke notary block payload for kv test'),
        contractAddress,
        aliceRevokeNotaryNode.privateKey!,
        notaryPub,
        PulsePurpose.EncryptRevokeNotaryBlock,
        chainId,
        consentNumber,
      );

      // ── Step 9: Alice encrypts revoke (purpose 5) ──────────────────────────
      // Revoke notary block is serialised as a plain EC blob (no GrantRef).
      const revokeNotaryCbor = marshalConsentEc(revokeNotaryResult);
      const revokePlaintext = new Uint8Array([
        ...revokeNotaryCbor,
        ...new TextEncoder().encode('|revoke payload for kv test'),
      ]);

      const aliceRevokeNode = deriveNode(
        alice,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptRevokeStructure,
      );
      const bobRevokeNode = deriveNode(
        bob,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.EncryptRevokeStructure,
      );
      const revokeResult = encryptEcdh(
        revokePlaintext,
        contractAddress,
        aliceRevokeNode.privateKey!,
        bobRevokeNode.publicKey!,
        PulsePurpose.EncryptRevokeStructure,
        chainId,
        consentNumber,
      );

      // Revoke CID must be computed from the full RevokeStructure (including
      // the GrantRef / consentCid) so it matches what the mid-tier verifies.
      const revokeCbor = marshalRevokeEc({ ...revokeResult, grant: consentCid });
      const revokeCid = await getCid(revokeCbor);
      expect(revokeCid).toBe('bafyreidjuyvb2sa5hy6guoow2cxiy6w7s52jtegwmetmc3d755vf4kgwgy');

      // Sanity: marshalConsentEc (no GrantRef) produces a different CID,
      // confirming that the GrantRef is what distinguishes the signed message.
      const wrongCbor = marshalConsentEc(revokeResult);
      const wrongCid = await getCid(wrongCbor);
      expect(wrongCid).not.toBe(revokeCid);

      // Alice signs the revoke using her SignTx key (purpose 1)
      const aliceSignNode = deriveNode(
        alice,
        otherParty,
        chainId,
        consentNumber,
        PulsePurpose.SignTx,
      );
      const sig = signRevoke(aliceSignNode.privateKey!, contractAddress, consentCid, revokeCid);
      expect(toHex(sig)).toBe(
        '1a5f0dfc10d7e40c45f39efbc2792664ca405ffca248dbc25896abfaeaa1cb1d7ec0f71d19484118d9f7343729c75338915823072b948c4b1a40f0c940e9ffdd1c',
      );

      const addr = getRevokeAddress(sig, contractAddress, consentCid, revokeCid);
      expect(toHex(addr)).toBe('1147b934b5c0fcabbaed2cf128a3db1eb71ef2c0');
    });
  });
});
