import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../hash.js';
import {
  buildMessage,
  ethereumTextHash,
  getConsentAddress,
  getRevokeAddress,
  packMessage,
  parseContractAddress,
  signConsent,
  signRevoke,
} from '../signing.js';

function h(hex: string): Uint8Array {
  return fromHex(hex);
}

describe('EIP-191 Signing — known values (mirrors pulse-protocol-go/crypto/signing_test.go)', () => {
  describe('message packing', () => {
    const contractAddress = '0x0102030405060708090a0b0c0d0e0f1011121314';
    const cid = 'bafyreihd744kp3ua6svk5t3chwlqicnzag22zmcohrwowvyqawjqogr65i';

    it('packMessage produces correct bytes', () => {
      const addr = parseContractAddress(contractAddress);
      const packed = packMessage(addr, cid);
      expect(toHex(packed)).toBe(
        '0102030405060708090a0b0c0d0e0f10111213146261667972656968643734346b703375613673766b3574336368776c7169636e7a616732327a6d636f6872776f7776797161776a716f6772363569',
      );
    });

    it('buildMessage (Keccak256 of packed) matches known hash', () => {
      expect(toHex(buildMessage(contractAddress, cid))).toBe(
        '48bf046023b71d67f433eb418347863959a5f02716b7c9dcb2b471c9d42b721d',
      );
    });

    it('ethereumTextHash matches known signing hash', () => {
      const msgHash = buildMessage(contractAddress, cid);
      expect(toHex(ethereumTextHash(msgHash))).toBe(
        '64920461bf4a9d15b68cf83b139ea4b941544ca9e4e52f4cf529f9b499abb967',
      );
    });
  });

  describe('SignConsent — table of known values', () => {
    const cases = [
      {
        name: 'EC grantee (send_test_consent)',
        privateKey: '89b58da1002bdd02ea9972c3c64c050f9a5236e430e030c18406035ca2be1856',
        address: 'fc3a23dade5b5a5c6b1790f9ac4256aed8ee8993',
        contractAddress: '0x9b980288ae5F7a1aca113faec133e765879a5fab',
        cid: 'bafyreialkztkqka6ki4arwlrryrhpamzaa3otihmegainx4puyyiq7yspm',
        expectedPacked:
          '9b980288ae5f7a1aca113faec133e765879a5fab62616679726569616c6b7a746b716b61366b69346172776c727279726870616d7a6161336f7469686d656761696e7834707579796971377973706d',
        expectedPackedHash: 'e70594616cdcabad2c33930134d92dd152d138de679cb4f21fcadf0db30d07b2',
        expectedSigningHash: 'a30638332e2051a57faa61224ef3920ed2cdb216c4c7b3b38b02a05a391c6140',
        expectedSignature:
          'b60d499d54b1a73eb9bb69c7289d5dcdd32e9893bc7e4f72df32fa75f395a1800cfa4eb49bf3a87bad7fc69b476ef5d5bea56883d2b9d0348963fcad34e5542e1b',
      },
      {
        name: 'EC grantor (send_test_consent)',
        privateKey: 'da4782769625a2cfe4c5ab998f71e19892d0769ed42c0551b2efab5eceae884c',
        address: '33a1debbe882df214f96a2b92b4062ee8fbb9c2f',
        contractAddress: '0x9b980288ae5F7a1aca113faec133e765879a5fab',
        cid: 'bafyreialkztkqka6ki4arwlrryrhpamzaa3otihmegainx4puyyiq7yspm',
        expectedPacked:
          '9b980288ae5f7a1aca113faec133e765879a5fab62616679726569616c6b7a746b716b61366b69346172776c727279726870616d7a6161336f7469686d656761696e7834707579796971377973706d',
        expectedPackedHash: 'e70594616cdcabad2c33930134d92dd152d138de679cb4f21fcadf0db30d07b2',
        expectedSigningHash: 'a30638332e2051a57faa61224ef3920ed2cdb216c4c7b3b38b02a05a391c6140',
        expectedSignature:
          '83dc442a0a67d27cccf8c57357f06b35b6f5b33082a81616fa0b0c4d144d572a0ca95431fe5262a41c83a04473b13c0cd5611bf6b5f1b560283ebceb88a295ff1b',
      },
      {
        name: 'Known Values Test (BIP-32 Test Vector 1 key)',
        privateKey: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        address: 'ede35562d3555e61120a151b3c8e8e91d83a378a',
        contractAddress: '0x0102030405060708090a0b0c0d0e0f1011121314',
        cid: 'bafyreihd744kp3ua6svk5t3chwlqicnzag22zmcohrwowvyqawjqogr65i',
        expectedPacked:
          '0102030405060708090a0b0c0d0e0f10111213146261667972656968643734346b703375613673766b3574336368776c7169636e7a616732327a6d636f6872776f7776797161776a716f6772363569',
        expectedPackedHash: '48bf046023b71d67f433eb418347863959a5f02716b7c9dcb2b471c9d42b721d',
        expectedSigningHash: '64920461bf4a9d15b68cf83b139ea4b941544ca9e4e52f4cf529f9b499abb967',
        expectedSignature:
          '83507ee48e57e629554080fb8c812119938c7e852451d54cd1dacf6688d10ab3672b5602ca24af6597da87c397b52769b5ba8ce30dae866f44c09fbaf4a951c91b',
      },
    ];

    for (const tc of cases) {
      it(tc.name, () => {
        const privKey = h(tc.privateKey);

        // Check packed message
        const addr = parseContractAddress(tc.contractAddress);
        expect(toHex(packMessage(addr, tc.cid))).toBe(tc.expectedPacked);

        // Check message hash
        expect(toHex(buildMessage(tc.contractAddress, tc.cid))).toBe(tc.expectedPackedHash);

        // Check signing hash
        expect(toHex(ethereumTextHash(h(tc.expectedPackedHash)))).toBe(tc.expectedSigningHash);

        // Check signature
        const sig = signConsent(privKey, tc.contractAddress, tc.cid);
        expect(toHex(sig)).toBe(tc.expectedSignature);

        // Check address recovery
        const recovered = getConsentAddress(sig, tc.contractAddress, tc.cid);
        expect(toHex(recovered)).toBe(tc.address);
      });
    }
  });

  describe('SignRevoke — known values', () => {
    it('revoke with two CIDs', () => {
      const privateKey = h('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
      const contractAddress = '0x0102030405060708090a0b0c0d0e0f1011121314';
      const cid = 'bafyreihd744kp3ua6svk5t3chwlqicnzag22zmcohrwowvyqawjqogr65i';
      const rcid = 'bafyreidxxmeu4hn46zhbwclzwykj7vdbixj5boduhql7ihm4i2djqt4dmq';

      const expectedPacked =
        '0102030405060708090a0b0c0d0e0f10111213146261667972656968643734346b703375613673766b3574336368776c7169636e7a616732327a6d636f6872776f7776797161776a716f6772363569626166797265696478786d657534686e34367a686277636c7a77796b6a3776646269786a35626f647568716c3769686d346932646a717434646d71';
      const expectedPackedHash = '26f90118453374476e6d1c9462e6dbc16e17fa88974ef780c385a3e66847757d';
      const expectedSigningHash =
        '01eae01192709113c2bebbf955e237757a8d2a9e6e30f147bcf61f44abced572';
      const expectedSignature =
        'eb2ccdade157f21e4a790f0acaa1aa1f74222754e88004bbc94f8829a7b039cb04270295d7cf72a52d2003830e09cac7a14f03b301834937e92ff8f600c0171d1b';
      const address = 'ede35562d3555e61120a151b3c8e8e91d83a378a';

      // Verify packed bytes
      const addr = parseContractAddress(contractAddress);
      expect(toHex(packMessage(addr, cid, rcid))).toBe(expectedPacked);

      // Verify message hash
      expect(toHex(buildMessage(contractAddress, cid, rcid))).toBe(expectedPackedHash);

      // Verify signing hash
      expect(toHex(ethereumTextHash(h(expectedPackedHash)))).toBe(expectedSigningHash);

      // Verify signature
      const sig = signRevoke(privateKey, contractAddress, cid, rcid);
      expect(toHex(sig)).toBe(expectedSignature);

      // Verify recovery
      const recovered = getRevokeAddress(sig, contractAddress, cid, rcid);
      expect(toHex(recovered)).toBe(address);
    });
  });
});
