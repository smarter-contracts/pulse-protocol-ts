import { describe, it, expect } from 'vitest'
import { PulsePurpose } from '@pulse-protocol/types'
import { fromHex, toHex, pulseHashBytes } from '../hash.js'
import { pulseSeal, pulseOpen, buildAad } from '../symmetric.js'

function h(hex: string): Uint8Array { return fromHex(hex) }
function enc(s: string): Uint8Array { return new TextEncoder().encode(s) }

describe('PulseSeal / PulseOpen — known values (mirrors pulse-protocol-go/crypto/internal/symmetric)', () => {
  it('Key Exchange known values — AAD and ciphertext', () => {
    const plaintext = enc('This is the consent record')
    const aesKey = h('e52121ff74c5fc185d5aa165c47283889378492f64a53fbf5d53f3e5dc5e4e82')
    const nonce = h('9b6585bef61692965127d170')
    const purpose = PulsePurpose.EncryptConsentStructure
    const cipherSuite = 'ecdh-secp256k1+hkdf-keccak256+aes-gcm-256'
    const recipientHash = new Uint8Array(0)
    const contextHash = h('7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3')
    const transcriptHash = h('1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4')

    const expectedAAD = '|pulse|consent|v1|ecdh-secp256k1+hkdf-keccak256+aes-gcm-256|rid=|ctx=7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3|th=1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4|nonce=9b6585bef61692965127d170|'
    const expectedCipher = h('8f8852ab16bb09596b9d8ce94a7482ac715dacd711537878a48a6d7628287baa3423a0535346593375ee')

    const aad = buildAad(purpose, cipherSuite, recipientHash, nonce, contextHash, transcriptHash)
    expect(new TextDecoder().decode(aad)).toBe(expectedAAD)

    const ciphertext = pulseSeal(plaintext, aesKey, nonce, purpose, cipherSuite, recipientHash, contextHash, transcriptHash)
    expect(toHex(ciphertext)).toBe(toHex(expectedCipher))

    const decrypted = pulseOpen(ciphertext, aesKey, nonce, purpose, cipherSuite, recipientHash, contextHash, transcriptHash)
    expect(decrypted).toEqual(plaintext)
  })

  it('Key Encapsulation known values — data layer (rng+aes-gcm-256)', () => {
    const plaintext = enc('This is the consent record')
    const aesKey = h('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    const nonce = h('202122232425262728292a2b')
    const purpose = PulsePurpose.EncryptConsentStructure
    const cipherSuite = 'rng+aes-gcm-256'
    const recipientHash = h('9674817700045e99280b08deebeb495374fd63823ed53130b16e84c3fc558922')
    const contextHash = h('7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3')
    const transcriptHash = pulseHashBytes(nonce)

    const expectedAAD = '|pulse|consent|v1|rng+aes-gcm-256|rid=9674817700045e99280b08deebeb495374fd63823ed53130b16e84c3fc558922|ctx=7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3|th=08cbbdefe5c86347efb3a00eda9ac05c0e8b8da6d0443410f229ad7bd0a82253|nonce=202122232425262728292a2b|'
    const expectedCipher = h('8652cf034cf1692e6e1427eea2779a8ab52798bcf5e500811e92c70cc2d6433e08b09e086a5989071d69')

    const aad = buildAad(purpose, cipherSuite, recipientHash, nonce, contextHash, transcriptHash)
    expect(new TextDecoder().decode(aad)).toBe(expectedAAD)

    const ciphertext = pulseSeal(plaintext, aesKey, nonce, purpose, cipherSuite, recipientHash, contextHash, transcriptHash)
    expect(toHex(ciphertext)).toBe(toHex(expectedCipher))

    const decrypted = pulseOpen(ciphertext, aesKey, nonce, purpose, cipherSuite, recipientHash, contextHash, transcriptHash)
    expect(decrypted).toEqual(plaintext)
  })

  it('Key Encapsulation known values — Alice key wrap (kyber768+hkdf-keccak256+aes-gcm-256)', () => {
    const plaintext = h('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b')
    const aesKey = h('8c00e2528428927b81befef1022cf7de7aae639b8f714a90c1c6106237000822')
    const nonce = h('504f2d28709e2db670a59cc4')
    const purpose = PulsePurpose.EncryptConsentStructure
    const cipherSuite = 'kyber768+hkdf-keccak256+aes-gcm-256'
    const recipientHash = h('01b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd')
    const contextHash = h('7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3')
    const aliceCiphertext = h('b236c30d44fa247895e19d4b249ef8a07db4f15b5280f8fca53587093884b182e34e5af87163402b51ece1c1945532fa297b3307a42e37aca5f93de09e53af17564b16c073c80d928ac7e21d11876789c3060498ace470a431e8fe13b67a856e641dcce741229193766a2b9b9533e5b47e328a9aa1f930a51581c11d79815a270f82ce3b78d4c0235746004a480f6101ac77eeea0ce879c354f0c18a0afa230a880f97f443ddf0a63027529ee452b311510baa59d89e0d8e8f20478ba95c19b006a8d22313e6f648f9c6f9c6c2af67bc76be832dc49feda76afcceb41dc56dfe81db2238b50883ef2e9bc3df0cc0af57b7cc02e87e6b3cd24d82f0bc563f5aef7eb29facef912c96fe7f0b0dba53497a0f992ad3b0f43346678851ee99b36cbd2b8e7012bcfddc5e01ecdd7a8c59030ae908ade990d2471acf4541b283b2c2c68d39c3ea75c3df3e9748b7796cd8a5e9cbc22752c3ff487debbebe342edf19057bec457047c6172d954df1abf57b3be492a35a4e8f778aba2ad1b3b56a2aef2841e348cf5bb475620622030c255f3b32ee59c0676149be0725024d0aa64923f329b03bffc424b2040ac5cc9f1c976fdfec41b65e66e0c9cd6bd68d1e66978197cd4f1e3f5a991ca95445f75caa19cc3ce4b433d53a3ffb25039fd312ea40975a7065ef32edd08335ef8a71ce6c7697eab7c37f37594665ee62d4a82005df15660fcd92fe710e85cef0d57631801fc878245c4ee96c2cebf537c3f628ef777a8b4a54f1d5b72fa4953cff152cb35e188eaa2b14ad749d5350abfdfcb2ad73d64362f8379ed034c37865d2c0a0c38226bffd80a4b5981afbd84ce8f4f89c757e902b5ea441d74783352d3a60aa6447420e27cf6992d5d0b1dfbcd237d7e39dd080b2e629795ec30603a4562fb9b46d33b6a9692d59f7e032d8d0420d42a3a492c61189f1357a7a1b1c49e3622246137d0b5d4a5bc589ee29be1e10b9346c148f41e1403491f4d599436f5929760ceaee077b496a1a1bb095b1f7bb20b80e626a2ef7b83631c650074c56b9a2dfc08cae48b65255e7571a4928266a4f9c5ecaa9a546447f350c34ccccc22b8748ed323d19e712e5d41c6726a87a4bcb9b26f7f12ea5bf42ce66dcadfb16b143238d193499b56141a87e1168483f59fc1156d7f26b03b1f48d3553fa828bc3c87885a6c7942be3886209117151d3e59ff0610ef6e40e7e05c72e0a16fa80ae401c8fb1738a214bae41a9a3601951bf61c49227909d91f65aad5183d6adfefc48a2bd3c4ee3c2a013aac269eb709f2499c724f445feb750e48db19f33e6303be50d614029a3c27ec3191a51e0fcf6183f82ecbc44a96892d971e4bdc346634170ed1b6635aa7660143a6e2aae92fb5c128cad73a1bf9c450c22accebbdd099fe8b8e82915acf09364edb6e16fc245baa8e8c684400e5dac29c9fce2a5ba9dcbd66aaaf087c2effe80ccb2a750579479ff16ca6fc472dea7d2120bf672df3d4050ef69ebe9e5dffe73395da4a09a8ed157bb2c63f9d9')
    const transcriptHash = pulseHashBytes(aliceCiphertext)

    const expectedAAD = '|pulse|consent|v1|kyber768+hkdf-keccak256+aes-gcm-256|rid=01b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd|ctx=7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3|th=a0194d43f581fef367cf0b3d70020f48d742884e80fff1f7e952e0bb9a4ee58a|nonce=504f2d28709e2db670a59cc4|'
    const expectedCipher = h('b500e45683a54614d13c6c239dda4829089657ce965b5d28ab8920f3a87d96cf69bf85893de9c1a938caf63cf48ec3f0c29f30045b8ec1249f046812')

    const aad = buildAad(purpose, cipherSuite, recipientHash, nonce, contextHash, transcriptHash)
    expect(new TextDecoder().decode(aad)).toBe(expectedAAD)

    const ciphertext = pulseSeal(plaintext, aesKey, nonce, purpose, cipherSuite, recipientHash, contextHash, transcriptHash)
    expect(toHex(ciphertext)).toBe(toHex(expectedCipher))

    const decrypted = pulseOpen(ciphertext, aesKey, nonce, purpose, cipherSuite, recipientHash, contextHash, transcriptHash)
    expect(decrypted).toEqual(plaintext)
  })

  it('Symmetric known values 1 (aes-gcm-256)', () => {
    const plaintext = enc('pulse test')
    const aesKey = h('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    const nonce = h('000102030405060708090a0b')
    const purpose = PulsePurpose.EncryptConsentStructure
    const cipherSuite = 'aes-gcm-256'
    const recipientHash = h('0102030405060708090a0b0c0d0e0f1011121314')
    const contextHash = h('212223')
    const transcriptHash = h('313233')

    const expectedAAD = '|pulse|consent|v1|aes-gcm-256|rid=0102030405060708090a0b0c0d0e0f1011121314|ctx=212223|th=313233|nonce=000102030405060708090a0b|'
    const expectedCipher = h('3777ba68a0c5b67efe35cfa9a692dd1bd440590a55ab87a1ca4f')

    const aad = buildAad(purpose, cipherSuite, recipientHash, nonce, contextHash, transcriptHash)
    expect(new TextDecoder().decode(aad)).toBe(expectedAAD)

    const ciphertext = pulseSeal(plaintext, aesKey, nonce, purpose, cipherSuite, recipientHash, contextHash, transcriptHash)
    expect(toHex(ciphertext)).toBe(toHex(expectedCipher))

    const decrypted = pulseOpen(ciphertext, aesKey, nonce, purpose, cipherSuite, recipientHash, contextHash, transcriptHash)
    expect(decrypted).toEqual(plaintext)
  })

  it('Symmetric known values 2 — key wrap (SymmetricKeyWrap purpose)', () => {
    const plaintext = h('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f11223344556677889900aabbccddeeff')
    const aesKey = h('4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60')
    const nonce = h('1112131415161718191a1b1c')
    const purpose = PulsePurpose.SymmetricKeyWrap
    const cipherSuite = 'kyber768+hkdf-keccak256+aes-gcm-256'
    const recipientHash = h('70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde')
    const contextHash = h('6d7aace2b827d9377fc9bfb261f50b2ab4dbf041500a2ac837d8dcba19e54aea')
    const transcriptHash = h('1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4')

    const expectedAAD = '|pulse|keywrap|v1|kyber768+hkdf-keccak256+aes-gcm-256|rid=70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde|ctx=6d7aace2b827d9377fc9bfb261f50b2ab4dbf041500a2ac837d8dcba19e54aea|th=1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4|nonce=1112131415161718191a1b1c|'
    const expectedCipher = h('f6058785d4fea6790470dfce54417e1cef02f62ef7351ee5fea187865ad407a864c428eb25e17f764f0be39541f2550a1fb69b7ccd6cee56bedf691d0cdc3ca8')

    const aad = buildAad(purpose, cipherSuite, recipientHash, nonce, contextHash, transcriptHash)
    expect(new TextDecoder().decode(aad)).toBe(expectedAAD)

    const ciphertext = pulseSeal(plaintext, aesKey, nonce, purpose, cipherSuite, recipientHash, contextHash, transcriptHash)
    expect(toHex(ciphertext)).toBe(toHex(expectedCipher))

    const decrypted = pulseOpen(ciphertext, aesKey, nonce, purpose, cipherSuite, recipientHash, contextHash, transcriptHash)
    expect(decrypted).toEqual(plaintext)
  })

  it('wrong key causes decryption failure', () => {
    const plaintext = enc('pulse test')
    const aesKey = h('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    const nonce = h('000102030405060708090a0b')
    const purpose = PulsePurpose.EncryptConsentStructure
    const cipherSuite = 'test-suite'
    const recipientHash = new Uint8Array(20).fill(1)
    const contextHash = new TextEncoder().encode('context')
    const transcriptHash = new TextEncoder().encode('transcript')

    const ciphertext = pulseSeal(plaintext, aesKey, nonce, purpose, cipherSuite, recipientHash, contextHash, transcriptHash)

    const wrongKey = new Uint8Array(aesKey)
    wrongKey[0] ^= 0xff
    expect(() => pulseOpen(ciphertext, wrongKey, nonce, purpose, cipherSuite, recipientHash, contextHash, transcriptHash)).toThrow()
  })

  it('wrong purpose causes decryption failure', () => {
    const plaintext = enc('pulse test')
    const aesKey = h('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    const nonce = h('000102030405060708090a0b')
    const purpose = PulsePurpose.EncryptConsentStructure
    const cipherSuite = 'test-suite'
    const recipientHash = new Uint8Array(20).fill(1)
    const contextHash = new TextEncoder().encode('context')
    const transcriptHash = new TextEncoder().encode('transcript')

    const ciphertext = pulseSeal(plaintext, aesKey, nonce, purpose, cipherSuite, recipientHash, contextHash, transcriptHash)
    expect(() => pulseOpen(ciphertext, aesKey, nonce, PulsePurpose.EncryptRevokeStructure, cipherSuite, recipientHash, contextHash, transcriptHash)).toThrow()
  })
})
