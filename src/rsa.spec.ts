/* eslint-env mocha */

import forge from 'node-forge'
import { PrivateKey, PublicKey } from './rsa-forge'
import { intToBuffer } from './utils'
import crc32 from 'crc-32'
import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import * as crypto from 'crypto'

chai.use(chaiAsPromised)
const { assert, expect } = chai

describe('RSA forge', () => {
  let privateKey: PrivateKey, privateKey2: PrivateKey

  before('generate keys', () =>
    Promise.all([
      PrivateKey.generate(1024),
      PrivateKey.generate(1024)
    ])
      .then(([_key1, _key2]) => {
        privateKey = _key1
        privateKey2 = _key2
      })
  )

  const message = Buffer.from('TESTtest', 'ascii')
  const messageUtf8 = 'Iñtërnâtiônàlizætiøn\u2603\uD83D\uDCA9'
  const messageBinary = crypto.randomBytes(32)

  it('Fail to construct a PublicKey because of an invalid type of argument', () => {
    // @ts-ignore
    expect(PrivateKey.generate('notAValidType')).to.be.rejectedWith(Error).and.eventually.satisfy(error => {
      assert.include(error.message, 'INVALID_INPUT')
      return true
    })
  })

  it('fail to produce a new PrivateKey with a wrong size', () => {
    // @ts-ignore
    expect(PrivateKey.generate(588)).to.be.rejectedWith(Error).and.eventually.satisfy(error => {
      assert.include(error.message, 'INVALID_INPUT')
      return true
    })
  })

  it('fail to import PrivateKey', () => {
    expect(() => PrivateKey.fromB64(privateKey.toB64().slice(2))).to.throw(Error).and.satisfy(error => {
      assert.include(error.message, 'INVALID_KEY')
      return true
    })
  })

  it('fail to import PrivateKey because of an invalid type', () => {
    // @ts-ignore
    expect(() => new PrivateKey(2)).to.throw(Error).and.satisfy(error => {
      assert.include(error.message, 'INVALID_KEY')
      return true
    })
  })

  it('fail to import PublicKey', () => {
    expect(() => PublicKey.fromB64(privateKey.toB64({ publicOnly: true }).slice(0, -2))).to.throw(Error).and.satisfy(error => {
      assert.include(error.message, 'INVALID_KEY')
      return true
    })
  })

  it('export public key then import', () => {
    const _publicKeyImported = PublicKey.fromB64(privateKey.toB64({ publicOnly: true }))
    const publicKeyImported = PublicKey.fromB64(_publicKeyImported.toB64())
    const publicKeyProperties = ['n', 'e']

    publicKeyProperties.forEach((property) => {
      assert(privateKey.publicKey[property].equals(publicKeyImported.publicKey[property]),
        `${property} doesn't match in both public keys`
      )
    })
  })

  it('export the private key then import it', () => {
    const privateKeyImported = PrivateKey.fromB64(privateKey.toB64())
    const privateKeyProperties = ['n', 'e', 'd', 'p', 'q', 'dP', 'dQ', 'qInv']

    privateKeyProperties.forEach((property) => {
      assert(privateKey.privateKey[property].equals(privateKeyImported.privateKey[property]),
        `${property} doesn't match in both private keys`
      )
    })
  })

  it('cipher & decipher', () => {
    const cipheredMessage = privateKey.encrypt(message)
    assert.isTrue(privateKey.decrypt(cipheredMessage).equals(message), 'Message cannot be deciphered')
  })

  it('cipher & decipher without CRC', () => {
    const cipheredMessage = privateKey.encrypt(message, false)
    assert.isTrue(privateKey.decrypt(cipheredMessage, false).equals(message), 'Message cannot be deciphered')
  })

  it('cipher & decipher with invalid CRC', () => {
    const textToEncrypt = Buffer.concat([intToBuffer(crc32.bstr('ThisIsNotTheClearText')), message])
    const cipheredMessage = Buffer.from(
      privateKey.publicKey.encrypt(textToEncrypt.toString('binary'), 'RSA-OAEP', {
        md: forge.md.sha1.create(),
        mgf1: {
          md: forge.md.sha1.create()
        }
      }),
      'binary'
    )
    expect(() => privateKey.decrypt(cipheredMessage)).to.throw(Error).and.satisfy(error => {
      assert.include(error.message, 'INVALID_CRC32')
      return true
    })
  })

  it('cipher & decipher UTF8', () => {
    const cipheredMessage = privateKey.encrypt(Buffer.from(messageUtf8, 'utf8'))
    const decipheredMessage = privateKey.decrypt(cipheredMessage).toString('utf8')
    assert.strictEqual(decipheredMessage, messageUtf8, 'Message cannot be deciphered')
  })

  it('cipher & decipher binary', () => {
    const cipheredMessage = privateKey.encrypt(messageBinary)
    assert.isTrue(privateKey.decrypt(cipheredMessage).equals(messageBinary), 'Message cannot be deciphered')
  })

  it('fail with bad key', () => {
    const cipheredMessage = privateKey2.encrypt(message)
    expect(() => privateKey.decrypt(cipheredMessage)).to.throw(Error).and.satisfy(error => {
      assert.include(error.message, 'INVALID_CIPHER_TEXT')
      return true
    })
  })

  it('sign & verify', () => {
    const messageSignatureByPrivateKey = privateKey.sign(message)
    assert(privateKey.verify(message, messageSignatureByPrivateKey), 'Signature doesn\'t match')
  })

  it('get hash', () => {
    const hash = privateKey.getHash()
    assert.strictEqual(hash, privateKey.getHash())
    assert.notStrictEqual(hash, privateKey2.getHash())
  })
})
