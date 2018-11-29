/* global describe, it, before */

import forge from 'node-forge'
import { PrivateKey, PublicKey } from './rsa'
import { intToBytes } from './utils'
import crc32 from 'crc-32'
import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'

chai.use(chaiAsPromised)
const { assert, expect } = chai

describe('Crypto - Unit - RSA', () => {
  let privateKey, privateKey2
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

  // noinspection SpellCheckingInspection
  const message = 'TESTtest'
  // noinspection SpellCheckingInspection
  const messageUtf8 = 'Iñtërnâtiônàlizætiøn\u2603\uD83D\uDCA9'
  const messageBinary = forge.random.getBytesSync(32)

  it('Fail to construct a PublicKey because of an invalid type of argument', () => {
    expect(PrivateKey.generate('notAValidType')).to.be.rejectedWith(Error).and.eventually.satisfy(error => {
      assert.include(error.message, 'INVALID_INPUT')
      return true
    })
  })

  it('fail to produce a new PrivateKey with a wrong size', () => {
    expect(PrivateKey.generate(588)).to.be.rejectedWith(Error).and.eventually.satisfy(error => {
      assert.include(error.message, 'INVALID_INPUT')
      return true
    })
  })

  it('fail to import PrivateKey', () => {
    expect(() => PrivateKey.from(privateKey.serialize().slice(0, -2))).to.throw(Error).and.satisfy(error => {
      assert.include(error.message, 'INVALID_KEY')
      return true
    })
  })

  it('fail to import PrivateKey because of an invalid type', () => {
    expect(() => new PrivateKey(2)).to.throw(Error).and.satisfy(error => {
      assert.include(error.message, 'INVALID_KEY')
      return true
    })
  })

  it('fail to import PublicKey', () => {
    expect(() => PublicKey.from(privateKey.serialize({ publicOnly: true }).slice(0, -2))).to.throw(Error).and.satisfy(error => {
      assert.include(error.message, 'INVALID_KEY')
      return true
    })
  })

  it('export public key then import', () => {
    const _publicKeyImported = PublicKey.from(privateKey.serialize({ publicOnly: true }))
    const publicKeyImported = PublicKey.from(_publicKeyImported.serialize())
    const publicKeyProperties = ['n', 'e']

    publicKeyProperties.forEach((property) => {
      assert(privateKey.publicKey[property].equals(publicKeyImported.publicKey[property]),
        `${property} doesn't match in both public keys`
      )
    })
  })

  it('export the private key then import it', () => {
    const privateKeyImported = PrivateKey.from(privateKey.serialize())
    const privateKeyProperties = ['n', 'e', 'd', 'p', 'q', 'dP', 'dQ', 'qInv']

    privateKeyProperties.forEach((property) => {
      assert(privateKey.privateKey[property].equals(privateKeyImported.privateKey[property]),
        `${property} doesn't match in both private keys`
      )
    })
  })

  it('cipher & decipher', () => {
    const cipheredMessage = privateKey.encrypt(message)
    assert.strictEqual(privateKey.decrypt(cipheredMessage), message, 'Message cannot be deciphered')
  })

  it('cipher & decipher without CRC', () => {
    const cipheredMessage = privateKey.encrypt(message, false)
    assert.strictEqual(privateKey.decrypt(cipheredMessage, false), message, 'Message cannot be deciphered')
  })

  it('cipher & decipher with invalid CRC', () => {
    const textToEncrypt = intToBytes(crc32.bstr('ThisIsNotTheClearText')) + message
    // noinspection JSCheckFunctionSignatures
    const cipheredMessage = privateKey.publicKey.encrypt(textToEncrypt, 'RSA-OAEP', {
      md: forge.md.sha1.create(),
      mgf1: {
        md: forge.md.sha1.create()
      }
    })
    expect(() => privateKey.decrypt(cipheredMessage)).to.throw(Error).and.satisfy(error => {
      assert.include(error.message, 'INVALID_CRC32')
      return true
    })
  })

  it('cipher & decipher UTF8', () => {
    const cipheredMessage = privateKey.encrypt(Buffer.from(messageUtf8, 'utf8').toString('binary'))
    const decipheredMessage = Buffer.from(privateKey.decrypt(cipheredMessage), 'binary').toString('utf8')
    assert.strictEqual(decipheredMessage, messageUtf8, 'Message cannot be deciphered')
  })

  it('cipher & decipher binary', () => {
    // noinspection JSCheckFunctionSignatures
    const cipheredMessage = privateKey.encrypt(messageBinary)
    assert.strictEqual(privateKey.decrypt(cipheredMessage), messageBinary, 'Message cannot be deciphered')
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
    assert.notEqual(hash, privateKey2.getHash())
  })
})
