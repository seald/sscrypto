/* global describe, it */

import * as crypto from 'crypto'
import { SymKey } from './aes-node'
import multipipe from 'multipipe'
import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { _streamHelper, splitLength } from './specUtils.spec'

chai.use(chaiAsPromised)
const { assert, expect } = chai

describe('Crypto - Unit - AES node', () => {
  const key128 = new SymKey(128)
  const key192 = new SymKey(192)
  const key256 = new SymKey(256)
  const badKey = new SymKey(256)

  const message = Buffer.from('TESTtest')

  it('Try creating a key with an invalid type in constructor', () => {
    expect(() => new SymKey('NotAValidType')).to.throw(Error)
  })

  it('Try creating a key with an invalid size', () => {
    expect(() => new SymKey(42)).to.throw(Error)
  })

  it('Try creating a key with an invalid size buffer', () => {
    expect(() => new SymKey(Buffer.from('zkejglzeigh'))).to.throw(Error)
  })

  it('Try deciphering a cipherText with invalid HMAC', () => {
    const cipheredMessage = key256.encrypt(message)
    expect(() => key256.decrypt(cipheredMessage.slice(0, -1))).to.throw(Error)
  })

  it('cipher & decipher 128', () => {
    const cipheredMessage = key128.encrypt(message)
    const decipheredMessage = key128.decrypt(cipheredMessage)
    assert.isTrue(message.equals(decipheredMessage))
  })

  it('cipher & decipher 192', () => {
    const cipheredMessage = key192.encrypt(message)
    const decipheredMessage = key192.decrypt(cipheredMessage)
    assert.isTrue(message.equals(decipheredMessage))
  })

  it('cipher & decipher 256', () => {
    const cipheredMessage = key256.encrypt(message)
    const decipheredMessage = key256.decrypt(cipheredMessage)
    assert.isTrue(message.equals(decipheredMessage))
  })

  it('fail with bad key', () => {
    const cipheredMessage = key256.encrypt(message)
    expect(() => badKey.decrypt(cipheredMessage)).to.throw(Error)
  })

  it('serialize and import key', () => {
    const cipheredMessage = key256.encrypt(message)
    const exportedKey = key256.toB64()
    const importedKey = SymKey.fromB64(exportedKey)
    const decipheredMessage = importedKey.decrypt(cipheredMessage)
    assert.isTrue(message.equals(decipheredMessage))
  })

  it('cipher stream & decipher', () => {
    const input = crypto.randomBytes(100)
    const chunks = splitLength(input, 20)

    const cipher = key256.encryptStream()

    return _streamHelper(chunks, cipher)
      .then(output => {
        assert.isTrue(key256.decrypt(output).equals(input))
      })
  })

  it('Try deciphering a stream with a cipherText with invalid HMAC', () => {
    const cipheredMessage = key256.encrypt(message).slice(0, -1)
    const cipherChunks = splitLength(cipheredMessage, 15)
    const decipher = key256.decryptStream()
    return expect(_streamHelper(cipherChunks, decipher)).to.be.rejectedWith(Error)
  })

  it('cipher & decipher stream', () => {
    const clearText = crypto.randomBytes(1000)
    const cipherText = key256.encrypt(clearText)
    const cipherChunks = splitLength(cipherText, 200)
    const decipher = key256.decryptStream()

    return _streamHelper(cipherChunks, decipher)
      .then(output => {
        assert.isTrue(clearText.equals(output))
      })
  })

  it('cipher stream & decipher stream', () => {
    const input = crypto.randomBytes(100)
    const chunks = splitLength(input, 20)

    const cipher = key256.encryptStream()
    const decipher = key256.decryptStream()

    return _streamHelper(chunks, multipipe(cipher, decipher))
      .then(output => {
        assert.isTrue(output.equals(input))
      })
  })
})
