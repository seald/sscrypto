'use strict'
/* global describe, it */

import forge from 'node-forge'
import { SymKey } from './aes-forge'
import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import * as crypto from 'crypto'
import { _streamHelper, splitLength } from './specUtils.spec'

chai.use(chaiAsPromised)
const { assert, expect } = chai

describe('Crypto - Unit - AES forge', () => {
  const key = new SymKey(256)
  const badKey = new SymKey(256)

  const message = 'TESTtest'
  const messageUtf8 = 'Iñtërnâtiônàlizætiøn\u2603\uD83D\uDCA9'
  const messageBinary = forge.random.getBytesSync(100)

  it('Try creating a key with an invalid type in constructor', () => {
    expect(() => new SymKey({ thisIs: 'NotAValidType' })).to.throw(Error).and.satisfy(error => {
      assert.include(error.message, 'INVALID_ARG')
      return true
    })
  })

  it('Try creating a key with an invalid size', () => {
    expect(() => new SymKey(42)).to.throw(Error).and.satisfy(error => {
      assert.include(error.message, 'INVALID_ARG')
      return true
    })
  })

  it('Try creating a key with an invalid size string', () => {
    expect(() => new SymKey('zkejglzeigh')).to.throw(Error).and.satisfy(error => {
      assert.include(error.message, 'INVALID_ARG')
      return true
    })
  })

  it('Try deciphering a cipherText with invalid HMAC', () => {
    const cipheredMessage = key.encrypt(message)
    expect(() => key.decrypt(cipheredMessage.slice(0, -1))).to.throw(Error).and.satisfy(error => {
      assert.include(error.message, 'INVALID_HMAC')
      return true
    })
  })

  it('cipher & decipher', () => {
    const cipheredMessage = key.encrypt(message)
    const decipheredMessage = key.decrypt(cipheredMessage)
    assert.strictEqual(message, decipheredMessage)
  })

  it('cipher & decipher UTF8', () => {
    const cipheredMessage = key.encrypt(Buffer.from(messageUtf8, 'utf8').toString('binary'))
    const decipheredMessage = Buffer.from(key.decrypt(cipheredMessage), 'binary').toString('utf8')
    assert.strictEqual(messageUtf8, decipheredMessage)
  })

  it('cipher & decipher Binary', () => {
    // noinspection JSCheckFunctionSignatures
    const cipheredMessage = key.encrypt(messageBinary)
    const decipheredMessage = key.decrypt(cipheredMessage)
    assert.strictEqual(messageBinary, decipheredMessage)
  })

  it('fail with bad key', () => {
    const cipheredMessage = key.encrypt(message)
    expect(() => badKey.decrypt(cipheredMessage)).to.throw(Error).and.satisfy(error => {
      assert.include(error.message, 'INVALID_HMAC')
      return true
    })
  })

  it('serialize and import key', () => {
    const cipheredMessage = key.encrypt(message)
    const exportedKey = key.serialize()
    const importedKey = SymKey.fromB64(exportedKey)
    const decipheredMessage = importedKey.decrypt(cipheredMessage)
    assert.strictEqual(message, decipheredMessage)
  })

  it('cipher stream & decipher', () => {
    const input = crypto.randomBytes(100)
    const chunks = splitLength(input, 20)

    const cipher = key.encryptStream()

    return _streamHelper(chunks, cipher).then((output) => {
      assert.isTrue(Buffer.from(key.decrypt(output.toString('binary')), 'binary').equals(input))
    })
  })

  it('Try deciphering a stream with a cipherText with invalid HMAC', () => {
    const cipheredMessage = key.encrypt(message).slice(0, -1).toString('binary')
    const cipherChunks = splitLength(cipheredMessage, 15)
    const decipher = key.decryptStream()
    return expect(_streamHelper(cipherChunks, decipher)).to.be.rejectedWith(Error).and.eventually.satisfy(error => {
      assert.include(error.message, 'INVALID_HMAC')
      return true
    })
  })

  it('cipher & decipher stream', () => {
    const clearText = crypto.randomBytes(1000)
    const cipherText = Buffer.from(key.encrypt(clearText.toString('binary')), 'binary')
    const cipherChunks = splitLength(cipherText, 15)
    const decipher = key.decryptStream()

    return _streamHelper(cipherChunks, decipher).then((output) => {
      assert.isTrue(output.equals(clearText))
    })
  })

  it('Test encryptStream cancel and progress', async () => {
    const size = 200
    const input = crypto.randomBytes(size)
    const chunks = splitLength(input, 20)

    let progress

    const error = await new Promise(async (resolve, reject) => {
      const stream = key.encryptStream()
        .on('end', reject)
        .on('error', resolve)
        .on('progress', _progress => {
          progress = _progress
        })
      for (const chunk of chunks) stream.write(chunk)
      stream.emit('cancel')
      for (const chunk of chunks) stream.write(chunk)
    })
    if (!progress) throw new Error('Stream hasn\'t worked at all')
    if (progress > size) throw new Error('Stream has\'t been canceled')
    assert.include(error.message, 'STREAM_CANCELED')
  })

  it('Test decryptStream cancel and progress', async () => {
    const size = 200
    const input = crypto.randomBytes(size)
    const chunks = splitLength(input, 20)

    let progress

    const error = await new Promise(async (resolve, reject) => {
      const stream = key.decryptStream()
        .on('end', reject)
        .on('error', resolve)
        .on('progress', _progress => {
          progress = _progress
        })
      for (const chunk of chunks) stream.write(chunk)
      stream.emit('cancel')
      for (const chunk of chunks) stream.write(chunk)
    })
    if (!progress) throw new Error('Stream hasn\'t worked at all')
    if (progress > size) throw new Error('Stream has\'t been canceled')
    assert.include(error.message, 'STREAM_CANCELED')
  })
})
