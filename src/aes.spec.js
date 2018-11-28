'use strict'
/* global describe, it */

import forge from 'node-forge'
import { SymKey } from './aes'
import MemoryStream from 'memorystream'
import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import * as crypto from 'crypto'

chai.use(chaiAsPromised)
const { assert, expect } = chai

/**
 * Should compare the input and the output, and throw an error if the output is not as intended.
 * @callback validationCallback
 * @param {string} input
 * @param {string} output
 */

/**
 * Helper function for the tests.
 * @param {Array<String>} chunks - Array of chunks for the input stream
 * @param {Transform} transformStream - stream.Transform instance
 * @param {validationCallback} validation - Function to validate that the output is like intended
 * @returns {Promise} - Promise that is rejected if the validation function throws an Error, resolved otherwise
 */
const _streamHelper = (chunks, transformStream, validation) => {
  chunks = chunks.map(c => Buffer.from(c, 'binary'))
  const inputStream = new MemoryStream()
  const outputStream = inputStream.pipe(transformStream)
  let outputText = ''

  const finished = new Promise((resolve, reject) => {
    outputStream.on('end', resolve)
    outputStream.on('error', reject)
  })
  outputStream.on('data', data => {
    outputText += data.toString('binary')
  })

  chunks.forEach(chunk => inputStream.write(chunk))
  inputStream.end()

  return finished.then(() => validation(chunks.join(''), outputText))
}

const splitLength = (str, length) => {
  const chunks = []
  while (str.length) {
    chunks.push(str.slice(0, length))
    str = str.slice(length)
  }
  return chunks
}

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
    const chunks = []
    for (let i = 0; i < 5; i++) {
      chunks.push(forge.random.getBytesSync(20))
    }

    const cipher = key.encryptStream()

    return _streamHelper(chunks, cipher, (input, output) => {
      assert.strictEqual(key.decrypt(output), chunks.join(''))
    })
  })

  it('Try deciphering a stream with a cipherText with invalid HMAC', () => {
    const cipheredMessage = key.encrypt(message).slice(0, -1)
    const cipherChunks = splitLength(cipheredMessage, 15)
    const decipher = key.decryptStream()
    return expect(_streamHelper(cipherChunks, decipher, () => {})).to.be.rejectedWith(Error).and.eventually.satisfy(error => {
      assert.include(error.message, 'INVALID_HMAC')
      return true
    })
  })

  it('cipher & decipher stream', () => {
    const clearText = forge.random.getBytesSync(1000)
    const cipherText = key.encrypt(clearText)
    const cipherChunks = splitLength(cipherText, 15)
    const decipher = key.decryptStream()

    return _streamHelper(cipherChunks, decipher, (input, output) => {
      assert.strictEqual(clearText, output)
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
