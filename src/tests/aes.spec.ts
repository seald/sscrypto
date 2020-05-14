/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { _streamHelper, splitLength, TestHooks } from './specUtils.spec'
import { SymKey, SymKeyConstructor } from '../utils/aes'

chai.use(chaiAsPromised)
const { assert, expect } = chai

export const testSymKeyImplem = (name: string, SymKeyClass: SymKeyConstructor, randomBytes: (size: number) => Buffer, { duringBefore, duringAfter }: TestHooks = {}): void => {
  describe(`AES ${name}`, () => {
    let key128: SymKey
    let key192: SymKey
    let key256: SymKey
    let badKey: SymKey

    const message = Buffer.from('TESTtest', 'ascii')
    const messageUtf8 = 'Iñtërnâtiônàlizætiøn\u2603\uD83D\uDCA9'
    const messageBinary = randomBytes(100)

    before(async () => {
      key128 = await SymKeyClass.generate(128)
      key192 = await SymKeyClass.generate(192)
      key256 = await SymKeyClass.generate(256)
      badKey = await SymKeyClass.generate(256)
      if (duringBefore) duringBefore()
    })

    after(() => {
      if (duringAfter) duringAfter()
    })

    it('Try creating a key with an invalid type in constructor', () => {
      // @ts-ignore: voluntary test of what happens with bad type
      expect(() => new SymKeyClass({ thisIs: 'NotAValidType' })).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_ARG')
        return true
      })
    })

    it('Try creating a key with an invalid size', () => {
      // @ts-ignore: voluntary test of what happens with bad type
      expect(() => new SymKeyClass(42)).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_ARG')
        return true
      })
    })

    it('Try creating a key with an invalid size buffer', () => {
      expect(() => new SymKeyClass(Buffer.from('zkejglzeigh', 'binary'))).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_ARG')
        return true
      })
    })

    it('Try deciphering sync a cipherText with invalid HMAC', () => {
      const cipheredMessage = key256.encryptSync(message)
      expect(() => key256.decryptSync(cipheredMessage.slice(0, -1))).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_HMAC')
        return true
      })
    })

    it('Try deciphering a cipherText with invalid HMAC', async () => {
      const cipheredMessage = await key256.encrypt(message)
      await expect(key256.decrypt(cipheredMessage.slice(0, -1))).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_HMAC')
        return true
      })
    })

    it('cipher & decipher sync 128', () => {
      const cipheredMessage = key128.encryptSync(message)
      const decipheredMessage = key128.decryptSync(cipheredMessage)
      assert.isTrue(message.equals(decipheredMessage))
    })

    it('cipher & decipher 128', async () => {
      const cipheredMessage = await key128.encrypt(message)
      const decipheredMessage = await key128.decrypt(cipheredMessage)
      assert.isTrue(message.equals(decipheredMessage))
    })

    it('cipher & decipher sync 192', () => {
      const cipheredMessage = key192.encryptSync(message)
      const decipheredMessage = key192.decryptSync(cipheredMessage)
      assert.isTrue(message.equals(decipheredMessage))
    })

    it('cipher & decipher 192', async () => {
      const cipheredMessage = await key192.encrypt(message)
      const decipheredMessage = await key192.decrypt(cipheredMessage)
      assert.isTrue(message.equals(decipheredMessage))
    })

    it('cipher & decipher sync 256', () => {
      const cipheredMessage = key256.encryptSync(message)
      const decipheredMessage = key256.decryptSync(cipheredMessage)
      assert.isTrue(message.equals(decipheredMessage))
    })

    it('cipher & decipher 256', async () => {
      const cipheredMessage = await key256.encrypt(message)
      const decipheredMessage = await key256.decrypt(cipheredMessage)
      assert.isTrue(message.equals(decipheredMessage))
    })

    it('cipher & decipher sync UTF8', () => {
      const cipheredMessage = key256.encryptSync(Buffer.from(messageUtf8, 'utf8'))
      const decipheredMessage = key256.decryptSync(cipheredMessage).toString('utf8')
      assert.strictEqual(messageUtf8, decipheredMessage)
    })

    it('cipher & decipher UTF8', async () => {
      const cipheredMessage = await key256.encrypt(Buffer.from(messageUtf8, 'utf8'))
      const decipheredMessage = (await key256.decrypt(cipheredMessage)).toString('utf8')
      assert.strictEqual(messageUtf8, decipheredMessage)
    })

    it('cipher & decipher sync Binary', () => {
      const cipheredMessage = key256.encryptSync(messageBinary)
      const decipheredMessage = key256.decryptSync(cipheredMessage)
      assert.isTrue(messageBinary.equals(decipheredMessage))
    })

    it('cipher & decipher Binary', async () => {
      const cipheredMessage = await key256.encrypt(messageBinary)
      const decipheredMessage = await key256.decrypt(cipheredMessage)
      assert.isTrue(messageBinary.equals(decipheredMessage))
    })

    it('fail with bad key sync', () => {
      const cipheredMessage = key256.encryptSync(message)
      expect(() => badKey.decryptSync(cipheredMessage)).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_HMAC')
        return true
      })
    })

    it('fail with bad key', async () => {
      const cipheredMessage = await key256.encrypt(message)
      await expect(badKey.decrypt(cipheredMessage)).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_HMAC')
        return true
      })
    })

    it('serialize and import key', async () => {
      const cipheredMessage = await key256.encrypt(message)
      const exportedKey = key256.toB64()
      const importedKey = SymKeyClass.fromB64(exportedKey)
      const decipheredMessage = await importedKey.decrypt(cipheredMessage)
      assert.isTrue(message.equals(decipheredMessage))
    })

    it('cipher sync & decipher async', async () => {
      const cipheredMessage = key256.encryptSync(messageBinary)
      const decipheredMessage = await key256.decrypt(cipheredMessage)
      assert.isTrue(messageBinary.equals(decipheredMessage))
    })

    it('cipher async & decipher sync', async () => {
      const cipheredMessage = await key256.encrypt(messageBinary)
      const decipheredMessage = key256.decryptSync(cipheredMessage)
      assert.isTrue(messageBinary.equals(decipheredMessage))
    })

    it('cipher stream & decipher sync', async () => {
      const input = randomBytes(100)
      const chunks = splitLength(input, 20)

      const cipher = key256.encryptStream()

      const output = await _streamHelper(chunks, cipher)
      assert.isTrue(key256.decryptSync(output).equals(input))
    })

    it('cipher stream & decipher', async () => {
      const input = randomBytes(100)
      const chunks = splitLength(input, 20)

      const cipher = key256.encryptStream()

      const output = await _streamHelper(chunks, cipher)
      assert.isTrue((await key256.decrypt(output)).equals(input))
    })

    it('cipher short stream (single chunk) & decipher sync', async () => {
      const input = randomBytes(10)
      const chunks = splitLength(input, 100)

      const cipher = key256.encryptStream()

      const output = await _streamHelper(chunks, cipher)
      assert.isTrue(key256.decryptSync(output).equals(input))
    })

    it('cipher short stream (single chunk) & decipher', async () => {
      const input = randomBytes(10)
      const chunks = splitLength(input, 100)

      const cipher = key256.encryptStream()

      const output = await _streamHelper(chunks, cipher)
      assert.isTrue((await key256.decrypt(output)).equals(input))
    })

    it('cipher stream with small blocks & decipher sync', async () => {
      const input = randomBytes(100)
      const chunks = splitLength(input, 10)

      const cipher = key256.encryptStream()

      const output = await _streamHelper(chunks, cipher)
      assert.isTrue(key256.decryptSync(output).equals(input))
    })

    it('cipher stream with small blocks & decipher', async () => {
      const input = randomBytes(100)
      const chunks = splitLength(input, 10)

      const cipher = key256.encryptStream()

      const output = await _streamHelper(chunks, cipher)
      assert.isTrue((await key256.decrypt(output)).equals(input))
    })

    it('cipher sync & decipher stream', async () => {
      const clearText = randomBytes(1000)
      const cipherText = key256.encryptSync(clearText)
      const cipherChunks = splitLength(cipherText, 20)
      const decipher = key256.decryptStream()

      const output = await _streamHelper(cipherChunks, decipher)
      assert.isTrue(output.equals(clearText))
    })

    it('cipher & decipher stream', async () => {
      const clearText = randomBytes(1000)
      const cipherText = await key256.encrypt(clearText)
      const cipherChunks = splitLength(cipherText, 20)
      const decipher = key256.decryptStream()

      const output = await _streamHelper(cipherChunks, decipher)
      assert.isTrue(output.equals(clearText))
    })

    it('cipher sync & decipher short stream (single chunk)', async () => {
      const clearText = randomBytes(10)
      const cipherText = key256.encryptSync(clearText)
      const cipherChunks = splitLength(cipherText, 100)
      const decipher = key256.decryptStream()

      const output = await _streamHelper(cipherChunks, decipher)
      assert.isTrue(output.equals(clearText))
    })

    it('cipher & decipher short stream (single chunk)', async () => {
      const clearText = randomBytes(10)
      const cipherText = await key256.encrypt(clearText)
      const cipherChunks = splitLength(cipherText, 100)
      const decipher = key256.decryptStream()

      const output = await _streamHelper(cipherChunks, decipher)
      assert.isTrue(output.equals(clearText))
    })

    it('cipher sync & decipher stream with small blocks', async () => {
      const clearText = randomBytes(1000)
      const cipherText = key256.encryptSync(clearText)
      const cipherChunks = splitLength(cipherText, 10)
      const decipher = key256.decryptStream()

      const output = await _streamHelper(cipherChunks, decipher)
      assert.isTrue(output.equals(clearText))
    })

    it('cipher & decipher stream with small blocks', async () => {
      const clearText = randomBytes(1000)
      const cipherText = await key256.encrypt(clearText)
      const cipherChunks = splitLength(cipherText, 10)
      const decipher = key256.decryptStream()

      const output = await _streamHelper(cipherChunks, decipher)
      assert.isTrue(output.equals(clearText))
    })

    it('cipher stream & decipher stream', async () => {
      const input = randomBytes(100)
      const chunks = splitLength(input, 20)

      const cipher = key256.encryptStream()
      const decipher = key256.decryptStream()

      const output = await _streamHelper(chunks, cipher, decipher)
      assert.isTrue(output.equals(input))
    })

    it('Try deciphering a stream with a cipherText with invalid HMAC', async () => {
      const cipheredMessage = await key256.encrypt(message)
      cipheredMessage[cipheredMessage.length - 1]++
      const cipherChunks = splitLength(cipheredMessage, 15)
      const decipher = key256.decryptStream()
      await expect(_streamHelper(cipherChunks, decipher)).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_HMAC')
        return true
      })
    })

    it('Test encryptStream cancel and progress', async () => {
      const size = 200
      const input = randomBytes(size)
      const chunks = splitLength(input, 20)

      let progress: number

      const error = await new Promise((resolve: (err: Error) => void, reject: (err: Error) => void) => {
        const stream = key256.encryptStream()
          .on('end', () => reject(new Error('stream succeeded')))
          .on('error', resolve)
          .on('progress', _progress => {
            progress = _progress
          })
        for (const chunk of chunks) stream.write(chunk)
        stream.emit('cancel')
        for (const chunk of chunks) stream.write(chunk)
      })
      if (progress === undefined) throw new Error('Stream hasn\'t worked at all')
      if (progress > size) throw new Error('Stream has\'t been canceled')
      assert.include(error.message, 'STREAM_CANCELED')
    })

    it('Test decryptStream cancel and progress', async () => {
      const size = 200
      const input = randomBytes(size)
      const chunks = splitLength(input, 20)

      let progress: number

      const error = await new Promise((resolve: (err: Error) => void, reject: (err: Error) => void) => {
        const stream = key256.decryptStream()
          .on('end', () => reject(new Error('stream succeeded')))
          .on('error', resolve)
          .on('progress', _progress => {
            progress = _progress
          })
        for (const chunk of chunks) stream.write(chunk)
        stream.emit('cancel')
        for (const chunk of chunks) stream.write(chunk)
      })
      if (progress === undefined) throw new Error('Stream hasn\'t worked at all')
      if (progress > size) throw new Error('Stream has\'t been canceled')
      assert.include(error.message, 'STREAM_CANCELED')
    })
  })
}

export const testSymKeyCompatibility = (name: string, SymKeyClass1: SymKeyConstructor, SymKeyClass2: SymKeyConstructor, randomBytes: (size: number) => Buffer): void => {
  describe(`AES compatibility ${name}`, () => {
    let key1: SymKey
    let key2: SymKey

    const message = Buffer.from('TESTtest', 'ascii')

    before(async () => {
      key1 = await SymKeyClass1.generate(256)
      key2 = SymKeyClass2.fromString(key1.toString())
    })

    it('cipher 1 & decipher 2 sync', () => {
      const cipheredMessage = key1.encryptSync(message)
      const decipheredMessage = key2.decryptSync(cipheredMessage)
      assert.isTrue(message.equals(decipheredMessage))
    })

    it('cipher 1 & decipher 2 async', async () => {
      const cipheredMessage = await key1.encrypt(message)
      const decipheredMessage = await key2.decrypt(cipheredMessage)
      assert.isTrue(message.equals(decipheredMessage))
    })

    it('cipher 2 & decipher 1 sync', () => {
      const cipheredMessage = key2.encryptSync(message)
      const decipheredMessage = key1.decryptSync(cipheredMessage)
      assert.isTrue(message.equals(decipheredMessage))
    })

    it('cipher 2 & decipher 1 async', async () => {
      const cipheredMessage = await key2.encrypt(message)
      const decipheredMessage = await key1.decrypt(cipheredMessage)
      assert.isTrue(message.equals(decipheredMessage))
    })

    it('cipher stream 1 & decipher stream 2', () => {
      const input = randomBytes(100)
      const chunks = splitLength(input, 20)

      const cipher = key1.encryptStream()
      const decipher = key2.decryptStream()

      return _streamHelper(chunks, cipher, decipher)
        .then(output => {
          assert.isTrue(output.equals(input))
        })
    })

    it('cipher stream 2 & decipher stream 1', () => {
      const input = randomBytes(100)
      const chunks = splitLength(input, 20)

      const cipher = key2.encryptStream()
      const decipher = key1.decryptStream()

      return _streamHelper(chunks, cipher, decipher)
        .then(output => {
          assert.isTrue(output.equals(input))
        })
    })
  })
}

export const testSymKeyPerf = (name: string, SymKeyClass: SymKeyConstructor, randomBytes: (size: number) => Buffer): void => {
  describe(`AES perf ${name}`, function () {
    this.timeout(30000)

    it('Encrypt/Decrypt sync perf', async () => {
      const inputSize = 10000
      const nInput = 500
      const inputs = []
      const keys = []
      for (let i = 0; i < nInput; i++) {
        keys.push(await SymKeyClass.generate(256))
        inputs.push(randomBytes(inputSize))
      }
      const start = Date.now()
      for (let i = 0; i < nInput; i++) {
        const cipherText = keys[i].encryptSync(inputs[i])
        const clearText = keys[i].decryptSync(cipherText)
        assert.isOk(clearText.equals(inputs[i]))
      }
      const end = Date.now()
      const delta = (end - start) / 1000
      console.log(`Finished in ${delta.toFixed(1)}s:\n${(nInput / delta).toFixed(1)} block/s\n${(nInput * inputSize / delta / 1000000).toFixed(1)} MB/s`)
    })

    it('Encrypt/Decrypt async perf', async () => {
      const inputSize = 10000
      const nInput = 500
      const inputs = []
      const keys = []
      for (let i = 0; i < nInput; i++) {
        keys.push(await SymKeyClass.generate(256))
        inputs.push(randomBytes(inputSize))
      }
      const start = Date.now()
      for (let i = 0; i < nInput; i++) {
        const cipherText = await keys[i].encrypt(inputs[i])
        const clearText = await keys[i].decrypt(cipherText)
        assert.isOk(clearText.equals(inputs[i]))
      }
      const end = Date.now()
      const delta = (end - start) / 1000
      console.log(`Finished in ${delta.toFixed(1)}s:\n${(nInput / delta).toFixed(1)} block/s\n${(nInput * inputSize / delta / 1000000).toFixed(1)} MB/s`)
    })

    it('Encrypt/Decrypt stream perf', async () => {
      const totalSize = 10e6
      const input = Buffer.alloc(totalSize).fill(randomBytes(1000))

      const k = await SymKeyClass.generate(256)

      const chunksClear = splitLength(input, 256 * 1024)
      const startEncrypt = Date.now()
      const encrypted = await _streamHelper(chunksClear, k.encryptStream())
      const endEncrypt = Date.now()
      const deltaEncrypt = (endEncrypt - startEncrypt) / 1000
      console.log(`Finished encrypting in ${deltaEncrypt.toFixed(1)}s:\n${(totalSize / deltaEncrypt / 1000000).toFixed(1)} MB/s`)

      const chunksEncrypted = splitLength(encrypted, 256 * 1024)
      const startDecrypt = Date.now()
      const decrypted = await _streamHelper(chunksEncrypted, k.decryptStream())
      const endDecrypt = Date.now()
      const deltaDecrypt = (endDecrypt - startDecrypt) / 1000
      console.log(`Finished decrypting in ${deltaDecrypt.toFixed(1)}s:\n${(totalSize / deltaDecrypt / 1000000).toFixed(1)} MB/s`)

      assert.isOk(decrypted.equals(input))
    })
  })
}
