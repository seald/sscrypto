/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { _streamHelper, splitLength, TestHooks } from './specUtils.spec'
import { SymKey, SymKeyConstructor, SymKeySize } from '../utils/aes'

chai.use(chaiAsPromised)
const { assert, expect } = chai

export const testSymKeyImplem = (name: string, SymKeyClass: SymKeyConstructor<SymKey>, randomBytes: (size: number) => Buffer, { duringBefore, duringAfter }: TestHooks = {}): void => {
  describe(`AES ${name}`, () => {
    const message = Buffer.from('TESTtest', 'ascii')
    const messageUtf8 = 'Iñtërnâtiônàlizætiøn\u2603\uD83D\uDCA9'
    const messageBinary = randomBytes(100)

    before(async () => {
      if (duringBefore) duringBefore()
    })

    after(() => {
      if (duringAfter) duringAfter()
    })

    describe(`AES ${name} - General`, () => {
      it('Try creating a key with an invalid type in constructor', () => {
        // @ts-expect-error
        expect(() => new SymKeyClass({ thisIs: 'NotAValidType' })).to.throw(Error).and.satisfy((error: Error) => {
          assert.include(error.message, 'INVALID_ARG')
          return true
        })
      })

      it('Try creating a key with an invalid size', () => {
        // @ts-expect-error
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
    })

    for (const size of [128, 192, 256] as Array<SymKeySize>) {
      let key: InstanceType<typeof SymKeyClass>
      let badKey: InstanceType<typeof SymKeyClass>

      describe(`AES ${name} - AES-${size}`, () => {
        it('generation', async () => {
          key = await SymKeyClass.generate(size)
          badKey = new SymKeyClass(size) // deprecated usage, but we still have to test it
          assert.instanceOf(key, SymKeyClass)
          assert.instanceOf(badKey, SymKeyClass)
          assert.instanceOf(key, SymKey)
          assert.instanceOf(badKey, SymKey)
          assert.strictEqual(key.keySize, size)
          assert.strictEqual(badKey.keySize, size)
        })

        it('Try deciphering sync a cipherText with invalid HMAC', () => {
          const cipheredMessage = key.encrypt(message)
          expect(() => key.decrypt(cipheredMessage.slice(0, -1))).to.throw(Error).and.satisfy((error: Error) => {
            assert.include(error.message, 'INVALID_HMAC')
            return true
          })
        })

        it('Try deciphering async a cipherText with invalid HMAC', async () => {
          const cipheredMessage = await key.encryptAsync(message)
          await expect(key.decryptAsync(cipheredMessage.slice(0, -1))).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
            assert.include(error.message, 'INVALID_HMAC')
            return true
          })
        })

        it('Try deciphering sync a short invalid cipherText', () => {
          const cipheredMessage = randomBytes(10)
          expect(() => key.decrypt(cipheredMessage.slice(0, -1))).to.throw(Error).and.satisfy((error: Error) => {
            assert.include(error.message, 'INVALID_HMAC')
            return true
          })
        })

        it('Try deciphering async a short invalid cipherText', async () => {
          const cipheredMessage = randomBytes(10)
          await expect(key.decryptAsync(cipheredMessage.slice(0, -1))).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
            assert.include(error.message, 'INVALID_HMAC')
            return true
          })
        })

        it('Try deciphering sync a long invalid cipherText', () => {
          const cipheredMessage = randomBytes(100)
          expect(() => key.decrypt(cipheredMessage.slice(0, -1))).to.throw(Error).and.satisfy((error: Error) => {
            assert.include(error.message, 'INVALID_HMAC')
            return true
          })
        })

        it('Try deciphering async a long invalid cipherText', async () => {
          const cipheredMessage = randomBytes(100)
          await expect(key.decryptAsync(cipheredMessage.slice(0, -1))).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
            assert.include(error.message, 'INVALID_HMAC')
            return true
          })
        })

        it('cipher & decipher sync', () => {
          const cipheredMessage = key.encrypt(message)
          const decipheredMessage = key.decrypt(cipheredMessage)
          assert.isTrue(message.equals(decipheredMessage))
        })

        it('cipher & decipher async', async () => {
          const cipheredMessage = await key.encryptAsync(message)
          const decipheredMessage = await key.decryptAsync(cipheredMessage)
          assert.isTrue(message.equals(decipheredMessage))
        })

        it('cipher & decipher sync UTF8', () => {
          const cipheredMessage = key.encrypt(Buffer.from(messageUtf8, 'utf8'))
          const decipheredMessage = key.decrypt(cipheredMessage).toString('utf8')
          assert.strictEqual(messageUtf8, decipheredMessage)
        })

        it('cipher & decipher async UTF8', async () => {
          const cipheredMessage = await key.encryptAsync(Buffer.from(messageUtf8, 'utf8'))
          const decipheredMessage = (await key.decryptAsync(cipheredMessage)).toString('utf8')
          assert.strictEqual(messageUtf8, decipheredMessage)
        })

        it('cipher & decipher sync Binary', () => {
          const cipheredMessage = key.encrypt(messageBinary)
          const decipheredMessage = key.decrypt(cipheredMessage)
          assert.isTrue(messageBinary.equals(decipheredMessage))
        })

        it('cipher & decipher async Binary', async () => {
          const cipheredMessage = await key.encryptAsync(messageBinary)
          const decipheredMessage = await key.decryptAsync(cipheredMessage)
          assert.isTrue(messageBinary.equals(decipheredMessage))
        })

        it('fail with bad key sync', () => {
          const cipheredMessage = key.encrypt(message)
          expect(() => badKey.decrypt(cipheredMessage)).to.throw(Error).and.satisfy((error: Error) => {
            assert.include(error.message, 'INVALID_HMAC')
            return true
          })
        })

        it('fail with bad key async', async () => {
          const cipheredMessage = await key.encryptAsync(message)
          await expect(badKey.decryptAsync(cipheredMessage)).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
            assert.include(error.message, 'INVALID_HMAC')
            return true
          })
        })

        it('serialize and import key async', async () => {
          const cipheredMessage = await key.encryptAsync(message)
          const exportedKey = key.toB64()
          const importedKey = SymKeyClass.fromB64(exportedKey)
          const decipheredMessage = await importedKey.decryptAsync(cipheredMessage)
          assert.isTrue(message.equals(decipheredMessage))
        })

        it('cipher sync & decipher async', async () => {
          const cipheredMessage = key.encrypt(messageBinary)
          const decipheredMessage = await key.decryptAsync(cipheredMessage)
          assert.isTrue(messageBinary.equals(decipheredMessage))
        })

        it('cipher async & decipher sync', async () => {
          const cipheredMessage = await key.encryptAsync(messageBinary)
          const decipheredMessage = key.decrypt(cipheredMessage)
          assert.isTrue(messageBinary.equals(decipheredMessage))
        })

        it('rawEncrypt & rawDecrypt, sync, async & stream', async () => {
          const input = randomBytes(100)
          const iv = randomBytes(16)
          const cipherSync = key.rawEncryptSync_(input, iv)
          const cipherAsync = await key.rawEncryptAsync_(input, iv)
          const cipherStream = await _streamHelper(
            splitLength(input, 20),
            key.rawEncryptStream_(iv)
          )
          assert.isTrue(cipherSync.equals(cipherAsync))
          assert.isTrue(cipherSync.equals(cipherStream))

          const decipherSync = key.rawDecryptSync_(cipherSync, iv)
          const decipherAsync = await key.rawDecryptAsync_(cipherSync, iv)
          const decipherStream = await _streamHelper(
            splitLength(cipherSync, 20),
            key.rawDecryptStream_(iv)
          )
          assert.isTrue(input.equals(decipherSync))
          assert.isTrue(input.equals(decipherAsync))
          assert.isTrue(input.equals(decipherStream))
        })

        it('rawEncrypt & rawDecrypt, sync, async & stream empty', async () => {
          const input = Buffer.alloc(0)
          const iv = randomBytes(16)
          const cipherSync = key.rawEncryptSync_(input, iv)
          const cipherAsync = await key.rawEncryptAsync_(input, iv)
          const cipherStream = await _streamHelper(
            splitLength(input, 20),
            key.rawEncryptStream_(iv)
          )
          assert.isTrue(cipherSync.equals(cipherAsync))
          assert.isTrue(cipherSync.equals(cipherStream))

          const decipherSync = key.rawDecryptSync_(cipherSync, iv)
          const decipherAsync = await key.rawDecryptAsync_(cipherSync, iv)
          const decipherStream = await _streamHelper(
            splitLength(cipherSync, 20),
            key.rawDecryptStream_(iv)
          )
          assert.isTrue(input.equals(decipherSync))
          assert.isTrue(input.equals(decipherAsync))
          assert.isTrue(input.equals(decipherStream))
        })

        it('rawEncryptStream & rawDecryptStream piped', async () => {
          const input = randomBytes(100)
          const iv = randomBytes(16)
          const output = await _streamHelper(
            splitLength(input, 20),
            key.rawEncryptStream_(iv),
            key.rawDecryptStream_(iv)
          )
          assert.isTrue(input.equals(output))
        })

        it('HMAC sync, async & stream', async () => {
          const input = randomBytes(100)
          const hmacSync = key.calculateHMACSync_(input)
          const hmacAsync = await key.calculateHMACAsync_(input)
          const hmacStream = await _streamHelper(
            splitLength(input, 20),
            key.HMACStream_()
          )
          assert.isTrue(hmacSync.equals(hmacAsync))
          assert.isTrue(hmacSync.equals(hmacStream))
        })

        it('HMAC sync, async & stream empty', async () => {
          const input = Buffer.alloc(0)
          const hmacSync = key.calculateHMACSync_(input)
          const hmacAsync = await key.calculateHMACAsync_(input)
          const hmacStream = await _streamHelper(
            splitLength(input, 20),
            key.HMACStream_()
          )
          assert.isTrue(hmacSync.equals(hmacAsync))
          assert.isTrue(hmacSync.equals(hmacStream))
        })

        it('cipher stream & decipher sync', async () => {
          const input = randomBytes(100)
          const chunks = splitLength(input, 20)

          const cipher = key.encryptStream()

          const output = await _streamHelper(chunks, cipher)
          assert.isTrue(key.decrypt(output).equals(input))
        })

        it('cipher stream & decipher async', async () => {
          const input = randomBytes(100)
          const chunks = splitLength(input, 20)

          const cipher = key.encryptStream()

          const output = await _streamHelper(chunks, cipher)
          assert.isTrue((await key.decryptAsync(output)).equals(input))
        })

        it('cipher short stream (single chunk) & decipher sync', async () => {
          const input = randomBytes(10)
          const chunks = splitLength(input, 100)

          const cipher = key.encryptStream()

          const output = await _streamHelper(chunks, cipher)
          assert.isTrue(key.decrypt(output).equals(input))
        })

        it('cipher short stream (single chunk) & decipher async', async () => {
          const input = randomBytes(10)
          const chunks = splitLength(input, 100)

          const cipher = key.encryptStream()

          const output = await _streamHelper(chunks, cipher)
          assert.isTrue((await key.decryptAsync(output)).equals(input))
        })

        it('cipher empty stream & decipher sync', async () => {
          const input = Buffer.alloc(0)
          const chunks = splitLength(input, 100)

          const cipher = key.encryptStream()

          const output = await _streamHelper(chunks, cipher)
          assert.isTrue(key.decrypt(output).equals(input))
        })

        it('cipher empty stream & decipher async', async () => {
          const input = Buffer.alloc(0)
          const chunks = splitLength(input, 100)

          const cipher = key.encryptStream()

          const output = await _streamHelper(chunks, cipher)
          assert.isTrue((await key.decryptAsync(output)).equals(input))
        })

        it('cipher stream with small blocks & decipher sync', async () => {
          const input = randomBytes(100)
          const chunks = splitLength(input, 10)

          const cipher = key.encryptStream()

          const output = await _streamHelper(chunks, cipher)
          assert.isTrue(key.decrypt(output).equals(input))
        })

        it('cipher stream with small blocks & decipher async', async () => {
          const input = randomBytes(100)
          const chunks = splitLength(input, 10)

          const cipher = key.encryptStream()

          const output = await _streamHelper(chunks, cipher)
          assert.isTrue((await key.decryptAsync(output)).equals(input))
        })

        it('cipher sync & decipher stream', async () => {
          const clearText = randomBytes(1000)
          const cipherText = key.encrypt(clearText)
          const cipherChunks = splitLength(cipherText, 20)
          const decipher = key.decryptStream()

          const output = await _streamHelper(cipherChunks, decipher)
          assert.isTrue(output.equals(clearText))
        })

        it('cipher async & decipher stream', async () => {
          const clearText = randomBytes(1000)
          const cipherText = await key.encryptAsync(clearText)
          const cipherChunks = splitLength(cipherText, 20)
          const decipher = key.decryptStream()

          const output = await _streamHelper(cipherChunks, decipher)
          assert.isTrue(output.equals(clearText))
        })

        it('cipher sync & decipher short stream (single chunk)', async () => {
          const clearText = randomBytes(10)
          const cipherText = key.encrypt(clearText)
          const cipherChunks = splitLength(cipherText, 100)
          const decipher = key.decryptStream()

          const output = await _streamHelper(cipherChunks, decipher)
          assert.isTrue(output.equals(clearText))
        })

        it('cipher async & decipher short stream (single chunk)', async () => {
          const clearText = randomBytes(10)
          const cipherText = await key.encryptAsync(clearText)
          const cipherChunks = splitLength(cipherText, 100)
          const decipher = key.decryptStream()

          const output = await _streamHelper(cipherChunks, decipher)
          assert.isTrue(output.equals(clearText))
        })

        it('cipher sync empty & decipher stream', async () => {
          const clearText = Buffer.alloc(0)
          const cipherText = key.encrypt(clearText)
          const cipherChunks = splitLength(cipherText, 100)
          const decipher = key.decryptStream()

          const output = await _streamHelper(cipherChunks, decipher)
          assert.isTrue(output.equals(clearText))
        })

        it('cipher async empty & decipher stream', async () => {
          const clearText = Buffer.alloc(0)
          const cipherText = await key.encryptAsync(clearText)
          const cipherChunks = splitLength(cipherText, 100)
          const decipher = key.decryptStream()

          const output = await _streamHelper(cipherChunks, decipher)
          assert.isTrue(output.equals(clearText))
        })

        it('cipher sync & decipher stream with small blocks', async () => {
          const clearText = randomBytes(1000)
          const cipherText = key.encrypt(clearText)
          const cipherChunks = splitLength(cipherText, 10)
          const decipher = key.decryptStream()

          const output = await _streamHelper(cipherChunks, decipher)
          assert.isTrue(output.equals(clearText))
        })

        it('cipher async & decipher stream with small blocks', async () => {
          const clearText = randomBytes(1000)
          const cipherText = await key.encryptAsync(clearText)
          const cipherChunks = splitLength(cipherText, 10)
          const decipher = key.decryptStream()

          const output = await _streamHelper(cipherChunks, decipher)
          assert.isTrue(output.equals(clearText))
        })

        it('cipher stream & decipher stream', async () => {
          const input = randomBytes(100)
          const chunks = splitLength(input, 20)

          const cipher = key.encryptStream()
          const decipher = key.decryptStream()

          const output = await _streamHelper(chunks, cipher, decipher)
          assert.isTrue(output.equals(input))
        })

        it('Test encryptStream cancel and progress', async () => {
          const size = 200
          const input = randomBytes(size)
          const chunks = splitLength(input, 20)

          let progress: number
          const error = await new Promise((resolve: (err: Error) => void, reject: (err: Error) => void) => {
            const stream = key.encryptStream()
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
            const stream = key.decryptStream()
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

        it('Test decryptStream error on bad data', async () => {
          const input = randomBytes(100)
          const chunks = splitLength(input, 20)
          const decipher = key.decryptStream()
          await expect(_streamHelper(chunks, decipher)).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
            assert.match(error.message, /INVALID_HMAC|INVALID_STREAM/) // error depends on the implementation :/
            return true
          })
        })

        it('Try deciphering a stream with a cipherText with invalid HMAC', async () => {
          const cipheredMessage = await key.encryptAsync(message)
          cipheredMessage[cipheredMessage.length - 1]++
          const cipherChunks = splitLength(cipheredMessage, 15)
          const decipher = key.decryptStream()
          await expect(_streamHelper(cipherChunks, decipher)).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
            assert.include(error.message, 'INVALID_HMAC')
            return true
          })
        })

        it('Try deciphering empty stream ', async () => {
          const cipherChunks = [Buffer.alloc(0)]
          const decipher = key.decryptStream()
          await expect(_streamHelper(cipherChunks, decipher)).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
            assert.include(error.message, 'INVALID_STREAM')
            return true
          })
        })

        it('Test decryptStream error on short stream', async () => {
          const chunks = [randomBytes(10)]
          const decipher = key.decryptStream()
          await expect(_streamHelper(chunks, decipher)).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
            assert.include(error.message, 'INVALID_STREAM')
            return true
          })
        })

        it('Test decryptStream error on stream of 48b', async () => {
          const chunks = [randomBytes(48)]
          const decipher = key.decryptStream()
          await expect(_streamHelper(chunks, decipher)).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
            assert.match(error.message, /INVALID_HMAC|INVALID_STREAM/) // error depends on the implementation :/
            return true
          })
        })
      })
    }
  })
}

export const testSymKeyCompatibility = (name: string, SymKeyClass1: SymKeyConstructor<SymKey>, SymKeyClass2: SymKeyConstructor<SymKey>, randomBytes: (size: number) => Buffer): void => {
  describe(`AES compatibility ${name}`, () => {
    let key1: SymKey
    let key2: SymKey

    const message = Buffer.from('TESTtest', 'ascii')

    before(async () => {
      key1 = await SymKeyClass1.generate(256)
      key2 = SymKeyClass2.fromString(key1.toString())
    })

    it('cipher 1 & decipher 2 sync', () => {
      const cipheredMessage = key1.encrypt(message)
      const decipheredMessage = key2.decrypt(cipheredMessage)
      assert.isTrue(message.equals(decipheredMessage))
    })

    it('cipher 1 & decipher 2 async', async () => {
      const cipheredMessage = await key1.encryptAsync(message)
      const decipheredMessage = await key2.decryptAsync(cipheredMessage)
      assert.isTrue(message.equals(decipheredMessage))
    })

    it('cipher 2 & decipher 1 sync', () => {
      const cipheredMessage = key2.encrypt(message)
      const decipheredMessage = key1.decrypt(cipheredMessage)
      assert.isTrue(message.equals(decipheredMessage))
    })

    it('cipher 2 & decipher 1 async', async () => {
      const cipheredMessage = await key2.encryptAsync(message)
      const decipheredMessage = await key1.decryptAsync(cipheredMessage)
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

export const testSymKeyPerf = (name: string, SymKeyClass: SymKeyConstructor<SymKey>, randomBytes: (size: number) => Buffer): void => {
  describe(`AES perf ${name}`, function () {
    this.timeout(30000)

    it('Generate keys', async () => {
      const nKeys = 500
      const keys = []
      const start = Date.now()
      for (let i = 0; i < nKeys; i++) {
        keys.push(await SymKeyClass.generate(256))
      }
      const end = Date.now()
      const delta = (end - start) / 1000
      console.log(`Finished generating AES keys for ${name} in ${delta.toFixed(1)}s:\n${(nKeys / delta).toFixed(1)} keys/s`)
    })

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
        const cipherText = keys[i].encrypt(inputs[i])
        const clearText = keys[i].decrypt(cipherText)
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
        const cipherText = await keys[i].encryptAsync(inputs[i])
        const clearText = await keys[i].decryptAsync(cipherText)
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
