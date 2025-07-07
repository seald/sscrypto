/* eslint-env mocha */

import { _streamHelper, splitLength, TestHooks } from './specUtils.spec'
import { SymKey, SymKeyConstructor, SymKeySize } from '../utils/aes'
import assert from 'assert'

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
        assert.throws(
          // @ts-expect-error
          () => new SymKeyClass({ thisIs: 'NotAValidType' }),
          /INVALID_ARG/
        )
      })

      it('Try creating a key with an invalid size', () => {
        assert.throws(
          // @ts-expect-error
          () => new SymKeyClass({ thisIs: 42 }),
          /INVALID_ARG/
        )
      })

      it('Try creating a key with an invalid size buffer', () => {
        assert.throws(
          () => new SymKeyClass(Buffer.from('zkejglzeigh', 'binary')),
          /INVALID_ARG/
        )
      })
    })

    for (const size of [128, 192, 256] as Array<SymKeySize>) {
      let key: InstanceType<typeof SymKeyClass>
      let badKey: InstanceType<typeof SymKeyClass>

      describe(`AES ${name} - AES-${size}`, () => {
        it('generation', async () => {
          key = await SymKeyClass.generate(size)
          badKey = new SymKeyClass(size) // deprecated usage, but we still have to test it
          assert.ok(key instanceof SymKeyClass)
          assert.ok(badKey instanceof SymKeyClass)
          assert.ok(key instanceof SymKey)
          assert.ok(badKey instanceof SymKey)
          assert.strictEqual(key.keySize, size)
          assert.strictEqual(badKey.keySize, size)
        })

        it('Try deciphering sync a cipherText with invalid HMAC', () => {
          const cipheredMessage = key.encrypt(message)
          assert.throws(
            () => key.decrypt(cipheredMessage.slice(0, -1)),
            /INVALID_HMAC/
          )
        })

        it('Try deciphering async a cipherText with invalid HMAC', async () => {
          const cipheredMessage = await key.encryptAsync(message)
          await assert.rejects(
            key.decryptAsync(cipheredMessage.slice(0, -1)),
            /INVALID_HMAC/
          )
        })

        it('Try deciphering sync a short invalid cipherText', () => {
          const cipheredMessage = randomBytes(10)
          assert.throws(
            () => key.decrypt(cipheredMessage.slice(0, -1)),
            /INVALID_HMAC/
          )
        })

        it('Try deciphering async a short invalid cipherText', async () => {
          const cipheredMessage = randomBytes(10)
          await assert.rejects(
            key.decryptAsync(cipheredMessage.slice(0, -1)),
            /INVALID_HMAC/
          )
        })

        it('Try deciphering sync a long invalid cipherText', () => {
          const cipheredMessage = randomBytes(100)
          assert.throws(
            () => key.decrypt(cipheredMessage.slice(0, -1)),
            /INVALID_HMAC/
          )
        })

        it('Try deciphering async a long invalid cipherText', async () => {
          const cipheredMessage = randomBytes(100)
          await assert.rejects(
            key.decryptAsync(cipheredMessage.slice(0, -1)),
            /INVALID_HMAC/
          )
        })

        it('cipher & decipher sync', () => {
          const cipheredMessage = key.encrypt(message)
          const decipheredMessage = key.decrypt(cipheredMessage)
          assert.ok(message.equals(decipheredMessage))
        })

        it('cipher & decipher async', async () => {
          const cipheredMessage = await key.encryptAsync(message)
          const decipheredMessage = await key.decryptAsync(cipheredMessage)
          assert.ok(message.equals(decipheredMessage))
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
          assert.ok(messageBinary.equals(decipheredMessage))
        })

        it('cipher & decipher async Binary', async () => {
          const cipheredMessage = await key.encryptAsync(messageBinary)
          const decipheredMessage = await key.decryptAsync(cipheredMessage)
          assert.ok(messageBinary.equals(decipheredMessage))
        })

        it('fail with bad key sync', () => {
          const cipheredMessage = key.encrypt(message)
          assert.throws(
            () => badKey.decrypt(cipheredMessage),
            /INVALID_HMAC/
          )
        })

        it('fail with bad key async', async () => {
          const cipheredMessage = await key.encryptAsync(message)
          await assert.rejects(
            badKey.decryptAsync(cipheredMessage),
            /INVALID_HMAC/
          )
        })

        it('serialize and import key async', async () => {
          const cipheredMessage = await key.encryptAsync(message)
          const exportedKey = key.toB64()
          const importedKey = SymKeyClass.fromB64(exportedKey)
          const decipheredMessage = await importedKey.decryptAsync(cipheredMessage)
          assert.ok(message.equals(decipheredMessage))
        })

        it('serialize and import key with toString', async () => {
          const cipheredMessage = await key.encryptAsync(message)
          const exportedKey = key.toString()
          const importedKey = new SymKeyClass(Buffer.from(exportedKey, 'binary'))
          const decipheredMessage = await importedKey.decryptAsync(cipheredMessage)
          assert.ok(message.equals(decipheredMessage))
        })

        it('cipher sync & decipher async', async () => {
          const cipheredMessage = key.encrypt(messageBinary)
          const decipheredMessage = await key.decryptAsync(cipheredMessage)
          assert.ok(messageBinary.equals(decipheredMessage))
        })

        it('cipher async & decipher sync', async () => {
          const cipheredMessage = await key.encryptAsync(messageBinary)
          const decipheredMessage = key.decrypt(cipheredMessage)
          assert.ok(messageBinary.equals(decipheredMessage))
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
          assert.ok(cipherSync.equals(cipherAsync))
          assert.ok(cipherSync.equals(cipherStream))

          const decipherSync = key.rawDecryptSync_(cipherSync, iv)
          const decipherAsync = await key.rawDecryptAsync_(cipherSync, iv)
          const decipherStream = await _streamHelper(
            splitLength(cipherSync, 20),
            key.rawDecryptStream_(iv)
          )
          assert.ok(input.equals(decipherSync))
          assert.ok(input.equals(decipherAsync))
          assert.ok(input.equals(decipherStream))
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
          assert.ok(cipherSync.equals(cipherAsync))
          assert.ok(cipherSync.equals(cipherStream))

          const decipherSync = key.rawDecryptSync_(cipherSync, iv)
          const decipherAsync = await key.rawDecryptAsync_(cipherSync, iv)
          const decipherStream = await _streamHelper(
            splitLength(cipherSync, 20),
            key.rawDecryptStream_(iv)
          )
          assert.ok(input.equals(decipherSync))
          assert.ok(input.equals(decipherAsync))
          assert.ok(input.equals(decipherStream))
        })

        it('rawEncryptStream & rawDecryptStream piped', async () => {
          const input = randomBytes(100)
          const iv = randomBytes(16)
          const output = await _streamHelper(
            splitLength(input, 20),
            key.rawEncryptStream_(iv),
            key.rawDecryptStream_(iv)
          )
          assert.ok(input.equals(output))
        })

        it('HMAC sync, async & stream', async () => {
          const input = randomBytes(100)
          const hmacSync = key.calculateHMACSync_(input)
          const hmacAsync = await key.calculateHMACAsync_(input)
          const hmacStream = await _streamHelper(
            splitLength(input, 20),
            key.HMACStream_()
          )
          assert.ok(hmacSync.equals(hmacAsync))
          assert.ok(hmacSync.equals(hmacStream))
        })

        it('HMAC sync, async & stream empty', async () => {
          const input = Buffer.alloc(0)
          const hmacSync = key.calculateHMACSync_(input)
          const hmacAsync = await key.calculateHMACAsync_(input)
          const hmacStream = await _streamHelper(
            splitLength(input, 20),
            key.HMACStream_()
          )
          assert.ok(hmacSync.equals(hmacAsync))
          assert.ok(hmacSync.equals(hmacStream))
        })

        it('cipher stream & decipher sync', async () => {
          const input = randomBytes(100)
          const chunks = splitLength(input, 20)

          const cipher = key.encryptStream()

          const output = await _streamHelper(chunks, cipher)
          assert.ok(key.decrypt(output).equals(input))
        })

        it('cipher stream & decipher async', async () => {
          const input = randomBytes(100)
          const chunks = splitLength(input, 20)

          const cipher = key.encryptStream()

          const output = await _streamHelper(chunks, cipher)
          assert.ok((await key.decryptAsync(output)).equals(input))
        })

        it('cipher short stream (single chunk) & decipher sync', async () => {
          const input = randomBytes(10)
          const chunks = splitLength(input, 100)

          const cipher = key.encryptStream()

          const output = await _streamHelper(chunks, cipher)
          assert.ok(key.decrypt(output).equals(input))
        })

        it('cipher short stream (single chunk) & decipher async', async () => {
          const input = randomBytes(10)
          const chunks = splitLength(input, 100)

          const cipher = key.encryptStream()

          const output = await _streamHelper(chunks, cipher)
          assert.ok((await key.decryptAsync(output)).equals(input))
        })

        it('cipher empty stream & decipher sync', async () => {
          const input = Buffer.alloc(0)
          const chunks = splitLength(input, 100)

          const cipher = key.encryptStream()

          const output = await _streamHelper(chunks, cipher)
          assert.ok(key.decrypt(output).equals(input))
        })

        it('cipher empty stream & decipher async', async () => {
          const input = Buffer.alloc(0)
          const chunks = splitLength(input, 100)

          const cipher = key.encryptStream()

          const output = await _streamHelper(chunks, cipher)
          assert.ok((await key.decryptAsync(output)).equals(input))
        })

        it('cipher stream with small blocks & decipher sync', async () => {
          const input = randomBytes(100)
          const chunks = splitLength(input, 10)

          const cipher = key.encryptStream()

          const output = await _streamHelper(chunks, cipher)
          assert.ok(key.decrypt(output).equals(input))
        })

        it('cipher stream with small blocks & decipher async', async () => {
          const input = randomBytes(100)
          const chunks = splitLength(input, 10)

          const cipher = key.encryptStream()

          const output = await _streamHelper(chunks, cipher)
          assert.ok((await key.decryptAsync(output)).equals(input))
        })

        it('cipher sync & decipher stream', async () => {
          const clearText = randomBytes(1000)
          const cipherText = key.encrypt(clearText)
          const cipherChunks = splitLength(cipherText, 20)
          const decipher = key.decryptStream()

          const output = await _streamHelper(cipherChunks, decipher)
          assert.ok(output.equals(clearText))
        })

        it('cipher async & decipher stream', async () => {
          const clearText = randomBytes(1000)
          const cipherText = await key.encryptAsync(clearText)
          const cipherChunks = splitLength(cipherText, 20)
          const decipher = key.decryptStream()

          const output = await _streamHelper(cipherChunks, decipher)
          assert.ok(output.equals(clearText))
        })

        it('cipher sync & decipher short stream (single chunk)', async () => {
          const clearText = randomBytes(10)
          const cipherText = key.encrypt(clearText)
          const cipherChunks = splitLength(cipherText, 100)
          const decipher = key.decryptStream()

          const output = await _streamHelper(cipherChunks, decipher)
          assert.ok(output.equals(clearText))
        })

        it('cipher async & decipher short stream (single chunk)', async () => {
          const clearText = randomBytes(10)
          const cipherText = await key.encryptAsync(clearText)
          const cipherChunks = splitLength(cipherText, 100)
          const decipher = key.decryptStream()

          const output = await _streamHelper(cipherChunks, decipher)
          assert.ok(output.equals(clearText))
        })

        it('cipher sync empty & decipher stream', async () => {
          const clearText = Buffer.alloc(0)
          const cipherText = key.encrypt(clearText)
          const cipherChunks = splitLength(cipherText, 100)
          const decipher = key.decryptStream()

          const output = await _streamHelper(cipherChunks, decipher)
          assert.ok(output.equals(clearText))
        })

        it('cipher async empty & decipher stream', async () => {
          const clearText = Buffer.alloc(0)
          const cipherText = await key.encryptAsync(clearText)
          const cipherChunks = splitLength(cipherText, 100)
          const decipher = key.decryptStream()

          const output = await _streamHelper(cipherChunks, decipher)
          assert.ok(output.equals(clearText))
        })

        it('cipher sync & decipher stream with small blocks', async () => {
          const clearText = randomBytes(1000)
          const cipherText = key.encrypt(clearText)
          const cipherChunks = splitLength(cipherText, 10)
          const decipher = key.decryptStream()

          const output = await _streamHelper(cipherChunks, decipher)
          assert.ok(output.equals(clearText))
        })

        it('cipher async & decipher stream with small blocks', async () => {
          const clearText = randomBytes(1000)
          const cipherText = await key.encryptAsync(clearText)
          const cipherChunks = splitLength(cipherText, 10)
          const decipher = key.decryptStream()

          const output = await _streamHelper(cipherChunks, decipher)
          assert.ok(output.equals(clearText))
        })

        it('cipher stream & decipher stream', async () => {
          const input = randomBytes(100)
          const chunks = splitLength(input, 20)

          const cipher = key.encryptStream()
          const decipher = key.decryptStream()

          const output = await _streamHelper(chunks, cipher, decipher)
          assert.ok(output.equals(input))
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
          })
          if (progress === undefined) throw new Error('Stream hasn\'t worked at all')
          if (progress > size) throw new Error('Stream has\'t been canceled')
          assert.ok(error.message.includes('STREAM_CANCELED'))
        })

        it('Test decryptStream cancel and progress', async () => {
          const size = 80
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
          })

          if (progress === undefined) throw new Error('Stream hasn\'t worked at all')
          if (progress > size) throw new Error('Stream has\'t been canceled')
          assert.ok(error.message.includes('STREAM_CANCELED'), `GOT ${error.message}`)
        })

        it('Test encryptStream destroy', async () => {
          const size = 60
          const input = randomBytes(size)
          const chunks = splitLength(input, 20)
          const stream = key.encryptStream()

          const errorPromise = new Promise((resolve: (err: Error) => void) => {
            stream.on('error', err => {
              resolve(err)
            })
          })

          await new Promise<void>((resolve, reject: (err: Error) => void) => {
            stream.write(chunks[0], err => {
              if (err) reject(err)
              resolve()
            })
          })

          stream.destroy(new Error('Aborting'))
          assert.ok(stream.destroyed)
          const destroyedError = await errorPromise
          assert.equal(destroyedError.message, 'Aborting')

          await assert.rejects(
            new Promise((resolve: (err: Error) => void, reject: (err: Error) => void) => {
              stream.write(chunks[1], err => {
                reject(err)
              })
            }),
            /Cannot call write after a stream was destroyed/
          )
        })

        it('Test decryptStream destroy', async () => {
          const size = 60
          const input = randomBytes(size)
          const chunks = splitLength(input, 20)
          const stream = key.decryptStream()

          const errorPromise = new Promise((resolve: (err: Error) => void) => {
            stream.on('error', err => {
              resolve(err)
            })
          })

          await new Promise<void>((resolve, reject: (err: Error) => void) => {
            stream.write(chunks[0], err => {
              if (err) reject(err)
              resolve()
            })
          })
          stream.destroy(new Error('Aborting'))
          assert.ok(stream.destroyed)
          const destroyedError = await errorPromise
          assert.equal(destroyedError.message, 'Aborting')

          await assert.rejects(
            new Promise((resolve: (err: Error) => void, reject: (err: Error) => void) => {
              stream.write(chunks[1], err => {
                reject(err)
              })
            }),
            /Cannot call write after a stream was destroyed/
          )
        })

        it('Test decryptStream error on bad data', async () => {
          const input = randomBytes(100)
          const chunks = splitLength(input, 20)
          const decipher = key.decryptStream()
          await assert.rejects(
            _streamHelper(chunks, decipher),
            /INVALID_HMAC|INVALID_STREAM/ // error depends on the implementation :/
          )
        })

        it('Test decryptStream error with bad key', async () => {
          const input = randomBytes(100)
          const chunks = splitLength(input, 20)

          const cipher = key.encryptStream()
          const decipher = badKey.decryptStream()

          await assert.rejects(
            _streamHelper(chunks, cipher, decipher),
            /INVALID_HMAC|INVALID_STREAM/ // error depends on the implementation :/
          )
        })

        it('Try deciphering a stream with a cipherText with invalid HMAC', async () => {
          const cipheredMessage = await key.encryptAsync(message)
          cipheredMessage[cipheredMessage.length - 1]++
          const cipherChunks = splitLength(cipheredMessage, 15)
          const decipher = key.decryptStream()
          await assert.rejects(
            _streamHelper(cipherChunks, decipher),
            /INVALID_HMAC/
          )
        })

        it('Try deciphering empty stream ', async () => {
          const cipherChunks = [Buffer.alloc(0)]
          const decipher = key.decryptStream()
          await assert.rejects(
            _streamHelper(cipherChunks, decipher),
            /INVALID_STREAM/
          )
        })

        it('Test decryptStream error on short stream', async () => {
          const chunks = [randomBytes(10)]
          const decipher = key.decryptStream()
          await assert.rejects(
            _streamHelper(chunks, decipher),
            /INVALID_STREAM/
          )
        })

        it('Test decryptStream error on stream of 48b', async () => {
          const chunks = [randomBytes(48)]
          const decipher = key.decryptStream()
          await assert.rejects(
            _streamHelper(chunks, decipher),
            /INVALID_HMAC|INVALID_STREAM/ // error depends on the implementation :/
          )
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
      key2 = new SymKeyClass2(key1.key)
    })

    it('cipher 1 & decipher 2 sync', () => {
      const cipheredMessage = key1.encrypt(message)
      const decipheredMessage = key2.decrypt(cipheredMessage)
      assert.ok(message.equals(decipheredMessage))
    })

    it('cipher 1 & decipher 2 async', async () => {
      const cipheredMessage = await key1.encryptAsync(message)
      const decipheredMessage = await key2.decryptAsync(cipheredMessage)
      assert.ok(message.equals(decipheredMessage))
    })

    it('cipher 2 & decipher 1 sync', () => {
      const cipheredMessage = key2.encrypt(message)
      const decipheredMessage = key1.decrypt(cipheredMessage)
      assert.ok(message.equals(decipheredMessage))
    })

    it('cipher 2 & decipher 1 async', async () => {
      const cipheredMessage = await key2.encryptAsync(message)
      const decipheredMessage = await key1.decryptAsync(cipheredMessage)
      assert.ok(message.equals(decipheredMessage))
    })

    it('cipher stream 1 & decipher stream 2', () => {
      const input = randomBytes(100)
      const chunks = splitLength(input, 20)

      const cipher = key1.encryptStream()
      const decipher = key2.decryptStream()

      return _streamHelper(chunks, cipher, decipher)
        .then(output => {
          assert.ok(output.equals(input))
        })
    })

    it('cipher stream 2 & decipher stream 1', () => {
      const input = randomBytes(100)
      const chunks = splitLength(input, 20)

      const cipher = key2.encryptStream()
      const decipher = key1.decryptStream()

      return _streamHelper(chunks, cipher, decipher)
        .then(output => {
          assert.ok(output.equals(input))
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
        assert.ok(clearText.equals(inputs[i]))
      }
      const end = Date.now()
      const delta = (end - start) / 1000
      console.log(`AES ${name} Encrypt/Decrypt sync : Finished in ${delta.toFixed(1)}s:\n${(nInput / delta).toFixed(1)} block/s\n${(nInput * inputSize / delta / 1000000).toFixed(1)} MB/s`)
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
        assert.ok(clearText.equals(inputs[i]))
      }
      const end = Date.now()
      const delta = (end - start) / 1000
      console.log(`AES ${name} Encrypt/Decrypt async : Finished in ${delta.toFixed(1)}s:\n${(nInput / delta).toFixed(1)} block/s\n${(nInput * inputSize / delta / 1000000).toFixed(1)} MB/s`)
    })

    it('Encrypt/Decrypt stream perf', async function () {
      const totalSize = 10e6
      const input = Buffer.alloc(totalSize).fill(randomBytes(1000))

      const k = await SymKeyClass.generate(256)

      const chunksClear = splitLength(input, 256 * 1024)
      const startEncrypt = Date.now()
      const encrypted = await _streamHelper(chunksClear, k.encryptStream())
      const endEncrypt = Date.now()
      const deltaEncrypt = (endEncrypt - startEncrypt) / 1000
      console.log(`AES ${name} stream encrypt : Finished in ${deltaEncrypt.toFixed(1)}s:\n${(totalSize / deltaEncrypt / 1000000).toFixed(1)} MB/s`)

      const chunksEncrypted = splitLength(encrypted, 256 * 1024)
      const startDecrypt = Date.now()
      const decrypted = await _streamHelper(chunksEncrypted, k.decryptStream())
      const endDecrypt = Date.now()
      const deltaDecrypt = (endDecrypt - startDecrypt) / 1000
      console.log(`AES ${name} stream decrypt : Finished in ${deltaDecrypt.toFixed(1)}s:\n${(totalSize / deltaDecrypt / 1000000).toFixed(1)} MB/s`)

      assert.ok(decrypted.equals(input))
    })
  })
}
