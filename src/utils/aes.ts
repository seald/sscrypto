import { Transform } from 'stream'
import { getProgress, streamToData, writeInStream } from './commonUtils'

export type SymKeySize = 128 | 192 | 256

export interface SymKeyConstructor<T extends SymKey> {
  new (key?: Buffer | SymKeySize): T

  fromString (messageKey: string): T

  fromB64 (messageKey: string): T

  generate (size: SymKeySize): Promise<T>

  randomBytesAsync_ (size: number): Promise<Buffer>

  randomBytesSync_ (size: number): Buffer
}

export abstract class SymKey {
  readonly keySize: SymKeySize
  readonly key: Buffer

  /**
   * Constructor of SymKey
   *
   * Using a number as argument, or relying on default, is deprecated. Use `SymKey.generate` instead.
   *
   * Defaults to a new 256 bits key.
   *
   * @constructs SymKey
   * @param {Buffer|SymKeySize} [key = 256] The key to construct the SymKey with. Passing a keySize is deprecated. Use `SymKey.generate` instead.
   */
  protected constructor (key: Buffer | SymKeySize = 256) {
    if (typeof key === 'number') { // deprecated
      key = new.target.randomBytesSync_(key / 4) // `size / 4` is `(size / 8) * 2`
    }
    const keySize = key.length / 2 * 8
    if (keySize !== 128 && keySize !== 192 && keySize !== 256) {
      throw new Error('INVALID_ARG : Key size is invalid')
    }
    this.keySize = keySize
    this.key = key
  }

  static async randomBytesAsync_ (size: number): Promise<Buffer> {
    return this.randomBytesSync_(size)
  }

  static randomBytesSync_ (size: number): Buffer { // no abstract for static...
    throw new Error('Subclass needs to implement `randomBytesSync_`')
  }

  /**
   * Static method to generate a new SymKey of a given size asynchronously
   * @method
   * @static
   * @param {SymKeySize} [size=256]
   * @returns {Promise<SymKey>}
   */
  static async generate<T extends SymKey> (this: SymKeyConstructor<T>, size: SymKeySize = 256): Promise<T> {
    return new this(await this.randomBytesAsync_(size / 4)) // `size / 4` is `(size / 8) * 2`
  }

  /**
   * Static method to construct a new SymKey from a binary string encoded key
   * @method
   * @static
   * @param {string} messageKey binary encoded key
   * @returns {SymKey}
   */
  static fromString<T extends SymKey> (this: SymKeyConstructor<T>, messageKey: string): T {
    return new this(Buffer.from(messageKey, 'binary'))
  }

  /**
   * Static method to construct a new SymKey from a b64 encoded key
   * @method
   * @static
   * @param {string} messageKey b64 encoded key
   * @returns {SymKey}
   */
  static fromB64<T extends SymKey> (this: SymKeyConstructor<T>, messageKey: string): T {
    return new this(Buffer.from(messageKey, 'base64'))
  }

  /**
   * Returns the SymKey's key encoded with b64
   * @method
   * @returns {string}
   */
  toB64 (): string {
    return this.key.toString('base64')
  }

  /**
   * Returns the SymKey's key encoded as a binary string
   * @method
   * @deprecated
   * @returns {string}
   */
  toString (): string {
    return this.key.toString('binary')
  }

  /**
   * Calculates a SHA-256 HMAC with the SymKey#authenticationKey on the textToAuthenticate
   * @method
   * @param {Buffer} textToAuthenticate
   * @returns {Promise<Buffer>}
   */
  async calculateHMACAsync_ (textToAuthenticate: Buffer): Promise<Buffer> {
    return this.calculateHMACSync_(textToAuthenticate)
  }

  /**
   * Calculates a SHA-256 HMAC with the SymKey#authenticationKey on the textToAuthenticate
   * @method
   * @param {Buffer} textToAuthenticate
   * @returns {Buffer}
   */
  abstract calculateHMACSync_ (textToAuthenticate: Buffer): Buffer

  /**
   * Encrypts the clearText with SymKey#encryptionKey using raw AES-CBC with given IV
   * @method
   * @param {Buffer} clearText
   * @param {Buffer} iv
   * @returns {Promise<Buffer>}
   */
  async rawEncryptAsync_ (clearText: Buffer, iv: Buffer): Promise<Buffer> {
    return this.rawEncryptSync_(clearText, iv)
  }

  /**
   * Encrypts the clearText with SymKey#encryptionKey using AES-CBC, and a SHA-256 HMAC calculated with
   * SymKey#authenticationKey, returns it concatenated in the following order:
   * InitializationVector CipherText HMAC
   * @method
   * @param {Buffer} clearText
   * @returns {Promise<Buffer>}
   */
  async encryptAsync (clearText: Buffer): Promise<Buffer> {
    const iv = await (this.constructor as SymKeyConstructor<SymKey>).randomBytesAsync_(16)

    const crypt = await this.rawEncryptAsync_(clearText, iv)
    const cipherText = Buffer.concat([iv, crypt])

    return Buffer.concat([cipherText, await this.calculateHMACAsync_(cipherText)])
  }

  /**
   * Encrypts the clearText with SymKey#encryptionKey using raw AES-CBC with given IV
   * @method
   * @param {Buffer} clearText
   * @param {Buffer} iv
   * @returns {Buffer}
   */
  abstract rawEncryptSync_ (clearText: Buffer, iv: Buffer): Buffer

  /**
   * Encrypts the clearText with SymKey#encryptionKey using AES-CBC, and a SHA-256 HMAC calculated with
   * SymKey#authenticationKey, returns it concatenated in the following order:
   * InitializationVector CipherText HMAC
   * @method
   * @param {Buffer} clearText
   * @returns {Buffer}
   */
  encrypt (clearText: Buffer): Buffer {
    const iv = (this.constructor as SymKeyConstructor<SymKey>).randomBytesSync_(16)

    const crypt = this.rawEncryptSync_(clearText, iv)
    const cipherText = Buffer.concat([iv, crypt])

    return Buffer.concat([cipherText, this.calculateHMACSync_(cipherText)])
  }

  abstract rawEncryptStream_ (iv: Buffer): Transform

  abstract HMACStream_ (): Transform

  abstract rawDecryptStream_ (iv: Buffer): Transform

  /**
   * Creates a Transform stream that encrypts the data piped to it.
   * @returns {Transform}
   */
  encryptStream (): Transform {
    let canceled = false
    const progress = getProgress()
    const ivPromise = (this.constructor as SymKeyConstructor<SymKey>).randomBytesAsync_(16)
    let encryptStream: Transform
    const getEncryptStream = (iv: Buffer): void => { // this avoids having to save 'this'
      encryptStream = this.rawEncryptStream_(iv)
    }
    const hmacStream = this.HMACStream_()
    const hmacPromise = streamToData(hmacStream)
      .catch(err => {
        canceled = true
        transformStream.emit('error', err)
        return Buffer.alloc(0) // Fake return to have consistent return type
      })
    const transformStream = new Transform({
      async transform (chunk: Buffer, encoding, callback): Promise<void> {
        try {
          if (!encryptStream) progress(0, transformStream, 0)
          if (canceled) throw new Error('STREAM_CANCELED')
          if (!encryptStream) { // we have not gotten the IV yet, gotta wait for it
            const iv = await ivPromise
            getEncryptStream(iv)
            await writeInStream(hmacStream, iv)
            this.push(iv)
          }
          const output = encryptStream.read()
          if (output && output.length) {
            await writeInStream(hmacStream, output)
            this.push(output)
          }
          await writeInStream(encryptStream, chunk)
          progress(chunk.length, this)
          callback()
        } catch (e) {
          callback(e)
        }
      },
      async flush (callback): Promise<void> {
        try {
          if (canceled) throw new Error('STREAM_CANCELED')
          if (!encryptStream) { // no encryptStream means there was no transform called: stream is empty
            const iv = await ivPromise
            getEncryptStream(iv) // we still have to initialize the encryptStream to get valid padding
            await writeInStream(hmacStream, iv)
            this.push(iv)
          }
          const outputPromise = streamToData(encryptStream)
            .catch(() => { throw new Error('INVALID_STREAM') }) // This should never happen
          setImmediate(() => { // this is done in setImmediate so Promise has time to be awaited
            encryptStream.end()
          })
          const output = await outputPromise
          if (output && output.length) {
            await writeInStream(hmacStream, output)
            this.push(output)
          }
          setImmediate(() => { // this is done in setImmediate so Promise has time to be awaited
            hmacStream.end()
          })
          const hmac = await hmacPromise
          progress(0, this, 0)
          this.push(hmac)
          callback()
        } catch (e) {
          callback(e)
        }
      }
    })
    transformStream.on('cancel', () => {
      canceled = true
    })
    return transformStream
  }

  /**
   * Decrypts the cipherText using raw AES-CBC with the given IV
   * @method
   * @param {Buffer} cipherText
   * @param {Buffer} iv
   * @returns {Promise<Buffer>}
   */
  async rawDecryptAsync_ (cipherText: Buffer, iv: Buffer): Promise<Buffer> {
    return this.rawDecryptSync_(cipherText, iv)
  }

  /**
   * Decrypts the cipherText using AES-CBC with the embedded IV, and checking the embedded SHA-256 HMAC
   * @method
   * @param {Buffer} cipheredMessage
   * @returns {Promise<Buffer>}
   */
  async decryptAsync (cipheredMessage: Buffer): Promise<Buffer> {
    const iv = cipheredMessage.slice(0, 16)
    const cipherText = cipheredMessage.slice(16, -32)
    const hmac = cipheredMessage.slice(-32)

    if ((await this.calculateHMACAsync_(Buffer.concat([iv, cipherText]))).equals(hmac)) {
      return this.rawDecryptAsync_(cipherText, iv)
    } else throw new Error('INVALID_HMAC')
  }

  /**
   * Decrypts the cipherText using raw AES-CBC with the given IV
   * @method
   * @param {Buffer} cipherText
   * @param {Buffer} iv
   * @returns {Buffer}
   */
  abstract rawDecryptSync_ (cipherText: Buffer, iv: Buffer): Buffer

  /**
   * Decrypts the cipherText using AES-CBC with the embedded IV, and checking the embedded SHA-256 HMAC
   * @method
   * @param {Buffer} cipheredMessage
   * @returns {Buffer}
   */
  decrypt (cipheredMessage: Buffer): Buffer {
    const iv = cipheredMessage.slice(0, 16)
    const cipherText = cipheredMessage.slice(16, -32)
    const hmac = cipheredMessage.slice(-32)

    if (this.calculateHMACSync_(Buffer.concat([iv, cipherText])).equals(hmac)) {
      return this.rawDecryptSync_(cipherText, iv)
    } else throw new Error('INVALID_HMAC')
  }

  /**
   * Creates a Transform stream that decrypts the encrypted data piped to it.
   * @returns {Transform}
   */
  decryptStream (): Transform {
    let canceled = false
    const progress = getProgress()
    let buffer = Buffer.alloc(0)
    let decryptStream: Transform
    const getDecryptStream = (iv: Buffer): void => { // this avoids having to save 'this'
      decryptStream = this.rawDecryptStream_(iv)
    }
    const hmacStream = this.HMACStream_()
    const hmacPromise = streamToData(hmacStream)
      .catch(err => {
        canceled = true
        transformStream.emit('error', err)
        return Buffer.alloc(0) // Fake return to have consistent return type
      })
    const transformStream = new Transform({
      async transform (chunk: Buffer, encoding, callback): Promise<void> {
        try {
          if (!decryptStream) progress(0, transformStream, 0)
          if (canceled) throw new Error('STREAM_CANCELED')
          buffer = Buffer.concat([buffer, chunk])
          if (!decryptStream) { // we have not gotten the IV yet, gotta wait for it
            if (buffer.length >= 16) { // length of IV
              const iv = buffer.slice(0, 16)
              buffer = buffer.slice(16)
              getDecryptStream(iv)
              await writeInStream(hmacStream, iv)
            }
          }
          if (decryptStream) { // we have the IV, can decrypt
            if (buffer.length > 32) { // we have to leave 32 bytes, they may be the HMAC
              const cipherText = buffer.slice(0, -32)
              buffer = buffer.slice(-32)
              const output = decryptStream.read()
              if (output && output.length) this.push(output)
              await writeInStream(decryptStream, cipherText)
              await writeInStream(hmacStream, cipherText)
            }
          }
          progress(chunk.length, this)
          callback()
        } catch (e) {
          callback(e)
        }
      },
      async flush (callback): Promise<void> {
        try {
          if (canceled) throw new Error('STREAM_CANCELED')
          if (buffer.length !== 32) throw new Error('INVALID_STREAM')
          const outputPromise = streamToData(decryptStream)
            .catch(() => { throw new Error('INVALID_STREAM') }) // This happens when the final block is of invalid size. Note: some implementations will not throw in this case, like forge, so they will get INVALID_HMAC
          setImmediate(() => { // this is done in setImmediate so Promise has time to be awaited
            decryptStream.end()
            hmacStream.end()
          })
          const [hmac, output] = await Promise.all([hmacPromise, outputPromise]) // await both promises at the same time, to avoid having one being unhandled if the other fails
          if (output && output.length) this.push(output)
          progress(32, this, 0)
          if (!hmac.equals(buffer)) throw new Error('INVALID_HMAC')
          callback()
        } catch (e) {
          callback(e)
        }
      }
    })
    transformStream.on('cancel', () => {
      canceled = true
    })
    return transformStream
  }
}
