import forge from 'node-forge'
import { getProgress, staticImplements } from '../utils/commonUtils'
import { Transform } from 'stream'
import { SymKey, SymKeyConstructor, SymKeySize } from '../utils/aes' // eslint-disable-line no-unused-vars

/* eslint-disable */
// Necessary stuff because node-forge typings are incomplete...
declare module 'node-forge' {
  namespace hmac {
    interface HMAC {
      start (algorithm: string, singingKey: string): void

      update (str: string): void

      getMac (): forge.util.ByteStringBuffer

      digest (): forge.util.ByteStringBuffer
    }

    function create (): HMAC
  }
}
/* eslint-enable */

@staticImplements<SymKeyConstructor>()
class SymKeyForge implements SymKey {
  public readonly keySize: number
  private readonly signingKey: string
  private readonly encryptionKey: string

  /**
   * Constructor of SymKeyForge, if you want to construct an SymKeyForge with an existing key, use the static methods SymKeyForge.fromString or fromB64
   * Defaults to a new 256 bits key.
   * @constructs SymKeyForge
   * @param {number|Buffer} [arg] Size of the key to generate, or the key to construct the SymKeyForge with.
   */
  constructor (arg: SymKeySize | Buffer = 256) {
    if (typeof arg === 'number') {
      this.keySize = arg / 8
      this.signingKey = forge.random.getBytesSync(this.keySize)
      this.encryptionKey = forge.random.getBytesSync(this.keySize)
    } else if (Buffer.isBuffer(arg)) {
      this.keySize = arg.length / 2
      this.signingKey = arg.slice(0, this.keySize).toString('binary')
      this.encryptionKey = arg.slice(this.keySize).toString('binary')
    } else {
      throw new Error(`INVALID_ARG : Type of ${arg} is ${typeof arg}`)
    }
    if (![32, 24, 16].includes(this.keySize)) {
      throw new Error(`INVALID_ARG : Key size is invalid`)
    }
  }

  /**
   * Static method to construct a new SymKeyForge from a binary string encoded messageKey
   * @method
   * @static
   * @param {string} messageKey binary encoded messageKey
   * @returns {SymKeyForge}
   */
  static fromString (messageKey: string): SymKeyForge {
    return new this(Buffer.from(messageKey, 'binary'))
  }

  /**
   * Static method to construct a new SymKeyForge from a b64 encoded messageKey
   * @method
   * @static
   * @param {string} messageKey b64 encoded messageKey
   * @returns {SymKeyForge}
   */
  static fromB64 (messageKey: string): SymKeyForge {
    return new this(Buffer.from(messageKey, 'base64'))
  }

  /**
   * Returns both SymKeyForge#signingKey and SymKeyForge#encryptionKey concatenated encoded with b64
   * @method
   * @returns {string}
   */
  toB64 (): string {
    return Buffer.from(this.toString(), 'binary').toString('base64')
  }

  /**
   * Returns both SymKeyForge#signingKey and SymKeyForge#encryptionKey concatenated as a binary string
   * @method
   * @returns {string}
   */
  toString (): string {
    return `${this.signingKey}${this.encryptionKey}`
  }

  /**
   * Calculates a SHA-256 HMAC with the SymKeyForge#signingKey on the textToAuthenticate
   * @method
   * @param {Buffer} textToAuthenticate
   * @returns {Buffer}
   */
  calculateHMAC (textToAuthenticate: Buffer): Buffer {
    const hmac = forge.hmac.create()
    hmac.start('sha256', this.signingKey)
    hmac.update(textToAuthenticate.toString('binary'))
    return Buffer.from(hmac.digest().data, 'binary')
  }

  /**
   * Encrypts the clearText with SymKeyForge#encryptionKey using AES-CBC, and a SHA-256 HMAC calculated with
   * SymKeyForge#signingKey, returns it concatenated in the following order:
   * InitializationVector CipherText HMAC
   * @method
   * @param {Buffer} clearText
   * @returns {Buffer}
   */
  encrypt (clearText: Buffer): Buffer {
    const iv = forge.random.getBytesSync(16)

    const cipher: forge.cipher.BlockCipher = forge.cipher.createCipher('AES-CBC', this.encryptionKey)
    cipher.start({ iv: iv })
    cipher.update(forge.util.createBuffer(clearText))
    cipher.finish()

    const cipherText = Buffer.from(`${iv}${cipher.output.data}`, 'binary')

    return Buffer.concat([cipherText, this.calculateHMAC(cipherText)])
  }

  /**
   * Creates a Transform stream that encrypts the data piped to it.
   * @returns {Transform}
   */
  encryptStream (): Transform {
    let canceled = false
    const progress = getProgress()
    const iv = forge.random.getBytesSync(16)

    const cipher: forge.cipher.BlockCipher = forge.cipher.createCipher('AES-CBC', this.encryptionKey)
    cipher.start({ iv: iv })

    const hmac = forge.hmac.create()
    hmac.start('sha256', this.signingKey)

    let firstBlock = true
    return new Transform({
      transform (chunk: Buffer, encoding, callback) {
        try {
          if (canceled) throw new Error('STREAM_CANCELED')
          if (firstBlock) {
            const header = iv
            hmac.update(header)
            const buffer = Buffer.from(header, 'binary')
            this.push(buffer)
            firstBlock = false
          }
          const output = cipher.output.getBytes()
          cipher.update(forge.util.createBuffer(chunk))
          hmac.update(output)
          this.push(Buffer.from(output, 'binary'))
          progress(chunk.length, this)
          callback()
        } catch (e) {
          callback(e)
        }
      },
      flush (callback) {
        try {
          if (canceled) throw new Error('STREAM_CANCELED')
          progress(0, this, 0)
          cipher.finish()
          const output = cipher.output.getBytes()
          hmac.update(output)
          let buffer = Buffer.from(output, 'binary')
          this.push(buffer)
          const digest = hmac.digest()
          buffer = Buffer.from(digest.getBytes(), 'binary')
          this.push(buffer)
          callback()
        } catch (e) {
          callback(e)
        }
      }
    })
      .on('cancel', () => {
        canceled = true
      })
  }

  /**
   * Decrypts the cipheredMessage using the same algorithms as SymKeyForge#encrypt
   * @method
   * @param {Buffer} cipheredMessage
   * @returns {Buffer}
   */
  decrypt (cipheredMessage: Buffer): Buffer {
    const iv = cipheredMessage.slice(0, 16)
    const cipherText = cipheredMessage.slice(16, -32)
    const hmac = cipheredMessage.slice(-32)

    if (this.calculateHMAC(Buffer.concat([iv, cipherText])).equals(hmac)) {
      const cipher: forge.cipher.BlockCipher = forge.cipher.createDecipher('AES-CBC', this.encryptionKey)
      cipher.start({ iv: iv.toString('binary') })
      cipher.update(forge.util.createBuffer(cipherText))
      cipher.finish()
      return Buffer.from(cipher.output.data, 'binary')
    } else throw new Error('INVALID_HMAC')
  }

  /**
   * Creates a Transform stream that decrypts the encrypted data piped to it.
   * @returns {Transform}
   */
  decryptStream (): Transform {
    let canceled = false

    const progress = getProgress()

    const decipher: forge.cipher.BlockCipher = forge.cipher.createDecipher('AES-CBC', this.encryptionKey)

    const hmac = forge.hmac.create()
    hmac.start('sha256', this.signingKey)

    let buffer = Buffer.alloc(0)
    let gotIv = false

    return new Transform({
      transform (chunk: Buffer, encoding, callback) {
        try {
          if (canceled) throw new Error('STREAM_CANCELED')
          buffer = Buffer.concat([buffer, chunk])
          if (!gotIv) { // we have not gotten the IV yet, gotta wait for it
            if (buffer.length >= 16) { // length of IV
              const iv = buffer.slice(0, 16).toString('binary')
              buffer = buffer.slice(16)
              decipher.start({ iv: iv })
              hmac.update(iv)
              gotIv = true
            }
          }
          if (gotIv) { // we have the IV, can decrypt
            if (buffer.length > 32) { // we have to leave 32 bytes, they may be the HMAC
              const cipherText = buffer.slice(0, -32)
              buffer = buffer.slice(-32)
              hmac.update(cipherText.toString('binary'))
              this.push(Buffer.from(decipher.output.getBytes(), 'binary'))
              decipher.update(forge.util.createBuffer(cipherText))
            }
          }
          progress(chunk.length, this)
          callback()
        } catch (e) {
          callback(e)
        }
      },
      flush (callback) {
        try {
          if (canceled) throw new Error('STREAM_CANCELED')
          if (buffer.length !== 32) throw new Error('INVALID_STREAM')
          decipher.finish()
          progress(32, this, 0)
          const digest = hmac.digest().getBytes()
          if (digest !== buffer.toString('binary')) throw new Error('INVALID_HMAC')
          this.push(Buffer.from(decipher.output.getBytes(), 'binary'))
          callback()
        } catch (e) {
          callback(e)
        }
      }
    })
      .on('cancel', () => {
        canceled = true
      })
  }
}

export default SymKeyForge
