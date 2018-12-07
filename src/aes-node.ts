import * as crypto from 'crypto'
import { getProgress, staticImplements } from './utils'
import { Transform } from 'stream'
import { SymKey, SymKeyConstructor, SymKeySize } from './aes' // eslint-disable-line no-unused-vars

@staticImplements<SymKeyConstructor>()
class SymKeyNode implements SymKey {
  public readonly keySize: number
  private readonly signingKey: Buffer
  private readonly encryptionKey: Buffer

  /**
   * Constructor of SymKeyNode, if you want to construct an SymKeyNode with an existing key, use the static methods SymKeyNode.fromString or fromB64
   * Defaults to a new 256 bits key.
   * @constructs SymKeyNode
   * @param {number|Buffer} [arg] Size of the key to generate, or the key to construct the SymKeyNode with.
   */
  constructor (arg: SymKeySize | Buffer = 256) {
    if (typeof arg === 'number') {
      this.keySize = arg / 8
      this.signingKey = crypto.randomBytes(this.keySize)
      this.encryptionKey = crypto.randomBytes(this.keySize)
    } else if (Buffer.isBuffer(arg)) {
      this.keySize = arg.length / 2
      this.signingKey = arg.slice(0, this.keySize)
      this.encryptionKey = arg.slice(this.keySize)
    } else {
      throw new Error(`INVALID_ARG : Type of ${arg} is ${typeof arg}`)
    }
    if (![32, 24, 16].includes(this.keySize)) {
      throw new Error(`INVALID_ARG : Key size is invalid`)
    }
  }

  /**
   * Static method to construct a new SymKeyNode from a binary string encoded messageKey
   * @method
   * @static
   * @param {string} messageKey binary encoded messageKey
   * @returns {SymKeyNode}
   */
  static fromString (messageKey: string): SymKeyNode {
    return new this(Buffer.from(messageKey, 'binary'))
  }

  /**
   * Static method to construct a new SymKeyNode from a b64 encoded key
   * @method
   * @static
   * @param {string} messageKey b64 encoded messageKey
   * @returns {SymKeyNode}
   */
  static fromB64 (messageKey: string): SymKeyNode {
    return new this(Buffer.from(messageKey, 'base64'))
  }

  /**
   * Returns both SymKeyNode#signingKey and SymKeyNode#encryptionKey concatenated encoded with b64
   * @method
   * @returns {string}
   */
  toB64 (): string {
    return Buffer.concat([this.signingKey, this.encryptionKey]).toString('base64')
  }

  /**
   * Returns both SymKeyNode#signingKey and SymKeyNode#encryptionKey concatenated as a binary string
   * @method
   * @returns {string}
   */
  toString (): string {
    return `${this.signingKey.toString('binary')}${this.encryptionKey.toString('binary')}`
  }

  /**
   * Calculates a SHA-256 HMAC with the SymKeyNode#signingKey on the textToAuthenticate
   * @method
   * @param {Buffer} textToAuthenticate
   * @returns {Buffer}
   */
  calculateHMAC (textToAuthenticate: Buffer): Buffer {
    const hmac = crypto.createHmac('sha256', this.signingKey)
    hmac.update(textToAuthenticate)
    return hmac.digest()
  }

  /**
   * Encrypts the clearText with SymKeyNode#encryptionKey using AES-CBC, and a SHA-256 HMAC calculated with
   * SymKeyNode#signingKey, returns it concatenated in the following order:
   * InitializationVector CipherText HMAC
   * @method
   * @param {Buffer} clearText
   * @returns {Buffer}
   */
  encrypt (clearText: Buffer): Buffer {
    const iv = crypto.randomBytes(16)

    const cipher = crypto.createCipheriv(`aes-${this.keySize * 8}-cbc`, this.encryptionKey, iv)
    const crypt = cipher.update(clearText)
    const cipherText = Buffer.concat([iv, crypt, cipher.final()])

    return Buffer.concat([cipherText, this.calculateHMAC(cipherText)])
  }

  /**
   * Creates a Transform stream that encrypts the data piped to it.
   * @returns {Transform}
   */
  encryptStream (): Transform {
    const progress = getProgress()
    const iv = crypto.randomBytes(16)

    const cipher = crypto.createCipheriv(`aes-${this.keySize * 8}-cbc`, this.encryptionKey, iv)

    const hmac = crypto.createHmac('sha256', this.signingKey)

    let firstBlock = true
    let canceled = false
    return new Transform({
      transform (chunk, encoding, callback) {
        try {
          if (canceled) throw new Error('STREAM_CANCELED')
          if (firstBlock) {
            hmac.update(iv)
            this.push(iv)
            firstBlock = false
          }
          const crypt = cipher.update(chunk)
          hmac.update(crypt)
          this.push(crypt)
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
          const crypt = cipher.final()
          hmac.update(crypt)
          this.push(crypt)
          this.push(hmac.digest())
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
   * Decrypts the cipherText using the same algorithms as SymKeyNode#encrypt
   * @method
   * @param {Buffer} cipheredMessage
   * @returns {Buffer}
   */
  decrypt (cipheredMessage: Buffer): Buffer {
    const iv = cipheredMessage.slice(0, 16)
    const cipherText = cipheredMessage.slice(16, -32)
    const hmac = cipheredMessage.slice(-32)

    if (this.calculateHMAC(Buffer.concat([iv, cipherText])).equals(hmac)) {
      const decipher = crypto.createDecipheriv(`aes-${this.keySize * 8}-cbc`, this.encryptionKey, iv)
      return Buffer.concat([decipher.update(cipherText), decipher.final()])
    } else throw new Error('INVALID_HMAC')
  }

  /**
   * Creates a Transform stream that decrypts the encrypted data piped to it.
   * @returns {Transform}
   */
  decryptStream (): Transform {
    const progress = getProgress()

    const hmac = crypto.createHmac('sha256', this.signingKey)

    let decipher: crypto.Decipher
    let buffer = Buffer.alloc(0)

    const encryptionKey = this.encryptionKey
    const keySize = this.keySize

    let canceled = false
    return new Transform({
      transform (chunk, encoding, callback) {
        try {
          if (canceled) throw new Error('STREAM_CANCELED')
          buffer = Buffer.concat([buffer, chunk])
          if (!decipher) { // we have not gotten the IV yet, gotta wait for it
            if (buffer.length >= 16) { // length of IV
              const iv = buffer.slice(0, 16)
              buffer = buffer.slice(16)
              decipher = crypto.createDecipheriv(`aes-${keySize * 8}-cbc`, encryptionKey, iv)
              hmac.update(iv)
            }
          }
          if (decipher) { // we have the IV, can decrypt
            if (buffer.length > 32) { // we have to leave 32 bytes, they may be the HMAC
              const cipherText = buffer.slice(0, -32)
              buffer = buffer.slice(-32)
              const plainText = decipher.update(cipherText)
              this.push(plainText)
              hmac.update(cipherText)
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
          progress(32, this, 0)
          const computedHmac = hmac.digest()
          if (!computedHmac.equals(buffer)) throw new Error('INVALID_HMAC')
          this.push(decipher.final())
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

export default SymKeyNode
