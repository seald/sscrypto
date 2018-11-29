import * as crypto from 'crypto'
import { Transform } from 'stream'

const getProgress = () => {
  let counter = 0
  let lastEmitProgress
  return (increment, stream, delay = 30) => { // don't send progress more than each 30ms
    counter += increment
    if (delay === false || !lastEmitProgress || Date.now() - lastEmitProgress > delay) {
      lastEmitProgress = Date.now()
      stream.emit('progress', counter)
    }
  }
}

export class SymKey {
  /**
   * Constructor of SymKey, if you want to construct an SymKey with an existing key, use the static method SymKey.from
   * @constructs SymKey
   * @param {number|Buffer} [arg] Size of the key to generate, or the key to construct the SymKey with.
   *  Defaults to a new 256 bits key.
   */
  constructor (arg = 256) {
    if (typeof arg === 'number') {
      this.keySize = arg / 8
      this.signingKey = crypto.randomBytes(this.keySize)
      this.encryptionKey = crypto.randomBytes(this.keySize)
    } else if (Buffer.isBuffer(arg)) {
      this.keySize = arg.length / 2
      this.signingKey = arg.slice(0, this.keySize)
      this.encryptionKey = arg.slice(this.keySize)
    } else {
      throw new Error('INVALID_INPUT: invalid argument type')
    }
    if ([32, 24, 16].indexOf(this.keySize) === -1) {
      throw new Error('INVALID_INPUT: invalid key size')
    }
  }

  /**
   * Static method to construct a new SymKey from a b64 encoded encryption key
   * @method
   * @static
   * @param {string} key - b64 encoded key
   * @returns {SymKey}
   */
  static fromB64 (key) {
    return new SymKey(Buffer.from(key, 'base64'))
  }

  /**
   * Returns both SymKey#signingKey and SymKey#encryptionKey concatenated encoded with b64
   * @method
   * @returns {string}
   */
  toB64 () {
    return Buffer.concat([this.signingKey, this.encryptionKey]).toString('base64')
  }

  /**
   * Calculates a SHA-256 HMAC with the SymKey#signingKey on the textToAuthenticate
   * @method
   * @param {Buffer} textToAuthenticate
   * @returns {Buffer}
   */
  calculateHMAC (textToAuthenticate) {
    const hmac = crypto.createHmac('sha256', this.signingKey)
    hmac.update(textToAuthenticate)
    return hmac.digest()
  }

  /**
   * Encrypts the clearText with SymKey#encryptionKey using AES-CBC, and a SHA-256 HMAC calculated with
   * SymKey#signingKey, returns it concatenated in the following order:
   * \x80 InitializationVector CipherText HMAC
   * @method
   * @param {Buffer} clearText
   * @returns {Buffer}
   */
  encrypt (clearText) {
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
  encryptStream () {
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
   * Decrypts the cipherText using the same algorithms as SymKey#encrypt
   * @method
   * @param {Buffer} cipheredMessage
   * @returns {Buffer}
   */
  decrypt (cipheredMessage) {
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
  decryptStream () {
    const progress = getProgress()

    const hmac = crypto.createHmac('sha256', this.signingKey)

    let decipher
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
