'use strict'

import forge from 'node-forge'
import { b64, unb64 } from './utils'
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
   * @param {number|string} [arg] Size of the key to generate, or the messageKey to construct the SymKey with.
   *  Defaults to a new 256 bits key.
   */
  constructor (arg) {
    arg = arg || 256
    if (typeof arg === 'number') {
      this.keySize = arg / 8
      this.encryptionKey = forge.random.getBytesSync(this.keySize)
      this.signingKey = forge.random.getBytesSync(this.keySize)
    } else if (typeof arg === 'string') {
      this.keySize = arg.length / 2
      this.signingKey = arg.slice(0, this.keySize)
      this.encryptionKey = arg.slice(this.keySize)
    } else {
      throw new Error(`INVALID_ARG : Type of ${arg} is ${typeof arg}`)
    }
    if ([32, 24, 16].indexOf(this.keySize) === -1) {
      throw new Error(`INVALID_ARG : Key size is invalid`)
    }
  }

  /**
   * Static method to construct a new SymKey from a binary string encoded messageKey
   * @method
   * @static
   * @param {string} messageKey binary encoded messageKey
   * @returns {SymKey}
   */
  static fromString (messageKey) {
    return new SymKey(messageKey)
  }

  /**
   * Static method to construct a new SymKey from a b64 encoded messageKey
   * @method
   * @static
   * @param {string} messageKey b64 encoded messageKey
   * @returns {SymKey}
   */
  static fromB64 (messageKey) {
    return SymKey.fromString(unb64(messageKey))
  }

  /**
   * Returns both SymKey#signingKey and SymKey#encryptionKey concatenated encoded with b64
   * @method
   * @returns {string}
   */
  serialize () {
    return b64(this.toString())
  }

  toString () {
    return `${this.signingKey}${this.encryptionKey}`
  }

  /**
   * Calculates a SHA-256 HMAC with the SymKey#signingKey on the textToAuthenticate
   * @method
   * @param {string} textToAuthenticate
   * @returns {string}
   */
  calculateHMAC (textToAuthenticate) {
    const hmac = forge.hmac.create()
    hmac.start('sha256', this.signingKey)
    hmac.update(textToAuthenticate)
    return hmac.digest().data
  }

  /**
   * Encrypts the clearText with SymKey#encryptionKey using AES-CBC, and a SHA-256 HMAC calculated with
   * SymKey#signingKey, returns it concatenated in the following order:
   * InitializationVector CipherText HMAC
   * @method
   * @param {string} clearText
   * @returns {string}
   */
  encrypt (clearText) {
    const iv = forge.random.getBytesSync(16)

    const cipher = forge.cipher.createCipher('AES-CBC', this.encryptionKey)
    cipher.start({ iv: iv })
    cipher.update(forge.util.createBuffer(clearText))
    cipher.finish()

    const cipherTextWithIV = `${iv}${cipher.output.data}`
    return `${cipherTextWithIV}${this.calculateHMAC(cipherTextWithIV)}`
  }

  /**
   * Creates a Transform stream that encrypts the data piped to it.
   * @returns {Transform}
   */
  encryptStream () {
    let canceled = false
    const progress = getProgress()
    const iv = forge.random.getBytesSync(16)

    const cipher = forge.cipher.createCipher('AES-CBC', this.encryptionKey)
    cipher.start({ iv: iv })

    const hmac = forge.hmac.create()
    hmac.start('sha256', this.signingKey)

    let firstBlock = true
    return new Transform({
      transform (chunk, encoding, callback) {
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
          cipher.update(forge.util.createBuffer(chunk.toString('binary')))
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
          progress(0, this, false)
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
   * Decrypts the cipheredMessage using the same algorithms as SymKey#encrypt
   * @method
   * @param {string} cipheredMessage
   * @returns {string}
   */
  decrypt (cipheredMessage) {
    const iv = cipheredMessage.slice(0, 16)
    const hmac = cipheredMessage.slice(-32)
    const cipherText = cipheredMessage.slice(16, -32)
    if (this.calculateHMAC(`${iv}${cipherText}`) === hmac) {
      const cipher = forge.cipher.createDecipher('AES-CBC', this.encryptionKey)
      cipher.start({ iv: iv })
      cipher.update(forge.util.createBuffer(cipherText))
      cipher.finish()
      return cipher.output.data
    } else throw new Error('INVALID_HMAC')
  }

  /**
   * Creates a Transform stream that decrypts the encrypted data piped to it.
   * @returns {Transform}
   */
  decryptStream () {
    let canceled = false

    const progress = getProgress()

    const decipher = forge.cipher.createDecipher('AES-CBC', this.encryptionKey)

    const hmac = forge.hmac.create()
    hmac.start('sha256', this.signingKey)

    let buffer = Buffer.alloc(0)
    let gotIv = false

    return new Transform({
      transform (chunk, encoding, callback) {
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
              const cipherText = buffer.slice(0, -32).toString('binary')
              buffer = buffer.slice(-32)
              hmac.update(cipherText)
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
          progress(32, this, false)
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
