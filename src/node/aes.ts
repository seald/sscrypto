import crypto from 'crypto'
import { getProgress, staticImplements } from '../utils/commonUtils'
import { Transform } from 'stream'
import { SymKey, SymKeyConstructor } from '../utils/aes'

@staticImplements<SymKeyConstructor<SymKeyNode>>()
class SymKeyNode extends SymKey {
  protected readonly signingKey: Buffer
  protected readonly encryptionKey: Buffer

  constructor (key: Buffer) {
    super(key)
    this.signingKey = key.slice(0, this.keySize)
    this.encryptionKey = key.slice(this.keySize)
  }

  static randomBytesSync_ (size: number): Buffer {
    return crypto.randomBytes(size)
  }

  calculateHMACSync_ (textToAuthenticate: Buffer): Buffer {
    const hmac = crypto.createHmac('sha256', this.signingKey)
    hmac.update(textToAuthenticate)
    return hmac.digest()
  }

  rawEncryptSync_ (clearText: Buffer, iv: Buffer): Buffer {
    const cipher = crypto.createCipheriv(`aes-${this.keySize * 8}-cbc`, this.encryptionKey, iv)
    return Buffer.concat([cipher.update(clearText), cipher.final()])
  }

  encryptStream (): Transform {
    const progress = getProgress()
    const iv = crypto.randomBytes(16)

    const cipher = crypto.createCipheriv(`aes-${this.keySize * 8}-cbc`, this.encryptionKey, iv)

    const hmac = crypto.createHmac('sha256', this.signingKey)

    let firstBlock = true
    let canceled = false
    return new Transform({
      transform (chunk, encoding, callback): void {
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
      flush (callback): void {
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

  rawDecryptSync_ (cipherText: Buffer, iv: Buffer): Buffer {
    const decipher = crypto.createDecipheriv(`aes-${this.keySize * 8}-cbc`, this.encryptionKey, iv)
    return Buffer.concat([decipher.update(cipherText), decipher.final()])
  }

  decryptStream (): Transform {
    const progress = getProgress()

    const hmac = crypto.createHmac('sha256', this.signingKey)

    let decipher: crypto.Decipher
    let buffer = Buffer.alloc(0)

    const encryptionKey = this.encryptionKey
    const keySize = this.keySize

    let canceled = false
    return new Transform({
      transform (chunk, encoding, callback): void {
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
      flush (callback): void {
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
