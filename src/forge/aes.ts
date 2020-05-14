import forge from 'node-forge'
import { getProgress, staticImplements } from '../utils/commonUtils'
import { Transform } from 'stream'
import { SymKey, SymKeyConstructor } from '../utils/aes'
import { randomBytes, randomBytesSync } from './utils'

@staticImplements<SymKeyConstructor<SymKeyForge>>()
class SymKeyForge extends SymKey {
  protected readonly signingKey: string
  protected readonly encryptionKey: string

  constructor (key: Buffer) {
    super(key)
    this.signingKey = key.slice(0, this.keySize).toString('binary')
    this.encryptionKey = key.slice(this.keySize).toString('binary')
  }

  static async randomBytes_ (size: number): Promise<Buffer> {
    return randomBytes(size)
  }

  static randomBytesSync_ (size: number): Buffer {
    return randomBytesSync(size)
  }

  calculateHMACSync_ (textToAuthenticate: Buffer): Buffer {
    const hmac = forge.hmac.create()
    hmac.start('sha256', this.signingKey)
    hmac.update(textToAuthenticate.toString('binary'))
    return Buffer.from(hmac.digest().data, 'binary')
  }

  rawEncryptSync_ (clearText: Buffer, iv: Buffer): Buffer {
    const cipher: forge.cipher.BlockCipher = forge.cipher.createCipher('AES-CBC', this.encryptionKey)
    cipher.start({ iv: iv.toString('binary') })
    cipher.update(forge.util.createBuffer(clearText))
    cipher.finish()

    return Buffer.from(cipher.output.data, 'binary')
  }

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
      transform (chunk: Buffer, encoding, callback): void {
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
      flush (callback): void {
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

  rawDecryptSync_ (cipherText: Buffer, iv: Buffer): Buffer {
    const cipher: forge.cipher.BlockCipher = forge.cipher.createDecipher('AES-CBC', this.encryptionKey)
    cipher.start({ iv: iv.toString('binary') })
    cipher.update(forge.util.createBuffer(cipherText))
    cipher.finish()
    return Buffer.from(cipher.output.data, 'binary')
  }

  decryptStream (): Transform {
    let canceled = false

    const progress = getProgress()

    const decipher: forge.cipher.BlockCipher = forge.cipher.createDecipher('AES-CBC', this.encryptionKey)

    const hmac = forge.hmac.create()
    hmac.start('sha256', this.signingKey)

    let buffer = Buffer.alloc(0)
    let gotIv = false

    return new Transform({
      transform (chunk: Buffer, encoding, callback): void {
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
      flush (callback): void {
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
