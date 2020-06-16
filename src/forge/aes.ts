import forge from 'node-forge'
import { staticImplements } from '../utils/commonUtils'
import { Transform } from 'stream'
import { SymKey, SymKeyConstructor } from '../utils/aes'
import { randomBytes, randomBytesSync } from './utils'

const forgeCipherToStream = (cipher: forge.cipher.BlockCipher): Transform => {
  return new Transform({
    transform (chunk: Buffer, encoding, callback): void {
      try {
        const output = Buffer.from(cipher.output.getBytes(), 'binary') // getting output before updating to avoid getting weird padding at the end
        cipher.update(forge.util.createBuffer(chunk))
        this.push(output)
        callback(null)
      } catch (e) {
        callback(e)
      }
    },
    flush (callback): void {
      try {
        cipher.finish()
        const output = Buffer.from(cipher.output.getBytes(), 'binary')
        this.push(output)
        callback(null)
      } catch (e) {
        callback(e)
      }
    }
  })
}

@staticImplements<SymKeyConstructor<SymKeyForge>>()
class SymKeyForge extends SymKey {
  protected readonly authenticationKey: string
  protected readonly encryptionKey: string

  constructor (key: Buffer) {
    super(key)
    this.authenticationKey = key.slice(0, this.keySize / 8).toString('binary')
    this.encryptionKey = key.slice(this.keySize / 8).toString('binary')
  }

  static randomBytes_ (size: number): Promise<Buffer> {
    return randomBytes(size)
  }

  static randomBytesSync_ (size: number): Buffer {
    return randomBytesSync(size)
  }

  calculateHMACSync_ (textToAuthenticate: Buffer): Buffer {
    const hmac = forge.hmac.create()
    hmac.start('sha256', this.authenticationKey)
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

  rawEncryptStream_ (iv: Buffer): Transform {
    const cipher: forge.cipher.BlockCipher = forge.cipher.createCipher('AES-CBC', this.encryptionKey)
    cipher.start({ iv: iv.toString('binary') })
    return forgeCipherToStream(cipher)
  }

  HMACStream_ (): Transform {
    const hmac = forge.hmac.create()
    hmac.start('sha256', this.authenticationKey)
    return new Transform({
      transform (chunk: Buffer, encoding, callback): void {
        try {
          hmac.update(chunk.toString('binary'))
          callback()
        } catch (e) {
          callback(e)
        }
      },
      flush (callback): void {
        try {
          callback(null, Buffer.from(hmac.digest().getBytes(), 'binary'))
        } catch (e) {
          callback(e)
        }
      }
    })
  }

  rawDecryptSync_ (cipherText: Buffer, iv: Buffer): Buffer {
    const decipher: forge.cipher.BlockCipher = forge.cipher.createDecipher('AES-CBC', this.encryptionKey)
    decipher.start({ iv: iv.toString('binary') })
    decipher.update(forge.util.createBuffer(cipherText))
    decipher.finish()
    return Buffer.from(decipher.output.data, 'binary')
  }

  rawDecryptStream_ (iv: Buffer): Transform {
    const decipher: forge.cipher.BlockCipher = forge.cipher.createDecipher('AES-CBC', this.encryptionKey)
    decipher.start({ iv: iv.toString('binary') })
    return forgeCipherToStream(decipher)
  }
}

export default SymKeyForge
