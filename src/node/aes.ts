import crypto from 'crypto'
import { staticImplements } from '../utils/commonUtils'
import { Transform } from 'stream'
import { SymKey, SymKeyConstructor } from '../utils/aes'

@staticImplements<SymKeyConstructor<SymKeyNode>>()
class SymKeyNode extends SymKey {
  protected readonly signingKey: Buffer
  protected readonly encryptionKey: Buffer

  constructor (key: Buffer) {
    super(key)
    this.signingKey = key.slice(0, this.keySize / 8)
    this.encryptionKey = key.slice(this.keySize / 8)
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
    const cipher = crypto.createCipheriv(`aes-${this.keySize}-cbc`, this.encryptionKey, iv)
    return Buffer.concat([cipher.update(clearText), cipher.final()])
  }

  rawEncryptStream_ (iv: Buffer): Transform {
    return crypto.createCipheriv(`aes-${this.keySize}-cbc`, this.encryptionKey, iv)
  }

  HMACStream_ (): Transform {
    return crypto.createHmac('sha256', this.signingKey)
  }

  rawDecryptSync_ (cipherText: Buffer, iv: Buffer): Buffer {
    const decipher = crypto.createDecipheriv(`aes-${this.keySize}-cbc`, this.encryptionKey, iv)
    return Buffer.concat([decipher.update(cipherText), decipher.final()])
  }

  rawDecryptStream_ (iv: Buffer): Transform {
    return crypto.createDecipheriv(`aes-${this.keySize}-cbc`, this.encryptionKey, iv)
  }
}

export default SymKeyNode
