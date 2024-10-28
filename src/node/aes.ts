import { randomBytes, createHmac, createCipheriv, createDecipheriv } from 'crypto'
import { staticImplements } from '../utils/commonUtils'
import { Transform } from 'stream'
import { SymKey, SymKeyConstructor } from '../utils/aes'

@staticImplements<SymKeyConstructor<SymKeyNode>>()
class SymKeyNode extends SymKey {
  protected readonly authenticationKey: Buffer
  protected readonly encryptionKey: Buffer

  constructor (key: Buffer) {
    super(key)
    this.authenticationKey = this.key.subarray(0, this.keySize / 8)
    this.encryptionKey = this.key.subarray(this.keySize / 8)
  }

  static randomBytesSync_ (size: number): Buffer {
    return randomBytes(size)
  }

  calculateHMACSync_ (textToAuthenticate: Buffer): Buffer {
    const hmac = createHmac('sha256', this.authenticationKey)
    hmac.update(textToAuthenticate)
    return hmac.digest()
  }

  rawEncryptSync_ (clearText: Buffer, iv: Buffer): Buffer {
    const cipher = createCipheriv(`aes-${this.keySize}-cbc`, this.encryptionKey, iv)
    return Buffer.concat([cipher.update(clearText), cipher.final()])
  }

  rawEncryptStream_ (iv: Buffer): Transform {
    return createCipheriv(`aes-${this.keySize}-cbc`, this.encryptionKey, iv)
  }

  HMACStream_ (): Transform {
    return createHmac('sha256', this.authenticationKey)
  }

  rawDecryptSync_ (cipherText: Buffer, iv: Buffer): Buffer {
    const decipher = createDecipheriv(`aes-${this.keySize}-cbc`, this.encryptionKey, iv)
    return Buffer.concat([decipher.update(cipherText), decipher.final()])
  }

  rawDecryptStream_ (iv: Buffer): Transform {
    return createDecipheriv(`aes-${this.keySize}-cbc`, this.encryptionKey, iv)
  }
}

export default SymKeyNode
