import SymKeyForge from '../forge/aes'
// TODO: react-native-cryptopp needs to be cloned and linked locally for the moment
import Cryptopp from 'react-native-cryptopp'
import { Transform } from 'stream'
import { bufferToArrayBuffer, randomBytes, randomBytesAsync } from './utils'

// TODO: do not extend SymKeyForge
class SymKeyRN extends SymKeyForge {
  protected cryptoppAuthenticationKey: ArrayBuffer
  protected cryptoppEncryptionKey: ArrayBuffer

  constructor (key: Buffer) {
    super(key)
    this.cryptoppAuthenticationKey = bufferToArrayBuffer(this.key.slice(0, this.keySize / 8))
    this.cryptoppEncryptionKey = bufferToArrayBuffer(this.key.slice(this.keySize / 8))
  }

  static async randomBytesAsync_ (size: number): Promise<Buffer> {
    return randomBytesAsync(size)
  }

  static randomBytesSync_ (size: number): Buffer {
    return randomBytes(size)
  }

  rawEncryptSync_ (clearText: Buffer, iv: Buffer): Buffer {
    return Buffer.from(Cryptopp.AES.encrypt(bufferToArrayBuffer(clearText), this.cryptoppEncryptionKey, bufferToArrayBuffer(iv), 'cbc'))
  }

  rawDecryptSync_ (cipherText: Buffer, iv: Buffer): Buffer {
    return Buffer.from(Cryptopp.AES.decrypt(bufferToArrayBuffer(cipherText), this.cryptoppEncryptionKey, bufferToArrayBuffer(iv), 'cbc'))
  }

  calculateHMACSync_ (textToAuthenticate: Buffer): Buffer {
    return Buffer.from(Cryptopp.HMAC.generate(bufferToArrayBuffer(textToAuthenticate), this.cryptoppAuthenticationKey, 'SHA256'))
  }

  HMACStream_ (): Transform {
    let authenticationKey = this.cryptoppAuthenticationKey
    if (authenticationKey.byteLength > 64) authenticationKey = bufferToArrayBuffer(Buffer.from(Cryptopp.hash.SHA2(authenticationKey, '256'), 'hex'))
    const K = new Uint8Array(64)
    K.set(new Uint8Array(authenticationKey))

    const KxorIpad = K.map((k) => 0xFF & (0x36 ^ k))
    const KxorOpad = K.map((k) => 0xFF & (0x5c ^ k))

    const inner = Cryptopp.hash.create('SHA256')
    inner.update(bufferToArrayBuffer(KxorIpad))

    return new Transform({
      transform (chunk: Buffer, encoding, callback): void {
        try {
          inner.update(bufferToArrayBuffer(chunk))
          callback()
        } catch (e) {
          callback(e)
        }
      },
      flush (callback): void {
        try {
          const outer = new Uint8Array(KxorOpad.byteLength + 32)
          outer.set(KxorOpad)
          outer.set(Buffer.from(inner.finalize(), 'hex'), KxorOpad.byteLength)

          // @ts-ignore
          callback(null, Buffer.from(Cryptopp.hash.SHA2(bufferToArrayBuffer(outer), '256'), 'hex'))
        } catch (e) {
          callback(e)
        }
      }
    })
  }

  rawEncryptStream_ (iv: Buffer): Transform {
    let remaining = Buffer.alloc(0)
    let nextIv: Buffer = iv
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this

    return new Transform({
      async transform (chunk: Buffer, encoding, callback): Promise<void> {
        try {
          const buff = Buffer.concat([remaining, chunk])
          const toEncryptLength = buff.length - (buff.length % 16)
          const toEncrypt = buff.slice(0, toEncryptLength)
          remaining = buff.slice(toEncryptLength)
          if (toEncryptLength === 0) return callback()
          const output = (
            await self.rawEncryptAsync_(toEncrypt, nextIv)
          ).slice(0, -16) // slice -16 to remove padding block (we encrypted a whole number of blocks, so the last block is pure padding)
          nextIv = output.slice(-16) // last block of output will be IV for next block (this is how CBC works)
          this.push(output)
          callback()
        } catch (e) {
          callback(e)
        }
      },
      async flush (callback): Promise<void> {
        try {
          const output = await self.rawEncryptAsync_(remaining, nextIv)
          this.push(output)
          callback()
        } catch (e) {
          callback(e)
        }
      }
    })
  }

  rawDecryptStream_ (iv: Buffer): Transform {
   let remaining = Buffer.alloc(0)
    let nextIv: Buffer = iv
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this

    return new Transform({
      async transform (chunk: Buffer, encoding, callback): Promise<void> {
        try {
          remaining = Buffer.concat([remaining, chunk])
          if (remaining.length >= 32) { // we have to leave 16 for the last block, and need at least 16 to perform decryption
            const toKeep = 16 + (remaining.length % 16)
            const cipherText = remaining.slice(0, -toKeep)
            remaining = remaining.slice(-toKeep)
            const iv = nextIv
            nextIv = cipherText.slice(-16)
            const padding = await self.rawEncryptAsync_(Buffer.alloc(0), nextIv)
            const clearText = await self.rawDecryptAsync_(Buffer.concat([cipherText, padding]), iv)
            this.push(clearText)
          }
          callback()
        } catch (e) {
          callback(e)
        }
      },
      async flush (callback): Promise<void> {
        try {
          if (remaining.length !== 16) throw new Error('INVALID_STREAM')
          const clearText = await self.rawDecryptAsync_(remaining, nextIv)
          this.push(clearText)
          callback()
        } catch (e) {
          callback(e)
        }
      }
    })
  }
}


export default SymKeyRN
