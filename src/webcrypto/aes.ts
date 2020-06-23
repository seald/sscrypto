import { Transform } from 'stream'
import SymKeyForge from '../forge/aes'
import { getEngine, isWebCryptoAvailable, randomBytes, randomBytesSync } from './utils'
import { SymKey, SymKeyConstructor, SymKeySize } from '../utils/aes'

class SymKeyWebCrypto extends SymKeyForge {
  protected subtleAuthenticationKey: Promise<CryptoKey>
  protected subtleEncryptionKey: Promise<CryptoKey>

  constructor (key: Buffer) {
    super(key)
    this.subtleAuthenticationKey = null
    this.subtleEncryptionKey = null
  }

  static async generate<T extends SymKey> (this: SymKeyConstructor<T>, size: SymKeySize = 256): Promise<T> {
    if (!isWebCryptoAvailable()) return new this(await this.randomBytesAsync_(size / 4)) // `size / 4` is `(size / 8) * 2`
    if (size === 192 && getEngine() === 'Blink') return new this(await this.randomBytesAsync_(size / 4)) // 192-bit AES keys are not supported in SubtleCrypto in Chromium
    const authenticationKey = await window.crypto.subtle.generateKey(
      { name: 'HMAC', length: size, hash: 'SHA-256' },
      true,
      ['sign']
    )
    const encryptionKey = await window.crypto.subtle.generateKey(
      { name: 'AES-CBC', length: size },
      true,
      ['encrypt', 'decrypt']
    )
    const exported = Buffer.concat([
      Buffer.from(await window.crypto.subtle.exportKey('raw', authenticationKey))
        .slice(0, size / 8), // this is mainly for old Edge, which always gives 256b auth keys regardless of the size argument
      Buffer.from(await window.crypto.subtle.exportKey('raw', encryptionKey))
    ])
    return new this(exported)
  }

  protected getSubtleEncryptionKey_ (): Promise<CryptoKey> {
    if (this.subtleEncryptionKey) return this.subtleEncryptionKey
    this.subtleEncryptionKey = window.crypto.subtle.importKey(
      'raw',
      this.key.slice(this.keySize / 8),
      'AES-CBC',
      false,
      ['encrypt', 'decrypt']
    ) as Promise<CryptoKey> // somehow TypeScript typings of DOM think importKey returns a PromiseLike, not a Promise
    return this.subtleEncryptionKey
  }

  protected getSubtleAuthenticationKey_ (): Promise<CryptoKey> {
    if (this.subtleAuthenticationKey) return this.subtleAuthenticationKey
    this.subtleAuthenticationKey = window.crypto.subtle.importKey(
      'raw',
      this.key.slice(0, this.keySize / 8),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    ) as Promise<CryptoKey> // somehow TypeScript typings of DOM think importKey returns a PromiseLike, not a Promise
    return this.subtleAuthenticationKey
  }

  static randomBytesAsync_ (size: number): Promise<Buffer> {
    return randomBytes(size)
  }

  static randomBytesSync_ (size: number): Buffer {
    return randomBytesSync(size)
  }

  async calculateHMACAsync_ (textToAuthenticate: Buffer): Promise<Buffer> {
    if (!isWebCryptoAvailable()) return this.calculateHMACSync_(textToAuthenticate) // using `super` causes problems on old Edge
    if (textToAuthenticate.length === 0 && getEngine() === 'EdgeHTML') return this.calculateHMACSync_(textToAuthenticate) // empty buffers cause problems on old Edge
    return Buffer.from(await window.crypto.subtle.sign(
      { name: 'HMAC', hash: 'SHA-256' }, // stupid old Edge needs the hash here
      await this.getSubtleAuthenticationKey_(),
      textToAuthenticate
    ))
  }

  async rawEncryptAsync_ (clearText: Buffer, iv: Buffer): Promise<Buffer> {
    if (!isWebCryptoAvailable()) return this.rawEncryptSync_(clearText, iv)
    if (this.keySize === 192 && getEngine() === 'Blink') return this.rawEncryptSync_(clearText, iv) // // 192-bit AES keys are not supported in SubtleCrypto in Chromium
    if (clearText.length === 0 && getEngine() === 'EdgeHTML') return this.rawEncryptSync_(clearText, iv) // empty buffers cause problems on old Edge
    return Buffer.from(await window.crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      await this.getSubtleEncryptionKey_(),
      clearText
    ))
  }

  rawEncryptStream_ (iv: Buffer): Transform {
    if (!isWebCryptoAvailable()) return super.rawEncryptStream_(iv)
    if (this.keySize === 192 && getEngine() === 'Blink') return super.rawEncryptStream_(iv) // // 192-bit AES keys are not supported in SubtleCrypto in Chromium
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

  async rawDecryptAsync_ (cipherText: Buffer, iv: Buffer): Promise<Buffer> {
    if (!isWebCryptoAvailable()) return this.rawDecryptSync_(cipherText, iv)
    if (this.keySize === 192 && getEngine() === 'Blink') return this.rawDecryptSync_(cipherText, iv) // // 192-bit AES keys are not supported in SubtleCrypto in Chromium
    if (cipherText.length === 16 && getEngine() === 'EdgeHTML') return this.rawDecryptSync_(cipherText, iv) // CipherText corresponding to empty buffer causes problems on old Edge. This way to check is a bit overzealous and will catch CipherTexts corresponding to everything <= 15bytes long, but I don't know how to check more precisely
    return Buffer.from(await window.crypto.subtle.decrypt(
      { name: 'AES-CBC', iv },
      await this.getSubtleEncryptionKey_(),
      cipherText
    ))
  }

  rawDecryptStream_ (iv: Buffer): Transform {
    if (!isWebCryptoAvailable()) return super.rawDecryptStream_(iv)
    if (this.keySize === 192 && getEngine() === 'Blink') return super.rawDecryptStream_(iv) // // 192-bit AES keys are not supported in SubtleCrypto in Chromium
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

export default SymKeyWebCrypto
