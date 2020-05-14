import forge from 'node-forge'
import { getProgress } from '../utils/commonUtils'
import { Transform } from 'stream'
import SymKeyForge from '../forge/aes'
import { SymKey } from '../utils/aes'

class SymKeyWebCrypto extends SymKeyForge implements SymKey {
  /**
   * Creates a Transform stream that encrypts the data piped to it.
   * @returns {Transform}
   */
  encryptStream (): Transform {
    // @ts-ignore
    if (!window.crypto || !window.crypto.subtle || !window.crypto.getRandomValues || window.SSCRYPTO_NO_WEBCRYPTO) return super.encryptStream()
    let canceled = false
    const progress = getProgress()
    const encryptionKey = this.encryptionKey

    let iv = Buffer.from(window.crypto.getRandomValues(new Uint8Array(16)))
    let remaining = Buffer.alloc(0)

    let webcryptoKey: CryptoKey
    let lock = Promise.resolve()

    const hmac = forge.hmac.create()
    hmac.start('sha256', this.signingKey)

    let firstBlock = true

    return new Transform({
      transform (chunk: Buffer, encoding, callback): void {
        lock = lock.then(async () => {
          try {
            if (firstBlock) progress(0, this, 0)
            if (canceled) throw new Error('STREAM_CANCELED')
            if (firstBlock) {
              webcryptoKey = await window.crypto.subtle.importKey(
                'raw',
                Buffer.from(encryptionKey, 'binary').buffer,
                'AES-CBC',
                false,
                ['encrypt']
              )
              if (canceled) throw new Error('STREAM_CANCELED')
              const header = iv
              hmac.update(header.toString('binary'))
              this.push(header)
              firstBlock = false
            }
            const buff = Buffer.concat([remaining, chunk])
            const toEncryptLength = buff.length - (buff.length % 16)
            const toEncrypt = buff.slice(0, toEncryptLength)
            remaining = buff.slice(toEncryptLength)
            if (toEncryptLength === 0) return callback()
            const output = Buffer.from(
              await window.crypto.subtle.encrypt(
                { name: 'AES-CBC', iv },
                webcryptoKey,
                toEncrypt
              )
            ).slice(0, -16) // slice -16 to remove padding block (we encrypted a whole number of blocks, so the last block is pure padding)
            if (canceled) throw new Error('STREAM_CANCELED')
            iv = output.slice(-16) // last block of output will be IV for next block (this is how CBC works)
            hmac.update(output.toString('binary'))
            this.push(output)
            progress(chunk.length, this)
            callback()
          } catch (e) {
            callback(e)
          }
        })
      },
      flush (callback): void {
        lock.then(async () => {
          try {
            if (canceled) throw new Error('STREAM_CANCELED')
            progress(0, this, 0)
            const output = Buffer.from(
              await window.crypto.subtle.encrypt(
                { name: 'AES-CBC', iv },
                webcryptoKey,
                remaining
              )
            )
            if (canceled) throw new Error('STREAM_CANCELED')
            hmac.update(output.toString('binary'))
            this.push(output)
            const digest = hmac.digest()
            const buffer = Buffer.from(digest.getBytes(), 'binary')
            this.push(buffer)
            callback()
          } catch (e) {
            callback(e)
          }
        })
      }
    })
      .on('cancel', () => {
        canceled = true
      })
  }

  /**
   * Creates a Transform stream that decrypts the encrypted data piped to it.
   * @returns {Transform}
   */
  decryptStream (): Transform {
    // @ts-ignore
    if (!window.crypto || !window.crypto.subtle || window.SSCRYPTO_NO_WEBCRYPTO) return super.decryptStream()
    let canceled = false
    const progress = getProgress()
    const encryptionKey = this.encryptionKey

    let iv: Buffer
    let remaining = Buffer.alloc(0)

    let webcryptoKey: CryptoKey
    let lock = Promise.resolve()

    const hmac = forge.hmac.create()
    hmac.start('sha256', this.signingKey)

    let firstBlock = true

    return new Transform({
      transform (chunk: Buffer, encoding, callback) {
        lock = lock.then(async () => {
          try {
            if (firstBlock) {
              progress(0, this, 0)
              if (canceled) throw new Error('STREAM_CANCELED')
              webcryptoKey = await window.crypto.subtle.importKey(
                'raw',
                Buffer.from(encryptionKey, 'binary').buffer,
                'AES-CBC',
                false,
                ['encrypt', 'decrypt']
              )
              firstBlock = false
            }
            if (canceled) throw new Error('STREAM_CANCELED')
            remaining = Buffer.concat([remaining, chunk])
            if (!iv) { // we have not gotten the IV yet, gotta wait for it
              if (remaining.length >= 16) { // length of IV
                iv = remaining.slice(0, 16)
                remaining = remaining.slice(16)
                hmac.update(iv.toString('binary'))
              }
            }
            if (iv) { // we have the IV, can decrypt
              if (remaining.length >= 64) { // we have to leave 32 bytes for the HMAC, 16 for the last block, and need at least 16 to perform decryption
                const toKeep = 48 + (remaining.length % 16)
                const cipherText = remaining.slice(0, -toKeep)
                remaining = remaining.slice(-toKeep)
                hmac.update(cipherText.toString('binary'))
                const nextIv = cipherText.slice(-16)
                const padding = Buffer.from(
                  await window.crypto.subtle.encrypt(
                    { name: 'AES-CBC', iv: nextIv },
                    webcryptoKey,
                    Buffer.alloc(0)
                  )
                )
                const clearText = Buffer.from(
                  await window.crypto.subtle.decrypt(
                    { name: 'AES-CBC', iv },
                    webcryptoKey,
                    Buffer.concat([cipherText, padding])
                  )
                )
                if (canceled) throw new Error('STREAM_CANCELED')
                iv = nextIv
                this.push(clearText)
              }
            }
            progress(chunk.length, this)
            callback()
          } catch (e) {
            callback(e)
          }
        })
      },
      flush (callback) {
        lock.then(async () => {
          try {
            if (canceled) throw new Error('STREAM_CANCELED')
            if (remaining.length !== 48) throw new Error('INVALID_STREAM')
            const cipherText = remaining.slice(0, 16)
            const streamDigest = remaining.slice(16).toString('binary')
            const clearText = Buffer.from(
              await window.crypto.subtle.decrypt(
                { name: 'AES-CBC', iv },
                webcryptoKey,
                cipherText
              )
            )
            if (canceled) throw new Error('STREAM_CANCELED')
            this.push(clearText)
            progress(0, this, 0)
            hmac.update(cipherText.toString('binary'))
            const computedDigest = hmac.digest().getBytes()
            if (streamDigest !== computedDigest) throw new Error('INVALID_HMAC')
            callback()
          } catch (e) {
            callback(e)
          }
        })
      }
    })
      .on('cancel', () => {
        canceled = true
      })
  }
}

export default SymKeyWebCrypto
