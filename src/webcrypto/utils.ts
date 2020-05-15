import forge from 'node-forge'
import { promisify } from 'util'

declare global {
  interface Window {
    SSCRYPTO_NO_WEBCRYPTO: boolean
  }
}

export const isWebCryptoAvailable = (): boolean => window.crypto && window.crypto.subtle && !window.SSCRYPTO_NO_WEBCRYPTO

/**
 * Returns a Buffer containing the hash of the given data
 * @param {Buffer} data
 * @return {Buffer}
 */
export const sha256 = (data: Buffer): Buffer => {
  const md = forge.md.sha256.create()
  md.update(data.toString('binary'))
  return Buffer.from(md.digest().data, 'binary')
}

/**
 * Returns a Buffer containing the hash of the given data
 * @param {Buffer} data
 * @return {Buffer}
 */
export const sha256Async = async (data: Buffer): Promise<Buffer> => {
  return Buffer.from(
    await window.crypto.subtle.digest(
      'SHA-256',
      data
    )
  )
}

/**
 * Returns a Buffer of random bytes
 * @param {number} [length=10]
 * @return {Buffer}
 */
export const randomBytesSync = (length = 10): Buffer => {
  // @ts-ignore
  if (isWebCryptoAvailable()) {
    return Buffer.from(window.crypto.getRandomValues(new Uint8Array(length)))
  } else {
    return Buffer.from(forge.random.getBytesSync(length), 'binary')
  }
}

/**
 * Returns a Buffer of random bytes
 * @param {number} [length=10]
 * @return {Promise<Buffer>}
 */
export const randomBytes = async (length = 10): Promise<Buffer> => {
  // @ts-ignore
  if (isWebCryptoAvailable()) {
    return Buffer.from(window.crypto.getRandomValues(new Uint8Array(length)))
  } else {
    return Buffer.from(await promisify(forge.random.getBytes)(length), 'binary')
  }
}
