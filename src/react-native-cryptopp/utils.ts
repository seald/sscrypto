import { randomBytes as randomBytesForge, randomBytesAsync as randomBytesAsyncForge } from '../forge/utils'
// @ts-ignore
import Cryptopp from 'react-native-cryptopp'
import { sha256 as sha256Forge } from '../forge/utils'

export const bufferToArrayBuffer = (buffer: Buffer|Uint8Array): ArrayBuffer => {
  if (buffer.byteOffset === 0 && buffer.buffer.byteLength === buffer.length) return buffer.buffer
  else return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength)
}

const sha256RN = (data: Buffer): Buffer => {
  return Buffer.from(
    // @ts-ignore
    Cryptopp.hash.SHA256(bufferToArrayBuffer(data)),
    'hex'
  )
}

/* eslint-disable no-var,@typescript-eslint/ban-types */
declare global {
  var nativeCallSyncHook: Function
}
/* eslint-enable no-var,@typescript-eslint/ban-types */

const isChromeDebugger = (): boolean => {
  // https://github.com/facebook/react-native/commit/417e191a1cfd6a049d1d4b0a511f87aa7f176082
  return typeof global.nativeCallSyncHook === 'undefined'
}

const CRC32 = (buffer: Buffer): Buffer => {
  return Buffer.from(
    // @ts-ignore
    Cryptopp.hash.CRC32(bufferToArrayBuffer(buffer)).padStart(8, '0'),
    'hex'
  ).reverse()
}

/**
 * Prefixes the cleartext with a CRC32 of the clearText
 * @param {Buffer} clearText
 * @returns {Buffer}
 */
export const prefixCRC = (clearText: Buffer): Buffer =>
  Buffer.concat([
    CRC32(clearText),
    clearText
  ])

/**
 * Check that the cleartext is prefixed with a CRC32, and verifies it.
 * Throws with `INVALID_CRC32` if CRC32 does not match.
 * @param clearText
 * @return {Buffer}
 */
export const splitAndVerifyCRC = (clearText: Buffer): Buffer => {
  const crc = clearText.subarray(0, 4)
  const message = clearText.subarray(4)
  const calculatedCRC = CRC32(message)
  if (crc.equals(calculatedCRC)) return message
  else throw new Error('INVALID_CRC32')
}

const randomBytesRN = (length = 10): Buffer => Buffer.from(Cryptopp.utils.randomBytes(length))

const randomBytesAsyncRN = async (length = 10): Promise<Buffer> => Promise.resolve(randomBytesRN(length))

/**
 * Returns a Buffer of random bytes
 * @param {number} [length=10]
 * @return {Buffer}
 */
export const randomBytes = isChromeDebugger() ? randomBytesForge : randomBytesRN

/**
 * Returns a Buffer of random bytes
 * @param {number} [length=10]
 * @return {Promise<Buffer>}
 */
export const randomBytesAsync = isChromeDebugger() ? randomBytesAsyncForge : randomBytesAsyncRN

/**
 * Returns a Buffer containing the hash of the given data
 * @param {Buffer} data
 * @return {Buffer}
 */
export const sha256 = isChromeDebugger() ? sha256Forge : sha256RN
