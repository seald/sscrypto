import './patches'
import { NativeModules } from 'react-native'
import { randomBytes as randomBytesForge, randomBytesAsync as randomBytesAsyncForge } from '../forge/utils'
export { sha256 } from '../forge/utils'

/* eslint-disable no-var,@typescript-eslint/ban-types */
declare global {
  var nativeCallSyncHook: Function
}
/* eslint-enable no-var,@typescript-eslint/ban-types */

const isChromeDebugger = (): boolean => {
  // https://github.com/facebook/react-native/commit/417e191a1cfd6a049d1d4b0a511f87aa7f176082
  return typeof global.nativeCallSyncHook === 'undefined'
}

const getRandomBase64 = (byteLength: number) => {
  if (NativeModules.RNGetRandomValues) {
    return NativeModules.RNGetRandomValues.getRandomBase64(byteLength)
  } else {
    throw new Error('Please install react-native-get-random-values')
  }
}

const randomBytesRN = (length = 10): Buffer => Buffer.from(getRandomBase64(length), 'base64')

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
