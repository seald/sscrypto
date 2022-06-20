import { NativeModules } from 'react-native'

export { sha256 } from '../forge/utils'

// TODO: fix on chrome debugger

const getRandomBase64 = (byteLength: number) => {
  if (NativeModules.RNGetRandomValues) {
    return NativeModules.RNGetRandomValues.getRandomBase64(byteLength)
  } else if (NativeModules.ExpoRandom) {
    return NativeModules.ExpoRandom.getRandomBase64String(byteLength)
  } else {
    throw new Error('Please install react-native-get-random-values or expo-random')
  }
}

/**
 * Returns a Buffer of random bytes
 * @param {number} [length=10]
 * @return {Buffer}
 */
export const randomBytes = (length = 10): Buffer => Buffer.from(getRandomBase64(length), 'base64')

/**
 * Returns a Buffer of random bytes
 * @param {number} [length=10]
 * @return {Promise<Buffer>}
 */
export const randomBytesAsync = async (length = 10): Promise<Buffer> => Promise.resolve(randomBytes(length))
