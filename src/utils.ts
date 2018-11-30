import forge from 'node-forge'
import { Stream } from 'stream' // eslint-disable-line no-unused-vars

/**
 * Waits for 't' milliseconds
 * @param {number} t
 * @returns {Promise<void>}
 */
export const wait = (t: number = 1000): Promise<void> => new Promise(resolve => setTimeout(resolve, t))

/**
 * Encodes the given data to base64.
 * @param {string} data
 * @returns {string}
 */
export const b64 = (data: string): string =>
  (Buffer.from(data, 'binary')
    .toString('base64')
    .replace(/\//g, '%')
    .replace(/=/g, ''))

/**
 * Decodes the given data from base64.
 * @param {string} data
 * @returns {string}
 */
export const unb64 = (data: string): string => {
  if (data && /^[A-Za-z0-9%+]*$/.test(data)) {
    return (Buffer.from(`${data.replace(/%/g, '/')}${'='.repeat(4 - (data.length % 4))}`, 'base64').toString('binary'))
  } else {
    throw new Error('INVALID_B64')
  }
}

/**
 * Converts the given number to a bytes string.
 * @param {number} n
 * @returns {string}
 */
export const intToBytes = (n: number): string => {
  const buff = Buffer.alloc(4)
  buff.writeInt32LE(n, 0)
  return buff.toString('binary')
}

/**
 * Returns a hex string representing the SHA256 hash of the given string/
 * @param {string} str !! BINARY STRING EXPECTED !! => encodeUTF8
 */
export const sha256 = (str: string) => {
  const md = forge.md.sha256.create()
  md.update(str)
  return md.digest()
}

/**
 * Returns a random string containing [A-z0-9] of given length
 * @param {number} [length=10]
 * @returns {string}
 */
export const randomString = (length: number = 10): string => b64(randomBytes(length)).replace(/[^a-z0-9]/gi, '').slice(0, length)

/**
 * Returns a random string containing binary chars of given length
 * @param {number} [length=10]
 * @returns {string}
 */
export const randomBytes = (length: number): string => forge.random.getBytesSync(length)

/**
 * @param {string} string
 * @returns {string}
 */
export const encodeUTF8 = (string: string): string => forge.util.encodeUtf8(string)

/**
 * @param {string} string
 * @returns {string}
 */
export const decodeUTF8 = (string: string): string => forge.util.decodeUtf8(string)

export const getProgress: () => (increment: number, stream: Stream, delay?: number) => void = () => {
  let counter = 0
  let lastEmitProgress
  /**
   * @param {number} increment
   * @param {Stream} stream
   * @param {number} delay
   */
  return (increment: number, stream: Stream, delay: number = 30) => { // don't send progress more than each 30ms
    counter += increment
    if (delay === 0 || !lastEmitProgress || Date.now() - lastEmitProgress > delay) {
      lastEmitProgress = Date.now()
      stream.emit('progress', counter)
    }
  }
}
