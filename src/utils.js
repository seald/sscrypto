import forge from 'node-forge'

/**
 * Waits for 't' milliseconds
 * @param {number} t
 * @returns {Promise<void>}
 */
export const wait = (t = 1000) => new Promise(resolve => setTimeout(resolve, t))

/**
 * Encodes the given data to base64.
 * @param {string} data
 * @returns {string}
 */
export const b64 = (data) =>
  (Buffer.from(data, 'binary')
    .toString('base64')
    .replace(/\//g, '%')
    .replace(/=/g, ''))

/**
 * Decodes the given data from base64.
 * @param {string} data
 * @returns {string}
 */
export const unb64 = (data) => {
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
export const intToBytes = (n) => {
  // noinspection JSUnresolvedFunction
  const buff = Buffer.alloc(4)
  buff.writeInt32LE(n)
  return buff.toString('binary')
}

/**
 * Returns a hex string representing the SHA256 hash of the given string/
 * @param {string} str !! BINARY STRING EXPECTED !! => encodeUTF8
 * @returns {{data: string, read: integer, _constructedStringLength: integer}}
 */
export const sha256 = (str) => {
  const md = forge.md.sha256.create()
  md.update(str)
  // noinspection JSValidateTypes
  return md.digest()
}

// noinspection JSCheckFunctionSignatures
/**
 * Returns a random string containing [A-z0-9] of given length
 * @param {number} [length=10]
 * @returns {string}
 */
export const randomString = (length = 10) => b64(randomBytes(length)).replace(/[^a-z0-9]/gi, '').slice(0, length)

export const randomBytes = length => forge.random.getBytesSync(length)

export const encodeUTF8 = string => forge.util.encodeUtf8(string)

export const decodeUTF8 = string => forge.util.decodeUtf8(string)

export const getProgress = () => {
  let counter = 0
  let lastEmitProgress
  return (increment, stream, delay = 30) => { // don't send progress more than each 30ms
    counter += increment
    if (delay === false || !lastEmitProgress || Date.now() - lastEmitProgress > delay) {
      lastEmitProgress = Date.now()
      stream.emit('progress', counter)
    }
  }
}
