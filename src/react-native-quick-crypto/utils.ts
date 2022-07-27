import crypto from 'react-native-quick-crypto'

/**
 * Returns a Buffer containing the hash of the given data
 * @param {Buffer} data
 * @return {Buffer}
 */
export const sha256 = (data: Buffer): Buffer => {
  const md = crypto.createHash('sha256')
  md.update(data)
  return md.digest()
}

/**
 * Returns a Buffer of random bytes
 * @param {number} [length=10]
 * @return {Buffer}
 */
export const randomBytes = (length = 10): Buffer => crypto.randomBytes(length)

/**
 * Returns a Buffer of random bytes
 * @param {number} [length=10]
 * @return {Promise<Buffer>}
 */
export const randomBytesAsync = async (length = 10): Promise<Buffer> => crypto.randomBytes(length)
