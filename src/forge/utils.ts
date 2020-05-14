import forge, { Bytes } from 'node-forge'
import { promisify } from 'util'

// Necessary stuff because node-forge typings are incomplete...
declare module 'node-forge' {
  namespace random { // eslint-disable-line @typescript-eslint/no-namespace
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    function getBytes(count: number, callback?: (err: Error, bytes: Bytes) => any): Bytes;
  }
}

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
 * Returns a Buffer of random bytes
 * @param {number} [length=10]
 * @return {Buffer}
 */
export const randomBytesSync = (length = 10): Buffer => Buffer.from(forge.random.getBytesSync(length), 'binary')

/**
 * Returns a Buffer of random bytes
 * @param {number} [length=10]
 * @return {Promise<Buffer>}
 */
export const randomBytes = async (length = 10): Promise<Buffer> => Buffer.from(await promisify(forge.random.getBytes)(length), 'binary')
