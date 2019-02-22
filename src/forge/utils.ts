import forge from 'node-forge'

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
export const randomBytes = (length: number = 10): Buffer => Buffer.from(forge.random.getBytesSync(length), 'binary')
