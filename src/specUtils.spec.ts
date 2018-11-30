import MemoryStream from 'memorystream'
import { Transform } from 'stream' // eslint-disable-line no-unused-vars

/**
 * Helper function for the tests.
 * @param {Array<Buffer>} chunks - Array of chunks for the input stream
 * @param {Transform} transformStream - stream.Transform instance
 * @returns {Promise<Buffer>} - Promise that resolves to the output of the transformStream
 */
export const _streamHelper = async (chunks: Array<Buffer>, transformStream: Transform): Promise<Buffer> => {
  const inputStream = new MemoryStream()
  const outputStream = inputStream.pipe(transformStream)
  let outputBuffer = Buffer.alloc(0)

  const finished = new Promise((resolve, reject) => {
    outputStream.on('end', resolve)
    outputStream.on('error', reject)
  })
  outputStream.on('data', data => {
    outputBuffer = Buffer.concat([outputBuffer, data])
  })

  chunks.forEach(chunk => inputStream.write(chunk))
  inputStream.end()

  await finished
  return outputBuffer
}

/**
 * splits the given string or buffer into chunks of given length
 * @param {Buffer} input
 * @param {number} length
 * @return {Array<Buffer>}
 */
export const splitLength = (input: Buffer, length: number): Array<Buffer> => {
  const chunks = []
  while (input.length) {
    chunks.push(input.slice(0, length))
    input = input.slice(length)
  }
  return chunks
}
