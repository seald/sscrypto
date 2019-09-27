import { PassThrough, Readable, Transform, Writable } from 'stream'
import { promisify } from 'util'
import pump from 'pump'

const pipelineAsync: (input: Readable, ...streams: (Transform | Writable)[]) => Promise<void> = promisify(pump)

/**
 * Helper function for the tests.
 * @param {Array<Buffer>} chunks - Array of chunks for the input stream
 * @param {Transform[]} transformStreams - stream.Transform instance
 * @returns {Promise<Buffer>} - Promise that resolves to the output of the transformStream
 */
export const _streamHelper = async (chunks: Buffer[], ...transformStreams: Transform[]): Promise<Buffer> => {
  const inputStream = new PassThrough()
  const outputStream = new PassThrough()

  const output: Buffer[] = []

  outputStream.on('data', data => {
    output.push(data)
  })

  const finished = pipelineAsync(inputStream, ...transformStreams, outputStream)

  chunks.forEach(chunk => inputStream.push(chunk))
  inputStream.end()

  await finished
  return Buffer.concat(output)
}

/**
 * splits the given string or buffer into chunks of given length
 * @param {Buffer} input
 * @param {number} length
 * @return {Array<Buffer>}
 */
export const splitLength = (input: Buffer, length: number): Buffer[] => {
  const chunks = []
  while (input.length) {
    chunks.push(input.slice(0, length))
    input = input.slice(length)
  }
  return chunks
}
