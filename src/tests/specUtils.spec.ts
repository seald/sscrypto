import { PassThrough, pipeline, Transform, Readable, Writable } from 'stream' // eslint-disable-line no-unused-vars
import { promisify } from 'util'

const pipelineAsync: (input: Readable, ...streams: (Transform | Writable)[]) => Promise<void> = promisify(pipeline)

/**
 * Helper function for the tests.
 * @param {Array<Buffer>} chunks - Array of chunks for the input stream
 * @param {Transform[]} transformStreams - stream.Transform instance
 * @returns {Promise<Buffer>} - Promise that resolves to the output of the transformStream
 */
export const _streamHelper = async (chunks: Array<Buffer>, ...transformStreams: Transform[]): Promise<Buffer> => {
  const inputStream = new PassThrough()
  const outputStream = new PassThrough()

  let outputBuffer = Buffer.alloc(0)

  outputStream.on('data', data => {
    outputBuffer = Buffer.concat([outputBuffer, data])
  })

  const finished = pipelineAsync(inputStream, ...transformStreams, outputStream)

  chunks.forEach(chunk => inputStream.push(chunk))
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