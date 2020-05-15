import { PassThrough, Readable, Transform, Writable } from 'stream'
import { promisify } from 'util'
import pump from 'pump'

const pipelineAsync: (input: Readable, ...streams: (Transform | Writable)[]) => Promise<void> = promisify(pump)
// TODO: try node's pipeline thing

// Helper function for the tests.
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

// splits the given string or buffer into chunks of given length
export const splitLength = (input: Buffer, length: number): Buffer[] => {
  const chunks = []
  while (input.length) {
    chunks.push(input.slice(0, length))
    input = input.slice(length)
  }
  return chunks
}

export type TestHooks = { duringBefore?: () => void, duringAfter?: () => void }
