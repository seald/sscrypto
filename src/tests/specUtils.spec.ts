import { PassThrough, pipeline, Transform } from 'stream'
import { promisify } from 'util'

const pipelineAsync = promisify(pipeline) // 'stream/promises' only exists in node@16

export const wait = (t: number): Promise<void> => new Promise(resolve => setTimeout(resolve, t))

// Helper function for the tests.
export const _streamHelper = async (chunks: Buffer[], ...transformStreams: Transform[]): Promise<Buffer> => {
  const inputStream = new PassThrough()
  const outputStream = new PassThrough()

  const output: Buffer[] = []

  outputStream.on('data', data => {
    output.push(data)
  })

  const finished = pipelineAsync([inputStream, ...transformStreams, outputStream])

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

export const assertType = <T> (x: T): void => {
  // this function is just to assert that the argument type is correct, so nothing to actually do
}
