import { Readable, Stream, Writable } from 'stream'

/**
 * Converts the given number to a Buffer.
 * @param {number} n
 * @returns {Buffer}
 */
export const intToBuffer = (n: number): Buffer => {
  const buff = Buffer.alloc(4)
  buff.writeInt32LE(n, 0)
  return buff
}

type progressCallback = (increment: number, stream: Stream, delay?: number) => void

/**
 * Helper thingy for Stream progress
 */
export const getProgress: () => progressCallback = (): progressCallback => {
  let counter = 0
  let lastEmitProgress: number
  /**
   * @param {number} increment
   * @param {Stream} stream
   * @param {number} delay
   */
  return (increment: number, stream: Stream, delay = 30): void => { // don't send progress more than each 30ms
    counter += increment
    if (delay === 0 || !lastEmitProgress || Date.now() - lastEmitProgress > delay) {
      lastEmitProgress = Date.now()
      stream.emit('progress', counter)
    }
  }
}

// https://github.com/microsoft/TypeScript/issues/33892
export function staticImplements<T> (): ((constructor: T) => void) {
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  return <U extends T> (constructor: U): void => {}
}

export const streamToData = (inputStream: Readable): Promise<Buffer> => new Promise((resolve, reject) => {
  let output = Buffer.alloc(0)
  inputStream
    .on('data', chunk => {
      output = Buffer.concat([output, chunk])
    })
    .on('error', reject)
    .on('end', () => resolve(output))
})

export const writeInStream = async (stream: Writable, data: Buffer): Promise<void> => { // this should basically never be needed for crypto streams, but hey, better do things cleanly
  const shouldWait = !stream.write(data)
  if (shouldWait) await new Promise(resolve => stream.once('drain', resolve))
}
