import { Stream } from 'stream'

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

export function staticImplements<T> (): ((constructor: T) => void) {
  return (constructor: T) => {}
}
