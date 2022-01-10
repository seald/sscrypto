import { Readable, Stream } from 'stream'

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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const mergeInto = (x: Record<string, any>, y: Record<string, any>): void => {
  let y_ = y
  while (y_ !== Object.prototype && y_ !== Function.prototype) {
    for (const key of Object.getOwnPropertyNames(y_)) {
      if (key in x) { continue }
      if (key === 'constructor' || key === 'prototype' || key === 'name') { continue }
      Object.defineProperty(
        x,
        key,
        Object.getOwnPropertyDescriptor(y_, key)
      )
    }
    y_ = Object.getPrototypeOf(y_)
  }
}

export const mixClasses = <ARGS extends unknown[], T1 extends { new (...args: ARGS): InstanceType<T1> }, T2 extends { new (...args: ARGS): InstanceType<T2> }> (C1: T1, C2: T2): { new (...args: ARGS): InstanceType<T1> & InstanceType<T2> } & Omit<T1, 'new'> & Omit<T2, 'new'> => {
  // @ts-ignore : Yes, the type of C1 is unknown, that's the $*#§ing point!
  class C extends C1 {}

  mergeInto(C.prototype, C2.prototype)
  mergeInto(C, C2)

  return C as { new (...args: ARGS): InstanceType<typeof C1> & InstanceType<typeof C2> } & typeof C1 & typeof C2
}
