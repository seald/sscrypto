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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const mergeInto = (x: Record<string, any>, y: Record<string, any>): void => {
  let y_ = y
  while (y_ !== Object.prototype && y_ !== Function.prototype) {
    for (const name of Object.getOwnPropertyNames(y_)) {
      if (!(name in x)) {
        Object.defineProperty(
          x,
          name,
          Object.getOwnPropertyDescriptor(y_, name)
        )
      }
    }
    y_ = Object.getPrototypeOf(y_)
  }
}

export const mixClasses = <T1 extends { new (): unknown }, T2 extends { new (): unknown }> (C1: T1, C2: T2): { new (): InstanceType<T1> & InstanceType<T2> } & Omit<T1, 'new'> & Omit<T2, 'new'> => {
  // @ts-ignore : Yes, the type of C1 is unknown, that's the $*#§ing point!
  class C extends C1 {}

  mergeInto(C.prototype, C2.prototype)
  mergeInto(C, C2)

  return C as { new (): InstanceType<typeof C1> & InstanceType<typeof C2> } & typeof C1 & typeof C2
}

class Test0 {
  protected secret2 = 'bar'

  static staticT0 (): void {
    console.log('staticT0')
  }

  t0 (): void {
    console.log('t0 ' + this.secret2)
  }
}

class Test1 {
  private secret = 'foo'

  static staticT1 (): boolean {
    console.log('staticT1')
    return true
  }

  t1 (): void {
    console.log('t1 ' + this.secret)
  }

  tConflict (): void {
    console.log('TConflict t1')
  }
}

class Test2 extends Test0 {
  static staticT2 (): void {
    console.log('staticT2')
  }

  t2 (): void {
    console.log('t2')
  }

  tConflict (): void {
    console.log('TConflict t2')
  }
}

console.log('start')

class T extends mixClasses(Test1, Test2) {
  protected secret2 = 'bar'

  t0 () {
    console.log('TMIXED T0')
    super.t0()
  }

  t1 () {
    console.log('TMIXED T1')
    super.t1()
  }
}

const t = new T()
t.t1()
t.t2()
T.staticT1()
T.staticT2()
t.t0()
T.staticT0()
t.tConflict()
console.log(t instanceof Test0)
console.log(t instanceof Test1)
console.log(t instanceof Test2)
