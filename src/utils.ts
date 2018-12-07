import { Stream } from 'stream' // eslint-disable-line no-unused-vars
// @ts-ignore: TODO: typings
import asn from 'asn1.js'

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

/**
 * Helper thingy for Stream progress
 */
export const getProgress: () => (increment: number, stream: Stream, delay?: number) => void = () => {
  let counter = 0
  let lastEmitProgress: number
  /**
   * @param {number} increment
   * @param {Stream} stream
   * @param {number} delay
   */
  return (increment: number, stream: Stream, delay: number = 30) => { // don't send progress more than each 30ms
    counter += increment
    if (delay === 0 || !lastEmitProgress || Date.now() - lastEmitProgress > delay) {
      lastEmitProgress = Date.now()
      stream.emit('progress', counter)
    }
  }
}

/**
 * Convert DER to PEM
 * @param {Buffer} der
 * @param {string} label
 * @return {string}
 */
export const convertDERToPEM = (der: Buffer, label: string = 'RSA PUBLIC KEY'): string => {
  const base64 = der.toString('base64')
  const lines = []
  let i = 0
  while (i < base64.length) {
    const n = Math.min(base64.length - i, 64)
    lines.push(base64.substr(i, n))
    i += n
  }
  const body = lines.join('\n')
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`
}

/**
 * getRegExpForPEM
 * @param {string} label
 * @return {RegExp}
 */
export const getRegExpForPEM = (label: string = 'RSA PUBLIC KEY'): RegExp => {
  const head = `\\-\\-\\-\\-\\-BEGIN ${label}\\-\\-\\-\\-\\-`
  const body = '(?:[a-zA-Z0-9\\+/=]{64}\n)*[a-zA-Z0-9\\+/=]{1,64}'
  const end = `\\-\\-\\-\\-\\-END ${label}\\-\\-\\-\\-\\-`
  return new RegExp(`^${head}\n(${body})\n${end}\n$`)
}

/**
 * Convert PEM to DER
 * @param {string} pem
 * @param {string} label
 * @return {Buffer}
 */
export const convertPEMToDER = (pem: string, label: string = 'RSA PUBLIC KEY'): Buffer => {
  const regexp = getRegExpForPEM(label)
  const base64 = regexp.exec(pem)[1].replace(/\n/g, '')
  return Buffer.from(base64, 'base64')
}

export const privateKeyModel = asn.define('privateKeyModel', function () {
  this.seq().obj(
    this.key('zero').int(),
    this.key('n').int(),
    this.key('e').int(),
    this.key('d').int(),
    this.key('p').int(),
    this.key('q').int(),
    this.key('dP').int(),
    this.key('dQ').int(),
    this.key('qInv').int()
  )
})

export const publicKeyModel = asn.define('publicKeyModel', function () {
  this.seq().obj(
    this.key('n').int(),
    this.key('e').int()
  )
})

/**
 * privateToPublic
 * @param {Buffer} buff
 * @return {Buffer}
 */
export const privateToPublic = (buff: Buffer): Buffer => {
  const privateKey = privateKeyModel.decode(buff, 'der')
  return publicKeyModel.encode({ 'n': privateKey['n'], 'e': privateKey['e'] }, 'der')
}

export function staticImplements<T> () {
  return (constructor: T) => {}
}
