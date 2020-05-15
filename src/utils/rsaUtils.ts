// @ts-ignore: TODO: typings
import asn from 'asn1.js'
import crc32 from 'crc-32'
import { intToBuffer } from './commonUtils'

/**
 * Convert DER to PEM
 * @param {Buffer} der
 * @param {string} label
 * @return {string}
 */
export const convertDERToPEM = (der: Buffer, label = 'RSA PUBLIC KEY'): string => {
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
const getRegExpForPEM = (label = 'RSA PUBLIC KEY'): RegExp => {
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
export const convertPEMToDER = (pem: string, label = 'RSA PUBLIC KEY'): Buffer => {
  const regexp = getRegExpForPEM(label)
  const base64 = regexp.exec(pem)[1].replace(/\n/g, '')
  return Buffer.from(base64, 'base64')
}

const privateKeyModel = asn.define('privateKeyModel', function () {
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

const publicKeyWrapperModel = asn.define('publicKeyWrapperModel', function () {
  this.seq().obj(
    this.key('wrapper').seq().obj(
      this.key('desc').objid({ '1.2.840.113549.1.1.1': 'RSA' }),
      this.key('empty').null_()
    ),
    this.key('key').bitstr()
  )
})

const privateKeyWrapperModel = asn.define('privateKeyWrapperModel', function () {
  this.seq().obj(
    this.key('zero').int(),
    this.key('wrapper').seq().obj(
      this.key('desc').objid({ '1.2.840.113549.1.1.1': 'RSA' }),
      this.key('empty').null_()
    ),
    this.key('key').octstr()
  )
})

/**
 * wrapPublicKey
 * @param {Buffer} buff
 * @return {Buffer}
 */
export const wrapPublicKey = (buff: Buffer): Buffer => {
  return publicKeyWrapperModel.encode({
    wrapper: { desc: 'RSA', empty: null },
    key: { unused: 0, data: buff }
  })
}

export const wrapPrivateKey = (buff: Buffer): Buffer => {
  return privateKeyWrapperModel.encode({
    zero: 0,
    wrapper: { desc: 'RSA', empty: null },
    key: buff
  })
}
/**
 * unwrapPublicKey
 * @param {Buffer} buff
 * @return {Buffer}
 */
export const unwrapPublicKey = (buff: Buffer): Buffer => {
  return publicKeyWrapperModel.decode(buff).key.data
}

export const unwrapPrivateKey = (buff: Buffer): Buffer => {
  return privateKeyWrapperModel.decode(buff).key
}
/**
 * privateToPublic
 * @param {Buffer} buff
 * @return {Buffer}
 */
export const privateToPublic = (buff: Buffer): Buffer => {
  const privateKey = privateKeyModel.decode(buff, 'der')
  return wrapPublicKey(publicKeyModel.encode({ n: privateKey.n, e: privateKey.e }, 'der'))
}

export const prefixCRC = (clearText: Buffer): Buffer => Buffer.concat([
  intToBuffer(crc32.buf(clearText)),
  clearText
])
export const splitAndVerifyCRC = (clearText: Buffer): Buffer => {
  const crc = clearText.slice(0, 4)
  const message = clearText.slice(4)
  const calculatedCRC = intToBuffer(crc32.buf(message))
  if (crc.equals(calculatedCRC)) {
    return message
  } else {
    throw new Error('INVALID_CRC32')
  }
}
