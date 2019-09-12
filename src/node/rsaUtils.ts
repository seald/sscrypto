// @ts-ignore: TODO: typings
import asn from 'asn1.js'

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

/**
 * unwrapPublicKey
 * @param {Buffer} buff
 * @return {Buffer}
 */
export const unwrapPublicKey = (buff: Buffer): Buffer => {
  return publicKeyWrapperModel.decode(buff).key.data
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
