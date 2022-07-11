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

/**
 * ASN.1 model for bare private key, needed to decode key modulus and public exponent.
 */
export const privateKeyModel = asn.define('privateKeyModel', function () {
  this.seq().obj(
    // The naming comes from RFC8017 Appendix A.1.2
    this.key('version').int(), // Version, set as 0 because only single prime implementations are covered
    this.key('n').int(), // the RSA modulus, a positive integer
    this.key('e').int(), // the RSA public exponent, a positive integer
    this.key('d').int(), // the RSA private exponent, a positive integer
    this.key('p').int(), // the first factor, a positive integer
    this.key('q').int(), // the second factor, a positive integer
    this.key('dP').int(), // the first factor's CRT exponent, a positive integer
    this.key('dQ').int(), // the second factor's CRT exponent, a positive integer
    this.key('qInv').int() // the CRT coefficient, a positive integer
  )
})

/**
 * ASN.1 model for bare public key, needed to decode key modulus and public exponent.
 */
export const publicKeyModel = asn.define('publicKeyModel', function () {
  this.seq().obj(
    // Public key encoded as per PKCS#1 v2.2 (RFC8017 https://tools.ietf.org/html/rfc8017#appendix-A.1.1)
    this.key('n').int(), // Modulus
    this.key('e').int() // Public Exponent
  )
})

const publicKeyWrapperModel = asn.define('publicKeyWrapperModel', function () {
  this.seq().obj(
    // Public key encoded as per RFC5280 https://tools.ietf.org/html/rfc5280#section-4.1.2.7for RSAEncryption defined in
    // PKCS#1 v2.2 (RFC8017 https://tools.ietf.org/html/rfc8017#appendix-A.1.2)
    this.key('algorithmIdentifier').seq().obj(
      this.key('algorithm').objid({ '1.2.840.113549.1.1.1': 'rsaEncryption' }), // OID for rsaEncryption per PKCS#1 v2.2
      this.key('parameters').null_() // NULL for rsaEncryption
    ),
    this.key('publicKey').bitstr() // key as a bit string
  )
})

const privateKeyWrapperModel = asn.define('privateKeyWrapperModel', function () {
  this.seq().obj(
    // Private key encoded as per PKCS#8 (RFC5958 https://tools.ietf.org/html/rfc5958#section-2) for RSAEncryption
    // defined in PKCS#1 v2.2 (RFC8017 https://tools.ietf.org/html/rfc8017#appendix-A.1.2)
    this.key('version').int(), // Should be 0 because attributes are not used
    this.key('privateKeyAlgorithm').seq().obj(
      this.key('algorithmIdentifier').objid({ '1.2.840.113549.1.1.1': 'rsaEncryption' }), // OID for rsaEncryption
      this.key('algorithmParameters').null_() // NULL for rsaEncryption
    ),
    this.key('privateKey').octstr() // key as an octet string
  )
})

/**
 * Wraps the bare representation of the public key with an SPKI enveloppe.
 * @param {Buffer} buff
 * @returns {Buffer}
 */
export const wrapPublicKey = (buff: Buffer): Buffer => {
  return publicKeyWrapperModel.encode({
    algorithmIdentifier: { algorithm: 'rsaEncryption', parameters: null },
    publicKey: { unused: 0, data: buff }
  })
}

/**
 * Wraps the bare representation of the prviate key with a PKCS#8 enveloppe.
 * @param {Buffer} buff
 * @returns {Buffer}
 */
export const wrapPrivateKey = (buff: Buffer): Buffer => {
  return privateKeyWrapperModel.encode({
    version: 0,
    privateKeyAlgorithm: { algorithmIdentifier: 'rsaEncryption', algorithmParameters: null },
    privateKey: buff
  })
}

/**
 * Extracts the bare representation of the public key from its SPKI enveloppe.
 * @param {Buffer} buff
 * @returns {Buffer}
 */
export const unwrapPublicKey = (buff: Buffer): Buffer => {
  return publicKeyWrapperModel.decode(buff).publicKey.data
}

/**
 * Extracts the bare representation of the private key from PKCS#8 enveloppe.
 * @param {Buffer} buff
 * @returns {Buffer}
 */
export const unwrapPrivateKey = (buff: Buffer): Buffer => {
  return privateKeyWrapperModel.decode(buff).privateKey
}

/**
 * Checks if given RSA private key is wrapped with a PKCS#8 enveloppe or if it's a bare representation.
 * Throws if invalid representation with `INVALID_PRIVATE_KEY`.
 * @param {Buffer} buffer
 * @returns {boolean}
 */
export const privateKeyHasHeader = (buffer: Buffer): boolean => {
  if (!privateKeyModel.decode(buffer, 'der', { partial: true }).errors.length) return false
  if (!privateKeyWrapperModel.decode(buffer, 'der', { partial: true }).errors.length) return true
  throw new Error('INVALID_PRIVATE_KEY')
}

/**
 * Checks if given RSA public key is wrapped with an SPKI enveloppe or if it's a bare representation.
 * Throws if invalid representation with `INVALID_PUBLIC_KEY`
 * @param {Buffer} buffer
 * @returns {boolean}
 */
export const publicKeyHasHeader = (buffer: Buffer): boolean => {
  if (!publicKeyModel.decode(buffer, 'der', { partial: true }).errors.length) return false
  if (!publicKeyWrapperModel.decode(buffer, 'der', { partial: true }).errors.length) return true
  throw new Error('INVALID_PUBLIC_KEY')
}

/**
 * Extracts the public key from a private key.
 * Input encoding can either be bare the PKCS#1 representation using ASN.1 syntax with DER encoding, or with PKCS#8
 * encapsulation.
 * Output encoding will be the PKCS#1 representation using ASN.1 syntax with DER encoding wrapped with an SPKI
 * enveloppe.
 * @param {Buffer} buff
 * @returns {Buffer}
 */
export const privateToPublic = (buff: Buffer): Buffer => {
  const privateKey = privateKeyHasHeader(buff) ? privateKeyModel.decode(unwrapPrivateKey(buff), 'der') : privateKeyModel.decode(buff, 'der')
  return wrapPublicKey(publicKeyModel.encode({ n: privateKey.n, e: privateKey.e }, 'der'))
}

/**
 * Prefixes the cleartext with a CRC32 of the clearText
 * @param {Buffer} clearText
 * @param {function} calculateCRC32
 * @returns {Buffer}
 */
export const prefixCRC = (clearText: Buffer, calculateCRC32: (b: Buffer) => Buffer): Buffer => Buffer.concat([
  calculateCRC32(clearText),
  clearText
])

/**
 * Check that the cleartext is prefixed with a CRC32, and verifies it.
 * Throws with `INVALID_CRC32` if CRC32 does not match.
 * @param clearText
 * @return {Buffer}
 */
export const splitAndVerifyCRC = (clearText: Buffer, calculateCRC32: (b: Buffer) => Buffer): Buffer => {
  const crc = clearText.subarray(0, 4)
  const message = clearText.subarray(4)
  const calculatedCRC = calculateCRC32(message)
  if (crc.equals(calculatedCRC)) return message
  else throw new Error('INVALID_CRC32')
}
