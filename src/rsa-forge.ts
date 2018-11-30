import forge from 'node-forge'
import crc32 from 'crc-32'
import { intToBuffer } from './utils'

/* eslint-disable*/

// Necessary stuff because node-forge typings are incomplete...
declare module 'node-forge' {
  namespace pki {
    function publicKeyFromAsn1 (obj: forge.asn1.Asn1): forge.pki.PublicKey

    function privateKeyFromAsn1 (obj: forge.asn1.Asn1): forge.pki.PrivateKey

    function publicKeyToAsn1 (key: forge.pki.PublicKey): forge.asn1.Asn1

    function privateKeyToAsn1 (key: forge.pki.PrivateKey): forge.asn1.Asn1
  }
}

/* eslint-enable */

const sha256 = (str: string): forge.util.ByteStringBuffer => {
  const md = forge.md.sha256.create()
  md.update(str)
  return md.digest()
}

/**
 * @class PublicKey
 * @property publicKey
 */
export class PublicKey {
  public publicKey: any

  /**
   * PublicKey constructor. Should be given a binary string of the key.
   * @constructs PublicKey
   * @param {Buffer|null} key
   */
  constructor (key: Buffer | null) {
    if (key) {
      if (Buffer.isBuffer(key)) {
        try {
          this.publicKey = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(
            forge.util.createBuffer(key.toString('binary'), 'binary')
          ))
        } catch (e) {
          throw new Error(`INVALID_KEY : ${e.message}`)
        }
      } else {
        throw new Error(`INVALID_KEY : Type of ${key} is ${typeof key}`)
      }
    }
  }

  /**
   * Returns a PublicKey from it's base64 serialization.
   * @method
   * @static
   * @param {string} b64DERFormattedPublicKey - a b64 encoded public key formatted with DER
   * @returns {PublicKey}
   */
  static fromB64 (b64DERFormattedPublicKey: string): PublicKey {
    return new PublicKey(Buffer.from(b64DERFormattedPublicKey, 'base64'))
  }

  /**
   * Serializes the key to DER format and encodes it in b64.
   * @method
   * @param {object} [options]
   * @returns {string}
   */
  toB64 (options: object = null): string {
    return Buffer.from(forge.asn1.toDer(forge.pki.publicKeyToAsn1(this.publicKey)).getBytes(), 'binary').toString('base64')
  }

  /**
   * Encrypts a clearText for the Private Key corresponding to this PublicKey.
   * @method
   * @param {Buffer} clearText
   * @param {boolean} doCRC
   * @returns {Buffer}
   */
  encrypt (clearText: Buffer, doCRC: boolean = true): Buffer {
    const textToEncrypt = doCRC
      ? Buffer.concat([
        intToBuffer(crc32.buf(clearText)),
        clearText
      ])
      : clearText
    return Buffer.from(
      this.publicKey.encrypt(textToEncrypt.toString('binary'), 'RSA-OAEP', {
        md: forge.md.sha1.create(),
        mgf1: {
          md: forge.md.sha1.create()
        }
      }),
      'binary'
    )
  }

  /**
   * Verify that the message has been signed with the Private Key corresponding to this PublicKey.
   * @param {Buffer} textToCheckAgainst
   * @param {Buffer} signature
   * @returns {boolean}
   */
  verify (textToCheckAgainst: Buffer, signature: Buffer): boolean {
    try {
      const saltLength = (this.publicKey.n.bitLength() / 8) - 32 - 2 // TODO: EXPLAIN, EXPLAIN ! // TODO: why a variable ?
      const pss = forge.pss.create({
        md: forge.md.sha256.create(),
        mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
        saltLength: saltLength
      })
      return this.publicKey.verify(
        sha256(textToCheckAgainst.toString('binary')).getBytes(),
        signature.toString('binary'),
        pss
      )
    } catch (e) {
      return false
    }
  }

  /**
   * @returns {string}
   */
  getHash (): string {
    return sha256(this.toB64({ publicOnly: true })).toHex()
  }

  /**
   * @returns {string}
   */
  getB64Hash (): string {
    return Buffer.from(
      sha256(this.toB64({ publicOnly: true })).bytes(),
      'binary'
    ).toString('base64')
  }
}

export type AsymKeySize = 4096 | 2048 | 1024

/**
 * @class PrivateKey
 * @property privateKey
 * @property publicKey
 */
export class PrivateKey extends PublicKey {
  public privateKey: any

  /**
   * Private Key constructor. Shouldn't be used directly, user from or generate static methods
   * @constructs PrivateKey
   * @param {Buffer} arg
   */
  constructor (arg: object | Buffer) {
    super(null)
    if (Buffer.isBuffer(arg)) {
      try {
        this.privateKey = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(
          forge.util.createBuffer(arg.toString('binary'), 'binary')
        ))
      } catch (e) {
        throw new Error(`INVALID_KEY : ${e.message}`)
      }
      this.publicKey = forge.pki.rsa.setPublicKey(this.privateKey.n, this.privateKey.e)
    } else {
      throw new Error(`INVALID_KEY : Type of ${arg} is ${typeof arg}`)
    }
  }

  /**
   * Returns a PrivateKey from it's base64 serialization.
   * @method
   * @static
   * @param {string} b64DERFormattedPrivateKey - a b64 encoded private key formatted with DER
   * @returns {PrivateKey}
   */
  static fromB64 (b64DERFormattedPrivateKey: string): PrivateKey {
    return new PrivateKey(Buffer.from(b64DERFormattedPrivateKey, 'base64'))
  }

  /**
   * Generates a PrivateKey asynchronously, a synchronous call is way longer and may use a non-secure entropy source
   * @param {Number} [size = 4096] - key size in bits
   * @returns {PrivateKey}
   */
  static async generate (size: AsymKeySize = 4096) {
    if (![4096, 2048, 1024].includes(size)) {
      throw new Error('INVALID_INPUT')
    } else {
      const privateKey = await new Promise((resolve: (key: forge.pki.PrivateKey) => void, reject) => {
        forge.pki.rsa.generateKeyPair({
          bits: size,
          workers: -1
        }, (error, keyPair) => error ? reject(error) : resolve(keyPair.privateKey))
      })
      return new PrivateKey(Buffer.from(forge.asn1.toDer(forge.pki.privateKeyToAsn1(privateKey)).getBytes(), 'binary'))
    }
  }

  /**
   * Serializes the key to DER format and encodes it in b64.
   * @method
   * @param {Object} options
   * @param {boolean} [options.publicOnly]
   * @returns {string}
   */
  toB64 ({ publicOnly = false } = {}): string {
    return Buffer.from(
      forge.asn1.toDer(publicOnly
        ? forge.pki.publicKeyToAsn1(this.publicKey)
        : forge.pki.privateKeyToAsn1(this.privateKey)
      ).getBytes()
      , 'binary'
    ).toString('base64')
  }

  /**
   * Deciphers the given message.
   * @param {Buffer} cipherText
   * @param {boolean} [doCRC]
   * @returns {Buffer}
   */
  decrypt (cipherText: Buffer, doCRC: boolean = true): Buffer {
    let clearText
    try {
      clearText = Buffer.from(this.privateKey.decrypt(
        cipherText.toString('binary'),
        'RSA-OAEP',
        {
          md: forge.md.sha1.create(),
          mgf1: {
            md: forge.md.sha1.create()
          }
        }
      ), 'binary')
    } catch (e) {
      throw new Error(`INVALID_CIPHER_TEXT : ${e.message}`)
    }
    if (!doCRC) {
      return clearText
    } else {
      const crc = clearText.slice(0, 4)
      const message = clearText.slice(4)
      const calculatedCRC = intToBuffer(crc32.buf(message))
      if (crc.equals(calculatedCRC)) {
        return message
      } else {
        throw new Error('INVALID_CRC32')
      }
    }
  }

  /**
   * Signs the given message with this Private Key.
   * @param {Buffer} textToSign
   * @returns {Buffer}
   */
  sign (textToSign: Buffer): Buffer {
    const md = forge.md.sha256.create()
    md.update(textToSign.toString('binary'))
    const saltLength = (this.publicKey.n.bitLength() / 8) - 32 - 2 // TODO: EXPLAIN, EXPLAIN !
    const pss = forge.pss.create({
      md: forge.md.sha256.create(),
      mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
      saltLength: saltLength
    })
    return Buffer.from(this.privateKey.sign(md, pss), 'binary')
  }
}
