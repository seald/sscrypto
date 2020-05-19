import crypto from 'crypto'
import { staticImplements } from '../utils/commonUtils'
import {
  AsymKeySize,
  makePrivateKeyBaseClass,
  PrivateKeyInterface,
  PublicKey,
  PublicKeyConstructor
} from '../utils/rsa'
import { sha256 } from './utils'
import {
  convertDERToPEM,
  unwrapPrivateKey,
  unwrapPublicKey

} from '../utils/rsaUtils'

/**
 * Implementation of PublicKey using Node.js crypto module (https://nodejs.org/dist/latest/docs/api/crypto.html).
 * @class PublicKeyNode
 * @property {Buffer} publicKeyBuffer
 */
@staticImplements<PublicKeyConstructor<PublicKeyNode>>()
class PublicKeyNode extends PublicKey {
  /**
   * A Buffer that contains a representation of the instantiated RSA PublicKey using ASN.1 syntax with DER encoding
   * wrapped in an SPKI enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification.
   * @readonly
   * @type {Buffer}
   */
  readonly publicKeyBuffer: Buffer;

  /**
   * Stores the public key in a PEM serialization.
   * @type {string}
   * @protected
   */
  protected _publicKey: string

  /**
   * PublicKeyNode constructor. Should be given a Buffer either encoded in an SPKI enveloppe or as a bare public
   * key representation using ASN.1 syntax with DER encoding.
   * @constructs PublicKeyForge
   * @param {Buffer} key
   */
  constructor (key: Buffer) {
    super(key)
    try {
      this._publicKey = convertDERToPEM(unwrapPublicKey(this.publicKeyBuffer), 'RSA PUBLIC KEY')
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
  }

  /**
   * Encrypts synchronously with RSAES-OAEP-ENCRYPT with SHA-1 as a Hash function and MGF1-SHA-1 as a mask generation
   * function as per PKCS#1 v2.2 section 7.1.1.
   * @param {Buffer} clearText
   * @protected
   * @returns {Buffer}
   */
  protected _rawEncryptSync (clearText: Buffer): Buffer {
    return crypto.publicEncrypt(
      {
        key: this._publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
      },
      clearText
    )
  }

  /**
   * Encrypts asynchronously with RSAES-OAEP-ENCRYPT with SHA-1 as a Hash function and MGF1-SHA-1 as a mask generation
   * function as per PKCS#1 v2.2 section 7.1.1.
   * Shim for the synchronous method.
   * @param {Buffer} clearText
   * @protected
   * @returns {Promise<Buffer>}
   */
  protected async _rawEncrypt (clearText: Buffer): Promise<Buffer> {
    return this._rawEncryptSync(clearText)
  }

  /**
   * Verifies synchronously that the given signature is valid for textToCheckAgainst using RSASSA-PSS-VERIFY which
   * itself uses EMSA-PSS encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
   * `Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section 8.1.2.
   * @param {Buffer} textToCheckAgainst
   * @param {Buffer} signature
   * @returns {boolean}
   */
  verifySync (textToCheckAgainst: Buffer, signature: Buffer): boolean {
    const verify = crypto.createVerify('SHA256')
    verify.update(textToCheckAgainst)
    return verify.verify(
      {
        key: this._publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
      },
      signature
    )
  }

  /**
   * Verifies asynchronously that the given signature is valid for textToCheckAgainst using RSASSA-PSS-VERIFY which
   * itself uses EMSA-PSS encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
   * `Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section 8.1.2.
   * Shim for the synchronous method.
   * @param {Buffer} textToCheckAgainst
   * @param {Buffer} signature
   * @returns {Promise<boolean>}
   */
  async verify (textToCheckAgainst: Buffer, signature: Buffer): Promise<boolean> {
    return this.verifySync(textToCheckAgainst, signature)
  }

  /**
   * Gives a SHA-256 hash encoded in base64 of the RSA PublicKey encoded in base64 using ASN.1 syntax with DER encoding
   * wrapped in an SPKI enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification
   * @returns {string}
   */
  getHash (): string {
    return sha256(Buffer.from(this.toB64({ publicOnly: true }), 'base64')).toString('base64')
  }
}

/**
 * Implementation of PrivateKey using Node.js crypto module (https://nodejs.org/dist/latest/docs/api/crypto.html).
 * @class PrivateKeyWebCrypto
 * @property {Buffer} privateKeyBuffer
 */
// @staticImplements<PrivateKeyConstructor<PrivateKeyNode>>()
class PrivateKeyNode extends makePrivateKeyBaseClass(PublicKeyNode) implements PrivateKeyInterface {
  /**
   * A Buffer that contains a representation of the instantiated RSA PrivateKey using ASN.1 syntax with DER encoding
   * wrapped in a PKCS#8 enveloppe as per RFC 5958, and encoded per PKCS#1 v2.2 specification.
   * @type {Buffer}
   * @readonly
   */
  readonly privateKeyBuffer: Buffer;

  /**
   * Stores the private key in a PEM serialization.
   * @type {string}
   * @protected
   */
  protected _privateKey: string

  /**
   * PrivateKeyNode constructor. Should be given a Buffer either encoded in a PKCS#8 enveloppe or as a bare private
   * key representation using ASN.1 syntax with DER encoding.
   * @constructs PrivateKeyWebCrypto
   * @param {Buffer} key
   */
  constructor (key: Buffer) {
    super(key)
    try {
      this._privateKey = convertDERToPEM(unwrapPrivateKey(this.privateKeyBuffer), 'RSA PRIVATE KEY')
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
  }

  /**
   * Generates asynchronously an RSA Private Key Key and instantiates it as a PrivateKeyNode.
   * @param {AsymKeySize} [size = 4096] - key size in bits
   * @returns {Promise<PrivateKeyNode>}
   */
  static async generate (size: AsymKeySize = 4096): Promise<PrivateKeyNode> {
    if (![4096, 2048, 1024].includes(size)) {
      throw new Error('INVALID_ARG')
    } else {
      const privateKey = await new Promise((resolve: (key: Buffer) => void, reject) => {
        crypto.generateKeyPair(
          'rsa',
          {
            modulusLength: size,
            publicKeyEncoding: { type: 'pkcs1', format: 'der' },
            privateKeyEncoding: { type: 'pkcs1', format: 'der' }
          },
          (err: Error, publicKey: Buffer, privateKey: Buffer) => {
            if (err) return reject(err)
            resolve(privateKey)
          }
        )
      })
      return new this(privateKey)
    }
  }

  /**
   * Decrypts synchronously with RSAES-OAEP-DECRYPT as per PKCS#1 v2.2 section 7.1.2.
   * @param {Buffer} cipherText
   * @protected
   * @returns {Buffer}
   */
  protected _rawDecryptSync (cipherText: Buffer): Buffer {
    try {
      return crypto.privateDecrypt(
        {
          key: this._privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        },
        cipherText
      )
    } catch (e) {
      throw new Error(`INVALID_CIPHER_TEXT : ${e.message}`)
    }
  }

  /**
   * Decrypts asynchronously with RSAES-OAEP-DECRYPT as per PKCS#1 v2.2 section 7.1.2.
   * Shim for the synchronous method.
   * @param {Buffer} cipherText
   * @protected
   * @returns {Promise<Buffer>}
   */
  protected async _rawDecrypt (cipherText: Buffer): Promise<Buffer> {
    return this._rawDecryptSync(cipherText)
  }

  /**
   * Generates synchronously a signature for the given textToSign using RSASSA-PSS-Sign which itself uses EMSA-PSS
   * encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
   * `Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2`as per PKCS#1 v2.2 section 8.1.1.
   * @param {Buffer} textToSign
   * @returns {Buffer}
   */
  signSync (textToSign: Buffer): Buffer {
    const sign = crypto.createSign('SHA256')
    sign.update(textToSign)
    return sign.sign({
      key: this._privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
    })
  }

  /**
   * Generates asynchronously a signature for the given textToSign using RSASSA-PSS-Sign which itself uses EMSA-PSS
   * encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
   * `Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section
   * 8.1.1.
   * Shim for the synchronous method.
   * @param {Buffer} textToSign
   * @returns {Promise<Buffer>}
   */
  async sign (textToSign: Buffer): Promise<Buffer> {
    return this.signSync(textToSign)
  }
}

export { PublicKeyNode as PublicKey, PrivateKeyNode as PrivateKey }
