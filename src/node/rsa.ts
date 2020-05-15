import crypto from 'crypto'
import { staticImplements } from '../utils/commonUtils'
import { AsymKeySize, PrivateKey, PrivateKeyConstructor, PublicKey, PublicKeyConstructor } from '../utils/rsa'
import { sha256 } from './utils'
import {
  convertDERToPEM,
  convertPEMToDER,
  prefixCRC,
  privateToPublic,
  publicKeyModel,
  splitAndVerifyCRC,
  unwrapPublicKey,
  wrapPublicKey
} from '../utils/rsaUtils'

/**
 * @class PublicKeyNode
 * @property publicKey
 */
@staticImplements<PublicKeyConstructor>()
class PublicKeyNode implements PublicKey {
  protected publicKey: string

  /**
   * PublicKeyNode constructor. Should be given a Buffer containing a DER serialization of the key.
   * @constructs PublicKeyNode
   * @param {Buffer} key
   */
  constructor (key: Buffer) {
    if (!Buffer.isBuffer(key)) {
      throw new Error(`INVALID_KEY : Type of ${key} is ${typeof key}`)
    }
    try {
      const unwrappedKey = unwrapPublicKey(key)
      publicKeyModel.decode(unwrappedKey) // just to check that the key is valid
      this.publicKey = convertDERToPEM(unwrappedKey, 'RSA PUBLIC KEY')
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
  }

  /**
   * Returns a PublicKeyNode from it's DER base64 serialization.
   * @method
   * @static
   * @param {string} b64DERFormattedPublicKey - a b64 encoded public key formatted with DER
   * @returns {PublicKeyNode}
   */
  static fromB64 (b64DERFormattedPublicKey: string): PublicKeyNode {
    return new this(Buffer.from(b64DERFormattedPublicKey, 'base64'))
  }

  /**
   * Serializes the key to DER format and encodes it in b64.
   * @method
   * @param {object} [options]
   * @returns {string}
   */
  toB64 (options: object = null): string {
    return wrapPublicKey(convertPEMToDER(this.publicKey, 'RSA PUBLIC KEY')).toString('base64')
  }

  protected _rawEncryptSync (clearText: Buffer): Buffer {
    return crypto.publicEncrypt(
      {
        key: this.publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
      },
      clearText
    )
  }

  /**
   * Encrypts a clearText for the Private Key corresponding to this PublicKeyNode.
   * @method
   * @param {Buffer} clearText
   * @param {boolean} [doCRC]
   * @returns {Buffer}
   */
  encryptSync (clearText: Buffer, doCRC = true): Buffer {
    return doCRC ? this._rawEncryptSync(prefixCRC(clearText)) : this._rawEncryptSync(clearText)
  }

  async encrypt (clearText: Buffer, doCRC = true): Promise<Buffer> {
    return this.encryptSync(clearText, doCRC)
  }

  /**
   * Verify that the message has been signed with the Private Key corresponding to this PublicKeyNode.
   * @param {Buffer} textToCheckAgainst
   * @param {Buffer} signature
   * @returns {boolean}
   */
  verifySync (textToCheckAgainst: Buffer, signature: Buffer): boolean {
    const verify = crypto.createVerify('SHA256')
    verify.update(textToCheckAgainst)
    return verify.verify(
      {
        key: this.publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
      },
      signature
    )
  }

  async verify (textToCheckAgainst: Buffer, signature: Buffer): Promise<boolean> {
    return this.verifySync(textToCheckAgainst, signature)
  }

  /**
   * @returns {string}
   */
  getHashSync (): string {
    return sha256(Buffer.from(this.toB64({ publicOnly: true }), 'base64')).toString('base64')
  }

  async getHash (): Promise<string> {
    return this.getHashSync()
  }
}

/**
 * @class PrivateKeyNode
 */
@staticImplements<PrivateKeyConstructor>()
class PrivateKeyNode extends PublicKeyNode implements PrivateKey {
  protected privateKey: string

  /**
   * Private Key constructor. Shouldn't be used directly, use `fromB64` or `generate` static methods
   * @constructs PrivateKeyNode
   * @param {Buffer} key
   */
  constructor (key: Buffer) {
    if (!Buffer.isBuffer(key)) {
      throw new Error(`INVALID_KEY : Type of ${key} is ${typeof key}`)
    }
    try {
      super(privateToPublic(key))
      this.privateKey = convertDERToPEM(key, 'RSA PRIVATE KEY')
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
  }

  /**
   * Returns a PrivateKeyNode from it's DER base64 serialization.
   * @method
   * @static
   * @param {string} b64DERFormattedPrivateKey - a b64 encoded private key formatted with DER
   * @returns {PrivateKeyNode}
   */
  static fromB64 (b64DERFormattedPrivateKey: string): PrivateKeyNode {
    return new this(Buffer.from(b64DERFormattedPrivateKey, 'base64'))
  }

  /**
   * Generates a PrivateKeyNode asynchronously
   * @param {Number} [size = 4096] - key size in bits
   * @returns {PrivateKeyNode}
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
   * Serializes the key to DER format and encodes it in b64.
   * @method
   * @param {Object} options
   * @param {boolean} [options.publicOnly]
   * @returns {string}
   */
  toB64 ({ publicOnly = false } = {}): string {
    return publicOnly
      ? super.toB64()
      : convertPEMToDER(this.privateKey, 'RSA PRIVATE KEY').toString('base64')
  }

  protected _rawDecryptSync (cipherText: Buffer): Buffer {
    try {
      return crypto.privateDecrypt(
        {
          key: this.privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        },
        cipherText
      )
    } catch (e) {
      throw new Error(`INVALID_CIPHER_TEXT : ${e.message}`)
    }
  }

  /**
   * Deciphers the given message.
   * @param {Buffer} cipherText
   * @param {boolean} [doCRC]
   * @returns {Buffer}
   */
  decryptSync (cipherText: Buffer, doCRC = true): Buffer {
    const clearText = this._rawDecryptSync(cipherText)
    return doCRC ? splitAndVerifyCRC(clearText) : clearText
  }

  async decrypt (cipherText: Buffer, doCRC = true): Promise<Buffer> {
    return this.decryptSync(cipherText, doCRC)
  }

  /**
   * Signs the given message with this Private Key.
   * @param {Buffer} textToSign
   * @returns {Buffer}
   */
  signSync (textToSign: Buffer): Buffer {
    const sign = crypto.createSign('SHA256')
    sign.update(textToSign)
    return sign.sign({
      key: this.privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
    })
  }

  async sign (textToSign: Buffer): Promise<Buffer> {
    return this.signSync(textToSign)
  }
}

export { PublicKeyNode as PublicKey, PrivateKeyNode as PrivateKey }
