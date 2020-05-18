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
 * @class PublicKeyNode
 * @property publicKey
 */
@staticImplements<PublicKeyConstructor<PublicKeyNode>>()
class PublicKeyNode extends PublicKey {
  readonly publicKeyBuffer: Buffer;

  protected _publicKey: string

  /**
   * PublicKeyNode constructor. Should be given a Buffer containing a DER serialization of the key.
   * @constructs PublicKeyNode
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

  protected _rawEncryptSync (clearText: Buffer): Buffer {
    return crypto.publicEncrypt(
      {
        key: this._publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
      },
      clearText
    )
  }

  protected async _rawEncrypt (clearText: Buffer): Promise<Buffer> {
    return this._rawEncryptSync(clearText)
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
        key: this._publicKey,
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
  getHash (): string {
    return sha256(Buffer.from(this.toB64({ publicOnly: true }), 'base64')).toString('base64')
  }
}

/**
 * @class PrivateKeyNode
 */
// @staticImplements<PrivateKeyConstructor<PrivateKeyNode>>()
class PrivateKeyNode extends makePrivateKeyBaseClass(PublicKeyNode) implements PrivateKeyInterface {
  readonly privateKeyBuffer: Buffer;

  protected _privateKey: string

  /**
   * Private Key constructor. Shouldn't be used directly, use `fromB64` or `generate` static methods
   * @constructs PrivateKeyNode
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

  protected async _rawDecrypt (cipherText: Buffer): Promise<Buffer> {
    return this._rawDecryptSync(cipherText)
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
      key: this._privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
    })
  }

  async sign (textToSign: Buffer): Promise<Buffer> {
    return this.signSync(textToSign)
  }
}

export { PublicKeyNode as PublicKey, PrivateKeyNode as PrivateKey }
