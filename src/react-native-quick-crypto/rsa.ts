import crypto from 'react-native-quick-crypto'
import { mixClasses, staticImplements } from '../utils/commonUtils'
import {
  AsymKeySize,
  PublicKey,
  PublicKeyConstructor,
  PrivateKeyConstructor,
  PrivateKey
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
   * Stores the public key in a PEM serialization.
   * @type {string}
   * @protected
   */
  protected _publicKey: string

  constructor (key: Buffer) {
    super(key)
    try {
      this._publicKey = convertDERToPEM(unwrapPublicKey(this.publicKeyBuffer), 'RSA PUBLIC KEY')
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
  }

  _rawEncryptSync (clearText: Buffer): Buffer {
    return crypto.publicEncrypt(
      {
        key: this._publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
      },
      clearText
    )
  }

  verify (textToCheckAgainst: Buffer, signature: Buffer): boolean {
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

  getHash (): string {
    return sha256(Buffer.from(this.toB64({ publicOnly: true }), 'base64')).toString('base64')
  }
}

/**
 * Implementation of PrivateKey using Node.js crypto module (https://nodejs.org/dist/latest/docs/api/crypto.html).
 * @class PrivateKeyWebCrypto
 * @property {Buffer} privateKeyBuffer
 */
@staticImplements<PrivateKeyConstructor<PrivateKeyNode>>()
class PrivateKeyNode extends mixClasses(PublicKeyNode, PrivateKey) {
  readonly privateKeyBuffer: Buffer

  /**
   * Stores the private key in a PEM serialization.
   * @type {string}
   * @protected
   */
  protected _privateKey: string

  constructor (key: Buffer) {
    const { publicKeyBuffer, privateKeyBuffer } = new.target.constructor_(key)
    super(publicKeyBuffer)
    this.privateKeyBuffer = privateKeyBuffer
    try {
      this._privateKey = convertDERToPEM(unwrapPrivateKey(this.privateKeyBuffer), 'RSA PRIVATE KEY')
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
  }

  toB64 ({ publicOnly = false } = {}): string {
    return this.toB64_({ publicOnly })
  }

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

  _rawDecryptSync (cipherText: Buffer): Buffer {
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

  sign (textToSign: Buffer): Buffer {
    const sign = crypto.createSign('SHA256')
    sign.update(textToSign)
    return sign.sign({
      key: this._privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
    })
  }
}

export { PublicKeyNode as PublicKey, PrivateKeyNode as PrivateKey }
