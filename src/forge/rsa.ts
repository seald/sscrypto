import * as forge from 'node-forge'
import { mixClasses, staticImplements } from '../utils/commonUtils'
import { AsymKeySize, PrivateKey, PublicKey, PrivateKeyConstructor, PublicKeyConstructor } from '../utils/rsa'
import { sha256 } from './utils'

// Necessary stuff because node-forge typings are incomplete...
declare module 'node-forge' {
  namespace pki { // eslint-disable-line @typescript-eslint/no-namespace
    function publicKeyFromAsn1 (obj: forge.asn1.Asn1): forge.pki.rsa.PublicKey

    function privateKeyFromAsn1 (obj: forge.asn1.Asn1): forge.pki.rsa.PrivateKey
  }
}

/**
 * Implementation of PublicKey using Forge (https://github.com/digitalbazaar/forge).
 * @class PublicKeyForge
 * @property {Buffer} publicKeyBuffer
 */
@staticImplements<PublicKeyConstructor<PublicKeyForge>>()
class PublicKeyForge extends PublicKey {
  /**
   * Stores the forge public key representation of the public key.
   * @type {PublicKeyForge}
   * @protected
   */
  protected _publicKey: forge.pki.rsa.PublicKey

  constructor (key: Buffer) {
    super(key)
    try {
      this._publicKey = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(
        forge.util.createBuffer(this.publicKeyBuffer)
      ))
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
  }

  _rawEncryptSync (clearText: Buffer): Buffer {
    return Buffer.from(
      this._publicKey.encrypt(clearText.toString('binary'), 'RSA-OAEP', {
        md: forge.md.sha1.create(),
        mgf1: {
          md: forge.md.sha1.create()
        }
      }),
      'binary'
    )
  }

  verify (textToCheckAgainst: Buffer, signature: Buffer): boolean {
    try {
      // this corresponds to the RSA_PSS_SALTLEN_MAX : https://cryptography.io/en/latest/_modules/cryptography/hazmat/primitives/asymmetric/padding/#calculate_max_pss_salt_length
      const saltLength = (this._publicKey.n.bitLength() / 8) - 32 - 2
      const pss = forge.pss.create({
        md: forge.md.sha256.create(),
        mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
        saltLength
      })
      return this._publicKey.verify(
        sha256(textToCheckAgainst).toString('binary'),
        signature.toString('binary'),
        pss
      )
    } catch {
      return false
    }
  }

  getHash (): string {
    return sha256(this.publicKeyBuffer).toString('base64')
  }
}

/**
 * Implementation of PrivateKey using Forge (https://github.com/digitalbazaar/forge).
 * @class PrivateKeyWebCrypto
 * @property {Buffer} privateKeyBuffer
 */
@staticImplements<PrivateKeyConstructor<PrivateKeyForge>>()
class PrivateKeyForge extends mixClasses(PublicKeyForge, PrivateKey) {
  readonly privateKeyBuffer: Buffer

  /**
   * Stores the forge private key representation of the private key.
   * @type {PublicKeyForge}
   * @protected
   */
  protected _privateKeyForge: forge.pki.rsa.PrivateKey

  constructor (key: Buffer) {
    const { publicKeyBuffer, privateKeyBuffer } = new.target.constructor_(key)
    super(publicKeyBuffer)
    this.privateKeyBuffer = privateKeyBuffer
    try {
      this._privateKeyForge = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(this.privateKeyBuffer)))
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
  }

  toB64 ({ publicOnly = false } = {}): string {
    return this.toB64_({ publicOnly })
  }

  static async generate (size: AsymKeySize = 4096): Promise<PrivateKeyForge> {
    if (![4096, 2048, 1024].includes(size)) {
      throw new Error('INVALID_ARG')
    } else {
      const privateKey = await new Promise((resolve: (key: forge.pki.rsa.PrivateKey) => void, reject) => {
        forge.pki.rsa.generateKeyPair({
          bits: size,
          workers: -1
        }, (error, keyPair) => error ? reject(error) : resolve(keyPair.privateKey))
      })
      return new this(Buffer.from(forge.asn1.toDer(forge.pki.privateKeyToAsn1(privateKey)).getBytes(), 'binary'))
    }
  }

  _rawDecryptSync (cipherText: Buffer): Buffer {
    try {
      return Buffer.from(this._privateKeyForge.decrypt(
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
  }

  sign (textToSign: Buffer): Buffer {
    const md = forge.md.sha256.create()
    md.update(textToSign.toString('binary'))
    // this corresponds to the RSA_PSS_SALTLEN_MAX : https://cryptography.io/en/latest/_modules/cryptography/hazmat/primitives/asymmetric/padding/#calculate_max_pss_salt_length
    const saltLength = (this._privateKeyForge.n.bitLength() / 8) - 32 - 2
    const pss = forge.pss.create({
      md: forge.md.sha256.create(),
      mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
      saltLength
    })
    return Buffer.from(this._privateKeyForge.sign(md, pss), 'binary')
  }
}

export { PublicKeyForge as PublicKey, PrivateKeyForge as PrivateKey }
