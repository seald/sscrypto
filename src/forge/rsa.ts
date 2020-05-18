import forge from 'node-forge'
import { staticImplements } from '../utils/commonUtils'
import { BigInteger } from 'jsbn'
import {
  AsymKeySize,
  makePrivateKeyBaseClass,
  PrivateKeyInterface,
  PublicKey,
  PublicKeyConstructor
} from '../utils/rsa'
import { sha256 } from './utils'

// Necessary stuff because node-forge typings are incomplete...
declare module 'node-forge' {
  namespace pki { // eslint-disable-line @typescript-eslint/no-namespace
    function publicKeyFromAsn1 (obj: forge.asn1.Asn1): forge.pki.rsa.PublicKey

    function privateKeyFromAsn1 (obj: forge.asn1.Asn1): forge.pki.rsa.PrivateKey
  }
}

/**
 * @class PublicKeyForge
 * @property publicKey
 */
@staticImplements<PublicKeyConstructor<PublicKeyForge>>()
class PublicKeyForge extends PublicKey {
  readonly publicKeyBuffer: Buffer

  protected _publicKey: forge.pki.rsa.PublicKey

  /**
   * PublicKeyForge constructor. Should be given a Buffer containing a DER serialization of the key.
   * @constructs PublicKeyForge
   * @param {Buffer} key
   */
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

  protected _rawEncryptSync (clearText: Buffer): Buffer {
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

  protected async _rawEncrypt (clearText: Buffer): Promise<Buffer> {
    return this._rawEncryptSync(clearText)
  }

  /**
   * Verify that the message has been signed with the Private Key corresponding to this PublicKeyForge.
   * @param {Buffer} textToCheckAgainst
   * @param {Buffer} signature
   * @returns {boolean}
   */
  verifySync (textToCheckAgainst: Buffer, signature: Buffer): boolean {
    try {
      // this corresponds to the RSA_PSS_SALTLEN_MAX : https://cryptography.io/en/latest/_modules/cryptography/hazmat/primitives/asymmetric/padding/#calculate_max_pss_salt_length
      const saltLength = ((this._publicKey.n as BigInteger).bitLength() / 8) - 32 - 2
      const pss = forge.pss.create({
        md: forge.md.sha256.create(),
        mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
        saltLength: saltLength
      })
      return this._publicKey.verify(
        sha256(textToCheckAgainst).toString('binary'),
        signature.toString('binary'),
        pss
      )
    } catch (e) {
      return false
    }
  }

  async verify (textToCheckAgainst: Buffer, signature: Buffer): Promise<boolean> {
    return this.verifySync(textToCheckAgainst, signature)
  }

  getHash (): string {
    return sha256(this.publicKeyBuffer).toString('base64')
  }
}

/**
 * @class PrivateKeyForge
 */
// @staticImplements<PrivateKeyConstructor<PrivateKeyForge>>()
class PrivateKeyForge extends makePrivateKeyBaseClass(PublicKeyForge) implements PrivateKeyInterface {
  readonly privateKeyBuffer: Buffer

  protected _privateKey: forge.pki.rsa.PrivateKey

  protected get privateKey (): forge.pki.rsa.PrivateKey {
    if (!this._privateKey) {
      this._privateKey = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(
        forge.util.createBuffer(this.privateKeyBuffer)
      ))
    }
    return this._privateKey
  }

  /**
   * Private Key constructor. Shouldn't be used directly, use `fromB64` or `generate` static methods
   * @constructs PrivateKeyForge
   * @param {Buffer} key
   */
  constructor (key: Buffer) {
    super(key)
    try {
      this._privateKey = this._privateKey = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(
        forge.util.createBuffer(this.privateKeyBuffer)
      ))
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
  }

  /**
   * Generates a PrivateKeyForge asynchronously
   * @param {Number} [size = 4096] - key size in bits
   * @returns {PrivateKeyForge}
   */
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
      return new PrivateKeyForge(Buffer.from(forge.asn1.toDer(forge.pki.privateKeyToAsn1(privateKey)).getBytes(), 'binary'))
    }
  }

  protected _rawDecryptSync (cipherText: Buffer): Buffer {
    try {
      return Buffer.from(this.privateKey.decrypt(
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

  protected async _rawDecrypt (cipherText: Buffer): Promise<Buffer> {
    return this._rawDecryptSync(cipherText)
  }

  /**
   * Signs the given message with this Private Key.
   * @param {Buffer} textToSign
   * @returns {Buffer}
   */
  signSync (textToSign: Buffer): Buffer {
    const md = forge.md.sha256.create()
    md.update(textToSign.toString('binary'))
    // this corresponds to the RSA_PSS_SALTLEN_MAX : https://cryptography.io/en/latest/_modules/cryptography/hazmat/primitives/asymmetric/padding/#calculate_max_pss_salt_length
    const saltLength = ((this._privateKey.n as BigInteger).bitLength() / 8) - 32 - 2
    const pss = forge.pss.create({
      md: forge.md.sha256.create(),
      mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
      saltLength: saltLength
    })
    return Buffer.from(this.privateKey.sign(md, pss), 'binary')
  }

  async sign (textToSign: Buffer): Promise<Buffer> {
    return this.signSync(textToSign)
  }
}

export { PublicKeyForge as PublicKey, PrivateKeyForge as PrivateKey }
