import forge from 'node-forge'
import { staticImplements } from '../utils/commonUtils'
import { BigInteger } from 'jsbn'
import { AsymKeySize, PrivateKey, PrivateKeyConstructor, PublicKey, PublicKeyConstructor } from '../utils/rsa'
import { sha256 } from './utils'
import { prefixCRC, splitAndVerifyCRC } from '../utils/rsaUtils'

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
@staticImplements<PublicKeyConstructor>()
class PublicKeyForge implements PublicKey {
  protected publicKey: forge.pki.rsa.PublicKey

  /**
   * PublicKeyForge constructor. Should be given a Buffer containing a DER serialization of the key.
   * @constructs PublicKeyForge
   * @param {Buffer} key
   */
  constructor (key: Buffer) {
    if (!Buffer.isBuffer(key)) {
      throw new Error(`INVALID_KEY : Type of ${key} is ${typeof key}`)
    }
    try {
      this.publicKey = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(
        forge.util.createBuffer(key)
      ))
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
  }

  /**
   * Returns a PublicKeyForge from it's DER base64 serialization.
   * @method
   * @static
   * @param {string} b64DERFormattedPublicKey - a b64 encoded public key formatted with DER
   * @returns {PublicKeyForge}
   */
  static fromB64 (b64DERFormattedPublicKey: string): PublicKeyForge {
    return new PublicKeyForge(Buffer.from(b64DERFormattedPublicKey, 'base64'))
  }

  /**
   * Serializes the key to DER format and encodes it in b64.
   * @method
   * @param {object} [options]
   * @returns {string}
   */
  toB64 (options: {} = null): string {
    return Buffer.from(forge.asn1.toDer(forge.pki.publicKeyToAsn1(this.publicKey)).getBytes(), 'binary').toString('base64')
  }

  protected _rawEncryptSync (clearText: Buffer): Buffer {
    return Buffer.from(
      this.publicKey.encrypt(clearText.toString('binary'), 'RSA-OAEP', {
        md: forge.md.sha1.create(),
        mgf1: {
          md: forge.md.sha1.create()
        }
      }),
      'binary'
    )
  }

  encryptSync (clearText: Buffer, doCRC = true): Buffer {
    return doCRC ? this._rawEncryptSync(prefixCRC(clearText)) : this._rawEncryptSync(clearText)
  }

  async encrypt (clearText: Buffer, doCRC = true): Promise<Buffer> {
    return this.encryptSync(clearText, doCRC)
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
      const saltLength = ((this.publicKey.n as BigInteger).bitLength() / 8) - 32 - 2
      const pss = forge.pss.create({
        md: forge.md.sha256.create(),
        mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
        saltLength: saltLength
      })
      return this.publicKey.verify(
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

  getHashSync (): string {
    return sha256(Buffer.from(this.toB64({ publicOnly: true }), 'base64')).toString('base64')
  }

  async getHash (): Promise<string> {
    return this.getHashSync()
  }
}

/**
 * @class PrivateKeyForge
 */
@staticImplements<PrivateKeyConstructor>()
class PrivateKeyForge extends PublicKeyForge implements PrivateKey {
  protected privateKey: forge.pki.rsa.PrivateKey

  /**
   * Private Key constructor. Shouldn't be used directly, use `fromB64` or `generate` static methods
   * @constructs PrivateKeyForge
   * @param {Buffer} key
   */
  constructor (key: Buffer) {
    if (!Buffer.isBuffer(key)) {
      throw new Error(`INVALID_KEY : Type of ${key} is ${typeof key}`)
    }
    try {
      const privateKey = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(
        forge.util.createBuffer(key)
      ))
      const publicKey = forge.pki.rsa.setPublicKey(privateKey.n, privateKey.e)
      super(Buffer.from(forge.asn1.toDer(forge.pki.publicKeyToAsn1(publicKey)).getBytes(), 'binary'))
      this.privateKey = privateKey
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
  }

  /**
   * Returns a PrivateKeyForge from it's DER base64 serialization.
   * @method
   * @static
   * @param {string} b64DERFormattedPrivateKey - a b64 encoded private key formatted with DER
   * @returns {PrivateKeyForge}
   */
  static fromB64 (b64DERFormattedPrivateKey: string): PrivateKeyForge {
    return new PrivateKeyForge(Buffer.from(b64DERFormattedPrivateKey, 'base64'))
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

  /**
   * Serializes the key to DER format and encodes it in b64.
   * @method
   * @param {Object} options
   * @param {boolean} [options.publicOnly]
   * @returns {string}
   */
  toB64 ({ publicOnly = false } = {}): string {
    if (publicOnly) {
      return super.toB64()
    } else {
      return Buffer.from(
        forge.asn1.toDer(forge.pki.privateKeyToAsn1(this.privateKey)).getBytes(),
        'binary'
      ).toString('base64')
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
    const md = forge.md.sha256.create()
    md.update(textToSign.toString('binary'))
    // this corresponds to the RSA_PSS_SALTLEN_MAX : https://cryptography.io/en/latest/_modules/cryptography/hazmat/primitives/asymmetric/padding/#calculate_max_pss_salt_length
    const saltLength = ((this.publicKey.n as BigInteger).bitLength() / 8) - 32 - 2
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
