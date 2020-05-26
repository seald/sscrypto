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

  getHash (): string {
    return sha256(this.publicKeyBuffer).toString('base64')
  }
}

/**
 * Implementation of PrivateKey using Forge (https://github.com/digitalbazaar/forge).
 * @class PrivateKeyWebCrypto
 * @property {Buffer} privateKeyBuffer
 */
// @staticImplements<PrivateKeyConstructor<PrivateKeyForge>>()
class PrivateKeyForge extends makePrivateKeyBaseClass(PublicKeyForge) implements PrivateKeyInterface {
  /**
   * A Buffer that contains a representation of the instantiated RSA PrivateKey using ASN.1 syntax with DER encoding
   * wrapped in a PKCS#8 enveloppe as per RFC 5958, and encoded per PKCS#1 v2.2 specification.
   * @type {Buffer}
   * @readonly
   */
  readonly privateKeyBuffer: Buffer

  /**
   * Stores the forge private key representation of the private key.
   * @type {PublicKeyForge}
   * @protected
   */
  protected _privateKey: forge.pki.rsa.PrivateKey

  /**
   * PrivateKeyForge constructor. Should be given a Buffer either encoded in a PKCS#8 enveloppe or as a bare private
   * key representation using ASN.1 syntax with DER encoding.
   * @constructs PrivateKeyWebCrypto
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
   * Generates asynchronously an RSA Private Key Key and instantiates it as a PrivateKeyForge.
   * @param {AsymKeySize} [size = 4096] - key size in bits
   * @returns {Promise<PrivateKeyForge>}
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
   * Decrypts synchronously with RSAES-OAEP-DECRYPT as per PKCS#1 v2.2 section 7.1.2.
   * @param {Buffer} cipherText
   * @protected
   * @returns {Buffer}
   */
  protected _rawDecryptSync (cipherText: Buffer): Buffer {
    try {
      return Buffer.from(this._privateKey.decrypt(
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
   * `Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section
   * 8.1.1.
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
    return Buffer.from(this._privateKey.sign(md, pss), 'binary')
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

export { PublicKeyForge as PublicKey, PrivateKeyForge as PrivateKey }
