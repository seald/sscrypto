import {
  prefixCRC,
  privateKeyHasHeader,
  privateKeyModel,
  privateToPublic,
  publicKeyHasHeader,
  publicKeyModel,
  splitAndVerifyCRC,
  unwrapPrivateKey,
  unwrapPublicKey,
  wrapPrivateKey,
  wrapPublicKey
} from './rsaUtils'
import { intToBuffer, staticImplements } from './commonUtils'
import crc32 from 'crc-32'

/**
 * @type {AsymKeySize} Sizes of key authorized for AsymKeys in bits
 */
export type AsymKeySize = 4096 | 2048 | 1024

/**
 * @interface {PublicKeyConstructor<PublicKey>>} Constructor of a PublicKey
 * @constructs {PublicKey}
 */
export interface PublicKeyConstructor<T extends PublicKey> {
  new (key: Buffer): T

  fromB64 (messageKey: string): T
}

/**
 * Abstract class for any implementation of PublicKey
 * Not really an abstract class because TypeScript is *@#&$ and does not support multiple inheritance
 * @abstract
 * @class PublicKey
 * @property {Buffer} publicKeyBuffer
 */
export abstract class PublicKey {
  /**
   * A Buffer that contains a representation of the instantiated RSA PublicKey using ASN.1 syntax with DER encoding
   * wrapped in an SPKI enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification.
   * @readonly
   * @type {Buffer}
   */
  readonly publicKeyBuffer: Buffer

  /**
   * Constructor for PublicKey class for every public key implementation of SSCrypto.
   * It ensures that given buffer is a valid PublicKey, either encoded in an SPKI enveloppe or as a bare public key
   * representation using ASN.1 syntax with DER encoding, and sets the publicKeyBuffer
   * @param {Buffer} key
   * @constructs PublicKey
   * @protected
   */
  protected constructor (key: Buffer) {
    if (!Buffer.isBuffer(key)) throw new Error(`INVALID_KEY : Type of ${key} is ${typeof key}`)
    let n
    try {
      this.publicKeyBuffer = publicKeyHasHeader(key) ? key : wrapPublicKey(key)
      const unwrappedKey = unwrapPublicKey(this.publicKeyBuffer);
      ({ n } = publicKeyModel.decode(unwrappedKey)) // just to check that the key is valid
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
    if (![1024, 2048, 4096].includes(n.bitLength())) throw new Error(`INVALID_ARG : Key size is invalid, got ${n.bitLength()}`)
  }

  /**
   * Instantiates a PublicKey from a base64 representation of an RSA public key using ASN.1 syntax with DER encoding
   * per PKCS#1 v2.2 specification and optionally wrapped in an SPKI enveloppe as per RFC 5280.
   * @param {string} b64DERFormattedPublicKey
   * @returns {PublicKey}
   */
  static fromB64<T extends PublicKey> (this: PublicKeyConstructor<T>, b64DERFormattedPublicKey: string): T {
    return new this(Buffer.from(b64DERFormattedPublicKey, 'base64'))
  }

  /**
   * Exports the instance of an RSA PublicKey in base64 using ASN.1 syntax with DER encoding wrapped in an SPKI
   * enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification.
   * @param {options} [options=null] useless options argument in a PublicKey
   * @returns {string}
   */
  toB64 (options: { publicOnly?: boolean } = null): string {
    return this.publicKeyBuffer.toString('base64')
  }

  /**
   * Exports the instance of an RSA PublicKey in binary string using ASN.1 syntax with DER encoding wrapped in an SPKI
   * enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification.
   * @deprecated
   * @param {options} [options=null] useless options argument in a PublicKey.
   * @returns {string}
   */
  toString (options: { publicOnly?: boolean } = {}): string {
    return Buffer.from(this.toB64(options), 'base64').toString('binary')
  }

  /**
   * Encrypts synchronously with RSAES-OAEP-ENCRYPT with SHA-1 as a Hash function and MGF1-SHA-1 as a mask generation
   * function as per PKCS#1 v2.2 section 7.1.1 using the instantiated PublicKey
   * @param {Buffer} clearText
   * @protected
   * @abstract
   * @returns {Buffer}
   */
  _rawEncryptSync (clearText: Buffer): Buffer { // cannot be made actually abstract because of my inheritance trickery
    throw new Error('Must be subclassed')
  }

  /**
   * Encrypts asynchronously with RSAES-OAEP-ENCRYPT with SHA-1 as a Hash function and MGF1-SHA-1 as a mask generation
   * function as per PKCS#1 v2.2 section 7.1.1 using the instantiated PublicKey
   * @param {Buffer} clearText
   * @protected
   * @returns {Promise<Buffer>}
   */
  async _rawEncryptAsync (clearText: Buffer): Promise<Buffer> {
    return this._rawEncryptSync(clearText)
  }

  /**
   * Optionally prefixes the cleartext with a CRC32 of the initial clearText then, encrypts the result synchronously
   * with RSAES-OAEP-ENCRYPT with SHA-1 as a Hash function and MGF1-SHA-1 as a mask generation
   * function as per PKCS#1 v2.2 section 7.1.1 using the instantiated PublicKey
   * @param {Buffer} clearText
   * @param {boolean} [doCRC=true]
   * @returns {Buffer}
   */
  encrypt (clearText: Buffer, doCRC = true): Buffer {
    if (doCRC) return this._rawEncryptSync(prefixCRC(clearText, this._calculateCRC32))
    else return this._rawEncryptSync(clearText)
  }

  /**
   * Optionally prefixes the cleartext with a CRC32 of the initial clearText then, encrypts the result asynchronously
   * with RSAES-OAEP-ENCRYPT with SHA-1 as a Hash function and MGF1-SHA-1 as a mask generation
   * function as per PKCS#1 v2.2 section 7.1.1 using the instantiated PublicKey
   * @param {Buffer} clearText
   * @param {boolean} [doCRC=true]
   * @returns {Promise<Buffer>}
   */
  encryptAsync (clearText: Buffer, doCRC = true): Promise<Buffer> {
    if (doCRC) return this._rawEncryptAsync(prefixCRC(clearText, this._calculateCRC32))
    else return this._rawEncryptAsync(clearText)
  }

  /**
   * Verifies synchronously that the given signature is valid for textToCheckAgainst using RSASSA-PSS-VERIFY which itself
   * uses EMSA-PSS encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
   * `Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section 8.1.2 using
   * instantiated PublicKey.
   * @param {Buffer} textToCheckAgainst
   * @param {Buffer} signature
   * @abstract
   * @returns {boolean}
   */
  verify (textToCheckAgainst: Buffer, signature: Buffer): boolean { // cannot be made actually abstract because of my inheritance trickery
    throw new Error('Must be subclassed')
  }

  /**
   * Verifies asynchronously that the given signature is valid for textToCheckAgainst using RSASSA-PSS-VERIFY which itself
   * uses EMSA-PSS encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
   * `Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section 8.1.2 using instantiated
   * PublicKey.
   * @param {Buffer} textToCheckAgainst
   * @param {Buffer} signature
   * @returns {Promise<boolean>}
   */
  async verifyAsync (textToCheckAgainst: Buffer, signature: Buffer): Promise<boolean> {
    return this.verify(textToCheckAgainst, signature)
  }

  /**
   * Gives a SHA-256 hash encoded in base64 of the RSA PublicKey encoded in base64 using ASN.1 syntax with DER encoding
   * wrapped in an SPKI enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification
   * @abstract
   * @returns {string}
   */
  getHash (): string { // cannot be made actually abstract because of my inheritance trickery
    throw new Error('Must be subclassed')
  }

  _calculateCRC32 (buffer: Buffer): Buffer {
    return intToBuffer(crc32.buf(buffer))
  }
}

export interface PrivateKeyConstructor<T extends PrivateKey> extends PublicKeyConstructor<T> {
  new (key: Buffer): T

  fromB64 (b64DERFormattedPrivateKey: string): T

  generate (size: AsymKeySize): Promise<T>
}

/**
 * Abstract class for any implementation of PrivateKey
 * Not really an abstract class because TypeScript is *@#&$ and does not support multiple inheritance
 * @abstract
 * @class PrivateKey
 * @property {Buffer} privateKeyBuffer
 */
@staticImplements<PrivateKeyConstructor<PrivateKey>>()
export class PrivateKey extends PublicKey {
  /**
   * A Buffer that contains a representation of the instantiated RSA PrivateKey using ASN.1 syntax with DER encoding
   * wrapped in a PKCS#8 enveloppe as per RFC 5958, and encoded per PKCS#1 v2.2 specification.
   * @type {Buffer}
   * @readonly
   */
  readonly privateKeyBuffer: Buffer

  private static isPrivateKey = Symbol('isPrivateKey')

  /**
   * Returns true if instance is PrivateKey.
   * See https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Symbol/hasInstance
   * @param instance
   * @return {boolean}
   */
  static [Symbol.hasInstance] (instance: unknown) : instance is PrivateKey {
    return instance instanceof PublicKey && (instance.constructor as typeof PrivateKey).isPrivateKey === this.isPrivateKey
  }

  /**
   * PrivateKey constructor. Should be given a Buffer either encoded in a PKCS#8 enveloppe or as a bare private
   * key representation using ASN.1 syntax with DER encoding.
   * @constructs PrivateKey
   * @param {Buffer} key
   */
  constructor (key: Buffer) {
    // not an actual constructor, because PrivateKey is going to be parasitically inherited, so real constructor will not be called
    super(key)
    this.privateKeyBuffer = key
  }

  /**
   * Constructor for PrivateKey class for every private key implementation of SSCrypto.
   * It ensures that given buffer is a valid PrivateKey, either encoded in an PKCS#8 enveloppe or as a bare private key
   * representation using ASN.1 syntax, and sets the privateKeyBuffer
   * @constructs PrivateKey
   * @param {publicKeyBuffer: Buffer, privateKeyBuffer: Buffer} key
   * @protected
   */
  static constructor_ (key: Buffer): { publicKeyBuffer: Buffer, privateKeyBuffer: Buffer } {
    // not an actual constructor, because PrivateKey is going to be parasitically inherited, so real constructor will not be called
    // for the same reason, this cannot be actually `protected`
    if (!Buffer.isBuffer(key)) throw new Error(`INVALID_KEY : Type of ${key} is ${typeof key}`)
    let n, publicKeyBuffer, privateKeyBuffer
    try {
      privateKeyBuffer = privateKeyHasHeader(key) ? key : wrapPrivateKey(key)
      const unwrappedKey = unwrapPrivateKey(privateKeyBuffer);
      ({ n } = privateKeyModel.decode(unwrappedKey)) // just to check that the key is valid
      publicKeyBuffer = privateToPublic(privateKeyBuffer)
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
    if (![1024, 2048, 4096].includes(n.bitLength())) throw new Error(`INVALID_ARG : Key size is invalid, got ${n.bitLength()}`)
    return { publicKeyBuffer, privateKeyBuffer }
  }

  /**
   * Generates asynchronously an RSA Private Key Key and instantiates it.
   * @abstract
   * @param {AsymKeySize} size key size in bits
   * @returns {Promise<PrivateKey>}
   */
  static generate (size: AsymKeySize = 4096): Promise<PrivateKey> { // cannot be made actually abstract because of my inheritance trickery
    throw new Error('Must be subclassed')
  }

  protected toB64_ ({ publicOnly = false } = {}): string {
    return publicOnly
      ? super.toB64()
      : this.privateKeyBuffer.toString('base64')
  }

  /**
   * Exports the instance of an RSA PrivateKey in base64 using ASN.1 syntax with DER encoding wrapped in a PKCS#8
   * enveloppe as per RFC 5958, and encoded per PKCS#1 v2.2 specification.
   * If publicOnly is specified, it exports the RSA PublicKey in base64 using ASN.1 syntax with DER encoding wrapped
   * in an SPKI enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification.
   * @param {boolean} [publicOnly = false] Specify if it should export only the public key.
   * @returns {string}
   */
  // implementations are going to have to copy this, because it will get overridden by their PublicKey implementation
  toB64 ({ publicOnly = false } = {}): string {
    return this.toB64_({ publicOnly })
  }

  /**
   * Decrypts synchronously with RSAES-OAEP-DECRYPT as per PKCS#1 v2.2 section 7.1.2 using the instantiated PrivateKey
   * @param {Buffer} cipherText
   * @protected
   * @abstract
   * @returns {Buffer}
   */
  _rawDecryptSync (cipherText: Buffer): Buffer { // cannot be made actually abstract because of my inheritance trickery
    throw new Error('Must be subclassed')
  }

  /**
   * Decrypts asynchronously with RSAES-OAEP-DECRYPT as per PKCS#1 v2.2 section 7.1.2 using the instantiated PrivateKey
   * @param {Buffer} cipherText
   * @protected
   * @returns {Promise<Buffer>}
   */
  async _rawDecryptAsync (cipherText: Buffer): Promise<Buffer> {
    return this._rawDecryptSync(cipherText)
  }

  /**
   * Decrypts the given cipherText synchronously with RSAES-OAEP-DECRYPT as per PKCS#1 v2.2 section 7.1.2 using the
   * instantiated PrivateKey, and optionally checks that the result is prefixed with a valid CRC32.
   * @param {Buffer} cipherText
   * @param {boolean} [doCRC=true]
   * @returns {Buffer}
   */
  decrypt (cipherText: Buffer, doCRC = true): Buffer {
    const clearText = this._rawDecryptSync(cipherText)
    return doCRC ? splitAndVerifyCRC(clearText, this._calculateCRC32) : clearText
  }

  /**
   * Decrypts the given cipherText asynchronously with RSAES-OAEP-DECRYPT as per PKCS#1 v2.2 section 7.1.2 using the
   * instantiated PrivateKey, and optionally checks that the result is prefixed with a valid CRC32.
   * @param {Buffer} cipherText
   * @param {boolean} [doCRC=true]
   * @returns {Promise<Buffer>}
   */
  async decryptAsync (cipherText: Buffer, doCRC = true): Promise<Buffer> {
    const clearText = await this._rawDecryptAsync(cipherText)
    return doCRC ? splitAndVerifyCRC(clearText, this._calculateCRC32) : clearText
  }

  /**
   * Generates synchronously a signature for the given textToSign using RSASSA-PSS-Sign which itself uses EMSA-PSS
   * encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
   * `Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section
   * 8.1.1 using instantiated PrivateKey.
   * @abstract
   * @param {Buffer} textToSign
   * @returns {Buffer}
   */
  sign (textToSign: Buffer): Buffer { // cannot be made actually abstract because of my inheritance trickery
    throw new Error('Must be subclassed')
  }

  /**
   * Generates asynchronously a signature for the given textToSign using RSASSA-PSS-Sign which itself uses EMSA-PSS
   * encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
   * `Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section
   * 8.1.1 using instantiated PrivateKey.
   * @param {Buffer} textToSign
   * @returns {Promise<Buffer>}
   */
  async signAsync (textToSign: Buffer): Promise<Buffer> {
    return this.sign(textToSign)
  }
}
