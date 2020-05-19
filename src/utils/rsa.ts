import {
  prefixCRC,
  publicKeyHasHeader,
  publicKeyModel,
  unwrapPublicKey,
  wrapPublicKey,
  privateKeyHasHeader,
  unwrapPrivateKey,
  wrapPrivateKey,
  privateKeyModel,
  privateToPublic,
  splitAndVerifyCRC
} from './rsaUtils'

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
export class PublicKey {
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
  toB64 (options: {} = null): string {
    return this.publicKeyBuffer.toString('base64')
  }

  /**
   * Encrypts synchronously with RSAES-OAEP-ENCRYPT with SHA-1 as a Hash function and MGF1-SHA-1 as a mask generation
   * function as per PKCS#1 v2.2 section 7.1.1 using the instantiated PublicKey
   * @param {Buffer} clearText
   * @protected
   * @abstract
   * @returns {Buffer}
   */
  protected _rawEncryptSync (clearText: Buffer): Buffer {
    throw new Error('Must be subclassed')
  }

  /**
   * Encrypts asynchronously with RSAES-OAEP-ENCRYPT with SHA-1 as a Hash function and MGF1-SHA-1 as a mask generation
   * function as per PKCS#1 v2.2 section 7.1.1 using the instantiated PublicKey
   * @param {Buffer} clearText
   * @protected
   * @abstract
   * @returns {Promise<Buffer>}
   */
  protected _rawEncrypt (clearText: Buffer): Promise<Buffer> {
    throw new Error('Must be subclassed')
  }

  /**
   * Optionally prefixes the cleartext with a CRC32 of the initial clearText then, encrypts the result synchronously
   * with RSAES-OAEP-ENCRYPT with SHA-1 as a Hash function and MGF1-SHA-1 as a mask generation
   * function as per PKCS#1 v2.2 section 7.1.1 using the instantiated PublicKey
   * @param {Buffer} clearText
   * @param {boolean} [doCRC=true]
   * @returns {Buffer}
   */
  encryptSync (clearText: Buffer, doCRC = true): Buffer {
    return doCRC ? this._rawEncryptSync(prefixCRC(clearText)) : this._rawEncryptSync(clearText)
  }

  /**
   * Optionally prefixes the cleartext with a CRC32 of the initial clearText then, encrypts the result asynchronously
   * with RSAES-OAEP-ENCRYPT with SHA-1 as a Hash function and MGF1-SHA-1 as a mask generation
   * function as per PKCS#1 v2.2 section 7.1.1 using the instantiated PublicKey
   * @param {Buffer} clearText
   * @param {boolean} [doCRC=true]
   * @returns {Promise<Buffer>}
   */
  encrypt (clearText: Buffer, doCRC = true): Promise<Buffer> {
    return doCRC ? this._rawEncrypt(prefixCRC(clearText)) : this._rawEncrypt(clearText)
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
  verifySync (textToCheckAgainst: Buffer, signature: Buffer): boolean {
    throw new Error('Must be subclassed')
  }

  /**
   * Verifies asynchronously that the given signature is valid for textToCheckAgainst using RSASSA-PSS-VERIFY which itself
   * uses EMSA-PSS encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
   * `Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section 8.1.2 using instantiated
   * PublicKey.
   * @param {Buffer} textToCheckAgainst
   * @param {Buffer} signature
   * @abstract
   * @returns {Promise<boolean>}
   */
  verify (textToCheckAgainst: Buffer, signature: Buffer): Promise<boolean> {
    throw new Error('Must be subclassed')
  }

  /**
   * Gives a SHA-256 hash encoded in base64 of the RSA PublicKey encoded in base64 using ASN.1 syntax with DER encoding
   * wrapped in an SPKI enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification
   * @returns {string}
   */
  getHash (): string {
    throw new Error('Must be subclassed')
  }
}

export interface PrivateKeyConstructor<T extends PrivateKeyInterface> extends PublicKeyConstructor<T> {
  new (key: Buffer): T

  fromB64 (b64DERFormattedPrivateKey: string): T

  generate (size: AsymKeySize): Promise<T>
}

export interface PrivateKeyInterface extends PublicKey {
  readonly privateKeyBuffer: Buffer

  toB64 (options?: { publicOnly: boolean }): string

  decryptSync (cipherText: Buffer, doCRC?: boolean): Buffer

  decrypt (cipherText: Buffer, doCRC?: boolean): Promise<Buffer>

  signSync (textToSign: Buffer): Buffer

  sign (textToSign: Buffer): Promise<Buffer>
}

/**
 * Allows to do a mixin between the public key implementation (that inherits from PublicKey) and a common implementation
 * for PrivateKey.
 * @mixin
 * @param {PublicKeyConstructor<PublicKey>} myPublicKeyConstructor
 * @returns {PrivateKeyConstructor<PrivateKeyInterface>}
 */
export const makePrivateKeyBaseClass = <T extends PublicKey>(myPublicKeyConstructor: PublicKeyConstructor<T>): PrivateKeyConstructor<PrivateKeyInterface> => {
  /**
   * Abstract class for any implementation of PrivateKey
   * Not really an abstract class because TypeScript is *@#&$ and does not support multiple inheritance
   * @abstract
   * @class PrivateKey
   * @property {Buffer} privateKeyBuffer
   */
  // @ts-ignore // TODO: TS2415: Class 'PrivateKey' incorrectly extends base class 'T'. 'PrivateKey' is assignable to the constraint of type 'T', but 'T' could be instantiated with a different subtype of constraint 'PublicKey'.
  class PrivateKey extends myPublicKeyConstructor implements PrivateKeyInterface {
    /**
     * A Buffer that contains a representation of the instantiated RSA PrivateKey using ASN.1 syntax with DER encoding
     * wrapped in a PKCS#8 enveloppe as per RFC 5958, and encoded per PKCS#1 v2.2 specification.
     * @type {Buffer}
     * @readonly
     */
    readonly privateKeyBuffer: Buffer

    /**
     * Constructor for PrivateKey class for every private key implementation of SSCrypto.
     * It ensures that given buffer is a valid PrivateKey, either encoded in an PKCS#8 enveloppe or as a bare private key
     * representation using ASN.1 syntax, and sets the privateKeyBuffer
     * @constructs PrivateKey
     * @param {Buffer} key
     */
    constructor (key: Buffer) {
      if (!Buffer.isBuffer(key)) throw new Error(`INVALID_KEY : Type of ${key} is ${typeof key}`)
      let n
      try {
        const privateKeyBuffer = privateKeyHasHeader(key) ? key : wrapPrivateKey(key)
        const unwrappedKey = unwrapPrivateKey(privateKeyBuffer);
        ({ n } = privateKeyModel.decode(unwrappedKey)) // just to check that the key is valid
        super(privateToPublic(privateKeyBuffer))
        this.privateKeyBuffer = privateKeyBuffer
      } catch (e) {
        throw new Error(`INVALID_KEY : ${e.message}`)
      }
      if (![1024, 2048, 4096].includes(n.bitLength())) throw new Error(`INVALID_ARG : Key size is invalid, got ${n.bitLength()}`)
    }

    /**
     * Generates asynchronously an RSA Private Key Key and instantiates it.
     * @abstract
     * @param {AsymKeySize} size key size in bits
     * @returns {Promise<PrivateKey>}
     */
    static generate<T extends PrivateKey> (this: PrivateKeyConstructor<T>, size: AsymKeySize = 4096): Promise<T> {
      throw new Error('Must be subclassed')
    }

    /**
     * Instantiates a PrivateKey from a base64 representation of an RSA private key using ASN.1 syntax with DER encoding
     * per PKCS#1 v2.2 specification and optionally wrapped in an PKCS#8 enveloppe as per RFC 5958.
     * @param {string} b64DERFormattedPrivateKey
     * @returns {PrivateKey}
     */
    static fromB64<T extends PrivateKey> (this: PrivateKeyConstructor<T>, b64DERFormattedPrivateKey: string): T {
      return new this(Buffer.from(b64DERFormattedPrivateKey, 'base64'))
    }

    /**
     * Exports the instance of an RSA PrivateKey in base64 using ASN.1 syntax with DER encoding wrapped in a PKCS#8
     * enveloppe as per RFC 5958, and encoded per PKCS#1 v2.2 specification.
     * If publicOnly is specified, it exports the RSA PublicKey in base64 using ASN.1 syntax with DER encoding wrapped
     * in an SPKI enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification.
     * @param {boolean} [publicOnly = false] Specify if it should export only the public key.
     */
    toB64 ({ publicOnly = false } = {}): string {
      return publicOnly
        ? super.toB64()
        : this.privateKeyBuffer.toString('base64')
    }

    /**
     * Decrypts synchronously with RSAES-OAEP-DECRYPT as per PKCS#1 v2.2 section 7.1.2 using the instantiated PrivateKey
     * @param {Buffer} cipherText
     * @protected
     * @abstract
     * @returns {Buffer}
     */
    _rawDecryptSync (cipherText: Buffer): Buffer {
      throw new Error('Must be subclassed')
    }

    /**
     * Decrypts asynchronously with RSAES-OAEP-DECRYPT as per PKCS#1 v2.2 section 7.1.2 using the instantiated PrivateKey
     * @param {Buffer} cipherText
     * @protected
     * @abstract
     * @returns {Promise<Buffer>}
     */
    _rawDecrypt (cipherText: Buffer): Promise<Buffer> {
      throw new Error('Must be subclassed')
    }

    /**
     * Optionally prefixes the cleartext with a CRC32 of the initial clearText then, encrypts the result synchronously
     * with RSAES-OAEP-DECRYPT as per PKCS#1 v2.2 section 7.1.2 using the instantiated PrivateKey
     * @param {Buffer} cipherText
     * @param {boolean} [doCRC=true]
     * @returns {Buffer}
     */
    decryptSync (cipherText: Buffer, doCRC = true): Buffer {
      const clearText = this._rawDecryptSync(cipherText)
      return doCRC ? splitAndVerifyCRC(clearText) : clearText
    }

    /**
     * Optionally prefixes the cleartext with a CRC32 of the initial clearText then, encrypts the result asynchronously
     * with RSAES-OAEP-DECRYPT as per PKCS#1 v2.2 section 7.1.2 using the instantiated PrivateKey
     * @param {Buffer} cipherText
     * @param {boolean} [doCRC=true]
     * @returns {Promise<Buffer>}
     */
    async decrypt (cipherText: Buffer, doCRC = true): Promise<Buffer> {
      const clearText = await this._rawDecrypt(cipherText)
      return doCRC ? splitAndVerifyCRC(clearText) : clearText
    }

    /**
     * Generates synchronously a signature for the given textToSign using RSASSA-PSS-Sign which itself uses EMSA-PSS
     * encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
     * `Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section
     * 8.1.1 using instantiated PrivateKey.
     * @param {Buffer} textToSign
     * @returns {Buffer}
     */
    signSync (textToSign: Buffer): Buffer {
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
    sign (textToSign: Buffer): Promise<Buffer> {
      throw new Error('Must be subclassed')
    }
  }

  return PrivateKey
}
