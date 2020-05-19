import { staticImplements } from '../utils/commonUtils'
import {
  AsymKeySize,
  makePrivateKeyBaseClass,
  PrivateKeyInterface,
  PublicKey,
  PublicKeyConstructor
} from '../utils/rsa'
import { PublicKey as PublicKeyForge, PrivateKey as PrivateKeyForge } from '../forge/rsa'
import { isWebCryptoAvailable, sha256 } from './utils'

/**
 * Implementation of PublicKey using Subtle Crypto (https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) if
 * available, else uses PublicKeyForge as a fallback.
 * @class PublicKeyWebCrypto
 * @property {Buffer} publicKeyBuffer
 */
@staticImplements<PublicKeyConstructor<PublicKeyWebCrypto>>()
class PublicKeyWebCrypto extends PublicKey {
  /**
   * A Buffer that contains a representation of the instantiated RSA PublicKey using ASN.1 syntax with DER encoding
   * wrapped in an SPKI enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification.
   * @readonly
   * @type {Buffer}
   */
  readonly publicKeyBuffer: Buffer

  /**
   * Stores the CryptoKey representations of the PublicKeyWebCrypto for each usage.
   * @type {Map<'verify'|'encrypt', CryptoKey>}
   * @protected
   */
  protected _publicKeys: Map<'verify' | 'encrypt', CryptoKey>

  /**
   * Stores the PublicKeyForge representation of the public key to be used as a fallback.
   * @type {PublicKeyForge}
   * @protected
   */
  protected _forgeKey: PublicKeyForge

  /**
   * Gets asynchronously the CryptoKey representation of the PublicKeyWebCrypto for given keyUsage, and stores them in
   * in cache in _publicKeys protected property.
   * SSCrypto's interface is not designed to force a KeyPair to be used for a unique usage (encryption, signature,
   * authentication, etc.), it is up to the developer to make sure they don't use the same KeyPair for multiple usages.
   * @param {'verify'|'encrypt'} keyUsage
   * @protected
   */
  protected async _getPublicKey (keyUsage: 'verify' | 'encrypt'): Promise<CryptoKey> {
    if (!this._publicKeys.has(keyUsage)) {
      let algorithm = { name: 'RSA-OAEP', hash: 'SHA-1' } // Encryption algorithm used by SSCrypto
      if (keyUsage === 'verify') algorithm = { name: 'RSA-PSS', hash: 'SHA-256' } // Signature algorithm used by SSCrypto
      this._publicKeys.set(keyUsage, await window.crypto.subtle.importKey(
        'spki',
        this.publicKeyBuffer,
        algorithm,
        true,
        [keyUsage]
      ))
    }
    return this._publicKeys.get(keyUsage)
  }

  /**
   * PublicKeyWebCrypto constructor. Should be given a Buffer either encoded in an SPKI enveloppe or as a bare public
   * key representation using ASN.1 syntax with DER encoding.
   * @constructs PublicKeyWebCrypto
   * @param {Buffer} key
   */
  constructor (key: Buffer) {
    super(key)
    try {
      this._forgeKey = new PublicKeyForge(this.publicKeyBuffer)
      this._publicKeys = new Map()
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
  }

  /**
   * Encrypt synchronously with RSAES-OAEP-ENCRYPT with SHA-1 as a Hash function and MGF1-SHA-1 as a mask generation
   * function as per PKCS#1 v2.2 section 7.1.1 using the forge fallback implementation, because Subtle Crypto is not
   * available for synchronous operations.
   * @param {Buffer} clearText
   * @protected
   * @returns {Buffer}
   */
  protected _rawEncryptSync (clearText: Buffer): Buffer {
    return this._forgeKey.encryptSync(clearText, false) // TODO: a bit dirty to define forge's encryptSync with no CRC32 as _rawEncryptSync
  }

  /**
   * Encrypt asynchronously with RSAES-OAEP-ENCRYPT with SHA-1 as a Hash function and MGF1-SHA-1 as a mask generation
   * function as per PKCS#1 v2.2 section 7.1.1 using the Subtle Crypto implementation if available, else falls back to
   * forge.
   * @param {Buffer} clearText
   * @protected
   * @returns {Promise<Buffer>}
   */
  protected async _rawEncrypt (clearText: Buffer): Promise<Buffer> {
    return isWebCryptoAvailable()
      ? Buffer.from(await window.crypto.subtle.encrypt(
        {
          name: 'RSA-OAEP'
        },
        await this._getPublicKey('encrypt'), // from generateKey or importKey above
        clearText // ArrayBuffer of the data
      ))
      : this._rawEncryptSync(clearText)
  }

  /**
   * Verify synchronously that the given signature is valid for textToCheckAgainst using RSASSA-PSS-VERIFY which itself
   * uses EMSA-PSS encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
   * `Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section 8.1.2 using the forge
   * fallback implementation, because Subtle Crypto is not available for synchronous operations.
   * @param {Buffer} textToCheckAgainst
   * @param {Buffer} signature
   * @returns {boolean}
   */
  verifySync (textToCheckAgainst: Buffer, signature: Buffer): boolean {
    return this._forgeKey.verifySync(textToCheckAgainst, signature)
  }

  /**
   * Verify asynchronously that the given signature is valid for textToCheckAgainst using RSASSA-PSS-VERIFY which itself
   * uses EMSA-PSS encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
   * `Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2`  as per PKCS#1 v2.2 section 8.1.2 using the Subtle
   * Crypto implementation if available, else falls back to forge.
   * @param {Buffer} textToCheckAgainst
   * @param {Buffer} signature
   * @returns {Promise<boolean>}
   */
  async verify (textToCheckAgainst: Buffer, signature: Buffer): Promise<boolean> {
    if (isWebCryptoAvailable()) {
      const privateKey = await this._getPublicKey('verify')
      return window.crypto.subtle.verify(
        {
          name: 'RSA-PSS',
          saltLength: Math.ceil(((privateKey.algorithm as RsaHashedKeyGenParams).modulusLength - 1) / 8) - 32 - 2
        },
        await this._getPublicKey('verify'), // from generateKey or importKey above
        signature,
        textToCheckAgainst
      )
    } else return this.verifySync(textToCheckAgainst, signature)
  }

  /**
   * Gives a SHA-256 hash encoded in base64 of the RSA PublicKey encoded in base64 using ASN.1 syntax with DER encoding
   * wrapped in an SPKI enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification
   * It should be noted that forge's implementation for SHA256 is used because it is preferable to keep this method
   * synchronous in all implementations.
   * @returns {string}
   */
  getHash (): string {
    return sha256(this.publicKeyBuffer).toString('base64')
  }
}

/**
 * Implementation of PrivateKey using Subtle Crypto (https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) if
 * available, else uses PrivateKeyForge as a fallback.
 * @class PrivateKeyWebCrypto
 * @property {Buffer} privateKeyBuffer
 */
// @staticImplements<PrivateKeyConstructor<PrivateKeyWebCrypto>>() TODO: no way to make it work
class PrivateKeyWebCrypto extends makePrivateKeyBaseClass(PublicKeyWebCrypto) implements PrivateKeyInterface {
  /**
   * A Buffer that contains a representation of the instantiated RSA PrivateKey using ASN.1 syntax with DER encoding
   * wrapped in a PKCS#8 enveloppe as per RFC 5958, and encoded per PKCS#1 v2.2 specification.
   * @type {Buffer}
   * @readonly
   */
  readonly privateKeyBuffer: Buffer

  /**
   * Stores the CryptoKey representations of the PrivateKeyWebCrypto for each usage.
   * @type {Map<'sign'|'decrypt', CryptoKey>}
   * @protected
   */
  protected _privateKeys: Map<'sign' | 'decrypt', CryptoKey>

  /**
   * Stores the PrivateKeyForge representation of the public key to be used as a fallback.
   * Overrides the PublicKeyForge, but not a proble because PrivateKeyForge inherits from PublicKeyForge
   * @type {PrivateKeyForge}
   * @protected
   */
  protected _forgeKey: PrivateKeyForge

  /**
   * Gets asynchronously the CryptoKey representation of the PrivateKeyWebCrypto for given keyUsage, and stores them in
   * in cache in _privateKeys protected property.
   * SSCrypto's interface is not designed to force a KeyPair to be used for a unique usage (encryption, signature,
   * authentication, etc.), it is up to the developer to make sure they don't use the same KeyPair for multiple usages.
   * @param {'sign'|'decrypt'} keyUsage
   * @protected
   */
  protected async getPrivateKey (keyUsage: 'sign' | 'decrypt'): Promise<CryptoKey> {
    if (!this._privateKeys.has(keyUsage)) {
      let algorithm = { name: 'RSA-OAEP', hash: 'SHA-1' } // Encryption algorithm used by SSCrypto
      if (keyUsage === 'sign') algorithm = { name: 'RSA-PSS', hash: 'SHA-256' } // Signature algorithm used by SSCrypto
      this._privateKeys.set(keyUsage, await window.crypto.subtle.importKey(
        'pkcs8',
        this.privateKeyBuffer,
        algorithm,
        true,
        [keyUsage]
      ))
    }
    return this._privateKeys.get(keyUsage)
  }

  /**
   * PrivateKeyWebCrypto constructor. Should be given a Buffer either encoded in a PKCS#8 enveloppe or as a bare private
   * key representation using ASN.1 syntax with DER encoding.
   * @constructs PrivateKeyWebCrypto
   * @param {Buffer} key
   */
  constructor (key: Buffer) {
    super(key)
    try {
      this._forgeKey = new PrivateKeyForge(this.privateKeyBuffer)
      this._privateKeys = new Map()
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
  }

  /**
   * Generates asynchronously an RSA Private Key Key and instantiates it as a PrivateKeyWebCrypto.
   * Falls back to forge key generation if Subtle crypto is not available.
   * @param {AsymKeySize} [size = 4096] - key size in bits
   * @returns {Promise<PrivateKeyWebCrypto>}
   */
  static async generate (size: AsymKeySize = 4096): Promise<PrivateKeyWebCrypto> {
    if (![4096, 2048, 1024].includes(size)) {
      throw new Error('INVALID_ARG')
    } else if (isWebCryptoAvailable()) {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: size,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: 'SHA-256' // arbitrary, because we just want to export this key
        },
        true,
        ['encrypt', 'decrypt'] // arbitrary, because we are just going to export it anyway
      )
      const exported = Buffer.from(await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey))
      return new this(exported)
    } else return new this(Buffer.from((await PrivateKeyForge.generate(size)).toB64(), 'base64'))
  }

  /**
   * Decrypts synchronously with RSAES-OAEP-DECRYPT as per PKCS#1 v2.2 section 7.1.2 using the Subtle Crypto
   * implementation if available, else uses forge as fallback.
   * @param {Buffer} cipherText
   * @protected
   * @returns {Buffer}
   */
  protected _rawDecryptSync (cipherText: Buffer): Buffer {
    return this._forgeKey.decryptSync(cipherText, false)
  }

  /**
   * Decrypts asynchronously with RSAES-OAEP-DECRYPT as per PKCS#1 v2.2 section 7.1.2 using the Subtle Crypto
   * implementation if available, else uses forge as fallback.
   * @param {Buffer} cipherText
   * @protected
   * @returns {Promise<Buffer>}
   */
  protected async _rawDecrypt (cipherText: Buffer): Promise<Buffer> {
    if (!isWebCryptoAvailable()) return this._rawDecryptSync(cipherText)
    try {
      return Buffer.from(await window.crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        await this.getPrivateKey('decrypt'),
        cipherText
      ))
    } catch (e) {
      throw new Error(`INVALID_CIPHER_TEXT : ${e.message}`)
    }
  }

  /**
   * Generates synchronously a signature for the given textToSign using RSASSA-PSS-Sign which itself uses EMSA-PSS
   * encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
   * `Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section 8.1.1 using forge fallback
   * implementation, because Subtle Crypto is not available for synchronous operations.
   * @param {Buffer} textToSign
   * @returns {Buffer}
   */
  signSync (textToSign: Buffer): Buffer {
    return this._forgeKey.signSync(textToSign)
  }

  /**
   * Generates asynchronously a signature for the given textToSign using RSASSA-PSS-Sign which itself uses EMSA-PSS
   * encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
   * `Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section 8.1.1 using the Subtle Crypto
   * implementation if available, else falls back to forge.
   * @param {Buffer} textToSign
   * @returns {Promise<Buffer>}
   */
  async sign (textToSign: Buffer): Promise<Buffer> {
    if (!isWebCryptoAvailable()) return this._forgeKey.sign(textToSign)
    const privateKey = await this.getPrivateKey('sign')
    return Buffer.from(await window.crypto.subtle.sign(
      {
        name: 'RSA-PSS',
        saltLength: Math.ceil(((privateKey.algorithm as RsaHashedKeyGenParams).modulusLength - 1) / 8) - 32 - 2
      },
      privateKey,
      textToSign
    ))
  }
}

export { PublicKeyWebCrypto as PublicKey, PrivateKeyWebCrypto as PrivateKey }
