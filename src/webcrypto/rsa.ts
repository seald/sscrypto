import { mixClasses, staticImplements } from '../utils/commonUtils'
import { AsymKeySize, PrivateKeyConstructor, PublicKeyConstructor } from '../utils/rsa'
import { PrivateKey as PrivateKeyForge, PublicKey as PublicKeyForge } from '../forge/rsa'
import { isOldEdge, isWebCryptoAvailable } from './utils'
import forge from 'node-forge'

/**
 * Implementation of PublicKey using Subtle Crypto (https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) if
 * available, else uses PublicKeyForge as a fallback.
 * @class PublicKeyWebCrypto
 * @property {Buffer} publicKeyBuffer
 */
@staticImplements<PublicKeyConstructor<PublicKeyWebCrypto>>()
class PublicKeyWebCrypto extends PublicKeyForge {
  /**
   * Stores the CryptoKey representations of the PublicKeyWebCrypto for each usage.
   * @type {Map<'verify'|'encrypt', CryptoKey>}
   * @protected
   */
  protected _publicKeysWebCrypto: Map<'verify' | 'encrypt', CryptoKey>

  /**
   * Gets asynchronously the CryptoKey representation of the PublicKeyWebCrypto for given keyUsage, and stores them in
   * in cache in _publicKeysWebCrypto protected property.
   * SSCrypto's interface is not designed to force a KeyPair to be used for a unique usage (encryption, signature,
   * authentication, etc.), it is up to the developer to make sure they don't use the same KeyPair for multiple usages.
   * @param {'verify'|'encrypt'} keyUsage
   * @protected
   */
  protected async _getPublicKey (keyUsage: 'verify' | 'encrypt'): Promise<CryptoKey> {
    if (!this._publicKeysWebCrypto.has(keyUsage)) {
      let algorithm = { name: 'RSA-OAEP', hash: 'SHA-1' } // Encryption algorithm used by SSCrypto
      if (keyUsage === 'verify') algorithm = { name: 'RSA-PSS', hash: 'SHA-256' } // Signature algorithm used by SSCrypto
      this._publicKeysWebCrypto.set(keyUsage, await window.crypto.subtle.importKey(
        'spki',
        this.publicKeyBuffer,
        algorithm,
        true,
        [keyUsage]
      ))
    }
    return this._publicKeysWebCrypto.get(keyUsage)
  }

  constructor (key: Buffer) {
    super(key)
    this._publicKeysWebCrypto = new Map()
  }

  // using the Subtle Crypto implementation if available, else falls back to forge
  async _rawEncryptAsync (clearText: Buffer): Promise<Buffer> {
    if (!isWebCryptoAvailable()) return this._rawEncryptSync(clearText)
    return Buffer.from(await window.crypto.subtle.encrypt(
      {
        name: 'RSA-OAEP',
        // @ts-ignore : stupid old Edge needs this, even if it's against spec
        hash: 'SHA-1'
      },
      await this._getPublicKey('encrypt'), // from generateKey or importKey above
      clearText // ArrayBuffer of the data
    ))
  }

  // using the Subtle Crypto implementation if available, else falls back to forge
  async verifyAsync (textToCheckAgainst: Buffer, signature: Buffer): Promise<boolean> {
    if (!isWebCryptoAvailable() || isOldEdge()) return this.verify(textToCheckAgainst, signature) // old Edge does not like RSA-PSS
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
  }
}

/**
 * Implementation of PrivateKey using Subtle Crypto (https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) if
 * available, else uses PrivateKeyForge as a fallback.
 * @class PrivateKeyWebCrypto
 * @property {Buffer} privateKeyBuffer
 */
@staticImplements<PrivateKeyConstructor<PrivateKeyWebCrypto>>()
class PrivateKeyWebCrypto extends mixClasses(PublicKeyWebCrypto, PrivateKeyForge) {
  readonly privateKeyBuffer: Buffer

  /**
   * Stores the CryptoKey representations of the PrivateKeyWebCrypto for each usage.
   * @type {Map<'sign'|'decrypt', CryptoKey>}
   * @protected
   */
  protected _privateKeysWebCrypto: Map<'sign' | 'decrypt', CryptoKey>

  /**
   * Gets asynchronously the CryptoKey representation of the PrivateKeyWebCrypto for given keyUsage, and stores them in
   * in cache in _privateKeysWebCrypto protected property.
   * SSCrypto's interface is not designed to force a KeyPair to be used for a unique usage (encryption, signature,
   * authentication, etc.), it is up to the developer to make sure they don't use the same KeyPair for multiple usages.
   * @param {'sign'|'decrypt'} keyUsage
   * @protected
   */
  protected async getPrivateKey (keyUsage: 'sign' | 'decrypt'): Promise<CryptoKey> {
    if (!this._privateKeysWebCrypto.has(keyUsage)) {
      let algorithm = { name: 'RSA-OAEP', hash: 'SHA-1' } // Encryption algorithm used by SSCrypto
      if (keyUsage === 'sign') algorithm = { name: 'RSA-PSS', hash: 'SHA-256' } // Signature algorithm used by SSCrypto
      this._privateKeysWebCrypto.set(keyUsage, await window.crypto.subtle.importKey(
        'pkcs8',
        this.privateKeyBuffer,
        algorithm,
        true,
        [keyUsage]
      ))
    }
    return this._privateKeysWebCrypto.get(keyUsage)
  }

  constructor (key: Buffer) {
    // This has to basically re-write PrivateKeyForge's constructor because we inherit parasitically so the actual constructor does not run
    const { publicKeyBuffer, privateKeyBuffer } = new.target.constructor_(key)
    super(publicKeyBuffer)
    this.privateKeyBuffer = privateKeyBuffer
    try {
      this._privateKeyForge = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(this.privateKeyBuffer)))
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
    this._privateKeysWebCrypto = new Map()
  }

  toB64 ({ publicOnly = false } = {}): string {
    return this.toB64_({ publicOnly })
  }

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
    } else return await super.generate(size) as PrivateKeyWebCrypto
  }

  async _rawDecryptAsync (cipherText: Buffer): Promise<Buffer> {
    if (!isWebCryptoAvailable()) return this._rawDecryptSync(cipherText) // using `super` causes problems on old Edge
    try {
      return Buffer.from(await window.crypto.subtle.decrypt(
        {
          name: 'RSA-OAEP',
          // @ts-ignore : stupid old Edge needs this, even if it's against spec
          hash: 'SHA-1'
        },
        await this.getPrivateKey('decrypt'),
        cipherText
      ))
    } catch (e) {
      throw new Error(`INVALID_CIPHER_TEXT : ${e.message}`)
    }
  }

  async signAsync (textToSign: Buffer): Promise<Buffer> {
    if (!isWebCryptoAvailable() || isOldEdge()) return this.sign(textToSign) // old Edge does not like RSA-PSS
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
