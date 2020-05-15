import { staticImplements } from '../utils/commonUtils'
import { AsymKeySize, PrivateKey, PrivateKeyConstructor, PublicKey, PublicKeyConstructor } from '../utils/rsa'
import { prefixCRC, privateToPublic, splitAndVerifyCRC, unwrapPrivateKey, wrapPrivateKey } from '../utils/rsaUtils'
import { PublicKey as PublicKeyForge, PrivateKey as PrivateKeyForge } from '../forge/rsa'
import { isWebCryptoAvailable, sha256Async } from './utils'

/**
 * @class PublicKeyNode
 * @property publicKey
 */
@staticImplements<PublicKeyConstructor>()
class PublicKeyWebCrypto implements PublicKey {
  protected encodedPublicKey: Buffer
  protected publicKeys: Map<'verify' | 'encrypt', CryptoKey>
  protected forgeKey: PublicKeyForge

  protected async getPublicKey (keyUsage: 'verify' | 'encrypt'): Promise<CryptoKey> {
    if (!this.publicKeys) this.publicKeys = new Map()
    if (!this.publicKeys.has(keyUsage)) {
      let algorithm = { name: 'RSA-OAEP', hash: 'SHA-1' }
      if (keyUsage === 'verify') algorithm = { name: 'RSA-PSS', hash: 'SHA-256' }
      this.publicKeys.set(keyUsage, await window.crypto.subtle.importKey(
        'spki',
        this.encodedPublicKey,
        algorithm,
        true,
        [keyUsage]
      ))
    }
    return this.publicKeys.get(keyUsage)
  }

  /**
   * PublicKeyNode constructor. Should be given a Buffer containing a DER serialization of the key.
   * @constructs PublicKeyNode
   * @param {Buffer} key
   */
  constructor (key: Buffer) {
    if (!Buffer.isBuffer(key)) throw new Error(`INVALID_KEY : Type of ${key} is ${typeof key}`)
    this.encodedPublicKey = key
    this.forgeKey = new PublicKeyForge(key)
  }

  /**
   * Returns a PublicKeyNode from it's DER base64 serialization.
   * @method
   * @static
   * @param {string} b64DERFormattedPublicKey - a b64 encoded public key formatted with DER
   * @returns {PublicKeyNode}
   */
  static fromB64 (b64DERFormattedPublicKey: string): PublicKeyWebCrypto {
    return new this(Buffer.from(b64DERFormattedPublicKey, 'base64'))
  }

  /**
   * Serializes the key to DER format and encodes it in b64.
   * @method
   * @param {object} [options]
   * @returns {string}
   */
  toB64 (options: object = null): string {
    return this.encodedPublicKey.toString('base64')
  }

  protected async _rawEncrypt (clearText: Buffer): Promise<Buffer> {
    return Buffer.from(await window.crypto.subtle.encrypt(
      {
        name: 'RSA-OAEP'
      },
      await this.getPublicKey('encrypt'), // from generateKey or importKey above
      clearText // ArrayBuffer of the data
    ))
  }

  encryptSync (clearText: Buffer, doCRC?: boolean): Buffer {
    return this.forgeKey.encryptSync(clearText, doCRC)
  }

  /**
   * Encrypts a clearText for the Private Key corresponding to this PublicKeyNode.
   * @method
   * @param {Buffer} clearText
   * @param {boolean} doCRC
   * @returns {Buffer}
   */
  async encrypt (clearText: Buffer, doCRC = true): Promise<Buffer> {
    return isWebCryptoAvailable()
      ? doCRC ? this._rawEncrypt(prefixCRC(clearText)) : this._rawEncrypt(clearText)
      : this.forgeKey.encrypt(clearText, doCRC)
  }

  verifySync (textToCheckAgainst: Buffer, signature: Buffer): boolean {
    return this.forgeKey.verifySync(textToCheckAgainst, signature)
  }

  /**
   * Verify that the message has been signed with the Private Key corresponding to this PublicKeyNode.
   * @param {Buffer} textToCheckAgainst
   * @param {Buffer} signature
   * @returns {boolean}
   */
  async verify (textToCheckAgainst: Buffer, signature: Buffer): Promise<boolean> {
    if (isWebCryptoAvailable()) {
      const privateKey = await this.getPublicKey('verify')
      return window.crypto.subtle.verify(
        {
          name: 'RSA-PSS',
          saltLength: Math.ceil(((privateKey.algorithm as RsaHashedKeyGenParams).modulusLength - 1) / 8) - 32 - 2
        },
        await this.getPublicKey('verify'), // from generateKey or importKey above
        signature,
        textToCheckAgainst
      )
    } else return this.forgeKey.verify(textToCheckAgainst, signature)
  }

  getHashSync (): string {
    return this.forgeKey.getHashSync()
  }

  /**
   * @returns {string}
   */
  async getHash (): Promise<string> {
    return isWebCryptoAvailable()
      ? (await sha256Async(Buffer.from(await this.toB64({ publicOnly: true }), 'base64'))).toString('base64')
      : this.forgeKey.getHash()
  }
}

/**
 * @class PrivateKeyNode
 */
@staticImplements<PrivateKeyConstructor>()
class PrivateKeyWebCrypto extends PublicKeyWebCrypto implements PrivateKey {
  protected encodedPrivateKey: Buffer
  protected privateKeys: Map<'sign' | 'decrypt', CryptoKey>
  protected forgeKey: PrivateKeyForge

  constructor (key: Buffer) {
    try {
      const publicKey = privateToPublic(key)
      super(publicKey)
    } catch (error) {
      throw new Error(`INVALID_KEY:${error.message}`)
    }
    this.encodedPrivateKey = key
    this.forgeKey = new PrivateKeyForge(key)
    this.privateKeys = new Map()
  }

  protected async getPrivateKey (keyUsage: 'sign' | 'decrypt'): Promise<CryptoKey> {
    if (!this.privateKeys.has(keyUsage)) {
      let algorithm = { name: 'RSA-OAEP', hash: 'SHA-1' }
      if (keyUsage === 'sign') algorithm = { name: 'RSA-PSS', hash: 'SHA-256' }
      this.privateKeys.set(keyUsage, await window.crypto.subtle.importKey(
        'pkcs8',
        wrapPrivateKey(this.encodedPrivateKey),
        algorithm,
        true,
        [keyUsage]
      ))
    }
    return this.privateKeys.get(keyUsage)
  }

  /**
   * PublicKeyNode constructor. Should be given a Buffer containing a DER serialization of the key.
   * @constructs PublicKeyNode
   * @param {Buffer} key
   */

  /**
   * Returns a PrivateKeyNode from it's DER base64 serialization.
   * @method
   * @static
   * @param {string} b64DERFormattedPrivateKey - a b64 encoded private key formatted with DER
   * @returns {PrivateKeyNode}
   */
  static fromB64 (b64DERFormattedPrivateKey: string): PrivateKeyWebCrypto {
    return new this(Buffer.from(b64DERFormattedPrivateKey, 'base64'))
  }

  /**
   * Generates a PrivateKeyNode asynchronously
   * @param {Number} [size = 4096] - key size in bits
   * @returns {PrivateKeyNode}
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
      return new this(unwrapPrivateKey(exported))
    } else return new this(Buffer.from((await PrivateKeyForge.generate(size)).toB64(), 'base64'))
  }

  /**
   * Serializes the key to DER format and encodes it in b64.
   * @method
   * @param {Object} options
   * @param {boolean} [options.publicOnly]
   * @returns {string}
   */
  toB64 ({ publicOnly = false } = {}): string {
    return publicOnly
      ? super.toB64()
      : this.encodedPrivateKey.toString('base64')
  }

  decryptSync (cipherText: Buffer, doCRC?: boolean): Buffer {
    return this.forgeKey.decryptSync(cipherText, doCRC)
  }

  protected async _rawDecrypt (cipherText: Buffer): Promise<Buffer> {
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
   * Deciphers the given message.
   * @param {Buffer} cipherText
   * @param {boolean} [doCRC]
   * @returns {Buffer}
   */
  async decrypt (cipherText: Buffer, doCRC = true): Promise<Buffer> {
    return isWebCryptoAvailable()
      ? doCRC ? splitAndVerifyCRC(await this._rawDecrypt(cipherText)) : this._rawDecrypt(cipherText)
      : this.forgeKey.decrypt(cipherText, doCRC)
  }

  signSync (textToSign: Buffer): Buffer {
    return this.forgeKey.signSync(textToSign)
  }

  /**
   * Signs the given message with this Private Key.
   * @param {Buffer} textToSign
   * @returns {Buffer}
   */
  async sign (textToSign: Buffer): Promise<Buffer> {
    if (isWebCryptoAvailable()) {
      const privateKey = await this.getPrivateKey('sign')
      return Buffer.from(await window.crypto.subtle.sign(
        {
          name: 'RSA-PSS',
          saltLength: Math.ceil(((privateKey.algorithm as RsaHashedKeyGenParams).modulusLength - 1) / 8) - 32 - 2
        },
        privateKey,
        textToSign
      ))
    } else return this.forgeKey.sign(textToSign)
  }
}

export { PublicKeyWebCrypto as PublicKey, PrivateKeyWebCrypto as PrivateKey }
