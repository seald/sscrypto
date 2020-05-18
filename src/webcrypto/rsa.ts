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
 * @class PublicKeyNode
 * @property publicKey
 */
@staticImplements<PublicKeyConstructor<PublicKeyWebCrypto>>()
class PublicKeyWebCrypto extends PublicKey {
  readonly publicKeyBuffer: Buffer

  protected _publicKeys: Map<'verify' | 'encrypt', CryptoKey>
  protected _forgeKey: PublicKeyForge

  protected async _getPublicKey (keyUsage: 'verify' | 'encrypt'): Promise<CryptoKey> {
    if (!this._publicKeys.has(keyUsage)) {
      let algorithm = { name: 'RSA-OAEP', hash: 'SHA-1' }
      if (keyUsage === 'verify') algorithm = { name: 'RSA-PSS', hash: 'SHA-256' }
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
   * PublicKeyNode constructor. Should be given a Buffer containing a DER serialization of the key.
   * @constructs PublicKeyNode
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

  protected _rawEncryptSync (clearText: Buffer): Buffer {
    return this._forgeKey.encryptSync(clearText, false) // TODO: a bit dirty to define forge's encryptSync with no CRC32 as _rawEncryptSync
  }

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

  verifySync (textToCheckAgainst: Buffer, signature: Buffer): boolean {
    return this._forgeKey.verifySync(textToCheckAgainst, signature)
  }

  /**
   * Verify that the message has been signed with the Private Key corresponding to this PublicKeyNode.
   * @param {Buffer} textToCheckAgainst
   * @param {Buffer} signature
   * @returns {boolean}
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

  getHash (): string {
    return sha256(this.publicKeyBuffer).toString('base64')
  }
}

/**
 * @class PrivateKeyWebCrypto
 */
// @staticImplements<PrivateKeyConstructor<PrivateKeyWebCrypto>>() TODO: no way to make it work
class PrivateKeyWebCrypto extends makePrivateKeyBaseClass(PublicKeyWebCrypto) implements PrivateKeyInterface {
  readonly privateKeyBuffer: Buffer

  protected _privateKeys: Map<'sign' | 'decrypt', CryptoKey>
  protected _forgeKey: PrivateKeyForge

  protected async getPrivateKey (keyUsage: 'sign' | 'decrypt'): Promise<CryptoKey> {
    if (!this._privateKeys.has(keyUsage)) {
      let algorithm = { name: 'RSA-OAEP', hash: 'SHA-1' }
      if (keyUsage === 'sign') algorithm = { name: 'RSA-PSS', hash: 'SHA-256' }
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
   * PublicKeyNode constructor. Should be given a Buffer containing a DER serialization of the key.
   * @constructs PublicKeyNode
   * @param {Buffer} key
   */

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
      return new this(exported)
    } else return new this(Buffer.from((await PrivateKeyForge.generate(size)).toB64(), 'base64'))
  }

  protected _rawDecryptSync (cipherText: Buffer): Buffer {
    return this._forgeKey.decryptSync(cipherText, false)
  }

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

  signSync (textToSign: Buffer): Buffer {
    return this._forgeKey.signSync(textToSign)
  }

  /**
   * Signs the given message with this Private Key.
   * @param {Buffer} textToSign
   * @returns {Buffer}
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
