import { Transform } from 'stream'

export type SymKeySize = 128 | 192 | 256

export interface SymKeyConstructor<T extends SymKey> {
  new (key: Buffer): T

  fromString (messageKey: string): T

  fromB64 (messageKey: string): T

  generate (size: SymKeySize): Promise<T>

  randomBytes_ (size: number): Promise<Buffer>

  randomBytesSync_ (size: number): Buffer
}

export abstract class SymKey {
  readonly keySize: number
  readonly key: Buffer

  /**
   * Constructor of SymKey
   * @constructs SymKey
   * @param {Buffer} key The key to construct the SymKey with.
   */
  protected constructor (key: Buffer) {
    this.keySize = key.length / 2
    this.key = key
    if (![32, 24, 16].includes(this.keySize)) {
      throw new Error('INVALID_ARG : Key size is invalid')
    }
  }

  static async randomBytes_ (size: number): Promise<Buffer> {
    return this.randomBytesSync_(size)
  }

  static randomBytesSync_ (size: number): Buffer {
    throw new Error('Subclass needs to implement `randomBytesSync_`')
  }

  /**
   * Static method to generate a new SymKey of a given size
   * @method
   * @static
   * @param {SymKeySize} [size=256]
   * @returns {Promise<SymKeyForge>}
   */
  static async generate<T extends SymKey> (this: SymKeyConstructor<T>, size: SymKeySize = 256): Promise<T> {
    return new this(await this.randomBytes_(size / 4))
  }

  /**
   * Static method to construct a new SymKeyNode from a binary string encoded messageKey
   * @method
   * @static
   * @param {string} messageKey binary encoded messageKey
   * @returns {SymKeyNode}
   */
  static fromString<T extends SymKey> (this: SymKeyConstructor<T>, messageKey: string): T {
    return new this(Buffer.from(messageKey, 'binary'))
  }

  /**
   * Static method to construct a new SymKeyNode from a b64 encoded key
   * @method
   * @static
   * @param {string} messageKey b64 encoded messageKey
   * @returns {SymKeyNode}
   */
  static fromB64<T extends SymKey> (this: SymKeyConstructor<T>, messageKey: string): T {
    return new this(Buffer.from(messageKey, 'base64'))
  }

  /**
   * Returns both SymKeyNode#signingKey and SymKeyNode#encryptionKey concatenated encoded with b64
   * @method
   * @returns {string}
   */
  toB64 (): string {
    return this.key.toString('base64')
  }

  /**
   * Returns both SymKeyNode#signingKey and SymKeyNode#encryptionKey concatenated as a binary string
   * @method
   * @returns {string}
   */
  toString (): string {
    return this.key.toString('binary')
  }

  /**
   * Calculates a SHA-256 HMAC with the SymKeyNode#signingKey on the textToAuthenticate
   * @method
   * @param {Buffer} textToAuthenticate
   * @returns {Promise<Buffer>}
   */
  async calculateHMAC_ (textToAuthenticate: Buffer): Promise<Buffer> {
    return this.calculateHMACSync_(textToAuthenticate)
  }

  /**
   * Calculates a SHA-256 HMAC with the SymKeyNode#signingKey on the textToAuthenticate
   * @method
   * @param {Buffer} textToAuthenticate
   * @returns {Buffer}
   */
  abstract calculateHMACSync_ (textToAuthenticate: Buffer): Buffer

  /**
   * Encrypts the clearText with SymKeyNode#encryptionKey using raw AES-CBC with given IV
   * @method
   * @param {Buffer} clearText
   * @param {Buffer} iv
   * @returns {Promise<Buffer>}
   */
  async rawEncrypt_ (clearText: Buffer, iv: Buffer): Promise<Buffer> {
    return this.rawEncryptSync_(clearText, iv)
  }

  /**
   * Encrypts the clearText with SymKeyNode#encryptionKey using AES-CBC, and a SHA-256 HMAC calculated with
   * SymKeyNode#signingKey, returns it concatenated in the following order:
   * InitializationVector CipherText HMAC
   * @method
   * @param {Buffer} clearText
   * @returns {Promise<Buffer>}
   */
  async encrypt (clearText: Buffer): Promise<Buffer> {
    const iv = await (this.constructor as SymKeyConstructor<SymKey>).randomBytes_(16)

    const crypt = await this.rawEncrypt_(clearText, iv)
    const cipherText = Buffer.concat([iv, crypt])

    return Buffer.concat([cipherText, await this.calculateHMAC_(cipherText)])
  }

  /**
   * Encrypts the clearText with SymKeyNode#encryptionKey using raw AES-CBC with given IV
   * @method
   * @param {Buffer} clearText
   * @param {Buffer} iv
   * @returns {Buffer}
   */
  abstract rawEncryptSync_ (clearText: Buffer, iv: Buffer): Buffer

  /**
   * Encrypts the clearText with SymKeyNode#encryptionKey using AES-CBC, and a SHA-256 HMAC calculated with
   * SymKeyNode#signingKey, returns it concatenated in the following order:
   * InitializationVector CipherText HMAC
   * @method
   * @param {Buffer} clearText
   * @returns {Buffer}
   */
  encryptSync (clearText: Buffer): Buffer {
    const iv = (this.constructor as SymKeyConstructor<SymKey>).randomBytesSync_(16)

    const crypt = this.rawEncryptSync_(clearText, iv)
    const cipherText = Buffer.concat([iv, crypt])

    return Buffer.concat([cipherText, this.calculateHMACSync_(cipherText)])
  }

  /**
   * Creates a Transform stream that encrypts the data piped to it.
   * @returns {Transform}
   */
  abstract encryptStream (): Transform

  /**
   * Decrypts the cipherText using raw AES-CBC with the given IV
   * @method
   * @param {Buffer} cipherText
   * @param {Buffer} iv
   * @returns {Promise<Buffer>}
   */
  async rawDecrypt_ (cipherText: Buffer, iv: Buffer): Promise<Buffer> {
    return this.rawDecryptSync_(cipherText, iv)
  }

  /**
   * Decrypts the cipherText using AES-CBC with the embedded IV, and checking the embedded SHA-256 HMAC
   * @method
   * @param {Buffer} cipheredMessage
   * @returns {Promise<Buffer>}
   */
  async decrypt (cipheredMessage: Buffer): Promise<Buffer> {
    const iv = cipheredMessage.slice(0, 16)
    const cipherText = cipheredMessage.slice(16, -32)
    const hmac = cipheredMessage.slice(-32)

    if ((await this.calculateHMAC_(Buffer.concat([iv, cipherText]))).equals(hmac)) {
      return this.rawDecrypt_(cipherText, iv)
    } else throw new Error('INVALID_HMAC')
  }

  /**
   * Decrypts the cipherText using raw AES-CBC with the given IV
   * @method
   * @param {Buffer} cipherText
   * @param {Buffer} iv
   * @returns {Buffer}
   */
  abstract rawDecryptSync_ (cipherText: Buffer, iv: Buffer): Buffer

  /**
   * Decrypts the cipherText using AES-CBC with the embedded IV, and checking the embedded SHA-256 HMAC
   * @method
   * @param {Buffer} cipheredMessage
   * @returns {Buffer}
   */
  decryptSync (cipheredMessage: Buffer): Buffer {
    const iv = cipheredMessage.slice(0, 16)
    const cipherText = cipheredMessage.slice(16, -32)
    const hmac = cipheredMessage.slice(-32)

    if (this.calculateHMACSync_(Buffer.concat([iv, cipherText])).equals(hmac)) {
      return this.rawDecryptSync_(cipherText, iv)
    } else throw new Error('INVALID_HMAC')
  }

  /**
   * Creates a Transform stream that decrypts the encrypted data piped to it.
   * @returns {Transform}
   */
  abstract decryptStream (): Transform
}
