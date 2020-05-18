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

export type AsymKeySize = 4096 | 2048 | 1024

export interface PublicKeyConstructor<T extends PublicKey> {
  new (key: Buffer): T

  fromB64 (messageKey: string): T
}

export class PublicKey {
  readonly publicKeyBuffer: Buffer

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

  static fromB64<T extends PublicKey> (this: PublicKeyConstructor<T>, b64DERFormattedPublicKey: string): T {
    return new this(Buffer.from(b64DERFormattedPublicKey, 'base64'))
  }

  toB64 (options: {} = null): string {
    return this.publicKeyBuffer.toString('base64')
  }

  protected _rawEncryptSync (clearText: Buffer): Buffer {
    throw new Error('Must be subclassed')
  }

  protected _rawEncrypt (clearText: Buffer): Promise<Buffer> {
    throw new Error('Must be subclassed')
  }

  encryptSync (clearText: Buffer, doCRC = true): Buffer {
    return doCRC ? this._rawEncryptSync(prefixCRC(clearText)) : this._rawEncryptSync(clearText)
  }

  encrypt (clearText: Buffer, doCRC = true): Promise<Buffer> {
    return doCRC ? this._rawEncrypt(prefixCRC(clearText)) : this._rawEncrypt(clearText)
  }

  verifySync (textToCheckAgainst: Buffer, signature: Buffer): boolean {
    throw new Error('Must be subclassed')
  }

  verify (textToCheckAgainst: Buffer, signature: Buffer): Promise<boolean> {
    throw new Error('Must be subclassed')
  }

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

export const makePrivateKeyBaseClass = (myPublicKeyConstructor: { new (buffer: Buffer): PublicKey }): PrivateKeyConstructor<PrivateKeyInterface> => {
  class PrivateKey extends myPublicKeyConstructor implements PrivateKeyInterface {
    readonly privateKeyBuffer: Buffer

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

    static generate<T extends PrivateKey> (this: PrivateKeyConstructor<T>, size: AsymKeySize = 4096): Promise<T> {
      throw new Error('Must be subclassed')
    }

    static fromB64<T extends PrivateKey> (this: PrivateKeyConstructor<T>, b64DERFormattedPrivateKey: string): T {
      return new this(Buffer.from(b64DERFormattedPrivateKey, 'base64'))
    }

    toB64 ({ publicOnly = false } = {}): string {
      return publicOnly
        ? super.toB64()
        : this.privateKeyBuffer.toString('base64')
    }

    _rawDecryptSync (cipherText: Buffer): Buffer {
      throw new Error('Must be subclassed')
    }

    _rawDecrypt (cipherText: Buffer): Promise<Buffer> {
      throw new Error('Must be subclassed')
    }

    decryptSync (cipherText: Buffer, doCRC = true): Buffer {
      const clearText = this._rawDecryptSync(cipherText)
      return doCRC ? splitAndVerifyCRC(clearText) : clearText
    }

    async decrypt (cipherText: Buffer, doCRC = true): Promise<Buffer> {
      const clearText = await this._rawDecrypt(cipherText)
      return doCRC ? splitAndVerifyCRC(clearText) : clearText
    }

    signSync (textToSign: Buffer): Buffer {
      throw new Error('Must be subclassed')
    }

    sign (textToSign: Buffer): Promise<Buffer> {
      throw new Error('Must be subclassed')
    }
  }

  return PrivateKey
}
