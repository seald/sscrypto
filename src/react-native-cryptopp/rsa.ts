import { mixClasses, staticImplements } from '../utils/commonUtils'
import { AsymKeySize, PrivateKeyConstructor, PublicKeyConstructor } from '../utils/rsa'
import { PrivateKey as PrivateKeyForge, PublicKey as PublicKeyForge } from '../forge/rsa'
import forge from 'node-forge'
// TODO: react-native-cryptopp needs to be cloned and linked locally for the moment
// @ts-ignore
import Cryptopp from 'react-native-cryptopp'
import { bufferToArrayBuffer, splitAndVerifyCRC, prefixCRC } from './utils'
import { convertDERToPEM, unwrapPrivateKey } from '../utils/rsaUtils'


@staticImplements<PublicKeyConstructor<PublicKeyRN>>()
class PublicKeyRN extends PublicKeyForge {
  readonly publicKeyCryptopp: string

  constructor (key: Buffer) {
    super(key)
    this.publicKeyCryptopp = convertDERToPEM(this.publicKeyBuffer, 'RSA PUBLIC KEY')
  }

  _rawEncryptSync (clearText: Buffer): Buffer {
    return Buffer.from(Cryptopp.RSA.encrypt(bufferToArrayBuffer(clearText), this.publicKeyCryptopp, "OAEP_SHA1"))
  }

  async _rawEncryptAsync (clearText: Buffer): Promise<Buffer> {
    return Buffer.from(await Cryptopp.async.RSA.encrypt(bufferToArrayBuffer(clearText), this.publicKeyCryptopp, "OAEP_SHA1"))
  }

  _calculateCRC32 (buffer: Buffer): Buffer {
    // @ts-ignore
    return Buffer.from(Cryptopp.hash.CRC32(bufferToArrayBuffer(buffer)).padStart(8,'0'), 'hex').reverse()
  }
}

@staticImplements<PrivateKeyConstructor<PrivateKeyRN>>()
class PrivateKeyRN extends mixClasses(PublicKeyRN, PrivateKeyForge) {
  readonly privateKeyBuffer: Buffer
  readonly privateKeyCryptopp: string

  constructor (key: Buffer) {
    // This has to basically re-write PrivateKeyForge's constructor because we inherit parasitically so the actual constructor does not run
    const { publicKeyBuffer, privateKeyBuffer } = new.target.constructor_(key)
    super(publicKeyBuffer)
    this.privateKeyBuffer = privateKeyBuffer
    try {
      this._privateKeyForge = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(this.privateKeyBuffer)))
      this.privateKeyCryptopp = convertDERToPEM(unwrapPrivateKey(this.privateKeyBuffer), 'RSA PRIVATE KEY')
    } catch (e) {
      throw new Error(`INVALID_KEY : ${e.message}`)
    }
  }

   static async generate (size: AsymKeySize = 4096): Promise<PrivateKeyRN> {
    if (![4096, 2048, 1024].includes(size)) {
      throw new Error('INVALID_ARG')
    }

    // @ts-ignore
    const keys = await Cryptopp.async.RSA.generateKeyPair(size, 65537)
    const privateKey = keys.private
      .replace(/\n/g, '')
      .replace(/\r/g, '') // iOS
      .replace(/-----.*?-----/g, '')
    return new this(Buffer.from(privateKey, 'base64'))
  }

  toB64 ({ publicOnly = false } = {}): string {
    // We have to re-write this because we inherit parasitically, so we have to make sure to use the privateKey's toB64, and not the publicKey's
    return this.toB64_({ publicOnly })
  }

  _rawDecryptSync (cipherText: Buffer): Buffer {
    try {
      return Buffer.from(Cryptopp.RSA.decrypt(bufferToArrayBuffer(cipherText), this.privateKeyCryptopp, "OAEP_SHA1"))
    } catch (e) {
      throw new Error(`INVALID_CIPHER_TEXT : ${e.message}`)
    }
  }

  async _rawDecryptAsync (cipherText: Buffer): Promise<Buffer> {
    try {
      return Buffer.from(await Cryptopp.async.RSA.decrypt(bufferToArrayBuffer(cipherText), this.privateKeyCryptopp, "OAEP_SHA1"))
    } catch (e) {
      throw new Error(`INVALID_CIPHER_TEXT : ${e.message}`)
    }  }
}

export { PublicKeyRN as PublicKey, PrivateKeyRN as PrivateKey }
