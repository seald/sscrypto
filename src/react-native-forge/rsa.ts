import './patches'
import { mixClasses, staticImplements } from '../utils/commonUtils'
import { AsymKeySize, PrivateKeyConstructor, PublicKeyConstructor } from '../utils/rsa'
import { PrivateKey as PrivateKeyForge, PublicKey as PublicKeyForge } from '../forge/rsa'
import { RSA } from 'react-native-rsa-native'
import forge from 'node-forge'

@staticImplements<PublicKeyConstructor<PublicKeyRN>>()
class PublicKeyRN extends PublicKeyForge {}

@staticImplements<PrivateKeyConstructor<PrivateKeyRN>>()
class PrivateKeyRN extends mixClasses(PublicKeyRN, PrivateKeyForge) {
  readonly privateKeyBuffer: Buffer

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
  }

  static async generate (size: AsymKeySize = 4096): Promise<PrivateKeyRN> {
    if (![4096, 2048, 1024].includes(size)) {
      throw new Error('INVALID_ARG')
    }
    const keys = await RSA.generateKeys(size)
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
}

export { PublicKeyRN as PublicKey, PrivateKeyRN as PrivateKey }
