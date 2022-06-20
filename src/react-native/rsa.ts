import { mixClasses, staticImplements } from '../utils/commonUtils'
import { AsymKeySize, PrivateKeyConstructor, PublicKeyConstructor } from '../utils/rsa'
import { PrivateKey as PrivateKeyForge, PublicKey as PublicKeyForge } from '../forge/rsa'
import { RSA } from 'react-native-rsa-native'

@staticImplements<PublicKeyConstructor<PublicKeyRN>>()
class PublicKeyRN extends PublicKeyForge {}

@staticImplements<PrivateKeyConstructor<PrivateKeyRN>>()
class PrivateKeyRN extends mixClasses(PublicKeyRN, PrivateKeyForge) {
  static async generate (size: AsymKeySize = 4096): Promise<PrivateKeyRN> {
    if (![4096, 2048, 1024].includes(size)) {
      throw new Error('INVALID_ARG')
    }
    const keys = await RSA.generateKeys(size)
    const privateKey = keys.private
      .replace(/\n/g, '')
      .replace(/\r/g, '') // iOS
      .replace(/-----.*?-----/g, '')
    return new this(privateKey)
  }
}

export { PublicKeyRN as PublicKey, PrivateKeyRN as PrivateKey }
