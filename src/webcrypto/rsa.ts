import { staticImplements } from '../utils/commonUtils'
import { AsymKeySize, PrivateKey, PrivateKeyConstructor } from '../utils/rsa'
import { PrivateKey as PrivateKeyForge, PublicKey as PublicKeyForge } from '../forge/rsa'

/**
 * @class PrivateKeyForge
 */
@staticImplements<PrivateKeyConstructor>()
class PrivateKeyWebCrypto extends PrivateKeyForge implements PrivateKey {
  /**
   * Generates a PrivateKeyWebCrypto asynchronously
   * @param {Number} [size = 4096] - key size in bits
   * @returns {PrivateKeyWebCrypto}
   */
  static async generate (size: AsymKeySize = 4096): Promise<PrivateKeyForge> {
    if (![4096, 2048, 1024].includes(size)) {
      throw new Error('INVALID_ARG')
      // @ts-ignore
    } else if (window.crypto && window.crypto.subtle && !window.SSCRYPTO_NO_WEBCRYPTO) {
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
    } else {
      return super.generate(size)
    }
  }
}

export { PublicKeyForge as PublicKey, PrivateKeyWebCrypto as PrivateKey }
