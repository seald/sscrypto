import forge from 'node-forge'
import crc32 from 'crc-32'
import { b64, intToBytes, sha256, unb64 } from './utils'

/**
 * @class PublicKey
 * @property publicKey
 */
export class PublicKey {
  /**
   * PublicKey constructor. Should be given a binary string of the key.
   * @constructs PublicKey
   * @param {string} key
   */
  constructor (key) {
    if (key) {
      if (typeof key === 'string') {
        try {
          // noinspection JSValidateTypes
          this.publicKey = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(key)))
        } catch (e) {
          throw new Error(`INVALID_KEY : ${e.message}`)
        }
      } else {
        throw new Error(`INVALID_KEY : Type of ${key} is ${typeof key}`)
      }
    }
  }

  /**
   * Returns a PublicKey from it's base64 serialization.
   * @method
   * @static
   * @param {string} b64DERFormattedPublicKey - a b64 encoded public key formatted with DER
   * @returns {PublicKey}
   */
  static from (b64DERFormattedPublicKey) {
    return new PublicKey(unb64(b64DERFormattedPublicKey))
  }

  /**
   * Serializes the key to DER format and encodes it in b64.
   * @method
   * @param {object} [options]
   * @returns {string}
   */
  serialize (options) {
    // noinspection JSCheckFunctionSignatures
    return b64(forge.asn1.toDer(forge.pki.publicKeyToAsn1(this.publicKey)).getBytes())
  }

  /**
   * Encrypts a clearText for the Private Key corresponding to this PublicKey.
   * @method
   * @param {string} clearText
   * @param {boolean} doCRC
   * @returns {string}
   */
  encrypt (clearText, doCRC = true) {
    const textToEncrypt = doCRC
      ? intToBytes(crc32.bstr(clearText)) + clearText
      : clearText
    // noinspection JSCheckFunctionSignatures
    return this.publicKey.encrypt(textToEncrypt, 'RSA-OAEP', {
      md: forge.md.sha1.create(),
      mgf1: {
        md: forge.md.sha1.create()
      }
    })
  }

  /**
   * Verify that the message has been signed with the Private Key corresponding to this PublicKey.
   * @param {string} textToCheckAgainst
   * @param {string} signature Encoded in Base64
   * @returns {boolean}
   */
  verify (textToCheckAgainst, signature) {
    try {
      const saltLength = (this.publicKey.n.bitLength() / 8) - 32 - 2 // TODO: EXPLAIN, EXPLAIN ! // TODO: why a variable ?
      const pss = forge.pss.create({
        md: forge.md.sha256.create(),
        mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
        saltLength: saltLength
      })
      const md = forge.md.sha256.create()
      md.update(textToCheckAgainst)
      // noinspection JSCheckFunctionSignatures
      return this.publicKey.verify(md.digest().getBytes(), unb64(signature), pss)
    } catch (e) {
      return false
    }
  }

  getHash () {
    return sha256(this.serialize({ publicOnly: true })).toHex()
  }

  getB64Hash () {
    return b64(sha256(this.serialize({ publicOnly: true })).bytes())
  }
}

/**
 * @class PrivateKey
 * @property privateKey
 * @property publicKey
 */
export class PrivateKey extends PublicKey {
  /**
   * Private Key constructor. Shouldn't be used directly, user from or generate static methods
   * @constructs PrivateKey
   * @param {object|string} arg
   */
  constructor (arg) {
    super()
    if (typeof arg === 'string') {
      try {
        this.privateKey = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(arg)))
      } catch (e) {
        throw new Error(`INVALID_KEY : ${e.message}`)
      }
      this.publicKey = forge.pki.rsa.setPublicKey(this.privateKey.n, this.privateKey.e)
    } else if (typeof arg === 'object') {
      if (arg.hasOwnProperty('privateKey') && arg.hasOwnProperty('publicKey')) Object.assign(this, arg)
      else throw new Error(`INVALID_KEY`)
    } else {
      throw new Error(`INVALID_KEY : Type of ${arg} is ${typeof arg}`)
    }
  }

  /**
   * Returns a PrivateKey from it's base64 serialization.
   * @method
   * @static
   * @param {string} b64DERFormattedPrivateKey - a b64 encoded private key formatted with DER
   * @returns {PrivateKey}
   */
  static from (b64DERFormattedPrivateKey) {
    return new PrivateKey(unb64(b64DERFormattedPrivateKey))
  }

  /**
   * Generates a PrivateKey asynchronously, a synchronous call is way longer and may use a non-secure entropy source
   * @param {Number} [size = 4096] - key size in bits
   */
  static generate (size = 4096) {
    if (![4096, 2048, 1024].includes(size)) {
      return Promise.reject(new Error('INVALID_INPUT'))
    } else {
      return new Promise((resolve, reject) => {
        forge.pki.rsa.generateKeyPair({
          bits: size,
          workers: -1
        }, (error, keyPair) => error ? reject(error) : resolve(keyPair))
      })
        .then(keyPair => new PrivateKey(keyPair))
    }
  }

  /**
   * Serializes the key to DER format and encodes it in b64.
   * @method
   * @param {boolean} [publicOnly]
   * @returns string
   */
  serialize ({ publicOnly = false } = {}) {
    // noinspection JSCheckFunctionSignatures
    return publicOnly
      ? b64(forge.asn1.toDer(forge.pki.publicKeyToAsn1(this.publicKey)).getBytes())
      : b64(forge.asn1.toDer(forge.pki.privateKeyToAsn1(this.privateKey)).getBytes())
  }

  /**
   * Deciphers the given message.
   * @param {string} cipherText
   * @param {boolean} doCRC
   * @returns {string}
   */
  decrypt (cipherText, doCRC = true) {
    let clearText
    try {
      // noinspection JSCheckFunctionSignatures
      clearText = this.privateKey.decrypt(cipherText, 'RSA-OAEP', {
        md: forge.md.sha1.create(),
        mgf1: {
          md: forge.md.sha1.create()
        }
      })
    } catch (e) {
      throw new Error(`INVALID_CIPHER_TEXT : ${e.message}`)
    }
    if (!doCRC) {
      return clearText
    } else {
      const crc = clearText.slice(0, 4)
      const message = clearText.slice(4)
      const calculatedCRC = intToBytes(crc32.bstr(message))
      if (crc === calculatedCRC) {
        return message
      } else {
        throw new Error('INVALID_CRC32')
      }
    }
  }

  /**
   * Signs the given message with this Private Key.
   * @param {string} textToSign
   * @returns {string}
   */
  sign (textToSign) {
    const md = forge.md.sha256.create()
    md.update(textToSign)
    const saltLength = (this.publicKey.n.bitLength() / 8) - 32 - 2 // TODO: EXPLAIN, EXPLAIN !
    const pss = forge.pss.create({
      md: forge.md.sha256.create(),
      mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
      saltLength: saltLength
    })
    // noinspection JSCheckFunctionSignatures
    return b64(this.privateKey.sign(md, pss))
  }
}
