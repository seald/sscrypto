/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { AsymKeySize, PrivateKey, PrivateKeyConstructor, PublicKeyConstructor } from '../utils/rsa'
import { TestHooks } from './specUtils.spec'

chai.use(chaiAsPromised)
const { assert, expect } = chai

type AsymKeyImplem = { PrivateKey: PrivateKeyConstructor, PublicKey: PublicKeyConstructor }

export const testAsymKeyImplem = (name: string, { PrivateKey: PrivateKey_, PublicKey: PublicKey_ }: AsymKeyImplem, randomBytes: (size: number) => Buffer, { duringBefore, duringAfter }: TestHooks = {}): void => {
  describe(`RSA ${name}`, function () {
    this.timeout(5000)

    let privateKey: PrivateKey, privateKey2: PrivateKey

    before('generate keys', function () {
      this.timeout(30000)
      if (duringBefore) duringBefore()
      return Promise.all([
        PrivateKey_.generate(1024),
        PrivateKey_.generate(1024)
      ])
        .then(([_key1, _key2]) => {
          privateKey = _key1
          privateKey2 = _key2
        })
    })

    after(() => {
      if (duringAfter) duringAfter()
    })

    const message = Buffer.from('TESTtest', 'ascii')
    const messageUtf8 = 'Iñtërnâtiônàlizætiøn\u2603\uD83D\uDCA9'
    const messageBinary = randomBytes(32)

    it('Fail to construct a PublicKey because of an invalid type of argument', () => {
      expect(
        PrivateKey_
        // @ts-ignore: voluntary test of what happens with bad type
          .generate('notAValidType')
      ).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_ARG')
        return true
      })
    })

    it('fail to produce a new PrivateKey with a wrong size', () => {
      expect(
        PrivateKey_
        // @ts-ignore: voluntary test of what happens with bad type
          .generate(588)
      ).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_ARG')
        return true
      })
    })

    it('fail to import bad PrivateKey', () => {
      expect(() => PrivateKey_.fromB64(privateKey.toB64().slice(2))).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_KEY')
        return true
      })
    })

    it('fail to import PrivateKey because of an invalid type', () => {
      expect(
        // @ts-ignore: voluntary test of what happens with bad type
        () => new PrivateKey_(2)
      ).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_KEY')
        return true
      })
    })

    it('fail to import bad PublicKey', () => {
      expect(
        () => PublicKey_.fromB64(privateKey.toB64({ publicOnly: true }).slice(0, -2))
      ).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_KEY')
        return true
      })
    })

    it('export public key then import', () => {
      const publicKeyImported = PublicKey_.fromB64(privateKey.toB64({ publicOnly: true }))

      assert.strictEqual(publicKeyImported.toB64(), privateKey.toB64({ publicOnly: true }))
    })

    it('export the private key then import it', () => {
      const privateKeyImported = PrivateKey_.fromB64(privateKey.toB64())

      assert.strictEqual(privateKeyImported.toB64(), privateKey.toB64({ publicOnly: false }))
    })

    it('cipher & decipher', () => {
      const cipheredMessage = privateKey.encrypt(message)
      assert.isTrue(privateKey.decrypt(cipheredMessage).equals(message), 'Message cannot be deciphered')
    })

    it('cipher & decipher without CRC', () => {
      const cipheredMessage = privateKey.encrypt(message, false)
      assert.isTrue(privateKey.decrypt(cipheredMessage, false).equals(message), 'Message cannot be deciphered')
    })

    it('cipher & decipher with invalid CRC', () => {
      const cipheredMessage = privateKey.encrypt(message, false)
      expect(() => privateKey.decrypt(cipheredMessage)).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_CRC32')
        return true
      })
    })

    it('cipher & decipher UTF8', () => {
      const cipheredMessage = privateKey.encrypt(Buffer.from(messageUtf8, 'utf8'))
      const decipheredMessage = privateKey.decrypt(cipheredMessage).toString('utf8')
      assert.strictEqual(decipheredMessage, messageUtf8, 'Message cannot be deciphered')
    })

    it('cipher & decipher binary', () => {
      const cipheredMessage = privateKey.encrypt(messageBinary)
      assert.isTrue(privateKey.decrypt(cipheredMessage).equals(messageBinary), 'Message cannot be deciphered')
    })

    it('fail with bad key', () => {
      const cipheredMessage = privateKey2.encrypt(message)
      expect(() => privateKey.decrypt(cipheredMessage)).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_CIPHER_TEXT')
        return true
      })
    })

    it('sign & verify', () => {
      const messageSignatureByPrivateKey = privateKey.sign(message)
      assert(privateKey.verify(message, messageSignatureByPrivateKey), 'Signature doesn\'t match')
    })

    it('get hash', () => {
      const hash = privateKey.getHash()
      assert.strictEqual(hash, privateKey.getHash())
      assert.notStrictEqual(hash, privateKey2.getHash())
    })
  })
}

export const testAsymKeyCompatibility = (name: string, keySize: AsymKeySize, { PrivateKey: PrivateKey1, PublicKey: PublicKey1 }: AsymKeyImplem, { PrivateKey: PrivateKey2, PublicKey: PublicKey2 }: AsymKeyImplem): void => {
  describe(`RSA compatibility ${name} ${keySize}`, function () {
    this.timeout(5000)

    let privateKey1: PrivateKey, privateKey2: PrivateKey

    before('generate keys', function () {
      this.timeout(30000)
      return Promise.all([
        PrivateKey1.generate(keySize),
        PrivateKey2.generate(keySize)
      ])
        .then(([_key1, _key2]) => {
          privateKey1 = _key1
          privateKey2 = _key2
        })
    })

    const message = Buffer.from('TESTtest', 'ascii')

    it('export node & import forge, hash, encrypt & sign', () => {
      const privateKey = privateKey1
      const privateKey_ = PrivateKey2.fromB64(privateKey.toB64())
      const publicKey_ = PublicKey2.fromB64(privateKey.toB64({ publicOnly: true }))

      // compatibility
      const cipherText1 = privateKey.encrypt(message)
      const decipheredMessage1 = privateKey_.decrypt(cipherText1)
      assert.isTrue(message.equals(decipheredMessage1))

      const cipherText2 = privateKey_.encrypt(message)
      const decipheredMessage2 = privateKey.decrypt(cipherText2)
      assert.isTrue(message.equals(decipheredMessage2))

      const cipherText3 = publicKey_.encrypt(message)
      const decipheredMessage3 = privateKey.decrypt(cipherText3)
      assert.isTrue(message.equals(decipheredMessage3))

      const signature = privateKey.sign(message)
      assert.isTrue(privateKey_.verify(message, signature))
      assert.isTrue(publicKey_.verify(message, signature))

      // equality
      assert.strictEqual(privateKey.toB64(), privateKey_.toB64())
      assert.strictEqual(privateKey.toB64({ publicOnly: true }), publicKey_.toB64({ publicOnly: true }))
      assert.strictEqual(privateKey.toB64({ publicOnly: true }), privateKey_.toB64({ publicOnly: true }))

      assert.strictEqual(privateKey.getHash(), privateKey_.getHash())
    })

    it('export forge & import node, hash encrypt & sign', () => {
      const privateKey = privateKey2
      const privateKey_ = PrivateKey1.fromB64(privateKey.toB64())
      const publicKey_ = PublicKey1.fromB64(privateKey.toB64({ publicOnly: true }))

      // compatibility
      const cipherText1 = privateKey.encrypt(message)
      const decipheredMessage1 = privateKey_.decrypt(cipherText1)
      assert.isTrue(message.equals(decipheredMessage1))

      const cipherText2 = privateKey_.encrypt(message)
      const decipheredMessage2 = privateKey.decrypt(cipherText2)
      assert.isTrue(message.equals(decipheredMessage2))

      const cipherText3 = publicKey_.encrypt(message)
      const decipheredMessage3 = privateKey.decrypt(cipherText3)
      assert.isTrue(message.equals(decipheredMessage3))

      const signature = privateKey.sign(message)
      assert.isTrue(privateKey_.verify(message, signature))
      assert.isTrue(publicKey_.verify(message, signature))

      // equality
      assert.strictEqual(privateKey.toB64(), privateKey_.toB64())
      assert.strictEqual(privateKey.toB64({ publicOnly: true }), publicKey_.toB64({ publicOnly: true }))
      assert.strictEqual(privateKey.toB64({ publicOnly: true }), privateKey_.toB64({ publicOnly: true }))

      assert.strictEqual(privateKey.getHash(), privateKey_.getHash())
    })
  })
}

export const testAsymKeyPerf = (name: string, keySize: AsymKeySize, { PrivateKey: PrivateKey_, PublicKey: PublicKey_ }: AsymKeyImplem, randomBytes: (size: number) => Buffer, { duringBefore, duringAfter }: TestHooks = {}): void => {
  describe(`RSA perf ${name} - ${keySize}`, function () {
    this.timeout(30000)

    before(() => {
      if (duringBefore) duringBefore()
    })

    after(() => {
      if (duringAfter) duringAfter()
    })

    it('Private key generation', async () => {
      const nKeys = 10

      const privateKeys = []
      const start = Date.now()
      for (let i = 0; i < nKeys; i++) {
        const k = await PrivateKey_.generate(keySize)
        privateKeys.push(k)
      }
      const end = Date.now()
      const delta = (end - start) / 1000
      console.log(`Finished generating keys in ${delta.toFixed(1)}s:\n${(delta / nKeys).toFixed(2)} s / key`)
    })

    it('Encrypt / decrypt', async () => {
      const nData = 10

      const k = await PrivateKey_.generate(keySize)
      const randomData: Array<Buffer> = []

      for (let i = 0; i < nData; i++) {
        randomData.push(randomBytes(32))
      }

      const encryptedData = []
      const startEncrypt = Date.now()
      for (const d of randomData) {
        encryptedData.push(k.encrypt(d))
      }
      const endEncrypt = Date.now()
      const deltaEncrypt = (endEncrypt - startEncrypt) / 1000
      console.log(`Finished encrypting in ${deltaEncrypt.toFixed(1)}s:\n${(nData / deltaEncrypt).toFixed(2)} block / s`)

      const decryptedData = []
      const startDecrypt = Date.now()
      for (const d of encryptedData) {
        decryptedData.push(k.decrypt(d))
      }
      const endDecrypt = Date.now()
      const deltaDecrypt = (endDecrypt - startDecrypt) / 1000
      console.log(`Finished decrypting in ${deltaDecrypt.toFixed(1)}s:\n${(nData / deltaDecrypt).toFixed(2)} block / s`)

      assert.strictEqual(decryptedData.length, nData)
      assert.isTrue(decryptedData.every((d, i) => d.equals(randomData[i])))
    })
  })
}
