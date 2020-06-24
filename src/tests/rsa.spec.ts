/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { AsymKeySize, PrivateKey, PrivateKeyConstructor, PublicKey, PublicKeyConstructor } from '../utils/rsa'
import { TestHooks } from './specUtils.spec'

chai.use(chaiAsPromised)
const { assert, expect } = chai

type AsymKeyImplem = { PrivateKey: PrivateKeyConstructor<PrivateKey>, PublicKey: PublicKeyConstructor<PublicKey> }

const testAsymKeyImplemSize = (name: string, keySize: AsymKeySize, { PrivateKey: PrivateKey_, PublicKey: PublicKey_ }: AsymKeyImplem, randomBytes: (size: number) => Buffer, { duringBefore, duringAfter }: TestHooks = {}): void => {
  describe(`RSA ${keySize} - ${name}`, function () {
    this.timeout(5000)

    let privateKey: InstanceType<typeof PrivateKey_>, privateKey2: InstanceType<typeof PrivateKey_>

    after(() => {
      if (duringAfter) duringAfter()
    })

    const message = Buffer.from('TESTtest', 'ascii')
    const messageUtf8 = 'Iñtërnâtiônàlizætiøn\u2603\uD83D\uDCA9'
    const messageBinary = randomBytes(32)

    it('generate keys', async function () {
      this.timeout(30000)
      if (duringBefore) duringBefore()
      const [_key1, _key2] = await Promise.all([
        PrivateKey_.generate(keySize),
        PrivateKey_.generate(keySize)
      ])
      assert.instanceOf(_key1, PrivateKey_)
      assert.instanceOf(_key2, PrivateKey_)
      assert.instanceOf(_key1, PrivateKey)
      assert.instanceOf(_key2, PrivateKey)
      assert.instanceOf(_key1, PublicKey_)
      assert.instanceOf(_key2, PublicKey_)
      assert.instanceOf(_key1, PublicKey)
      assert.instanceOf(_key2, PublicKey)
      privateKey = _key1
      privateKey2 = _key2
    })

    it('Fail to construct a PublicKey because of an invalid type of argument', () =>
      expect(
        PrivateKey_
          // @ts-expect-error
          .generate('notAValidType')
      ).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_ARG')
        return true
      })
    )

    it('fail to produce a new PrivateKey with a wrong size', () =>
      expect(
        PrivateKey_
          // @ts-expect-error
          .generate(588)
      ).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_ARG')
        return true
      })
    )

    it('fail to import bad PrivateKey', () => {
      expect(() => PrivateKey_.fromB64(privateKey.toB64().slice(2))).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_KEY')
        return true
      })
    })

    it('fail to import PrivateKey because of an invalid type', () => {
      expect(
        // @ts-expect-error
        () => new PrivateKey_(2)
      ).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_KEY')
        return true
      })
    })

    it('fail to import bad PublicKey', () => {
      expect(
        () => PublicKey_.fromB64(privateKey.toB64({ publicOnly: true }).slice(0, -4))
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

    it('cipher & decipher sync', () => {
      const cipheredMessage = privateKey.encrypt(message)
      assert.isTrue((privateKey.decrypt(cipheredMessage)).equals(message), 'Message cannot be deciphered')
    })

    it('cipher & decipher async', async () => {
      const cipheredMessage = await privateKey.encryptAsync(message)
      assert.isTrue((await privateKey.decryptAsync(cipheredMessage)).equals(message), 'Message cannot be deciphered')
    })

    it('cipher & decipher without CRC sync', () => {
      const cipheredMessage = privateKey.encrypt(message, false)
      assert.isTrue((privateKey.decrypt(cipheredMessage, false)).equals(message), 'Message cannot be deciphered')
    })

    it('cipher & decipher without CRC async', async () => {
      const cipheredMessage = await privateKey.encryptAsync(message, false)
      assert.isTrue((await privateKey.decryptAsync(cipheredMessage, false)).equals(message), 'Message cannot be deciphered')
    })

    it('cipher & decipher with invalid CRC sync', () => {
      const cipheredMessage = privateKey.encrypt(message, false)
      return expect(() => privateKey.decrypt(cipheredMessage)).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_CRC32')
        return true
      })
    })

    it('cipher & decipher with invalid CRC async', async () => {
      const cipheredMessage = await privateKey.encryptAsync(message, false)
      return expect(privateKey.decryptAsync(cipheredMessage)).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_CRC32')
        return true
      })
    })

    it('cipher & decipher UTF8 sync', () => {
      const cipheredMessage = privateKey.encrypt(Buffer.from(messageUtf8, 'utf8'))
      const decipheredMessage = privateKey.decrypt(cipheredMessage).toString('utf8')
      assert.strictEqual(decipheredMessage, messageUtf8, 'Message cannot be deciphered')
    })

    it('cipher & decipher UTF8 async', async () => {
      const cipheredMessage = await privateKey.encryptAsync(Buffer.from(messageUtf8, 'utf8'))
      const decipheredMessage = (await privateKey.decryptAsync(cipheredMessage)).toString('utf8')
      assert.strictEqual(decipheredMessage, messageUtf8, 'Message cannot be deciphered')
    })

    it('cipher & decipher binary sync', () => {
      const cipheredMessage = privateKey.encrypt(messageBinary)
      assert.isTrue(privateKey.decrypt(cipheredMessage).equals(messageBinary), 'Message cannot be deciphered')
    })

    it('cipher & decipher binary async', async () => {
      const cipheredMessage = await privateKey.encryptAsync(messageBinary)
      assert.isTrue((await privateKey.decryptAsync(cipheredMessage)).equals(messageBinary), 'Message cannot be deciphered')
    })

    it('fail with bad key sync', async () => {
      const cipheredMessage = privateKey2.encrypt(message)
      return expect(() => privateKey.decrypt(cipheredMessage)).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_CIPHER_TEXT')
        return true
      })
    })

    it('fail with bad key async', async () => {
      const cipheredMessage = await privateKey2.encryptAsync(message)
      return expect(privateKey.decryptAsync(cipheredMessage)).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_CIPHER_TEXT')
        return true
      })
    })

    it('sign & verify sync', () => {
      const messageSignatureByPrivateKey = privateKey.sign(message)
      assert(privateKey.verify(message, messageSignatureByPrivateKey), 'Signature doesn\'t match')
    })

    it('sign & verify async', async () => {
      const messageSignatureByPrivateKey = await privateKey.signAsync(message)
      assert(await privateKey.verifyAsync(message, messageSignatureByPrivateKey), 'Signature doesn\'t match')
    })

    it('get hash', () => {
      const hash = privateKey.getHash()
      assert.strictEqual(hash, privateKey.getHash())
      assert.notStrictEqual(hash, privateKey2.getHash())
    })
  })
}

export const testAsymKeyImplem = (name: string, { PrivateKey: PrivateKey_, PublicKey: PublicKey_ }: AsymKeyImplem, randomBytes: (size: number) => Buffer, { duringBefore, duringAfter }: TestHooks = {}): void => {
  testAsymKeyImplemSize(name, 1024, { PrivateKey: PrivateKey_, PublicKey: PublicKey_ }, randomBytes, { duringBefore, duringAfter })
  testAsymKeyImplemSize(name, 2048, { PrivateKey: PrivateKey_, PublicKey: PublicKey_ }, randomBytes, { duringBefore, duringAfter })
  testAsymKeyImplemSize(name, 4096, { PrivateKey: PrivateKey_, PublicKey: PublicKey_ }, randomBytes, { duringBefore, duringAfter })
}

const testAsymKeyCompatibilitySize = (name: string, keySize: AsymKeySize, { PrivateKey: PrivateKey1, PublicKey: PublicKey1 }: AsymKeyImplem, { PrivateKey: PrivateKey2, PublicKey: PublicKey2 }: AsymKeyImplem): void => {
  describe(`RSA ${keySize} compatibility - ${name}`, function () {
    this.timeout(5000)

    let privateKey1: PrivateKey

    before('generate keys', function () {
      this.timeout(30000)
      return PrivateKey1.generate(keySize)
        .then((_key1) => {
          privateKey1 = _key1
        })
    })

    const message = Buffer.from('TESTtest', 'ascii')

    it(`export ${PublicKey1.name} & import ${PublicKey2.name}, hash, encrypt & sign sync`, () => {
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

    it(`export ${PublicKey1.name} & import ${PublicKey2.name}, hash, encrypt & sign async`, async () => {
      const privateKey = privateKey1
      const privateKey_ = PrivateKey2.fromB64(privateKey.toB64())
      const publicKey_ = PublicKey2.fromB64(privateKey.toB64({ publicOnly: true }))

      // compatibility
      const cipherText1 = await privateKey.encryptAsync(message)
      const decipheredMessage1 = await privateKey_.decryptAsync(cipherText1)
      assert.isTrue(message.equals(decipheredMessage1))

      const cipherText2 = await privateKey_.encryptAsync(message)
      const decipheredMessage2 = await privateKey.decryptAsync(cipherText2)
      assert.isTrue(message.equals(decipheredMessage2))

      const cipherText3 = await publicKey_.encryptAsync(message)
      const decipheredMessage3 = await privateKey.decryptAsync(cipherText3)
      assert.isTrue(message.equals(decipheredMessage3))

      const signature = await privateKey.signAsync(message)
      assert.isTrue(await privateKey_.verifyAsync(message, signature))
      assert.isTrue(await publicKey_.verifyAsync(message, signature))

      // equality
      assert.strictEqual(privateKey.toB64(), privateKey_.toB64())
      assert.strictEqual(privateKey.toB64({ publicOnly: true }), publicKey_.toB64({ publicOnly: true }))
      assert.strictEqual(privateKey.toB64({ publicOnly: true }), privateKey_.toB64({ publicOnly: true }))

      assert.strictEqual(await privateKey.getHash(), await privateKey_.getHash())
    })
  })
}

export const testAsymKeyCompatibility = (name: string, { PrivateKey: PrivateKey1, PublicKey: PublicKey1 }: AsymKeyImplem, { PrivateKey: PrivateKey2, PublicKey: PublicKey2 }: AsymKeyImplem): void => {
  testAsymKeyCompatibilitySize(name, 1024, { PrivateKey: PrivateKey1, PublicKey: PublicKey1 }, { PrivateKey: PrivateKey2, PublicKey: PublicKey2 })
  testAsymKeyCompatibilitySize(name, 2048, { PrivateKey: PrivateKey1, PublicKey: PublicKey1 }, { PrivateKey: PrivateKey2, PublicKey: PublicKey2 })
  testAsymKeyCompatibilitySize(name, 4096, { PrivateKey: PrivateKey1, PublicKey: PublicKey1 }, { PrivateKey: PrivateKey2, PublicKey: PublicKey2 })
}

export const testAsymKeyPerf = (name: string, keySize: AsymKeySize, { PrivateKey: PrivateKey_, PublicKey: PublicKey_ }: AsymKeyImplem, randomBytes: (size: number) => Buffer, { duringBefore, duringAfter }: TestHooks = {}): void => {
  describe(`RSA ${keySize} perf - ${name}`, function () {
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

    it('Encrypt / decrypt sync', async () => {
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

    it('Encrypt / decrypt async', async () => {
      const nData = 10

      const k = await PrivateKey_.generate(keySize)
      const randomData: Array<Buffer> = []

      for (let i = 0; i < nData; i++) {
        randomData.push(randomBytes(32))
      }

      const encryptedData = []
      const startEncrypt = Date.now()
      for (const d of randomData) {
        encryptedData.push(await k.encryptAsync(d))
      }
      const endEncrypt = Date.now()
      const deltaEncrypt = (endEncrypt - startEncrypt) / 1000
      console.log(`Finished encrypting in ${deltaEncrypt.toFixed(1)}s:\n${(nData / deltaEncrypt).toFixed(2)} block / s`)

      const decryptedData = []
      const startDecrypt = Date.now()
      for (const d of encryptedData) {
        decryptedData.push(await k.decryptAsync(d))
      }
      const endDecrypt = Date.now()
      const deltaDecrypt = (endDecrypt - startDecrypt) / 1000
      console.log(`Finished decrypting in ${deltaDecrypt.toFixed(1)}s:\n${(nData / deltaDecrypt).toFixed(2)} block / s`)

      assert.strictEqual(decryptedData.length, nData)
      assert.isTrue(decryptedData.every((d, i) => d.equals(randomData[i])))
    })

    it('Sign / verify sync', async () => {
      const nData = 10

      const k = await PrivateKey_.generate(keySize)
      const randomData: Array<Buffer> = []

      for (let i = 0; i < nData; i++) {
        randomData.push(randomBytes(32))
      }

      const signatures = []
      const startEncrypt = Date.now()
      for (const d of randomData) {
        signatures.push([d, k.sign(d)])
      }
      const endEncrypt = Date.now()
      const deltaEncrypt = (endEncrypt - startEncrypt) / 1000
      console.log(`Finished encrypting in ${deltaEncrypt.toFixed(1)}s:\n${(nData / deltaEncrypt).toFixed(2)} block / s`)

      const verifications = []
      const startDecrypt = Date.now()
      for (const [d, signature] of signatures) {
        verifications.push(k.verify(d, signature))
      }
      const endDecrypt = Date.now()
      const deltaDecrypt = (endDecrypt - startDecrypt) / 1000
      console.log(`Finished decrypting in ${deltaDecrypt.toFixed(1)}s:\n${(nData / deltaDecrypt).toFixed(2)} block / s`)

      assert.strictEqual(verifications.length, nData)
      assert.isTrue(verifications.every(x => x === true))
    })

    it('Sign / verify async', async () => {
      const nData = 10

      const k = await PrivateKey_.generate(keySize)
      const randomData: Array<Buffer> = []

      for (let i = 0; i < nData; i++) {
        randomData.push(randomBytes(32))
      }

      const signatures = []
      const startSign = Date.now()
      for (const d of randomData) {
        signatures.push([d, await k.signAsync(d)])
      }
      const endSign = Date.now()
      const deltaSign = (endSign - startSign) / 1000
      console.log(`Finished signing in ${deltaSign.toFixed(1)}s:\n${(nData / deltaSign).toFixed(2)} block / s`)

      const verifications = []
      const startVerify = Date.now()
      for (const [d, signature] of signatures) {
        verifications.push(await k.verifyAsync(d, signature))
      }
      const endVerification = Date.now()
      const deltaVerification = (endVerification - startVerify) / 1000
      console.log(`Finished verifying in ${deltaVerification.toFixed(1)}s:\n${(nData / deltaVerification).toFixed(2)} block / s`)

      assert.strictEqual(verifications.length, nData)
      assert.isTrue(verifications.every(x => x === true))
    })
  })
}
