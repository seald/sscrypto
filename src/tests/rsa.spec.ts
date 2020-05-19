/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { AsymKeySize, PrivateKeyInterface, PrivateKeyConstructor, PublicKeyConstructor, PublicKey } from '../utils/rsa'
import { TestHooks } from './specUtils.spec'

chai.use(chaiAsPromised)
const { assert, expect } = chai

type AsymKeyImplem = { PrivateKey: PrivateKeyConstructor<PrivateKeyInterface>, PublicKey: PublicKeyConstructor<PublicKey> }

export const testAsymKeyImplem = (name: string, { PrivateKey: PrivateKey_, PublicKey: PublicKey_ }: AsymKeyImplem, randomBytes: (size: number) => Buffer, { duringBefore, duringAfter }: TestHooks = {}): void => {
  describe(`RSA ${name}`, function () {
    this.timeout(5000)

    let privateKey: PrivateKeyInterface, privateKey2: PrivateKeyInterface

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

    it('Fail to construct a PublicKey because of an invalid type of argument', () =>
      expect(
        PrivateKey_
        // @ts-ignore: voluntary test of what happens with bad type
          .generate('notAValidType')
      ).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_ARG')
        return true
      })
    )

    it('fail to produce a new PrivateKey with a wrong size', () =>
      expect(
        PrivateKey_
        // @ts-ignore: voluntary test of what happens with bad type
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

    it('cipher & decipher sync', () => {
      const cipheredMessage = privateKey.encryptSync(message)
      assert.isTrue((privateKey.decryptSync(cipheredMessage)).equals(message), 'Message cannot be deciphered')
    })

    it('cipher & decipher async', async () => {
      const cipheredMessage = await privateKey.encrypt(message)
      assert.isTrue((await privateKey.decrypt(cipheredMessage)).equals(message), 'Message cannot be deciphered')
    })

    it('cipher & decipher without CRC sync', () => {
      const cipheredMessage = privateKey.encryptSync(message, false)
      assert.isTrue((privateKey.decryptSync(cipheredMessage, false)).equals(message), 'Message cannot be deciphered')
    })

    it('cipher & decipher without CRC async', async () => {
      const cipheredMessage = await privateKey.encrypt(message, false)
      assert.isTrue((await privateKey.decrypt(cipheredMessage, false)).equals(message), 'Message cannot be deciphered')
    })

    it('cipher & decipher with invalid CRC sync', () => {
      const cipheredMessage = privateKey.encryptSync(message, false)
      return expect(() => privateKey.decryptSync(cipheredMessage)).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_CRC32')
        return true
      })
    })

    it('cipher & decipher with invalid CRC async', async () => {
      const cipheredMessage = await privateKey.encrypt(message, false)
      return expect(privateKey.decrypt(cipheredMessage)).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_CRC32')
        return true
      })
    })

    it('cipher & decipher UTF8 sync', () => {
      const cipheredMessage = privateKey.encryptSync(Buffer.from(messageUtf8, 'utf8'))
      const decipheredMessage = privateKey.decryptSync(cipheredMessage).toString('utf8')
      assert.strictEqual(decipheredMessage, messageUtf8, 'Message cannot be deciphered')
    })

    it('cipher & decipher UTF8 async', async () => {
      const cipheredMessage = await privateKey.encrypt(Buffer.from(messageUtf8, 'utf8'))
      const decipheredMessage = (await privateKey.decrypt(cipheredMessage)).toString('utf8')
      assert.strictEqual(decipheredMessage, messageUtf8, 'Message cannot be deciphered')
    })

    it('cipher & decipher binary sync', () => {
      const cipheredMessage = privateKey.encryptSync(messageBinary)
      assert.isTrue(privateKey.decryptSync(cipheredMessage).equals(messageBinary), 'Message cannot be deciphered')
    })

    it('cipher & decipher binary async', async () => {
      const cipheredMessage = await privateKey.encrypt(messageBinary)
      assert.isTrue((await privateKey.decrypt(cipheredMessage)).equals(messageBinary), 'Message cannot be deciphered')
    })

    it('fail with bad key sync', async () => {
      const cipheredMessage = privateKey2.encryptSync(message)
      return expect(() => privateKey.decryptSync(cipheredMessage)).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_CIPHER_TEXT')
        return true
      })
    })

    it('fail with bad key async', async () => {
      const cipheredMessage = await privateKey2.encrypt(message)
      return expect(privateKey.decrypt(cipheredMessage)).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_CIPHER_TEXT')
        return true
      })
    })

    it('sign & verify sync', () => {
      const messageSignatureByPrivateKey = privateKey.signSync(message)
      assert(privateKey.verifySync(message, messageSignatureByPrivateKey), 'Signature doesn\'t match')
    })

    it('sign & verify async', async () => {
      const messageSignatureByPrivateKey = await privateKey.sign(message)
      assert(await privateKey.verify(message, messageSignatureByPrivateKey), 'Signature doesn\'t match')
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

    let privateKey1: PrivateKeyInterface

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
      const cipherText1 = privateKey.encryptSync(message)
      const decipheredMessage1 = privateKey_.decryptSync(cipherText1)
      assert.isTrue(message.equals(decipheredMessage1))

      const cipherText2 = privateKey_.encryptSync(message)
      const decipheredMessage2 = privateKey.decryptSync(cipherText2)
      assert.isTrue(message.equals(decipheredMessage2))

      const cipherText3 = publicKey_.encryptSync(message)
      const decipheredMessage3 = privateKey.decryptSync(cipherText3)
      assert.isTrue(message.equals(decipheredMessage3))

      const signature = privateKey.signSync(message)
      assert.isTrue(privateKey_.verifySync(message, signature))
      assert.isTrue(publicKey_.verifySync(message, signature))

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
      const cipherText1 = await privateKey.encrypt(message)
      const decipheredMessage1 = await privateKey_.decrypt(cipherText1)
      assert.isTrue(message.equals(decipheredMessage1))

      const cipherText2 = await privateKey_.encrypt(message)
      const decipheredMessage2 = await privateKey.decrypt(cipherText2)
      assert.isTrue(message.equals(decipheredMessage2))

      const cipherText3 = await publicKey_.encrypt(message)
      const decipheredMessage3 = await privateKey.decrypt(cipherText3)
      assert.isTrue(message.equals(decipheredMessage3))

      const signature = await privateKey.sign(message)
      assert.isTrue(await privateKey_.verify(message, signature))
      assert.isTrue(await publicKey_.verify(message, signature))

      // equality
      assert.strictEqual(privateKey.toB64(), privateKey_.toB64())
      assert.strictEqual(privateKey.toB64({ publicOnly: true }), publicKey_.toB64({ publicOnly: true }))
      assert.strictEqual(privateKey.toB64({ publicOnly: true }), privateKey_.toB64({ publicOnly: true }))

      assert.strictEqual(await privateKey.getHash(), await privateKey_.getHash())
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
        encryptedData.push(k.encryptSync(d))
      }
      const endEncrypt = Date.now()
      const deltaEncrypt = (endEncrypt - startEncrypt) / 1000
      console.log(`Finished encrypting in ${deltaEncrypt.toFixed(1)}s:\n${(nData / deltaEncrypt).toFixed(2)} block / s`)

      const decryptedData = []
      const startDecrypt = Date.now()
      for (const d of encryptedData) {
        decryptedData.push(k.decryptSync(d))
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
        encryptedData.push(await k.encrypt(d))
      }
      const endEncrypt = Date.now()
      const deltaEncrypt = (endEncrypt - startEncrypt) / 1000
      console.log(`Finished encrypting in ${deltaEncrypt.toFixed(1)}s:\n${(nData / deltaEncrypt).toFixed(2)} block / s`)

      const decryptedData = []
      const startDecrypt = Date.now()
      for (const d of encryptedData) {
        decryptedData.push(await k.decrypt(d))
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
        signatures.push([d, k.signSync(d)])
      }
      const endEncrypt = Date.now()
      const deltaEncrypt = (endEncrypt - startEncrypt) / 1000
      console.log(`Finished encrypting in ${deltaEncrypt.toFixed(1)}s:\n${(nData / deltaEncrypt).toFixed(2)} block / s`)

      const verifications = []
      const startDecrypt = Date.now()
      for (const [d, signature] of signatures) {
        verifications.push(k.verifySync(d, signature))
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
        signatures.push([d, await k.sign(d)])
      }
      const endSign = Date.now()
      const deltaSign = (endSign - startSign) / 1000
      console.log(`Finished signing in ${deltaSign.toFixed(1)}s:\n${(nData / deltaSign).toFixed(2)} block / s`)

      const verifications = []
      const startVerify = Date.now()
      for (const [d, signature] of signatures) {
        verifications.push(await k.verify(d, signature))
      }
      const endVerification = Date.now()
      const deltaVerification = (endVerification - startVerify) / 1000
      console.log(`Finished verifying in ${deltaVerification.toFixed(1)}s:\n${(nData / deltaVerification).toFixed(2)} block / s`)

      assert.strictEqual(verifications.length, nData)
      assert.isTrue(verifications.every(x => x === true))
    })
  })
}
