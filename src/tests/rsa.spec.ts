/* eslint-env mocha */

import { AsymKeySize, PrivateKey, PrivateKeyConstructor, PublicKey, PublicKeyConstructor } from '../utils/rsa'
import { TestHooks } from './specUtils.spec'
import assert from 'assert'

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
      assert.ok(_key1 instanceof PrivateKey_)
      assert.ok(_key2 instanceof PrivateKey_)
      assert.ok(_key1 instanceof PrivateKey)
      assert.ok(_key2 instanceof PrivateKey)
      assert.ok(_key1 instanceof PublicKey_)
      assert.ok(_key2 instanceof PublicKey_)
      assert.ok(_key1 instanceof PublicKey)
      assert.ok(_key2 instanceof PublicKey)
      privateKey = _key1
      privateKey2 = _key2

      assert.strictEqual(privateKey.keySize, keySize)
      assert.strictEqual(privateKey2.keySize, keySize)
    })

    it('Fail to construct a PublicKey because of an invalid type of argument', async () => {
      await assert.rejects(
        // @ts-expect-error
        PrivateKey_.generate('notAValidType'),
        /INVALID_ARG/
      )
    })

    it('fail to produce a new PrivateKey with a wrong size', async () => {
      await assert.rejects(
        // @ts-expect-error
        PrivateKey_.generate(588),
        /INVALID_ARG/
      )
    })

    it('fail to import bad PrivateKey', () => {
      assert.throws(
        () => PrivateKey_.fromB64(privateKey.toB64().slice(2)),
        /INVALID_KEY/
      )
    })

    it('fail to import PrivateKey because of an invalid type', () => {
      assert.throws(
        // @ts-expect-error
        () => new PrivateKey_(2),
        /INVALID_KEY/
      )
    })

    it('fail to import bad PublicKey', () => {
      assert.throws(
        () => PublicKey_.fromB64(privateKey.toB64({ publicOnly: true }).slice(0, -4)),
        /INVALID_KEY/
      )
    })

    it('export public key then import', () => {
      const publicKeyImported = PublicKey_.fromB64(privateKey.toB64({ publicOnly: true }))

      assert.strictEqual(publicKeyImported.toB64(), privateKey.toB64({ publicOnly: true }))
      assert.strictEqual(publicKeyImported.keySize, keySize)
    })

    it('export public key with toString then import', () => {
      const publicKeyImported = new PublicKey_(Buffer.from(privateKey.toString({ publicOnly: true }), 'binary'))

      assert.strictEqual(publicKeyImported.toString(), privateKey.toString({ publicOnly: true }))
      assert.strictEqual(publicKeyImported.keySize, keySize)
    })

    it('export the private key then import it', () => {
      const privateKeyImported = PrivateKey_.fromB64(privateKey.toB64())

      assert.strictEqual(privateKeyImported.toB64(), privateKey.toB64({ publicOnly: false }))
      assert.strictEqual(privateKeyImported.keySize, keySize)
    })

    it('export the private key with toString then import it', () => {
      const privateKeyImported = new PrivateKey_(Buffer.from(privateKey.toString(), 'binary'))

      assert.strictEqual(privateKeyImported.toString(), privateKey.toString({ publicOnly: false }))
      assert.strictEqual(privateKeyImported.keySize, keySize)
    })

    it('cipher & decipher sync', () => {
      const cipheredMessage = privateKey.encrypt(message)
      assert.ok(privateKey.decrypt(cipheredMessage).equals(message))
    })

    it('cipher & decipher async', async () => {
      const cipheredMessage = await privateKey.encryptAsync(message)
      assert.ok((await privateKey.decryptAsync(cipheredMessage)).equals(message))
    })

    it('cipher & decipher without CRC sync', () => {
      const cipheredMessage = privateKey.encrypt(message, false)
      assert.ok(privateKey.decrypt(cipheredMessage, false).equals(message))
    })

    it('cipher & decipher without CRC async', async () => {
      const cipheredMessage = await privateKey.encryptAsync(message, false)
      assert.ok((await privateKey.decryptAsync(cipheredMessage, false)).equals(message))
    })

    it('cipher & decipher with invalid CRC sync', () => {
      const cipheredMessage = privateKey.encrypt(message, false)
      assert.throws(
        () => privateKey.decrypt(cipheredMessage),
        /INVALID_CRC32/
      )
    })

    it('cipher & decipher with invalid CRC async', async () => {
      const cipheredMessage = await privateKey.encryptAsync(message, false)
      await assert.rejects(
        privateKey.decryptAsync(cipheredMessage),
        /INVALID_CRC32/
      )
    })

    it('cipher & decipher UTF8 sync', () => {
      const cipheredMessage = privateKey.encrypt(Buffer.from(messageUtf8, 'utf8'))
      const decipheredMessage = privateKey.decrypt(cipheredMessage).toString('utf8')
      assert.strictEqual(decipheredMessage, messageUtf8)
    })

    it('cipher & decipher UTF8 async', async () => {
      const cipheredMessage = await privateKey.encryptAsync(Buffer.from(messageUtf8, 'utf8'))
      const decipheredMessage = (await privateKey.decryptAsync(cipheredMessage)).toString('utf8')
      assert.strictEqual(decipheredMessage, messageUtf8)
    })

    it('cipher & decipher binary sync', () => {
      const cipheredMessage = privateKey.encrypt(messageBinary)
      assert.ok(privateKey.decrypt(cipheredMessage).equals(messageBinary))
    })

    it('cipher & decipher binary async', async () => {
      const cipheredMessage = await privateKey.encryptAsync(messageBinary)
      assert.ok((await privateKey.decryptAsync(cipheredMessage)).equals(messageBinary))
    })

    it('fail with bad key sync', async () => {
      const cipheredMessage = privateKey2.encrypt(message)
      assert.throws(
        () => privateKey.decrypt(cipheredMessage),
        /INVALID_CIPHER_TEXT/
      )
    })

    it('fail with bad key async', async () => {
      const cipheredMessage = await privateKey2.encryptAsync(message)
      await assert.rejects(
        privateKey.decryptAsync(cipheredMessage),
        /INVALID_CIPHER_TEXT/
      )
    })

    it('sign & verify sync', () => {
      const messageSignatureByPrivateKey = privateKey.sign(message)
      assert.strictEqual(privateKey.verify(message, messageSignatureByPrivateKey), true)
    })

    it('sign & verify async', async () => {
      const messageSignatureByPrivateKey = await privateKey.signAsync(message)
      assert.strictEqual(await privateKey.verifyAsync(message, messageSignatureByPrivateKey), true)
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
      assert.ok(message.equals(decipheredMessage1))

      const cipherText2 = privateKey_.encrypt(message)
      const decipheredMessage2 = privateKey.decrypt(cipherText2)
      assert.ok(message.equals(decipheredMessage2))

      const cipherText3 = publicKey_.encrypt(message)
      const decipheredMessage3 = privateKey.decrypt(cipherText3)
      assert.ok(message.equals(decipheredMessage3))

      const signature = privateKey.sign(message)
      assert.strictEqual(privateKey_.verify(message, signature), true)
      assert.strictEqual(publicKey_.verify(message, signature), true)

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
      assert.ok(message.equals(decipheredMessage1))

      const cipherText2 = await privateKey_.encryptAsync(message)
      const decipheredMessage2 = await privateKey.decryptAsync(cipherText2)
      assert.ok(message.equals(decipheredMessage2))

      const cipherText3 = await publicKey_.encryptAsync(message)
      const decipheredMessage3 = await privateKey.decryptAsync(cipherText3)
      assert.ok(message.equals(decipheredMessage3))

      const signature = await privateKey.signAsync(message)
      assert.strictEqual(await privateKey_.verifyAsync(message, signature), true)
      assert.strictEqual(await publicKey_.verifyAsync(message, signature), true)

      // equality
      assert.strictEqual(privateKey.toB64(), privateKey_.toB64())
      assert.strictEqual(privateKey.toB64({ publicOnly: true }), publicKey_.toB64({ publicOnly: true }))
      assert.strictEqual(privateKey.toB64({ publicOnly: true }), privateKey_.toB64({ publicOnly: true }))

      assert.strictEqual(privateKey.getHash(), privateKey_.getHash())
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
      assert.ok(decryptedData.every((d, i) => d.equals(randomData[i])))
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
      assert.ok(decryptedData.every((d, i) => d.equals(randomData[i])))
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
      assert.ok(verifications.every(x => x === true))
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
      assert.ok(verifications.every(x => x === true))
    })
  })
}
