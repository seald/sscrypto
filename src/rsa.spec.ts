/* eslint-env mocha */

import { PrivateKey as PrivateKeyForge, PublicKey as PublicKeyForge } from './rsa-forge'
import { PrivateKey as PrivateKeyNode, PublicKey as PublicKeyNode } from './rsa-node'
import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import * as crypto from 'crypto'
import { PrivateKey, PrivateKeyConstructor, PublicKeyConstructor } from './rsa' // eslint-disable-line no-unused-vars

chai.use(chaiAsPromised)
const { assert, expect } = chai

const testAsymKeyImplem = (name: string, { PrivateKey, PublicKey }: { PrivateKey: PrivateKeyConstructor, PublicKey: PublicKeyConstructor }) => {
  describe(`RSA ${name}`, () => {
    let privateKey: PrivateKey, privateKey2: PrivateKey

    before('generate keys', () =>
      Promise.all([
        PrivateKey.generate(1024),
        PrivateKey.generate(1024)
      ])
        .then(([_key1, _key2]) => {
          privateKey = _key1
          privateKey2 = _key2
        })
    )

    const message = Buffer.from('TESTtest', 'ascii')
    const messageUtf8 = 'Iñtërnâtiônàlizætiøn\u2603\uD83D\uDCA9'
    const messageBinary = crypto.randomBytes(32)

    it('Fail to construct a PublicKey because of an invalid type of argument', () => {
      // @ts-ignore: voluntary test of what happens with bad type
      expect(PrivateKey.generate('notAValidType')).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_ARG')
        return true
      })
    })

    it('fail to produce a new PrivateKey with a wrong size', () => {
      // @ts-ignore: voluntary test of what happens with bad type
      expect(PrivateKey.generate(588)).to.be.rejectedWith(Error).and.eventually.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_ARG')
        return true
      })
    })

    it('fail to import bad PrivateKey', () => {
      expect(() => PrivateKey.fromB64(privateKey.toB64().slice(2))).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_KEY')
        return true
      })
    })

    it('fail to import PrivateKey because of an invalid type', () => {
      // @ts-ignore: voluntary test of what happens with bad type
      expect(() => new PrivateKey(2)).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_KEY')
        return true
      })
    })

    it('fail to import bad PublicKey', () => {
      expect(() => PublicKey.fromB64(privateKey.toB64({ publicOnly: true }).slice(0, -2))).to.throw(Error).and.satisfy((error: Error) => {
        assert.include(error.message, 'INVALID_KEY')
        return true
      })
    })

    it('export public key then import', () => {
      const publicKeyImported = PublicKey.fromB64(privateKey.toB64({ publicOnly: true }))

      assert.strictEqual(publicKeyImported.toB64(), privateKey.toB64({ publicOnly: true }))
    })

    it('export the private key then import it', () => {
      const privateKeyImported = PrivateKey.fromB64(privateKey.toB64())

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
testAsymKeyImplem('node', { PrivateKey: PrivateKeyNode, PublicKey: PublicKeyNode })
testAsymKeyImplem('forge', { PrivateKey: PrivateKeyForge, PublicKey: PublicKeyForge })

describe('RSA node/forge', () => {
  let privateKeyNode: PrivateKeyNode, privateKeyForge: PrivateKeyForge

  before('generate keys', () =>
    Promise.all([
      PrivateKeyNode.generate(1024),
      PrivateKeyForge.generate(1024)
    ])
      .then(([_key1, _key2]) => {
        privateKeyNode = _key1
        privateKeyForge = _key2
      })
  )

  const message = Buffer.from('TESTtest', 'ascii')

  it('export node & import forge, encrypt & sign', () => {
    const privateKeyB64 = privateKeyNode.toB64()
    const privateKey_ = PrivateKeyForge.fromB64(privateKeyB64)

    const cipherText = privateKeyNode.encrypt(message)
    const decipheredMessage = privateKey_.decrypt(cipherText)
    assert.isTrue(message.equals(decipheredMessage))

    const signature = privateKeyNode.sign(message)
    assert.isTrue(privateKey_.verify(message, signature))
  })

  it('export forge & import node, encrypt & sign', () => {
    const privateKeyB64 = privateKeyForge.toB64()
    const privateKey_ = PrivateKeyNode.fromB64(privateKeyB64)

    const cipherText = privateKeyForge.encrypt(message)
    const decipheredMessage = privateKey_.decrypt(cipherText)
    assert.isTrue(message.equals(decipheredMessage))

    const signature = privateKeyForge.sign(message)
    assert.isTrue(privateKey_.verify(message, signature))
  })
})
