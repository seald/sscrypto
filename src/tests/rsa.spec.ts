/* eslint-env mocha */

import { PrivateKey as PrivateKeyForge, PublicKey as PublicKeyForge } from '../forge'
import { PrivateKey as PrivateKeyNode, PublicKey as PublicKeyNode } from '../node'
import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import * as crypto from 'crypto'
import { PrivateKey, PrivateKeyConstructor, PublicKeyConstructor } from '../utils/rsa'
import { forge, node } from '../index'

chai.use(chaiAsPromised)
const { assert, expect } = chai

const testAsymKeyImplem = (name: string, { PrivateKey: PrivateKey_, PublicKey: PublicKey_ }: { PrivateKey: PrivateKeyConstructor, PublicKey: PublicKeyConstructor }): void => {
  describe(`RSA ${name}`, () => {
    let privateKey: PrivateKey, privateKey2: PrivateKey

    before('generate keys', () =>
      Promise.all([
        PrivateKey_.generate(1024),
        PrivateKey_.generate(1024)
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

  it('packaging', () => {
    assert.strictEqual(node.PublicKey, PublicKeyNode)
    assert.strictEqual(node.PrivateKey, PrivateKeyNode)
    assert.strictEqual(forge.PublicKey, PublicKeyForge)
    assert.strictEqual(forge.PrivateKey, PrivateKeyForge)
  })

  it('export node & import forge, hash, encrypt & sign', () => {
    const privateKey = privateKeyNode
    const privateKey_ = PrivateKeyForge.fromB64(privateKey.toB64())
    const publicKey_ = PublicKeyForge.fromB64(privateKey.toB64({ publicOnly: true }))

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
    assert.strictEqual(privateKey.getB64Hash(), privateKey_.getB64Hash())
  })

  it('export forge & import node, hash encrypt & sign', () => {
    const privateKey = privateKeyForge
    const privateKey_ = PrivateKeyNode.fromB64(privateKey.toB64())
    const publicKey_ = PublicKeyNode.fromB64(privateKey.toB64({ publicOnly: true }))

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
    assert.strictEqual(privateKey.getB64Hash(), privateKey_.getB64Hash())
  })
})
