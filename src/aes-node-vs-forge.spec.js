/* global describe, it */

import * as crypto from 'crypto'
import { SymKey as SymKeyNode } from './aes-node'
import { SymKey as SymKeyForge } from './aes-forge'
import multipipe from 'multipipe'
import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { _streamHelper, splitLength } from './specUtils.spec'

chai.use(chaiAsPromised)
const { assert } = chai

describe('Crypto - Unit - AES node/forge', () => {
  const keyNode = new SymKeyNode(256)
  const keyForge = SymKeyForge.fromString(Buffer.from(keyNode.toB64(), 'base64').toString('binary'))

  const message = Buffer.from('TESTtest')

  it('cipher forge & decipher node', () => {
    const cipheredMessage = keyNode.encrypt(message)
    const decipheredMessage = Buffer.from(keyForge.decrypt(cipheredMessage.toString('binary')), 'binary')
    assert.isTrue(message.equals(decipheredMessage))
  })

  it('cipher forge & decipher node', () => {
    const cipheredMessage = Buffer.from(keyForge.encrypt(message.toString('binary')), 'binary')
    const decipheredMessage = keyNode.decrypt(cipheredMessage)
    assert.isTrue(message.equals(decipheredMessage))
  })

  it('cipher stream node & decipher stream forge', () => {
    const input = crypto.randomBytes(100)
    const chunks = splitLength(input, 20)

    const cipher = keyNode.encryptStream()
    const decipher = keyForge.decryptStream()

    return _streamHelper(chunks, multipipe(cipher, decipher))
      .then(output => {
        assert.isTrue(output.equals(input))
      })
  })

  it('cipher stream forge & decipher stream node', () => {
    const input = crypto.randomBytes(100)
    const chunks = splitLength(input, 20)

    const cipher = keyForge.encryptStream()
    const decipher = keyNode.decryptStream()

    return _streamHelper(chunks, multipipe(cipher, decipher))
      .then(output => {
        assert.isTrue(output.equals(input))
      })
  })
})
