/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { TestHooks } from './specUtils.spec'

chai.use(chaiAsPromised)
const { assert } = chai

const knownHashes: { [key: string]: string } = {
  test: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
  test2: '60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752',
  testTEST: '3a16f0fd02b75b2607d5157a73dab35453dbeb02cdca2d50b73392503e56c6dc'
}

type utils = {
  sha256: (data: Buffer) => Buffer
  randomBytesSync: (length: number) => Buffer
  randomBytes: (length: number) => Promise<Buffer>
}

export const testUtilsImplem = (name: string, { sha256, randomBytesSync, randomBytes }: utils, { duringBefore, duringAfter }: TestHooks = {}): void => {
  describe(`Utils ${name}`, () => {
    before(() => {
      if (duringBefore) duringBefore()
    })

    after(() => {
      if (duringAfter) duringAfter()
    })

    it('sha256', () => {
      for (const val in knownHashes) {
        const hash = sha256(Buffer.from(val, 'binary')).toString('hex')
        assert.strictEqual(hash, knownHashes[val])
      }
    })

    it('randomBytes sync', () => {
      for (let i = 0; i < 1000; i++) {
        const rand = randomBytesSync(i)
        const rand2 = randomBytesSync(i)
        assert.notStrictEqual(rand, rand2)
        assert.strictEqual(rand.length, i)
        assert.strictEqual(rand2.length, i)
      }
    })

    it('randomBytes', async () => {
      for (let i = 0; i < 1000; i++) {
        const rand = await randomBytes(i)
        const rand2 = await randomBytes(i)
        assert.notStrictEqual(rand, rand2)
        assert.strictEqual(rand.length, i)
        assert.strictEqual(rand2.length, i)
      }
    })
  })
}

export const testUtilsCompatibility = (name: string, utils1: utils, utils2: utils) => {
  describe(`Utils compatibility ${name}`, () => {
    it('sha256 & randomBytes', () => {
      const rand1 = utils1.randomBytesSync(1000)
      const rand2 = utils2.randomBytesSync(1000)

      const sha11 = utils1.sha256(rand1)
      const sha12 = utils1.sha256(rand2)
      const sha21 = utils2.sha256(rand1)
      const sha22 = utils2.sha256(rand2)

      assert.isOk(sha21.equals(sha11))
      assert.isOk(sha22.equals(sha12))
    })
  })
}
