import forge from 'node-forge'
import { promisify } from 'util'

declare global {
  interface Window {
    SSCRYPTO_NO_WEBCRYPTO?: boolean
  }
}

const engines = [ // The order of these tests is important, hence the array
  { name: 'EdgeHTML', rgx: /windows.+\sedge\/([\w.]+)/i }, // EdgeHTML
  { name: 'Blink', rgx: /webkit\/537\.36.+chrome\/(?!27)([\w.]+)/i }, // Blink
  { name: 'WebKit', rgx: /webkit\/([\w.]+)/i }, // WebKit
  { name: 'Trident', rgx: /trident\/([\w.]+)/i }, // Trident
  { name: 'Gecko', rgx: /rv:([\w.]{1,9}).+(gecko)/i } // Gecko
]

const getEngine_ = () : string => {
  const ua = window.navigator.userAgent
  for (const engine of engines) {
    if (engine.rgx.test(ua)) return engine.name
  }
  return 'other'
}

let engineCache : string = null

export const getEngine = () : string => {
  if (engineCache) return engineCache
  engineCache = getEngine_()
  return engineCache
}

export const isWebCryptoAvailable = (): boolean => window.crypto && window.crypto.subtle && !window.SSCRYPTO_NO_WEBCRYPTO

/**
 * Returns a Buffer containing the hash of the given data
 * @param {Buffer} data
 * @return {Buffer}
 */
export const sha256 = (data: Buffer): Buffer => {
  const md = forge.md.sha256.create()
  md.update(data.toString('binary'))
  return Buffer.from(md.digest().data, 'binary')
}

/**
 * Returns a Buffer of random bytes
 * @param {number} [length=10]
 * @return {Buffer}
 */
export const randomBytesSync = (length = 10): Buffer => {
  if (length === 0) {
    return Buffer.alloc(0) // workaround for some dumb browsers that really don't like crypto.getRandomValues with length 0
  } else if (isWebCryptoAvailable()) {
    return Buffer.from(window.crypto.getRandomValues(new Uint8Array(length)))
  } else {
    return Buffer.from(forge.random.getBytesSync(length), 'binary')
  }
}

/**
 * Returns a Buffer of random bytes
 * @param {number} [length=10]
 * @return {Promise<Buffer>}
 */
export const randomBytes = async (length = 10): Promise<Buffer> => {
  if (length === 0) {
    return Buffer.alloc(0) // workaround for some dumb browsers that really don't like crypto.getRandomValues with length 0
  } else if (isWebCryptoAvailable()) {
    return Buffer.from(window.crypto.getRandomValues(new Uint8Array(length)))
  } else {
    return Buffer.from(await promisify(forge.random.getBytes)(length), 'binary')
  }
}
