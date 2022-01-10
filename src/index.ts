import * as node from './node'
import * as forge from './forge'
import * as webcrypto from './webcrypto'
import { SymKey, SymKeyConstructor } from './utils/aes'
import { PrivateKey, PrivateKeyConstructor, PublicKey, PublicKeyConstructor } from './utils/rsa'

export type Utils = {
  sha256: (data: Buffer) => Buffer
  randomBytes: (length: number) => Buffer
  randomBytesAsync: (length: number) => Promise<Buffer>
}

export type SSCrypto = {
  utils: Utils
  SymKey: SymKeyConstructor<SymKey>
  PublicKey: PublicKeyConstructor<PublicKey>
  PrivateKey: PrivateKeyConstructor<PrivateKey>
}

export {
  node,
  forge,
  webcrypto,
  SymKey,
  PrivateKey,
  PublicKey
}
