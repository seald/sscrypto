import { Transform } from 'stream' // eslint-disable-line no-unused-vars

export type SymKeySize = 128 | 192 | 256

export interface SymKeyConstructor {
  new (arg: SymKeySize | Buffer): SymKey

  fromString (messageKey: string): SymKey

  fromB64 (messageKey: string): SymKey
}

export interface SymKey {
  readonly keySize: number

  toB64 (): string

  toString (): string

  calculateHMAC (textToAuthenticate: Buffer): Buffer

  encrypt (clearText: Buffer): Buffer

  encryptStream (): Transform

  decrypt (cipheredMessage: Buffer): Buffer

  decryptStream (): Transform
}
