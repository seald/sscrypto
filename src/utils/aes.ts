import { Transform } from 'stream'

export type SymKeySize = 128 | 192 | 256

export interface SymKeyConstructor {
  new (key: Buffer): SymKey

  fromString (messageKey: string): SymKey

  fromB64 (messageKey: string): SymKey

  generate (size: SymKeySize): Promise<SymKey>
}

export interface SymKey {
  readonly keySize: number

  toB64 (): string

  toString (): string

  calculateHMAC_ (textToAuthenticate: Buffer): Promise<Buffer>

  calculateHMACSync_ (textToAuthenticate: Buffer): Buffer

  rawEncrypt_ (clearText: Buffer, iv: Buffer): Promise<Buffer>

  encrypt (clearText: Buffer): Promise<Buffer>

  rawEncryptSync_ (clearText: Buffer, iv: Buffer): Buffer

  encryptSync (clearText: Buffer): Buffer

  encryptStream (): Transform

  rawDecrypt_ (cipheredMessage: Buffer, iv: Buffer): Promise<Buffer>

  decrypt (cipheredMessage: Buffer): Promise<Buffer>

  rawDecryptSync_ (cipheredMessage: Buffer, iv: Buffer): Buffer

  decryptSync (cipheredMessage: Buffer): Buffer

  decryptStream (): Transform
}
