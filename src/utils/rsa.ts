export type AsymKeySize = 4096 | 2048 | 1024

export interface PublicKeyConstructor {
  new (key: Buffer): PublicKey

  fromB64 (b64DERFormattedPublicKey: string): PublicKey
}

export interface PublicKey {
  toB64 (options?: {}): string

  encryptSync (clearText: Buffer, doCRC?: boolean): Buffer

  encrypt (clearText: Buffer, doCRC?: boolean): Promise<Buffer>

  verifySync (textToCheckAgainst: Buffer, signature: Buffer): boolean

  verify (textToCheckAgainst: Buffer, signature: Buffer): Promise<boolean>

  getHashSync (): string

  getHash (): Promise<string>
}

export interface PrivateKeyConstructor extends PublicKeyConstructor {
  new (key: Buffer): PrivateKey

  fromB64 (b64DERFormattedPrivateKey: string): PrivateKey

  generate (size: AsymKeySize): Promise<PrivateKey>
}

export interface PrivateKey extends PublicKey {
  toB64 (options?: { publicOnly: boolean }): string

  decryptSync (cipherText: Buffer, doCRC?: boolean): Buffer

  decrypt (cipherText: Buffer, doCRC?: boolean): Promise<Buffer>

  signSync (textToSign: Buffer): Buffer

  sign (textToSign: Buffer): Promise<Buffer>
}
