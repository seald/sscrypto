export type AsymKeySize = 4096 | 2048 | 1024

export interface PublicKeyConstructor {
  new (key: Buffer): PublicKey

  fromB64 (b64DERFormattedPublicKey: string): PublicKey
}

export interface PublicKey {
  toB64 (options?: {}): string

  encrypt (clearText: Buffer, doCRC?: boolean): Buffer

  verify (textToCheckAgainst: Buffer, signature: Buffer): boolean

  getHash (): string

  getB64Hash (): string
}

export interface PrivateKeyConstructor extends PublicKeyConstructor {
  new (key: Buffer): PrivateKey

  fromB64 (b64DERFormattedPrivateKey: string): PrivateKey

  generate (size: AsymKeySize): Promise<PrivateKey>
}

export interface PrivateKey extends PublicKey {
  toB64 (options?: { publicOnly: boolean }): string

  decrypt (cipherText: Buffer, doCRC?: boolean): Buffer

  sign (textToSign: Buffer): Buffer
}
