## v1.0.1

- \[enhancement\] Exporting type for SSCrypto implementation
- \[enhancement\] Update documentation


## v1.0.0

- \[enhancement\] Massive rewrite.
- \[new feature\] Creating a new SymKey should be done through `SymKey.generate(size)`. Using `new SymKey(size)` is deprecated.
- \[new feature\] There are now both sync and async versions of functions.
- \[new feature\] (Async only) Asym encryption/decryption with actual WebCrypto: much faster.
- \[enhancement\] Compatibility with Edge 1x and Safari


## v0.4.2

- Update dependencies
- Remove useless test files in exported package


## v0.4.1

- Fix webcrypto encryptStream with small chunks


## v0.4.0

- Implement initial sscrypto/webcrypto. For now, it uses actual webcrypto for generating randomness, for generating AsymKeys, and for SymKey's encryptStream & decryptStream. For everything else, or if webcrypto is unavailable, it falls back to forge.


## v0.3.1

- Update dependencies
- Minor change of import style to avoid deprecation warnings


## v0.3.0

- Go with Forge's way of serializing publicKeys for legacy purposes


## v0.2.0

- Add util functions for sha256 and randomBytes
- Fix a bug that caused the Forge and Node implementations to have different serializations of publicKeys
- remove getB64hash() PublicKey method, and change the behaviour of getHash()


## v0.1.1

- Update dependencies
- Put forge as a peerDependency


## v0.1.0

- Initial version
