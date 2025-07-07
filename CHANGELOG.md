## v1.4.0 - 2025/07/07
- \[enhancement\] Correctly handle `encryptStream.destroy(error)` and `decryptStream.destroy(error)` functions.
- \[deprecation\] Deprecate `encryptStream.emit('cancel')'` and `decryptStream.emit('cancel')` in favor of `stream.destroy()`
- \[enhancement\] Update dependencies


## v1.3.0 - 2025/03/20
- \[new feature\] Expose keySize for AsymKeys
- \[enhancement\] Update dependencies


## v1.2.0 - 2024/10/28
- \[bug fix\] Cleaner node crypto imports to fix use with some bundlers
- \[enhancement\] Stop using deprecated Buffer.slice
- \[enhancement\] Update dependencies


## v1.1.1 - 2022/06/21
- \[enhancement\] Update dependencies
- \[bug fix\] Fix import in certain typescript environments


## v1.1.0 -  2022/01/12
- \[enhancement\] Update dependencies
- \[enhancement\] Exporting types for key instances
- \[bug fix\] Fix `encryptStream` & `decryptStream` in node@16 for large chunks


## v1.0.1 / v1.0.2 - 2020/09/28

- \[enhancement\] Exporting type for SSCrypto implementation
- \[enhancement\] Update documentation


## v1.0.0 - 2020/07/03

- \[enhancement\] Massive rewrite.
- \[new feature\] Creating a new SymKey should be done through `SymKey.generate(size)`. Using `new SymKey(size)` is deprecated.
- \[new feature\] There are now both sync and async versions of functions.
- \[new feature\] (Async only) Asym encryption/decryption with actual WebCrypto: much faster.
- \[enhancement\] Compatibility with Edge 1x and Safari


## v0.4.2 - 2020/04/15

- Update dependencies
- Remove useless test files in exported package


## v0.4.1 - 2019/11/18

- Fix webcrypto encryptStream with small chunks


## v0.4.0 - 2019/10/08

- Implement initial sscrypto/webcrypto. For now, it uses actual webcrypto for generating randomness, for generating AsymKeys, and for SymKey's encryptStream & decryptStream. For everything else, or if webcrypto is unavailable, it falls back to forge.


## v0.3.1 - 2019/09/12

- Update dependencies
- Minor change of import style to avoid deprecation warnings


## v0.3.0 - 2019/02/25

- Go with Forge's way of serializing publicKeys for legacy purposes


## v0.2.0 - 2019/02/25

- Add util functions for sha256 and randomBytes
- Fix a bug that caused the Forge and Node implementations to have different serializations of publicKeys
- remove getB64hash() PublicKey method, and change the behaviour of getHash()


## v0.1.1 - 2019/02/21

- Update dependencies
- Put forge as a peerDependency


## v0.1.0 - 2019/01/29

- Initial version
