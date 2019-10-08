SSCrypto
==========

[![npm version](https://img.shields.io/npm/v/sscrypto.svg)](https://www.npmjs.com/package/sscrypto)

_Super-Simple Crypto_ is a wrapper around other cryptography libraries, intended to be simple to use, provide a consistent interface for multiple encryption backends (for now, forge, nodeJS [`crypto`](https://nodejs.org/api/crypto.html), and [WebCrypto.subtle](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)), and well-chosen parameters.

It was created by [Seald](https://www.seald.io/) to unify crypto accross its projects.

# Table of Contents

[Installation](#installation)  

**API:**
- [SymKey](#symkey)
  
  * [constructor](#symkey-constructor)

  * Properties
    * [encryptionKey](#symkey-encryptionkey)
    * [keySize](#symkey-keysize)
    * [signingKey](#symkey-signingkey)

  * Methods
    * [calculateHMAC](#symkey-calculatehmac)
    * [decrypt](#symkey-decrypt)
    * [decryptStream](#symkey-decryptstream)
    * [encrypt](#symkey-encrypt)
    * [encryptStream](#symkey-encryptstream)
    * [toB64](#symkey-tob64)
    * [toString](#symkey-tostring)
    * [fromB64](#symkey-fromb64)
    * [fromString](#symkey-fromstring)

- [PublicKey](#publickey)
  
  * [constructor](#publickey-constructor)
  
  * Properties
    * [publicKey](#publickey-publickey)
  
  * Methods
    * [encrypt](#publickey-encrypt)
    * [getB64Hash](#publickey-getb64hash)
    * [getHash](#publickey-gethash)
    * [toB64](#publickey-tob64)
    * [verify](#publickey-verify)
    * [fromB64](#publickey-fromb64)
  
- [PrivateKey](#privatekey)

  * [constructor](#privatekey-constructor)

  * Properties
    * [privateKey](#privatekey-privatekey)
    * [publicKey](#privatekey-publickey)

  * Methods
    * [decrypt](#privatekey-decrypt)
    * [encrypt](#privatekey-encrypt)
    * [getB64Hash](#privatekey-getb64hash)
    * [getHash](#privatekey-gethash)
    * [sign](#privatekey-sign)
    * [toB64](#privatekey-tob64)
    * [verify](#privatekey-verify)
    * [fromB64](#privatekey-fromb64)
    * [generate](#privatekey-generate)

- [Utils](#utils)

  * [randomBytes](#randombytes)
  * [sha256](#sha256)


# Installation

### For use with the nodeJS back-end:

```bash
npm i -S sscrypto
```
```javascript
// ES Module syntax
import { node } from 'sscrypto' // this may cause trouble if you do not have forge installed and are not using a build-system with tree-shaking
// or
import { SymKey, PrivateKey, PublicKey } from 'sscrypto/node'
// or
import SymKey from 'sscrypto/node/aes'
import { PrivateKey, PublicKey } from 'sscrypto/node/rsa'

// CommonJS syntax
const { node } = require('sscrypto') // this may cause trouble if you do not have forge installed and are not using a build-system with tree-shaking
// or
const { SymKey, PrivateKey, PublicKey } = require('sscrypto/node')
// or
const SymKey = require('sscrypto/node/aes')
const { PrivateKey, PublicKey } = require('sscrypto/node/rsa')
```

### For use with the forge back-end:

```bash
npm i -S sscrypto node-forge
```
```javascript
// ES Module syntax
import { forge } from 'sscrypto'
// or
import { SymKey, PrivateKey, PublicKey, utils } from 'sscrypto/forge'
// or
import SymKey from 'sscrypto/forge/aes'
import { PrivateKey, PublicKey } from 'sscrypto/forge/rsa'

// CommonJS syntax
const { forge } = require('sscrypto')
// or
const { SymKey, PrivateKey, PublicKey, utils } = require('sscrypto/forge')
// or
const SymKey = require('sscrypto/forge/aes')
const { PrivateKey, PublicKey } = require('sscrypto/forge/rsa')
```

### For use with the WebCrypto back-end:

To use the WebCrypto back-end, you still need to install forge, because it falls back to forge for unimplemented features & when the browser is not compatible with WebCrypto.

Of course, the WebCrypto back-end only works in browsers. You will have to use a build system to package everything, and provide the relevant NodeJS polyfills (such as Buffer). Using Webpack works well.

```bash
npm i -S sscrypto node-forge
```
```javascript
// ES Module syntax
import { webcrypto } from 'sscrypto'
// or
import { SymKey, PrivateKey, PublicKey, utils } from 'sscrypto/webcrypto'
// or
import SymKey from 'sscrypto/webcrypto/aes'
import { PrivateKey, PublicKey } from 'sscrypto/webcrypto/rsa'

// CommonJS syntax
const { webcrypto } = require('sscrypto')
// or
const { SymKey, PrivateKey, PublicKey, utils } = require('sscrypto/webcrypto')
// or
const SymKey = require('sscrypto/webcrypto/aes')
const { PrivateKey, PublicKey } = require('sscrypto/webcrypto/rsa')
```

<a id="symkey"></a>

# Class: SymKey

<a id="symkey-constructor"></a>

## Constructor

⊕ **new SymKey**(arg?: *[SymKeySize](#symkeysize) \| `Buffer`*): [SymKey](#symkey)

Constructor of SymKey, if you want to construct an SymKey with an existing key, use the static methods SymKey.fromString or fromB64 Defaults to a new 256 bits key.

*__constructs__*: SymKey

**Parameters:**

| Name | Type | Default value |
| ------ | ------ | ------ |
| `Default value` arg | [SymKeySize](#symkeysize) \| `Buffer` | 256 |

**Returns:** [SymKey](#symkey)

___

## Properties

<a id="symkey-encryptionkey"></a>

### `<Private>` encryptionKey

**● encryptionKey**: *`string`*

___
<a id="symkey-keysize"></a>

###  keySize

**● keySize**: *`number`*

___
<a id="symkey-signingkey"></a>

### `<Private>` signingKey

**● signingKey**: *`string`*

___

## Methods

<a id="symkey-calculatehmac"></a>

###  calculateHMAC

▸ **calculateHMAC**(textToAuthenticate: *`Buffer`*): `Buffer`

Calculates a SHA-256 HMAC with the SymKey#signingKey on the textToAuthenticate

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| textToAuthenticate | `Buffer` |  \- |

**Returns:** `Buffer`

___
<a id="symkey-decrypt"></a>

###  decrypt

▸ **decrypt**(cipheredMessage: *`Buffer`*): `Buffer`

Decrypts the cipheredMessage using the same algorithms as SymKey#encrypt

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| cipheredMessage | `Buffer` |  \- |

**Returns:** `Buffer`

___
<a id="symkey-decryptstream"></a>

###  decryptStream

▸ **decryptStream**(): `Transform`

Creates a Transform stream that decrypts the encrypted data piped to it.

**Returns:** `Transform`

___
<a id="symkey-encrypt"></a>

###  encrypt

▸ **encrypt**(clearText: *`Buffer`*): `Buffer`

Encrypts the clearText with SymKey#encryptionKey using AES-CBC, and a SHA-256 HMAC calculated with SymKey#signingKey, returns it concatenated in the following order: InitializationVector CipherText HMAC

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| clearText | `Buffer` |  \- |

**Returns:** `Buffer`

___
<a id="symkey-encryptstream"></a>

###  encryptStream

▸ **encryptStream**(): `Transform`

Creates a Transform stream that encrypts the data piped to it.

**Returns:** `Transform`

___
<a id="symkey-tob64"></a>

###  toB64

▸ **toB64**(): `string`

Returns both SymKey#signingKey and SymKey#encryptionKey concatenated encoded with b64

**Returns:** `string`

___
<a id="symkey-tostring"></a>

###  toString

▸ **toString**(): `string`

Returns both SymKey#signingKey and SymKey#encryptionKey concatenated as a binary string

**Returns:** `string`

___
<a id="symkey-fromb64"></a>

### `<Static>` fromB64

▸ **fromB64**(messageKey: *`string`*): [SymKey](#symkey)

Static method to construct a new SymKey from a b64 encoded messageKey

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| messageKey | `string` |  b64 encoded messageKey |

**Returns:** [SymKey](#symkey)

___
<a id="symkey-fromstring"></a>

### `<Static>` fromString

▸ **fromString**(messageKey: *`string`*): [SymKey](#symkey)

Static method to construct a new SymKey from a binary string encoded messageKey

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| messageKey | `string` |  binary encoded messageKey |

**Returns:** [SymKey](#symkey)

___


<a id="publickey"></a>

# Class: PublicKey

## Hierarchy

**PublicKey**

↳  [PrivateKey](#privatekey)

---

<a id="publickey-constructor"></a>

## Constructor

⊕ **new PublicKey**(key: *`Buffer`*): [PublicKey](#publickey)

PublicKey constructor. Should be given a Buffer containing a DER serialization of the key.

*__constructs__*: PublicKey

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| key | `Buffer` |   |

**Returns:** [PublicKey](#publickey)

___

## Properties

<a id="publickey-publickey"></a>

### `<Protected>` publicKey

**● publicKey**: *`PublicKey`*

___

## Methods

<a id="publickey-encrypt"></a>

###  encrypt

▸ **encrypt**(clearText: *`Buffer`*, doCRC?: *`boolean`*): `Buffer`

Encrypts a clearText for the Private Key corresponding to this PublicKey.

*__method__*: 

**Parameters:**

| Name | Type | Default value | Description |
| ------ | ------ | ------ | ------ |
| clearText | `Buffer` | - |  \- |
| `Default value` doCRC | `boolean` | true |  \- |

**Returns:** `Buffer`

___
<a id="publickey-getb64hash"></a>

###  getB64Hash

▸ **getB64Hash**(): `string`

**Returns:** `string`

___
<a id="publickey-gethash"></a>

###  getHash

▸ **getHash**(): `string`

**Returns:** `string`

___
<a id="publickey-tob64"></a>

###  toB64

▸ **toB64**(options?: *`__type`*): `string`

Serializes the key to DER format and encodes it in b64.

*__method__*: 

**Parameters:**

| Name | Type | Default value |
| ------ | ------ | ------ |
| `Default value` options | `__type` |  null |

**Returns:** `string`

___
<a id="publickey-verify"></a>

###  verify

▸ **verify**(textToCheckAgainst: *`Buffer`*, signature: *`Buffer`*): `boolean`

Verify that the message has been signed with the Private Key corresponding to this PublicKey.

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| textToCheckAgainst | `Buffer` |  \- |
| signature | `Buffer` |  \- |

**Returns:** `boolean`

___
<a id="publickey-fromb64"></a>

### `<Static>` fromB64

▸ **fromB64**(b64DERFormattedPublicKey: *`string`*): [PublicKey](#publickey)

Returns a PublicKey from it's DER base64 serialization.

*__method__*: 

*__static__*: 

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| b64DERFormattedPublicKey | `string` |  a b64 encoded public key formatted with DER |

**Returns:** [PublicKey](#publickey)

___

<a id="privatekey"></a>

# Class: PrivateKey

## Hierarchy

 [PublicKey](#publickey)

**↳ PrivateKey**

---

<a id="privatekey-constructor"></a>

## Constructor

⊕ **new PrivateKey**(key: *`Buffer`*): [PrivateKey](#privatekey)

*Overrides [PublicKey](#publickey).[constructor](#publickey-constructor)*

Private Key constructor. Shouldn't be used directly, use `fromB64` or `generate` static methods

*__constructs__*: PrivateKey

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| key | `Buffer` |   |

**Returns:** [PrivateKey](#privatekey)

___

## Properties

<a id="privatekey-privatekey"></a>

### `<Protected>` privateKey

**● privateKey**: *`PrivateKey`*

___
<a id="privatekey-publickey"></a>

### `<Protected>` publicKey

**● publicKey**: *`PublicKey`*

*Inherited from [PublicKey](#publickey).[publicKey](#publickey-publickey)*

___

## Methods

<a id="privatekey-decrypt"></a>

###  decrypt

▸ **decrypt**(cipherText: *`Buffer`*, doCRC?: *`boolean`*): `Buffer`

Deciphers the given message.

**Parameters:**

| Name | Type | Default value | Description |
| ------ | ------ | ------ | ------ |
| cipherText | `Buffer` | - |  \- |
| `Default value` doCRC | `boolean` | true |

**Returns:** `Buffer`

___
<a id="privatekey-encrypt"></a>

###  encrypt

▸ **encrypt**(clearText: *`Buffer`*, doCRC?: *`boolean`*): `Buffer`

*Inherited from [PublicKey](#publickey).[encrypt](#publickey-encrypt)*

Encrypts a clearText for the Private Key corresponding to this PublicKey.

*__method__*: 

**Parameters:**

| Name | Type | Default value | Description |
| ------ | ------ | ------ | ------ |
| clearText | `Buffer` | - |  \- |
| `Default value` doCRC | `boolean` | true |  \- |

**Returns:** `Buffer`

___
<a id="privatekey-getb64hash"></a>

###  getB64Hash

▸ **getB64Hash**(): `string`

*Inherited from [PublicKey](#publickey).[getB64Hash](#publickey-getb64hash)*

**Returns:** `string`

___
<a id="privatekey-gethash"></a>

###  getHash

▸ **getHash**(): `string`

*Inherited from [PublicKey](#publickey).[getHash](#publickey-gethash)*

**Returns:** `string`

___
<a id="privatekey-sign"></a>

###  sign

▸ **sign**(textToSign: *`Buffer`*): `Buffer`

Signs the given message with this Private Key.

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| textToSign | `Buffer` |  \- |

**Returns:** `Buffer`

___
<a id="privatekey-tob64"></a>

###  toB64

▸ **toB64**(__namedParameters?: *`object`*): `string`

*Overrides [PublicKey](#publickey).[toB64](#publickey-tob64)*

Serializes the key to DER format and encodes it in b64.

*__method__*: 

**Parameters:**

**`Default value` __namedParameters: `object`**

| Name | Type | Default value |
| ------ | ------ | ------ |
| publicOnly | `boolean` | false |

**Returns:** `string`

___
<a id="privatekey-verify"></a>

###  verify

▸ **verify**(textToCheckAgainst: *`Buffer`*, signature: *`Buffer`*): `boolean`

*Inherited from [PublicKey](#publickey).[verify](#publickey-verify)*

Verify that the message has been signed with the Private Key corresponding to this PublicKey.

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| textToCheckAgainst | `Buffer` |  \- |
| signature | `Buffer` |  \- |

**Returns:** `boolean`

___
<a id="privatekey-fromb64"></a>

### `<Static>` fromB64

▸ **fromB64**(b64DERFormattedPrivateKey: *`string`*): [PrivateKey](#privatekey)

*Overrides [PublicKey](#publickey).[fromB64](#publickey-fromb64)*

Returns a PrivateKey from it's DER base64 serialization.

*__method__*: 

*__static__*: 

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| b64DERFormattedPrivateKey | `string` |  a b64 encoded private key formatted with DER |

**Returns:** [PrivateKey](#privatekey)

___
<a id="privatekey-generate"></a>

### `<Static>` generate

▸ **generate**(size?: *[AsymKeySize](#asymkeysize)*): `Promise`<[PrivateKey](#privatekey)>

Generates a PrivateKey asynchronously

⚠️ On nodeJS back-end, this is only available if you have node 10.12 or newer

**Parameters:**

| Name | Type | Default value |
| ------ | ------ | ------ |
| `Default value` size | [AsymKeySize](#asymkeysize) | 4096 |

**Returns:** `Promise`<[PrivateKey](#privatekey)>

___

<a id="utils"></a>

# Utils

<a id="randombytes"></a>

### randomBytes

▸ **randomBytes**(length?: *`number`*): `Buffer`

Returns a Buffer of random bytes

**Parameters:**

| Name | Type | Default value |
| ------ | ------ | ------ |
| `Default value` length | `number` | 10 |

**Returns:** `Buffer`

___
<a id="sha256"></a>

### sha256

▸ **sha256**(data: *`Buffer`*): `Buffer`

Returns a Buffer containing the hash of the given data

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| data | `Buffer` |  \- |

**Returns:** `Buffer`

___


# Type aliases

<a id="symkeysize"></a>

###  SymKeySize

**Ƭ SymKeySize**: *`128` \| `192` \| `256`*


<a id="asymkeysize"></a>

###  AsymKeySize

**Ƭ AsymKeySize**: *`4096` \| `2048` \| `1024`*

---
