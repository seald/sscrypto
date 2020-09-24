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
    * [authenticationKey](#symkey-authenticationkey)

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

⊕ **new SymKey**(key: *`Buffer` | [SymKeySize](#symkeysize)*): [SymKey](#symkey)
    
Constructor of SymKey

Using a number as argument, or relying on default, is deprecated. Use [`SymKey.generate`](#symkey-generate) instead.

Defaults to a new 256 bits key (deprecated).
  
*__constructs__*: SymKey

**Parameters:**

Name | Type | Default | Description |
------ | ------ | ------ | ------ |
`key` | Buffer &#124; [SymKeySize](#symkeysize) | 256 | The key to construct the SymKey with. Passing a keySize is deprecated. Use `SymKey.generate` instead. |

**Returns:** [SymKey](#symkey)

___

## Properties

<a id="symkey-key"></a>

### `Readonly` key

**● key**: *`Buffer`*

___
<a id="symkey-keysize"></a>

###  `Readonly` keySize

**● keySize**: *`[SymKeySize](#symkeysize)`*

___

## Methods

<a id="symkey-decrypt"></a>

###  decrypt

▸ **decrypt**(cipheredMessage: *`Buffer`*): `Buffer`

Decrypts the cipherText using AES-CBC with the embedded IV, and checking the embedded SHA-256 HMAC

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| cipheredMessage | `Buffer` | - |

**Returns:** `Buffer`

___
<a id="symkey-decryptasync"></a>

###  decryptAsync

▸ **decryptAsync**(cipheredMessage: *`Buffer`*): `Promise<Buffer>`

Decrypts the cipherText using AES-CBC with the embedded IV, and checking the embedded SHA-256 HMAC

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| cipheredMessage | `Buffer` | - |

**Returns:** `Promise<Buffer>`

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

Encrypts the clearText with SymKey#encryptionKey using AES-CBC, and a SHA-256 HMAC calculated with
SymKey#authenticationKey, returns it concatenated in the following order:
InitializationVector CipherText HMAC

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| clearText | `Buffer` | - |

**Returns:** `Buffer`

___
<a id="symkey-encryptasync"></a>

###  encryptAsync

▸ **encryptAsync**(clearText: *`Buffer`*): `Promise<Buffer>`

Encrypts the clearText with SymKey#encryptionKey using AES-CBC, and a SHA-256 HMAC calculated with
SymKey#authenticationKey, returns it concatenated in the following order:
InitializationVector CipherText HMAC

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| clearText | `Buffer` | - |

**Returns:** `Promise<Buffer>`

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

Returns the SymKey's key encoded with b64

**Returns:** `string`

___
<a id="symkey-tostring"></a>

###  toString

▸ **toString**(): `string`

Returns the SymKey's key encoded as a binary string

**Returns:** `string`

___
<a id="symkey-fromb64"></a>

### `<Static>` fromB64

▸ **fromB64**(messageKey: *`string`*): [SymKey](#symkey)

Static method to construct a new SymKey from a b64 encoded key

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| messageKey | `string` |  b64 encoded key |

**Returns:** [SymKey](#symkey)

___
<a id="symkey-fromstring"></a>

### `<Static>` fromString

▸ **fromString**(messageKey: *`string`*): [SymKey](#symkey)

Static method to construct a new SymKey from a binary string encoded key

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| messageKey | `string` |  binary encoded key |

**Returns:** [SymKey](#symkey)

___
<a id="symkey-generate"></a>

### `<Static>` generate

▸ **generate**(size?: *[SymKeySize](#symkeysize)*): `Promise`<[SymKey](#symkey)>

Static method to generate a new SymKey of a given size asynchronously

**Parameters:**

| Name | Type | Default value |
| ------ | ------ | ------ |
| size | [SymKeySize](#symkeysize) | 256 |

**Returns:** `Promise`<[SymKey](#symkey)>

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

Constructor for PublicKey class for every public key implementation of SSCrypto.
It ensures that given buffer is a valid PublicKey, either encoded in an SPKI enveloppe or as a bare public key
representation using ASN.1 syntax with DER encoding, and sets the [`publicKeyBuffer`](#publickey-publickeybuffer)

*__constructs__*: PublicKey

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| key | `Buffer` |   |

**Returns:** [PublicKey](#publickey)

___

## Properties

<a id="publickey-publickeybuffer"></a>

### `Readonly` publicKeyBuffer

**● publicKeyBuffer**: *`Buffer`*

A Buffer that contains a representation of the instantiated RSA PublicKey using ASN.1 syntax with DER encoding
wrapped in an SPKI enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification.

___

## Methods

<a id="publickey-encrypt"></a>

###  encrypt

▸ **encrypt**(clearText: *`Buffer`*, doCRC?: *`boolean`*): `Buffer`

Optionally prefixes the cleartext with a CRC32 of the initial clearText then, encrypts the result synchronously
with RSAES-OAEP-ENCRYPT with SHA-1 as a Hash function and MGF1-SHA-1 as a mask generation
function as per PKCS#1 v2.2 section 7.1.1 using the instantiated PublicKey

**Parameters:**

| Name | Type | Default value | Description |
| ------ | ------ | ------ | ------ |
| clearText | `Buffer` | - | - |
| doCRC | `boolean` | true | - |

**Returns:** `Buffer`

___
<a id="publickey-encryptasync"></a>

###  encryptAsync

▸ **encryptAsync**(clearText: *`Buffer`*, doCRC?: *`boolean`*): `Promise‹Buffer›`

Optionally prefixes the cleartext with a CRC32 of the initial clearText then, encrypts the result asynchronously
with RSAES-OAEP-ENCRYPT with SHA-1 as a Hash function and MGF1-SHA-1 as a mask generation
function as per PKCS#1 v2.2 section 7.1.1 using the instantiated PublicKey

**Parameters:**

| Name | Type | Default value | Description |
| ------ | ------ | ------ | ------ |
| clearText | `Buffer` | - | - |
| doCRC | `boolean` | true | - |

**Returns:** `Promise‹Buffer›`

___
<a id="publickey-gethash"></a>

###  getHash

▸ **getHash**(): `string`

Gives a SHA-256 hash encoded in base64 of the RSA PublicKey encoded in base64 using ASN.1 syntax with DER encoding
wrapped in an SPKI enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification

**Returns:** `string`

___
<a id="publickey-tob64"></a>

###  toB64

▸ **toB64**(options?: *`object`*): `string`

Exports the instance of an RSA PublicKey in base64 using ASN.1 syntax with DER encoding wrapped in an SPKI
enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification.

**Parameters:**

▪`Default value`  **options**: *object*= null

| Name | Type |
| ------ | ------ |
| publicOnly? | `boolean` |

**Returns:** `string`

___
<a id="publickey-tostring"></a>

###  toString

▸ **toString**(options?: *`object`*): `string`

Exports the instance of an RSA PublicKey in binary string using ASN.1 syntax with DER encoding wrapped in an SPKI
enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification.

**`deprecated`** 

**Parameters:**

▪`Default value`  **options**: *object*= null

| Name | Type |
| ------ | ------ |
| publicOnly? | `boolean` |

**Returns:** `string`

___
<a id="publickey-verify"></a>

###  verify

▸ **verify**(textToCheckAgainst: *`Buffer`*, signature: *`Buffer`*): `boolean`

Verifies synchronously that the given signature is valid for textToCheckAgainst using RSASSA-PSS-VERIFY which itself
uses EMSA-PSS encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
`Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section 8.1.2 using
instantiated PublicKey.

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| textToCheckAgainst | `Buffer` | - |
| signature | `Buffer` | - |

**Returns:** `boolean`

___
<a id="publickey-verifyasync"></a>

###  verifyAsync

▸ **verifyAsync**(textToCheckAgainst: *`Buffer`*, signature: *`Buffer`*): `Promise<boolean>`

Verifies asynchronously that the given signature is valid for textToCheckAgainst using RSASSA-PSS-VERIFY which itself
uses EMSA-PSS encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
`Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section 8.1.2 using
instantiated PublicKey.

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| textToCheckAgainst | `Buffer` | - |
| signature | `Buffer` | - |

**Returns:** `Promise<boolean>`

___
<a id="publickey-fromb64"></a>

### `<Static>` fromB64

▸ **fromB64**(b64DERFormattedPublicKey: *`string`*): [PublicKey](#publickey)

Instantiates a PublicKey from a base64 representation of an RSA public key using ASN.1 syntax with DER encoding
per PKCS#1 v2.2 specification and optionally wrapped in an SPKI enveloppe as per RFC 5280.

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

PrivateKey constructor. Should be given a Buffer either encoded in a PKCS#8 enveloppe or as a bare private
key representation using ASN.1 syntax with DER encoding.

*__constructs__*: PrivateKey

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| key | `Buffer` |   |

**Returns:** [PrivateKey](#privatekey)

___

## Properties

<a id="privatekey-privatekeybuffer"></a>

### `Readonly` privateKeyBuffer

**● privateKeyBuffer**: *`Buffer`*

___
<a id="privatekey-publickeybuffer"></a>

### `Readonly` publicKeyBuffer

**● publicKeyBuffer**: *`Buffer`*

*Inherited from [PublicKey](#publickey).[publicKeyBuffer](#publickey-publickeybuffer)*

___

## Methods

<a id="privatekey-decrypt"></a>

###  decrypt

▸ **decrypt**(cipherText: *`Buffer`*, doCRC?: *`boolean`*): `Buffer`

Decrypts the given cipherText synchronously with RSAES-OAEP-DECRYPT as per PKCS#1 v2.2 section 7.1.2 using the
instantiated PrivateKey, and optionally checks that the result is prefixed with a valid CRC32.

**Parameters:**

| Name | Type | Default value | Description |
| ------ | ------ | ------ | ------ |
| cipherText | `Buffer` | - | - |
| doCRC | `boolean` | true | - |

**Returns:** `Buffer`

___
<a id="privatekey-decryptasync"></a>

###  decryptAsync

▸ **decryptAsync**(cipherText: *`Buffer`*, doCRC?: *`boolean`*): `Promise<Buffer>`

Decrypts the given cipherText asynchronously with RSAES-OAEP-DECRYPT as per PKCS#1 v2.2 section 7.1.2 using the
instantiated PrivateKey, and optionally checks that the result is prefixed with a valid CRC32.

**Parameters:**

| Name | Type | Default value | Description |
| ------ | ------ | ------ | ------ |
| cipherText | `Buffer` | - | - |
| doCRC | `boolean` | true | - |

**Returns:** `Promise<Buffer>`

___
<a id="privatekey-encrypt"></a>

###  encrypt

▸ **encrypt**(clearText: *`Buffer`*, doCRC?: *`boolean`*): `Buffer`

*Inherited from [PublicKey](#publickey).[encrypt](#publickey-encrypt)*

Optionally prefixes the cleartext with a CRC32 of the initial clearText then, encrypts the result synchronously
with RSAES-OAEP-ENCRYPT with SHA-1 as a Hash function and MGF1-SHA-1 as a mask generation
function as per PKCS#1 v2.2 section 7.1.1 using the instantiated PublicKey

**Parameters:**

| Name | Type | Default value | Description |
| ------ | ------ | ------ | ------ |
| clearText | `Buffer` | - | - |
| doCRC | `boolean` | true | - |

**Returns:** `Buffer`

___
<a id="privatekey-encryptasync"></a>

###  encryptAsync

▸ **encryptAsync**(clearText: *`Buffer`*, doCRC?: *`boolean`*): `Promise<Buffer>`

*Inherited from [PublicKey](#publickey).[encryptAsync](#publickey-encryptasync)*

Optionally prefixes the cleartext with a CRC32 of the initial clearText then, encrypts the result asynchronously
with RSAES-OAEP-ENCRYPT with SHA-1 as a Hash function and MGF1-SHA-1 as a mask generation
function as per PKCS#1 v2.2 section 7.1.1 using the instantiated PublicKey

**Parameters:**

| Name | Type | Default value | Description |
| ------ | ------ | ------ | ------ |
| clearText | `Buffer` | - | - |
| doCRC | `boolean` | true | - |

**Returns:** `Promise<Buffer>`

___
<a id="privatekey-gethash"></a>

###  getHash

▸ **getHash**(): `string`

*Inherited from [PublicKey](#publickey).[getHash](#publickey-gethash)*

Gives a SHA-256 hash encoded in base64 of the RSA PublicKey encoded in base64 using ASN.1 syntax with DER encoding
wrapped in an SPKI enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification

**Returns:** `string`

___
<a id="privatekey-sign"></a>

###  sign

▸ **sign**(textToSign: *`Buffer`*): `Buffer`

Generates synchronously a signature for the given textToSign using RSASSA-PSS-Sign which itself uses EMSA-PSS
encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
`Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section
8.1.1 using instantiated PrivateKey.

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| textToSign | `Buffer` | - |

**Returns:** `Buffer`

___
<a id="privatekey-signasync"></a>

###  signAsync

▸ **signAsync**(textToSign: *`Buffer`*): `Promise‹Buffer›`

Generates asynchronously a signature for the given textToSign using RSASSA-PSS-Sign which itself uses EMSA-PSS
encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
`Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section
8.1.1 using instantiated PrivateKey.

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| textToSign | `Buffer` | - |

**Returns:** `Promise‹Buffer›`

___
<a id="privatekey-tob64"></a>

###  toB64

▸ **toB64**(__namedParameters?: *`object`*): `string`

*Overrides [PublicKey](#publickey).[toB64](#publickey-tob64)*

Exports the instance of an RSA PrivateKey in base64 using ASN.1 syntax with DER encoding wrapped in a PKCS#8
enveloppe as per RFC 5958, and encoded per PKCS#1 v2.2 specification.
If publicOnly is specified, it exports the RSA PublicKey in base64 using ASN.1 syntax with DER encoding wrapped
in an SPKI enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification.

**Parameters:**

**`Default value` __namedParameters: `object`**

| Name | Type | Default value |
| ------ | ------ | ------ |
| publicOnly | `boolean` | false |

**Returns:** `string`

___
<a id="privatekey-tostring"></a>

###  toString

▸ **toString**(__namedParameters?: *`object`*): `string`

*Overrides [PublicKey](#publickey).[toB64](#publickey-tostring)*

Exports the instance of an RSA PrivateKey in binary string using ASN.1 syntax with DER encoding wrapped in a PKCS#8
enveloppe as per RFC 5958, and encoded per PKCS#1 v2.2 specification.
If publicOnly is specified, it exports the RSA PublicKey in binary string using ASN.1 syntax with DER encoding wrapped
in an SPKI enveloppe as per RFC 5280, and encoded per PKCS#1 v2.2 specification.

**`deprecated`** 

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

Verifies synchronously that the given signature is valid for textToCheckAgainst using RSASSA-PSS-VERIFY which itself
uses EMSA-PSS encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
`Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section 8.1.2 using
instantiated PublicKey.

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| textToCheckAgainst | `Buffer` | - |
| signature | `Buffer` | - |

**Returns:** `boolean`

___
<a id="privatekey-verifyasync"></a>

###  verifyAsync

▸ **verifyAsync**(textToCheckAgainst: *`Buffer`*, signature: *`Buffer`*): `Promise‹boolean›`

*Inherited from [PublicKey](#publickey).[verify](#publickey-verifyasync)*

Verifies asynchronously that the given signature is valid for textToCheckAgainst using RSASSA-PSS-VERIFY which itself
uses EMSA-PSS encoding with SHA-256 as the Hash function and MGF1-SHA-256, and a salt length sLen of
`Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2` as per PKCS#1 v2.2 section 8.1.2 using
instantiated PublicKey.

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| textToCheckAgainst | `Buffer` | - |
| signature | `Buffer` | - |

**Returns:** `Promise‹boolean›`

___
<a id="privatekey-fromb64"></a>

### `<Static>` fromB64

▸ **fromB64**(b64DERFormattedPrivateKey: *`string`*): [PrivateKey](#privatekey)

*Overrides [PublicKey](#publickey).[fromB64](#publickey-fromb64)*

Instantiates a PrivateKey from a base64 ASN.1 syntax with DER encoding wrapped in a PKCS#8
enveloppe as per RFC 5958, and encoded per PKCS#1 v2.2 specification.

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

Generates asynchronously an RSA Private Key Key and instantiates it.

⚠️ On nodeJS back-end, this is only available if you have node 10.12 or newer

**Parameters:**

| Name | Type | Default value |
| ------ | ------ | ------ |
| size | [AsymKeySize](#asymkeysize) | 4096 |

**Returns:** `Promise`<[PrivateKey](#privatekey)>

___
<a id="privatekey-symbolhasinstance"></a>

### `<Static>` [Symbol.hasInstance]

▸ **[Symbol.hasInstance]**(instance: *`unknown`*): boolean

Returns true if instance is PrivateKey.
See https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Symbol/hasInstance

| Name | Type | Description |
| ------ | ------ | ------ |
| instance | `unknown` | - |

**Returns:** boolean

___

<a id="utils"></a>

# Utils

<a id="randombytes"></a>

### randomBytes

▸ **randomBytes**(length?: *`number`*): `Buffer`

Returns a Buffer of random bytes synchronously

**Parameters:**

| Name | Type | Default value |
| ------ | ------ | ------ |
| length | `number` | 10 |

**Returns:** `Buffer`

___
<a id="randombytesasync"></a>

### randomBytesAsync

▸ **randomBytesAsync**(length?: *`number`*): `Promise<Buffer>`

Returns a Buffer of random bytes asynchronously

**Parameters:**

| Name | Type | Default value |
| ------ | ------ | ------ |
| length | `number` | 10 |

**Returns:** `Promise<Buffer>`

___
<a id="sha256"></a>

### sha256

▸ **sha256**(data: *`Buffer`*): `Buffer`

Returns a Buffer containing the hash of the given data

**Parameters:**

| Name | Type | Description |
| ------ | ------ | ------ |
| data | `Buffer` | - |

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
