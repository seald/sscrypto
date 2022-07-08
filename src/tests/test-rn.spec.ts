import './patches'
import { testSymKeyCompatibility, testSymKeyImplem, testSymKeyPerf } from './aes.spec'
import { testAsymKeyImplem, testAsymKeyPerf } from './rsa.spec'
import { testUtilsImplem } from './utils.spec'
import { randomBytes } from '../react-native/utils'
import { assertType } from './specUtils.spec'
import type { SSCrypto } from '../index'
import * as SSCryptoRN from '../react-native'
import * as SSCryptoForge from '../forge'

// Test types
assertType<SSCrypto>(SSCryptoRN)

// SymKey
testSymKeyImplem('SSCryptoRN', SSCryptoRN.SymKey, randomBytes)
testSymKeyCompatibility('RN/forge', SSCryptoRN.SymKey, SSCryptoForge.SymKey, randomBytes)

testSymKeyPerf('SSCryptoRN', SSCryptoRN.SymKey, randomBytes)

testAsymKeyImplem('SSCryptoRN', SSCryptoRN, randomBytes)

testAsymKeyPerf('SSCryptoRN', 1024, SSCryptoRN, randomBytes)
testAsymKeyPerf('SSCryptoRN', 2048, SSCryptoRN, randomBytes)
// testAsymKeyPerf('SSCryptoRN', 4096, SSCryptoRN, randomBytes)

// Utils
testUtilsImplem('SSCryptoRN', SSCryptoRN.utils)
