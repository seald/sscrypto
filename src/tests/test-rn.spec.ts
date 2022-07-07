import './patches'
import { testSymKeyImplem, testSymKeyPerf } from './aes.spec'
import { testAsymKeyImplem, testAsymKeyPerf } from './rsa.spec'
import { testUtilsImplem } from './utils.spec'
import { randomBytes } from '../forge/utils'
import { assertType } from './specUtils.spec'
import type { SSCrypto } from '../index'
import * as SSCryptoRN from '../react-native'

// Test types
assertType<SSCrypto>(SSCryptoRN)

// SymKey
testSymKeyImplem('SSCryptoRN', SSCryptoRN.SymKey, randomBytes)

testSymKeyPerf('SSCryptoRN', SSCryptoRN.SymKey, randomBytes)

testAsymKeyImplem('SSCryptoRN', SSCryptoRN, randomBytes)

testAsymKeyPerf('SSCryptoRN', 1024, SSCryptoRN, randomBytes)
testAsymKeyPerf('SSCryptoRN', 2048, SSCryptoRN, randomBytes)
// testAsymKeyPerf('SSCryptoRN', 4096, SSCryptoRN, randomBytes)

// Utils
testUtilsImplem('SSCryptoRN', SSCryptoRN.utils)
