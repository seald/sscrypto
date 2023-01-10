import { testSymKeyCompatibility, testSymKeyImplem, testSymKeyPerf } from './aes.spec'
import { testAsymKeyImplem, testAsymKeyPerf } from './rsa.spec'
import { testUtilsImplem } from './utils.spec'
import { randomBytes } from '../react-native-forge/utils'
import { assertType } from './specUtils.spec'
import type { SSCrypto } from '../index'
import * as SSCryptoRNForge from '../react-native-forge'
// import * as SSCryptoRNCryptoPP from '../react-native-cryptopp'
import * as SSCryptoRNQuickCrypto from '../react-native-quick-crypto'

// Test types
assertType<SSCrypto>(SSCryptoRNForge)
// assertType<SSCrypto>(SSCryptoRNCryptoPP)
assertType<SSCrypto>(SSCryptoRNQuickCrypto)

// SymKey
testSymKeyImplem('SSCryptoRN', SSCryptoRNForge.SymKey, randomBytes)
// testSymKeyImplem('SSCryptoRNCryptoPP', SSCryptoRNCryptoPP.SymKey, randomBytes)
testSymKeyImplem('SSCryptoRNQuickCrypto', SSCryptoRNQuickCrypto.SymKey, randomBytes)
// testSymKeyCompatibility('RNForge/SSCryptoRNCryptoPP', SSCryptoRNForge.SymKey, SSCryptoRNCryptoPP.SymKey, randomBytes)
testSymKeyCompatibility('RNForge/SSCryptoRNQuickCrypto', SSCryptoRNForge.SymKey, SSCryptoRNQuickCrypto.SymKey, randomBytes)

testSymKeyPerf('SSCryptoRNForge', SSCryptoRNForge.SymKey, randomBytes)
// testSymKeyPerf('SSCryptoRNCryptoPP', SSCryptoRNCryptoPP.SymKey, randomBytes)
testSymKeyPerf('SSCryptoRNQuickCrypto', SSCryptoRNQuickCrypto.SymKey, randomBytes)

testAsymKeyImplem('SSCryptoRNForge', SSCryptoRNForge, randomBytes)
// testAsymKeyImplem('SSCryptoRNCryptoPP', SSCryptoRNCryptoPP, randomBytes)
testAsymKeyImplem('SSCryptoRNQuickCrypto', SSCryptoRNQuickCrypto, randomBytes)

testAsymKeyPerf('SSCryptoRNForge', 1024, SSCryptoRNForge, randomBytes)
testAsymKeyPerf('SSCryptoRNForge', 2048, SSCryptoRNForge, randomBytes)
testAsymKeyPerf('SSCryptoRNForge', 4096, SSCryptoRNForge, randomBytes)
// testAsymKeyPerf('SSCryptoRNCryptoPP', 1024, SSCryptoRNCryptoPP, randomBytes)
// testAsymKeyPerf('SSCryptoRNCryptoPP', 2048, SSCryptoRNCryptoPP, randomBytes)
// testAsymKeyPerf('SSCryptoRNCryptoPP', 4096, SSCryptoRNCryptoPP, randomBytes)
testAsymKeyPerf('SSCryptoRNQuickCrypto', 1024, SSCryptoRNQuickCrypto, randomBytes)
testAsymKeyPerf('SSCryptoRNQuickCrypto', 2048, SSCryptoRNQuickCrypto, randomBytes)
testAsymKeyPerf('SSCryptoRNQuickCrypto', 4096, SSCryptoRNQuickCrypto, randomBytes)

// Utils
testUtilsImplem('SSCryptoRNForge', SSCryptoRNForge.utils)
// testUtilsImplem('SSCryptoRNCryptoPP', SSCryptoRNCryptoPP.utils)
testUtilsImplem('SSCryptoRNQuickCrypto', SSCryptoRNQuickCrypto.utils)
