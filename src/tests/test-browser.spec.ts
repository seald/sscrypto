import { testSymKeyCompatibility, testSymKeyImplem, testSymKeyPerf } from './aes.spec'
import { testAsymKeyCompatibility, testAsymKeyImplem, testAsymKeyPerf } from './rsa.spec'
import { testUtilsCompatibility, testUtilsImplem } from './utils.spec'
import { randomBytes } from '../forge/utils'
import { assertType } from './specUtils.spec'
import { forge, SSCrypto, webcrypto } from '../index'

const disableWebCrypto = {
  duringBefore: () => {
    window.SSCRYPTO_NO_WEBCRYPTO = true
  },
  duringAfter: () => {
    window.SSCRYPTO_NO_WEBCRYPTO = false
  }
}

// Test types
assertType<SSCrypto>(forge)
assertType<SSCrypto>(webcrypto)

// SymKey
testSymKeyImplem('forge', forge.SymKey, randomBytes)
testSymKeyImplem('webcrypto', webcrypto.SymKey, randomBytes)

testSymKeyCompatibility('forge/webcrypto', forge.SymKey, webcrypto.SymKey, randomBytes)

testSymKeyPerf('forge', forge.SymKey, randomBytes)
testSymKeyPerf('webcrypto', webcrypto.SymKey, randomBytes)

testSymKeyImplem('webcrypto fallback', webcrypto.SymKey, randomBytes, disableWebCrypto)

// AsymKey
testAsymKeyImplem('forge', forge, randomBytes)
testAsymKeyImplem('webcrypto', webcrypto, randomBytes)

testAsymKeyCompatibility('forge/webcrypto', forge, webcrypto)
testAsymKeyCompatibility('webcrypto/forge', webcrypto, forge)

testAsymKeyImplem('webcrypto fallback', webcrypto, randomBytes, disableWebCrypto)

testAsymKeyPerf('forge', 1024, forge, randomBytes)
testAsymKeyPerf('forge', 2048, forge, randomBytes)
// testAsymKeyPerf('forge', 4096, forge, randomBytes) // this is a bit long, so we disable it by default
testAsymKeyPerf('webcrypto', 1024, webcrypto, randomBytes)
testAsymKeyPerf('webcrypto', 2048, webcrypto, randomBytes)
// testAsymKeyPerf('webcrypto', 4096, AsymKeyWebCrypto, randomBytes)
testAsymKeyPerf('webcrypto fallback', 1024, webcrypto, randomBytes, disableWebCrypto)
testAsymKeyPerf('webcrypto fallback', 2048, webcrypto, randomBytes, disableWebCrypto)
// testAsymKeyPerf('webcrypto fallback', 4096, webcrypto, randomBytes, disableWebCrypto)

// Utils
testUtilsImplem('forge', forge.utils)
testUtilsImplem('webcrypto', webcrypto.utils)

testUtilsCompatibility('forge/webcrypto', forge.utils, webcrypto.utils)

testUtilsImplem('webcrypto fallback', webcrypto.utils, disableWebCrypto)
