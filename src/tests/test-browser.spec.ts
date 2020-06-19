import {
  PrivateKey as PrivateKeyForge,
  PublicKey as PublicKeyForge,
  SymKey as SymKeyForge,
  utils as utilsForge
} from '../forge'
import {
  PrivateKey as PrivateKeyWebCrypto,
  PublicKey as PublicKeyWebCrypto,
  SymKey as SymKeyWebCrypto,
  utils as utilsWebCrypto
} from '../webcrypto'
import { testSymKeyCompatibility, testSymKeyImplem, testSymKeyPerf } from './aes.spec'
import { testAsymKeyCompatibility, testAsymKeyImplem, testAsymKeyPerf } from './rsa.spec'
import { testUtilsCompatibility, testUtilsImplem } from './utils.spec'
import { randomBytesSync } from '../forge/utils'

const disableWebCrypto = {
  duringBefore: () => {
    window.SSCRYPTO_NO_WEBCRYPTO = true
  },
  duringAfter: () => {
    window.SSCRYPTO_NO_WEBCRYPTO = false
  }
}

// SymKey
testSymKeyImplem('forge', SymKeyForge, randomBytesSync)
testSymKeyImplem('webcrypto', SymKeyWebCrypto, randomBytesSync)

testSymKeyCompatibility('forge/webcrypto', SymKeyForge, SymKeyWebCrypto, randomBytesSync)

testSymKeyPerf('forge', SymKeyForge, randomBytesSync)
testSymKeyPerf('webcrypto', SymKeyWebCrypto, randomBytesSync)

testSymKeyImplem('webcrypto fallback', SymKeyWebCrypto, randomBytesSync, disableWebCrypto)

// AsymKey
const AsymKeyForge = { PrivateKey: PrivateKeyForge, PublicKey: PublicKeyForge }
const AsymKeyWebCrypto = { PrivateKey: PrivateKeyWebCrypto, PublicKey: PublicKeyWebCrypto }
testAsymKeyImplem('forge', AsymKeyForge, randomBytesSync)
testAsymKeyImplem('webcrypto', AsymKeyWebCrypto, randomBytesSync)

testAsymKeyCompatibility('forge/webcrypto', 1024, AsymKeyForge, AsymKeyWebCrypto)
testAsymKeyCompatibility('forge/webcrypto', 2048, AsymKeyForge, AsymKeyWebCrypto)
testAsymKeyCompatibility('forge/webcrypto', 4096, AsymKeyForge, AsymKeyWebCrypto)

testAsymKeyCompatibility('webcrypto/forge', 1024, AsymKeyWebCrypto, AsymKeyForge)
testAsymKeyCompatibility('webcrypto/forge', 2048, AsymKeyWebCrypto, AsymKeyForge)
testAsymKeyCompatibility('webcrypto/forge', 4096, AsymKeyWebCrypto, AsymKeyForge)

testAsymKeyImplem('webcrypto fallback', AsymKeyWebCrypto, randomBytesSync, disableWebCrypto)

testAsymKeyPerf('forge', 1024, AsymKeyForge, randomBytesSync)
testAsymKeyPerf('forge', 2048, AsymKeyForge, randomBytesSync)
// testAsymKeyPerf('forge', 4096, AsymKeyForge, randomBytesSync) // this is a bit long, so we disable it by default
testAsymKeyPerf('webcrypto', 1024, AsymKeyWebCrypto, randomBytesSync)
testAsymKeyPerf('webcrypto', 2048, AsymKeyWebCrypto, randomBytesSync)
// testAsymKeyPerf('webcrypto', 4096, AsymKeyWebCrypto, randomBytesSync)
testAsymKeyPerf('webcrypto fallback', 1024, AsymKeyWebCrypto, randomBytesSync, disableWebCrypto)
testAsymKeyPerf('webcrypto fallback', 2048, AsymKeyWebCrypto, randomBytesSync, disableWebCrypto)
// testAsymKeyPerf('webcrypto fallback', 4096, AsymKeyWebCrypto, randomBytesSync, disableWebCrypto)

// Utils
testUtilsImplem('forge', utilsForge)
testUtilsImplem('webcrypto', utilsWebCrypto)

testUtilsCompatibility('forge/webcrypto', utilsForge, utilsWebCrypto)

testUtilsImplem('webcrypto fallback', utilsWebCrypto, disableWebCrypto)
