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
import { testAsymKeyCompatibility, testAsymKeyImplem } from './rsa.spec'
import { testUtilsCompatibility, testUtilsImplem } from './utils.spec'
import { randomBytes } from '../forge/utils'

const disableWebCrypto = {
  duringBefore: () => {
    // @ts-ignore
    window.SSCRYPTO_NO_WEBCRYPTO = true
  },
  duringAfter: () => {
    // @ts-ignore
    window.SSCRYPTO_NO_WEBCRYPTO = false
  }
}

// SymKey
testSymKeyImplem('forge', SymKeyForge, randomBytes)
testSymKeyImplem('webcrypto', SymKeyWebCrypto, randomBytes)

testSymKeyCompatibility('forge/webcrypto', SymKeyForge, SymKeyWebCrypto, randomBytes)

testSymKeyPerf('forge', SymKeyForge, randomBytes)
testSymKeyPerf('webcrypto', SymKeyWebCrypto, randomBytes)

testSymKeyImplem('webcrypto fallback', SymKeyWebCrypto, randomBytes, disableWebCrypto)

// AsymKey
const AsymKeyForge = { PrivateKey: PrivateKeyForge, PublicKey: PublicKeyForge }
const AsymKeyWebCrypto = { PrivateKey: PrivateKeyWebCrypto, PublicKey: PublicKeyWebCrypto }
testAsymKeyImplem('forge', AsymKeyForge, randomBytes)
testAsymKeyImplem('webcrypto', AsymKeyWebCrypto, randomBytes)

testAsymKeyCompatibility('forge/webcrypto', 1024, AsymKeyForge, AsymKeyWebCrypto)
testAsymKeyCompatibility('forge/webcrypto', 2048, AsymKeyForge, AsymKeyWebCrypto)
testAsymKeyCompatibility('forge/webcrypto', 4096, AsymKeyForge, AsymKeyWebCrypto)

testAsymKeyImplem('webcrypto fallback', AsymKeyWebCrypto, randomBytes, disableWebCrypto)

// Utils
testUtilsImplem('forge', utilsForge)
testUtilsImplem('webcrypto', utilsWebCrypto)

testUtilsCompatibility('forge/webcrypto', utilsForge, utilsWebCrypto)

testUtilsImplem('webcrypto fallback', utilsWebCrypto, disableWebCrypto)
