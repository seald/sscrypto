import {
  PrivateKey as PrivateKeyForge,
  PublicKey as PublicKeyForge,
  SymKey as SymKeyForge,
  utils as utilsForge
} from '../forge'
import { SymKey as SymKeyWebCrypto } from '../webcrypto'
import { testSymKeyCompatibility, testSymKeyImplem, testSymKeyPerf } from './aes.spec'
import { testAsymKeyImplem } from './rsa.spec'
import { testUtilsImplem } from './utils.spec'
import { randomBytes } from '../forge/utils'

// SymKey
testSymKeyImplem('forge', SymKeyForge, randomBytes)
testSymKeyImplem('webcrypto', SymKeyWebCrypto, randomBytes)

testSymKeyCompatibility('forge/webcrypto', SymKeyForge, SymKeyWebCrypto, randomBytes)

testSymKeyPerf('forge', SymKeyForge, randomBytes)
testSymKeyPerf('webcrypto', SymKeyWebCrypto, randomBytes)

// @ts-ignore
window.SSCRYPTO_NO_WEBCRYPTO = true
testSymKeyImplem('webcrypto fallback', SymKeyWebCrypto, randomBytes)

// AsymKey
const AsymKeyForge = { PrivateKey: PrivateKeyForge, PublicKey: PublicKeyForge }
testAsymKeyImplem('forge', AsymKeyForge, randomBytes)

// Utils
testUtilsImplem('forge', utilsForge)
