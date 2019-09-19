import {
  PrivateKey as PrivateKeyForge,
  PublicKey as PublicKeyForge,
  SymKey as SymKeyForge,
  utils as utilsForge
} from '../forge'
import { testSymKeyImplem } from './aes.spec'
import { testAsymKeyImplem } from './rsa.spec'
import { testUtilsImplem } from './utils.spec'
import { randomBytes } from '../forge/utils'

// SymKey
testSymKeyImplem('forge', SymKeyForge, randomBytes)

// AsymKey
const AsymKeyForge = { PrivateKey: PrivateKeyForge, PublicKey: PublicKeyForge }
testAsymKeyImplem('forge', AsymKeyForge, randomBytes)

// Utils
testUtilsImplem('forge', utilsForge)
