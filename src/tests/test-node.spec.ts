import {
  PrivateKey as PrivateKeyNode,
  PublicKey as PublicKeyNode,
  SymKey as SymKeyNode,
  utils as utilsNode
} from '../node'
import {
  PrivateKey as PrivateKeyForge,
  PublicKey as PublicKeyForge,
  SymKey as SymKeyForge,
  utils as utilsForge
} from '../forge'
import { testSymKeyCompatibility, testSymKeyImplem, testSymKeyPerf } from './aes.spec'
import { testAsymKeyCompatibility, testAsymKeyImplem } from './rsa.spec'
import { testUtilsCompatibility, testUtilsImplem } from './utils.spec'
import { randomBytes } from 'crypto'

// SymKey
testSymKeyImplem('node', SymKeyNode, randomBytes)
testSymKeyImplem('forge', SymKeyForge, randomBytes)

testSymKeyCompatibility('node/forge', SymKeyNode, SymKeyForge, randomBytes)

testSymKeyPerf('node', SymKeyNode, randomBytes)
testSymKeyPerf('forge', SymKeyForge, randomBytes)

// AsymKey
const AsymKeyNode = { PrivateKey: PrivateKeyNode, PublicKey: PublicKeyNode }
const AsymKeyForge = { PrivateKey: PrivateKeyForge, PublicKey: PublicKeyForge }

testAsymKeyImplem('node', AsymKeyNode, randomBytes)
testAsymKeyImplem('forge', AsymKeyForge, randomBytes)

testAsymKeyCompatibility('node/forge', 1024, AsymKeyNode, AsymKeyForge)
testAsymKeyCompatibility('node/forge', 2048, AsymKeyNode, AsymKeyForge)
testAsymKeyCompatibility('node/forge', 4096, AsymKeyNode, AsymKeyForge)

// Utils
testUtilsImplem('node', utilsNode)
testUtilsImplem('forge', utilsForge)

testUtilsCompatibility('node/forge', utilsNode, utilsForge)
