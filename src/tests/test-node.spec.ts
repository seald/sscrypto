import { testSymKeyCompatibility, testSymKeyImplem, testSymKeyPerf } from './aes.spec'
import { testAsymKeyCompatibility, testAsymKeyImplem, testAsymKeyPerf } from './rsa.spec'
import { testUtilsCompatibility, testUtilsImplem } from './utils.spec'
import { randomBytes } from 'crypto'
import { assertType } from './specUtils.spec'
import { SSCrypto, node, forge } from '../index'

// Test types
assertType<SSCrypto>(node)
assertType<SSCrypto>(forge)

// SymKey
testSymKeyImplem('node', node.SymKey, randomBytes)
testSymKeyImplem('forge', forge.SymKey, randomBytes)

testSymKeyCompatibility('node/forge', node.SymKey, forge.SymKey, randomBytes)

testSymKeyPerf('node', node.SymKey, randomBytes)
testSymKeyPerf('forge', forge.SymKey, randomBytes)

testAsymKeyImplem('node', node, randomBytes)
testAsymKeyImplem('forge', forge, randomBytes)

testAsymKeyCompatibility('node/forge', node, forge)
testAsymKeyCompatibility('forge/node', forge, node)

testAsymKeyPerf('node', 1024, node, randomBytes)
testAsymKeyPerf('node', 2048, node, randomBytes)
// testAsymKeyPerf('node', 4096, node, randomBytes) // this is a bit long, so we disable it by default
testAsymKeyPerf('forge', 1024, forge, randomBytes)
testAsymKeyPerf('forge', 2048, forge, randomBytes)
// testAsymKeyPerf('forge', 4096, forge, randomBytes)

// Utils
testUtilsImplem('node', node.utils)
testUtilsImplem('forge', forge.utils)

testUtilsCompatibility('node/forge', node.utils, forge.utils)
