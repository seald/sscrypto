// RN URL has a lots of know issues. So we have to polyfill it.
import 'react-native-url-polyfill/auto' // we have to do this before forge

import type { BigInteger } from 'jsbn'
import Forge from 'node-forge'
import modPow from 'react-native-modpow'
import { NativeModules } from 'react-native'

const isChromeDebugger = (): boolean => {
  // https://github.com/facebook/react-native/commit/417e191a1cfd6a049d1d4b0a511f87aa7f176082
  return typeof global.nativeCallSyncHook === 'undefined'
}

// We don't use index.js of react-native-get-random-values because it modifies the global namespace, we directly use the
// native module like the original module does (https://github.com/LinusU/react-native-get-random-values/blob/master/index.js)
// Copied under MIT License

// MIT License
//
// Copyright (c) 2018, 2020 Linus Unnebäck
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
//   The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
const getRandomBase64 = (byteLength: number) => {
  if (NativeModules.RNGetRandomValues) {
    return NativeModules.RNGetRandomValues.getRandomBase64(byteLength)
  } else {
    throw new Error('Please install react-native-get-random-values')
  }
}

// Necessary stuff because node-forge typings are incomplete...
declare module 'node-forge' {
  namespace random { // eslint-disable-line @typescript-eslint/no-namespace
    function collect(rand: string): void

    function seedFileSync(needed: number): string

    function seedFile(needed: number, callback: (err: Error, rand: string) => void): void
  }
}

// in Chrome debugger, do not use patches with synchronous native modules : they do not work
if (!isChromeDebugger()) {
  // native-modpow to accelerate RSA encryption
  (Forge.jsbn.BigInteger as unknown as typeof BigInteger).prototype.modPow = function nativeModPow (e: BigInteger, m: BigInteger) {
    const result = modPow({
      target: this.toString(16),
      value: e.toString(16),
      modifier: m.toString(16)
    })

    return new (Forge.jsbn.BigInteger as unknown as typeof BigInteger)(result, 16)
  }

  // proper entropy for forge's prng
  Forge.random.collect(Buffer.from(getRandomBase64(1024), 'base64').toString('binary'))
  Forge.random.seedFileSync = function (needed) {
    return Buffer.from(getRandomBase64(needed)).toString('binary')
  }
  Forge.random.seedFile = function (needed: number, callback) {
    callback(null, Buffer.from(getRandomBase64(needed)).toString('binary'))
  }
}
