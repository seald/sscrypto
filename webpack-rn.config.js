/* eslint-disable @typescript-eslint/no-var-requires */
const path = require('path')
const webpack = require('webpack')

const basename = s => path.basename(s, path.extname(s))
module.exports = () => {
  return {
    mode: 'production',
    cache: false,
    watch: false,
    target: 'web',
    node: {
      global: true
    },
    optimization: {
      minimize: false
    },
    entry: {
      testRn: path.join(__dirname, 'tests', 'test-rn.spec.js')
    },
    externals: ['react-native', 'react-native-modpow', 'react-native-get-random-values', 'react-native-rsa-native', 'react-native-cryptopp', 'react-native-quick-crypto', 'react-native-quick-base64', '@craftzdog/react-native-buffer'],
    output: {
      library: {
        type: 'commonjs2',
        export: 'default'
      },
      path: path.resolve(__dirname, 'tests'),
      filename: (pathData) => basename(pathData.chunk.entryModule.resource) + '.bundle.js' // trick to get the original file name
    },
    devtool: 'source-map',
    resolve: {
      aliasFields: ['react-native', 'browser', 'main'],
      fallback: {
        assert: require.resolve('assert/'), // necessary for tests
        util: require.resolve('util/'), // necessary for promisify
        stream: require.resolve('stream-browserify'),
        crypto: false
      }
    },
    plugins: [
      new webpack.ProvidePlugin({
        process: require.resolve('process/browser'), // necessary for `process.nextTick` in streams
        Buffer: ['@craftzdog/react-native-buffer', 'Buffer'], // necessary, well, everywhere ^^
        setImmediate: ['timers-browserify', 'setImmediate'], // necessary for streams
        clearImmediate: ['timers-browserify', 'clearImmediate']
      })
    ]
  }
}