/* eslint-disable @typescript-eslint/no-var-requires */
const path = require('path')
const webpack = require('webpack')

const basename = s => path.basename(s, path.extname(s))
// react, modpow, async-storage => Peer dependencies, don't bundle it !
// react-native/[...]/PolyfillFunctions => Direct import from our polyfill of URL.
module.exports = () => {
  return {
    mode: 'production',
    cache: false,
    watch: false,
    target: 'web',
    node: {
      global: true
    },
    entry: {
      testRn: path.join(__dirname, 'tests', 'test-rn.spec.js')
    },
    externals: ['react-native', 'react-native-modpow', 'react-native-get-random-values', 'react-native-rsa-native', 'react-native-url-polyfill/auto', 'react-native/Libraries/Utilities/PolyfillFunctions'],
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
      alias: {
        // TODO: probably removable ?
        punycode: require.resolve('punycode/') // To force using the CJS version. We keep punycode@^2.1.1 in devDependencies to ensure the latest version is bundled (url/ formally depends on a the v1.x.x, but the v2 is non-breaking in this environment).
      },
      aliasFields: ['react-native', 'browser', 'main'],
      fallback: {
        // TODO: check which dependencies are removable
        assert: require.resolve('assert/'),
        fs: false,
        path: require.resolve('path-browserify'),
        events: require.resolve('events/'),
        constants: require.resolve('constants-browserify'),
        os: require.resolve('os-browserify/browser'),
        util: require.resolve('util/'),
        url: require.resolve('url/'),
        stream: require.resolve('stream-browserify'),
        crypto: false
      }
    },
    plugins: [
      new webpack.ProvidePlugin({
        process: require.resolve('process/browser'),
        Buffer: ['buffer', 'Buffer'],
        setImmediate: ['timers-browserify', 'setImmediate'],
        clearImmediate: ['timers-browserify', 'clearImmediate']
      })
    ]
  }
}
