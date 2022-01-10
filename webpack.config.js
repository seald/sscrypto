'use strict'
/* eslint-disable @typescript-eslint/no-var-requires */

const path = require('path')
const webpack = require('webpack')

module.exports = (env, argv) => {
  return {
    mode: argv.mode,
    cache: false,
    watch: false,
    entry: {
      test: path.join(__dirname, 'tests', 'test-browser.spec.js')
    },
    resolve: {
      fallback: {
        util: require.resolve('util/'),
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
    ],
    module: {
      rules: [
        {
          test: /\.js$/,
          enforce: 'pre',
          use: ['source-map-loader']
        },
        {
          exclude: [/node_modules/],
          use: ['@jsdevtools/coverage-istanbul-loader']
        }
      ]
    },
    output: {
      path: path.join(__dirname, 'tests'),
      filename: 'test-browser.built.spec.js'
    },
    devtool: 'source-map'
  }
}
