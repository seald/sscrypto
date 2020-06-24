'use strict'
/* eslint-disable @typescript-eslint/no-var-requires */

const path = require('path')

module.exports = (env, argv) => {
  return {
    mode: argv.mode,
    cache: false,
    watch: false,
    entry: {
      test: path.join(__dirname, 'tests', 'test-browser.spec.js')
    },
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
