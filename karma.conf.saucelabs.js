'use strict'
/* eslint-disable @typescript-eslint/no-var-requires */

const template = require('./karma.conf.template.js')
const browsers = require('./browsers.js')

const browsers_ = Object.fromEntries( // convert format for selenium (so we can copy/paste from other projects) to format for karma
  Object.entries(browsers)
    .map(([key, { platform, browser, version }]) => ([key, {
      base: 'SauceLabs',
      platform,
      browserName: browser,
      version
    }]))
)

const rand = Math.floor(Math.random() * 10e10)

const browser = process.env.SSCRYPTO_KARMA_BROWSER || Object.keys(browsers)[0]
const username = process.env.SAUCE_USERNAME
const accessKey = process.env.SAUCE_ACCESS_KEY

if (!username || !accessKey) {
  console.error('Missing saucelabs credentials')
  process.exit(1)
}

const tunnelIdentifier = `SSCRYPTO-${browser}-${rand}`

module.exports = function (config) {
  // Karma conf
  config.set(Object.assign({}, template(config), {

    customLaunchers: browsers_,
    browsers: Object.keys(browsers_).filter(b => b === browser),

    sauceLabs: {
      testName: `SSCrypto ${browser} - test ${rand}`,
      username,
      accessKey,
      // Somehow, forcing european saucelabs datacenter does not work at all
      // connectLocationForSERelay: 'ondemand.eu-central-1.saucelabs.com',
      tunnelIdentifier,
      idleTimeout: 300 /* s */ // tests are run with a single command, and it can take a while
    },
    pingTimeout: 10000, /* ms */

    junitReporter: {
      outputDir: 'test-results', // results will be saved as $outputDir/$browserName.xml
      useBrowserName: true // add browser name to report and classes names
    },

    reporters: ['progress', 'saucelabs', 'junit']
  }))
}
