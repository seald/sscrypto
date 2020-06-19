'use strict'
/* eslint-disable @typescript-eslint/no-var-requires */

const template = require('./karma.conf.template.js')

// Browsers to run on Sauce Labs
// Check out https://saucelabs.com/platforms for all browser/OS combos

const browsers = {
  /* *********** SAFARI ************ */
  macOS_safari_latest: {
    platform: 'macOS 10.15',
    browser: 'safari',
    version: 'latest'
  },

  /* *********** CHROME ************ */
  w10_chrome: {
    platform: 'Windows 10',
    browser: 'chrome',
    version: 'latest'
  },
  macOS_chrome: {
    platform: 'macOS 10.15',
    browser: 'chrome',
    version: 'latest'
  },
  /* *********** FIREFOX ************* */
  // LATEST
  w10_firefox: {
    platform: 'Windows 10',
    browser: 'firefox',
    version: 'latest'
  },
  macOS_firefox: {
    platform: 'macOS 10.15',
    browser: 'firefox',
    version: 'latest'
  },
  // Current LTS
  macOS_firefox_ESR: {
    platform: 'macOS 10.15',
    browser: 'firefox',
    version: '68'
  },
  // Last non quantum
  macOS_firefox_56: {
    platform: 'macOS 10.15',
    browser: 'firefox',
    version: '56'
  },
  /* *********** IE ************** */
  w10_ie_11: {
    platform: 'Windows 10',
    browser: 'internet explorer',
    version: 'latest'
  },

  /* ********* EDGE ************ */
  w10_edge: {
    platform: 'Windows 10',
    browser: 'MicrosoftEdge',
    version: 'latest'
  },
  // Supported non-chromium edge... Yeah, they are still supported
  w10_edge_18: {
    platform: 'Windows 10',
    browser: 'microsoftedge',
    version: '18'
  },
  w10_edge_17: {
    platform: 'Windows 10',
    browser: 'microsoftedge',
    version: '17'
  },
  w10_edge_16: {
    platform: 'Windows 10',
    browser: 'microsoftedge',
    version: '16'
  },
  w10_edge_15: {
    platform: 'Windows 10',
    browser: 'microsoftedge',
    version: '15'
  }
}

const browsers_ = Object.fromEntries(
  Object.entries(browsers)
    .map(([key, { platform, browser, version }]) => ([key, {
      base: 'SauceLabs',
      platform,
      browserName: browser,
      version
      // extendedDebugging: true
    }]))
)
console.log('BROWSERS:', browsers_)

const rand = Math.floor(Math.random() * 10e10)

const tunnelIdentifier = `SSCRYPTO${rand}`

module.exports = function (config) {
  // Karma conf
  config.set(Object.assign({}, template(config), {

    customLaunchers: browsers_,
    browsers: Object.keys(browsers_),

    sauceLabs: {
      testName: `SSCrypto test ${rand}`,
      username: process.env.SAUCE_USERNAME, // process.env.SAUCE_USERNAME
      accessKey: process.env.SAUCE_ACCESS_KEY, // process.env.SAUCE_ACCESS_KEY
      // Somehow, forcing european saucelabs datacenter does not work at all
      // connectLocationForSERelay: 'ondemand.eu-central-1.saucelabs.com',
      tunnelIdentifier,
      idleTimeout: 300 // tests are run with a single command, and it can take a while
    },

    junitReporter: {
      outputDir: 'test-results', // results will be saved as $outputDir/$browserName.xml
      useBrowserName: true // add browser name to report and classes names
    },

    reporters: ['progress', 'saucelabs', 'junit']
  }))
}
