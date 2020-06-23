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

const browser = process.env.SSCRYPTO_KARMA_BROWSER
const tunnelIdentifier = process.env.SSCRYPTO_KARMA_SAUCE_TUNNEL
const username = process.env.SAUCE_USERNAME
const accessKey = process.env.SAUCE_ACCESS_KEY

if (!username || !accessKey || !browser || !tunnelIdentifier) {
  console.error('Missing arguments')
  process.exit(1)
}

module.exports = function (config) {
  // Karma conf
  config.set(Object.assign({}, template(config), {

    customLaunchers: browsers_,
    browsers: Object.keys(browsers_).filter(b => b === browser),

    sauceLabs: {
      testName: `${tunnelIdentifier} - ${browser}`,
      username,
      accessKey,
      // Somehow, forcing european saucelabs datacenter does not work at all
      // connectLocationForSERelay: 'ondemand.eu-central-1.saucelabs.com',
      tunnelIdentifier,
      startConnect: false, // the tunnel is already connected
      idleTimeout: 300 /* s */ // tests are run with a single command, and it can take a while
    },
    pingTimeout: 10000, /* ms */

    reporters: ['progress', 'saucelabs', 'junit', 'coverage']
  }))
}
