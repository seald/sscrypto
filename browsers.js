'use strict'

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

module.exports = browsers
