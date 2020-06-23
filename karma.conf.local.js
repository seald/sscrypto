'use strict'
/* eslint-disable @typescript-eslint/no-var-requires */

const template = require('./karma.conf.template.js')

module.exports = function (config) {
  const localBrowser = {
    ChromeHeadlessNoSandbox: {
      base: 'ChromeHeadless',
      flags: ['--no-sandbox']
    }
  }

  config.set(Object.assign({}, template(config), {
    customLaunchers: localBrowser,
    browsers: Object.keys(localBrowser),
    // browsers: ['FirefoxHeadless'],
    // browsers: ['Safari'],

    junitReporter: {
      outputDir: 'test-results', // results will be saved as $outputDir/$browserName.xml
      useBrowserName: true // add browser name to report and classes names
    },

    reporters: ['progress', 'junit']
  }))
}
