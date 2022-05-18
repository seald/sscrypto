'use strict'
/* eslint-disable @typescript-eslint/no-var-requires */

const path = require('path')

module.exports = (config) => ({
  // Increase timeout in case connection in CI is slow
  captureTimeout: 120000,
  browserNoActivityTimeout: 300000,
  browserDisconnectTimeout: 300000,
  browserDisconnectTolerance: 3,

  // frameworks to use
  // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
  frameworks: ['mocha', 'fixture', 'source-map-support'],

  // list of files / patterns to load in the browser
  files: [
    'tests/test-browser.built.spec.js'
  ],

  // test results reporter to use
  // possible values: 'dots', 'progress'
  // available reporters: https://npmjs.org/browse/keyword/karma-reporter
  reporters: ['progress', 'junit', 'coverage-istanbul'],

  coverageIstanbulReporter: {
    // reports can be any that are listed here: https://github.com/istanbuljs/istanbuljs/tree/73c25ce79f91010d1ff073aa6ff3fd01114f90db/packages/istanbul-reports/lib
    reports: ['html', 'text', 'cobertura', 'text-summary'],
    // base output directory. If you include %browser% in the path it will be replaced with the karma browser name
    dir: path.join(__dirname, 'coverage', '%browser%'),
    // Combines coverage information from multiple browsers into one report rather than outputting a report
    // for each browser.
    combineBrowserReports: false,
    // if using webpack and pre-loaders, work around webpack breaking the source path
    fixWebpackSourcePaths: true,
    // Omit files with no statements, no functions and no branches covered from the report
    skipFilesWithNoCoverage: true,
    verbose: true // output config used by istanbul for debugging
  },

  junitReporter: {
    outputDir: 'test-results', // results will be saved as $outputDir/$browserName.xml
    useBrowserName: true // add browser name to report and classes names
  },

  // Continuous Integration mode
  // if true, Karma captures browsers, runs the tests and exits
  singleRun: true,

  // web server port
  port: 9876,

  // enable / disable colors in the output (reporters and logs)
  colors: true,

  // level of logging
  // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
  logLevel: config.LOG_INFO,

  // enable / disable watching file and executing tests whenever any file changes
  autoWatch: false,

  // Concurrency level
  // how many browser should be started simultaneous
  concurrency: 1,

  // base path that will be used to resolve all patterns (eg. files, exclude)
  basePath: '',

  // list of files to exclude
  exclude: []
})
