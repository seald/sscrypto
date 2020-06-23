'use strict'
/* eslint-env mocha */
/* eslint-disable @typescript-eslint/no-var-requires */

const childProcess = require('child_process')
const browsers = require('./browsers.js')

// I have to use this helper script because if I start karma with more than one browser at a time on saucelabs, it hangs...

// TODO: single karma instance & saucelabs proxy
const run = (browser) => {
  const cp = childProcess.spawn(
    'npx',
    ['karma', 'start', 'karma.conf.saucelabs.js'],
    { env: { SSCRYPTO_KARMA_BROWSER: browser, ...process.env } } // which browser to run
  )
  cp.stdout.pipe(process.stdout)
  cp.stderr.pipe(process.stderr)
  return new Promise((resolve, reject) => {
    cp.once('close', exitCode => {
      if (exitCode) reject(new Error('Test failed'))
      else resolve()
    })
  })
}

describe('Karma-saucelabs', function () {
  this.timeout(300000)

  for (const browser of Object.keys(browsers)) {
    it(browser, async function () {
      await run(browser)
    })
  }
})
