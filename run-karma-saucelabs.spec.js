'use strict'
/* eslint-env mocha */
/* eslint-disable @typescript-eslint/no-var-requires */

const childProcess = require('child_process')
const browsers = require('./browsers.js')
const { connectTunnel, disconnectTunnel } = require('./saucelabs-tunnel-utils.spec.js')

// I have to use this helper script because if I start karma with more than one browser at a time on saucelabs, it hangs...

const tunnelIdentifier = `SSCRYPTO-${Math.floor(Math.random() * 10e10)}`

const username = process.env.SAUCE_USERNAME
const accessKey = process.env.SAUCE_ACCESS_KEY

if (!username || !accessKey) {
  console.error('Missing saucelabs credentials')
  process.exit(1)
}

const run = (browser) => {
  const cp = childProcess.spawn(
    'npx',
    ['karma', 'start', 'karma.conf.saucelabs.js'],
    {
      env: {
        ...process.env,
        SSCRYPTO_KARMA_BROWSER: browser, // which browser to run
        SSCRYPTO_KARMA_SAUCE_TUNNEL: tunnelIdentifier
      }
    }
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

before(async function () {
  this.timeout(60000)
  await Promise.all([
    connectTunnel(username, accessKey, tunnelIdentifier)
  ])
})

after(async function () {
  this.timeout(30000)
  await disconnectTunnel()
})

describe('Karma-saucelabs', function () {
  this.timeout(300000)

  for (const browser of Object.keys(browsers)) {
    it(browser, async function () {
      await run(browser)
    })
  }
})
