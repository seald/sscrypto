'use strict'
/* eslint-disable @typescript-eslint/no-var-requires */

const sauceConnector = require('sauce-connect-launcher')
const { promisify } = require('util')
const path = require('path')

const sauceConnect = promisify(sauceConnector)

let sauceConnectProcess = null

const connectTunnel = async (username, accessKey, tunnelIdentifier) => {
  console.log(`Connecting SauceLabs tunnel ${tunnelIdentifier}...`)
  sauceConnectProcess = await sauceConnect({
    username: username,
    accessKey: accessKey,
    tunnelIdentifier: tunnelIdentifier,
    logfile: path.resolve(__dirname, '../sauceconnect.log')
    // 'no-ssl-bump-domains': 'all' // Otherwise crossbar websocket won't connect
  })
  console.log('Sauce Connect ready, tunnel id:', tunnelIdentifier)
}

const disconnectTunnel = () => new Promise((resolve) => {
  sauceConnectProcess.close(() => {
    console.log('Closed Sauce Connect process')
    resolve()
  })
})

module.exports = {
  connectTunnel,
  disconnectTunnel
}
