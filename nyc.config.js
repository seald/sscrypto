'use strict'

module.exports = {
  include: [
    'src/**/*.ts'
  ],
  exclude: [
    'src/tests/**/*.ts',
    '**/*.d.ts'
  ],
  all: true,
  'report-dir': './coverage/node-' + parseInt(process.versions.node), // parseInt so we only get major
  reporter: [
    'html',
    'text',
    'text-summary',
    'cobertura'
  ],
  excludeAfterRemap: false
}
