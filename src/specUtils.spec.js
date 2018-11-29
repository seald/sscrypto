import MemoryStream from 'memorystream'

/**
 * Helper function for the tests.
 * @param {Array<Buffer>} chunks - Array of chunks for the input stream
 * @param {Transform|Stream} transformStream - stream.Transform instance
 * @returns {Promise<Buffer>} - Promise that resolves to the output of the transformStream
 */
export const _streamHelper = (chunks, transformStream) => {
  const inputStream = new MemoryStream()
  const outputStream = inputStream.pipe(transformStream)
  let outputBuffer = Buffer.alloc(0)

  const finished = new Promise((resolve, reject) => {
    outputStream.on('end', resolve)
    outputStream.on('error', reject)
  })
  outputStream.on('data', data => {
    outputBuffer = Buffer.concat([outputBuffer, data])
  })

  chunks.forEach(chunk => inputStream.write(chunk))
  inputStream.end()

  return finished.then(() => outputBuffer)
}

/**
 * splits the given string or buffer into chunks of given length
 * @param {string|Buffer} input
 * @param {number} length
 * @return {Array<string|Buffer>}
 */
export const splitLength = (input, length) => {
  const chunks = []
  while (input.length) {
    chunks.push(input.slice(0, length))
    input = input.slice(length)
  }
  return chunks
}
