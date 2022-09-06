declare module 'react-native-quick-crypto' {
  export * from 'crypto'
}

declare module 'crypto-browserify' {
  export * from 'crypto'
}

declare module 'stream-browserify' {
  import Stream from 'stream'
  export default Stream
}
