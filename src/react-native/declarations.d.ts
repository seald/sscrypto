declare module 'react-native' {
  namespace NativeModules {
    namespace RNGetRandomValues {
      function getRandomBase64 (byteLength: number): string
    }

    namespace ExpoRandom {
      function getRandomBase64String (byteLength: number): string
    }
  }
}
