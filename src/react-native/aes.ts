import SymKeyForge from '../forge/aes'
import { randomBytes, randomBytesAsync } from './utils'

// TODO: https://github.com/tectiv3/react-native-aes
class SymKeyRN extends SymKeyForge {
  static randomBytesAsync_ (size: number): Promise<Buffer> {
    return randomBytesAsync(size)
  }

  static randomBytesSync_ (size: number): Buffer {
    return randomBytes(size)
  }
}

export default SymKeyRN
