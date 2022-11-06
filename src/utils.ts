// import { Buff } from '@cmdcode/bytes-utils'
import { Utils as CryptoUtils } from '@cmdcode/crypto-utils'

export default class Utils {
  public static HIGHEST_BIT = 0x80000000
  public static UINT31_MAX  = Math.pow(2, 31) - 1

  public static checkPath(path : string) : boolean { 
    return path.match(/^(m\/)?(\d+['#]?\/)*\d+'?$/) !== null
  }

  public static checkUint31(num : number) : boolean {
    return num <= Utils.UINT31_MAX
  }

  public static toXOnly(pubKey : Uint8Array) : Uint8Array {
    return pubKey.length === 32 ? pubKey : pubKey.slice(1, 33)
  }

  // public static bytesToPath = bytesToPath

  public static checksum = CryptoUtils.checksum

}

// function bytesToPath(data : Uint8Array, prefix? : Uint8Array) {
//   /** 
//    * Convert a hex string into a valid BIP32 key derivation path.
//    * A 'hardened' path must be at most 31 bits in size. A 256-bit 
//    * hash + 8 prefix bits = 264 bits / 3 = 24 bits for each path.
//    **/
//   const arr = [] // Array to store our paths.
//   const idx = 3  // 3 bytes (24 bits).

//   prefix = prefix || Uint8Array.of(0x01)

//   const bytes = Buff.of(...prefix, ...data)

//   if (bytes.length % 3 !== 0) {
//     throw new Error(`Bytes length is invalid: ${bytes.length}`)
//   }

//   for (let i = 0; i < bytes.length; i += idx) {
//     arr.push(bytes.slice(i, i + idx).toNum())
//   }

//   return arr.join('\'/')
// }
