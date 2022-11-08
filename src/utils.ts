// import { Buff } from '@cmdcode/bytes-utils'
const HIGHEST_BIT = 0x80000000
const UINT31_MAX  = Math.pow(2, 31) - 1

const checkPath = (path : string) : boolean => { 
  return path.match(/^(m\/)?(\d+['#]?\/)*\d+'?$/) !== null
}

const checkUint31 = (num : number) : boolean => {
  return num <= UINT31_MAX
}

const toXOnly = (pubKey : Uint8Array) : Uint8Array => {
  return pubKey.length === 32 ? pubKey : pubKey.slice(1, 33)
}

export {
  HIGHEST_BIT,
  UINT31_MAX,
  checkPath,
  checkUint31,
  toXOnly
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
