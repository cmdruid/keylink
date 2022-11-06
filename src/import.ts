import * as ecc from 'tiny-secp256k1'
import { Buff, Stream } from '@cmdcode/bytes-utils'
import { Hash } from '@cmdcode/crypto-utils'
import { getConfig } from './config.js'
import KeyRing from './index.js'

const ec = new TextEncoder()

export default class KeyImport {

  static DEFAULT_TYPE : string = 'bitcoin'

  static fromBase58(
    b58string : string,
    keytype = KeyImport.DEFAULT_TYPE
  ) : KeyRing {

    const buffer = new Stream(Buff.base58(b58string))

    if (buffer.size !== 78) {
      // Base58 imports must be 78 bytes long.
      throw new TypeError('Invalid buffer length')
    }

    // Fetch configuration for imported key.
    const config = getConfig(keytype)

    // Parse version number: 4 bytes.
    const version = buffer.read(4).toNum()

    if (version !== config.version.private && version !== config.version.public) {
      throw new TypeError('Invalid version number for key type: ' + keytype)
    }

    // Parse depth: 1 byte [0x00] for master nodes, [0x01+] for descendants.
    const depth = buffer.read(1).toNum()

    // Parse parent key fingerprint: 4 bytes (0x00000000 if master key).
    // Only used for quicker indexing.
    const fprint = buffer.read(4).toNum()

    if (depth === 0 && fprint !== 0x00000000) {
      throw new TypeError('Invalid parent fingerprint for depth: 0')
    }

    // Parse child index: 4 bytes (0x00000000 if master key).
    // This is the number i in xi = xpar/i, with xi the key being serialized.
    const index = buffer.read(4)

    if (depth === 0 && index.toNum() !== 0) {
      throw new TypeError('Invalid index for depth: 0')
    }

    // Parse chain code: 32 bytes.
    const chaincode = buffer.read(32)

    // Parse key data: 33 bytes.
    if (version === config.version.private) {
      if (buffer.peek(1).toNum() !== 0x00) {
        throw new TypeError('Private key must start with: 0x00')
      }
      const key = buffer.read(33)
      return KeyImport.fromPrivateKeyLocal(key, chaincode, keytype, index, depth, fprint)
      // 33 bytes: public key data (0x02 + X or 0x03 + X)
    }
    else {
      if (![0x02, 0x03].includes(buffer.peek(1).toNum())) {
        throw new TypeError('Public key must start with: 0x02 || 0x03')
      }
      const key = buffer.read(33)
      return KeyImport.fromPublicKeyLocal(key, chaincode, keytype, index, depth, fprint)
    }
  }
  
  static fromPrivateKey(
    privateKey : Uint8Array,
    chaincode  : Uint8Array,
    keytype    : string
  ) : KeyRing {
    return KeyImport.fromPrivateKeyLocal(privateKey, chaincode, keytype)
  }
  
  static fromPrivateKeyLocal(
    privateKey : Uint8Array,
    chaincode  : Uint8Array,
    keytype    : string,
    index?     : Uint8Array,
    depth?     : number,
    fprint?    : number
  ) : KeyRing {
    // typeforce({
    //     privateKey: UINT256_TYPE,
    //     chainCode: UINT256_TYPE,
    // }, { privateKey, chainCode });
    if (!ecc.isPrivate(privateKey))
        throw new TypeError('Private key not in range [1, n)')
    return new KeyRing(privateKey, null, chaincode, keytype, index, depth, fprint)
  }
  

  static fromPublicKey(
    publicKey : Uint8Array,
    chaincode : Uint8Array, 
    keytype   : string
  ) : KeyRing {
    return KeyImport.fromPublicKeyLocal(publicKey, chaincode, keytype)
  }

  static fromPublicKeyLocal(
    publicKey : Uint8Array,
    chaincode : Uint8Array,
    keytype   : string,
    index?    : Uint8Array,
    depth?    : number,
    fprint?   : number
  ) : KeyRing {
    // typeforce({
    //     publicKey: typeforce.BufferN(33),
    //     chainCode: UINT256_TYPE,
    // }, { publicKey, chainCode });
    // verify the X coordinate is a point on the curve
    if (!ecc.isPoint(publicKey))
        throw new TypeError('Point is not on the curve');
    return new KeyRing(publicKey, null, chaincode, keytype, index, depth, fprint)
  }

  static async fromSeed(
    seed   : Uint8Array,
    config = KeyImport.DEFAULT_TYPE
  ) : Promise<KeyRing> {
    if (seed.length < 16 || seed.length > 64) {
      throw new TypeError('Seed should be at least 128 bits, and at most 512 bits.')
    }
    const I = await Hash.hmac512(ec.encode('Bitcoin seed'), seed)
    const IL = I.slice(0, 32)
    const IR = I.slice(32)
    return KeyImport.fromPrivateKey(IL, IR, config)
  }
}
