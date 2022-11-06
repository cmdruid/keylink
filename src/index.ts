import * as ecc  from 'tiny-secp256k1'
import { Buff }  from '@cmdcode/bytes-utils'
import { Hash }  from '@cmdcode/crypto-utils'
import Utils     from './utils.js'
import KeyImport from './import.js'
import KeySign   from './signer.js'

import { KeyConfig, getConfig } from './config.js'

export default class KeyRing extends KeySign {

  private __chain  : Uint8Array
  private __index  : Uint8Array
  private __depth  : number
  private __fprint : number
  private config   : KeyConfig

  constructor(
    prvKey  : Uint8Array | null,
    pubKey  : Uint8Array | null,
    chain   : Uint8Array,
    keytype : string,
    index  = new Uint8Array([0x00]),
    depth  = 0,
    fprint = 0x00000000
  ) {
    super(prvKey, pubKey)
    this.__chain  = chain
    this.__index  = index
    this.__depth  = depth
    this.__fprint = fprint
    this.config = getConfig(keytype)
  }

  get chaincode() {
    return this.__chain
  }

  get depth() {
    return this.__depth
  }

  get index() {
    return this.__index
  }

  get fprint() {
    return this.__fprint
  }

  get identifier() {
    return Hash.ripe160(this.publicKey)
  }

  get fingerprint() {
    return Buff.buff(this.identifier.slice(0, 4)).toNum()
  }

  get compressed() {
    return true
  }

  isNeutered() {
    return this.privateKey === null
  }

  neutered() {
    return KeyImport.fromPublicKeyLocal(
      this.publicKey,
      this.chaincode,
      this.config.name,
      this.index,
      this.depth,
      this.fprint
    )
  }

  toBase58() {
    const version = !this.isNeutered()
      ? this.config.version.private
      : this.config.version.public
    const buffer = Buff.buff(new ArrayBuffer(78))
    // 4 bytes = version
    buffer.write(Buff.num(version, 4), 0)
    // 1 byte = depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
    buffer.write(Buff.num(this.depth, 1), 4)
    // 4 bytes = parentFp: fingerprint of the parent's key (0x00000000 if master key)
    buffer.write(Buff.num(this.fingerprint, 4), 5)
    // 4 bytes = index: child index number (i) in xi = xpar/i, with xi the key being serialized.
    // This is encoded in big endian. (0x00000000 if master key)
    buffer.write(this.index, 9)
    // 32 bytes = chainCode: the chain code
    buffer.write(this.chaincode, 13)
    // 33 bytes: the public key or private key data
    if (!this.isNeutered() && this.privateKey) {
      // 0x00 + k for private keys
      buffer.write(Buff.num(0), 45)
      buffer.write(this.privateKey, 46)
    }
    else {
      // 33 bytes: the public key
      // X9.62 encoding for public keys
      buffer.write(this.publicKey, 45)
    }
    return buffer.toBase58()
  }

  async toWIF() {
    if (!this.privateKey) {
      throw new TypeError('Missing private key')
    }
    const buffer = Buff.buff(new ArrayBuffer(34))
    // Write WIF version byte: 1 byte.
    buffer.write(Buff.num(this.config.wif), 0)
    // Write private key: 33 bytes.
    buffer.write(this.privateKey, 1)
    // Write compression flag: 1 byte.
    buffer.write(Buff.num(0x01), 33)
    // Write hash256 checksum: 4 bytes.
    buffer.write(await Utils.checksum(buffer), 34)
    return buffer.toBase58()
  }

  // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions

  async derive(
    buffer : Uint8Array, 
    isPrivate = false
  ) : Promise<KeyRing> {
    const data = Buff.buff(new ArrayBuffer(33 + buffer.length))

    // TODO: Add better checks for proper 
    // formatting of private/public keys.

    if (isPrivate) {
      if (!this.privateKey) {
        throw TypeError('Missing private key for hardened child key')
      }
      if (buffer[0] < 0x80) {
        buffer.set([ buffer[0] + 0x80 ])
      }
      data.write(this.privateKey, 0)
      data.write(buffer, 33)
    }
    else {
      if (buffer[0] >= 0x80) {
        buffer.set([ buffer[0] - 0x80 ])
      }
      // Normal child
      data.write(this.publicKey, 0)
      data.write(buffer, 33)
    }

    const I = await Hash.hmac512(this.chaincode, data)
    const IL = I.slice(0, 32)
    const IR = I.slice(32)

    // If IL value >= N, then use the next index value.
    if (!ecc.isPrivate(IL)) {
      return this.derive(incrementBuffer(buffer))
    }

    // Private parent key -> private child key
    if (!this.isNeutered() && this.privateKey) {
        // ki = parse256(IL) + kpar (mod n)
        const ki = ecc.privateAdd(this.privateKey, IL)
        // If ki == 0, then use the next index value.
        if (ki == null)
            return this.derive(incrementBuffer(buffer))
        return KeyImport.fromPrivateKeyLocal(ki, IR, this.config.name, buffer, this.depth + 1, this.fprint)
        // Public parent key -> public child key
    }
    else {
        // Ki = point(parse256(IL)) + Kpar
        //    = G*IL + Kpar
        const Ki = ecc.pointAddScalar(this.publicKey, IL, true)
        // In case Ki is the point at infinity, proceed with the next value for i
        if (Ki === null)
            return this.derive(incrementBuffer(buffer))
        return KeyImport.fromPublicKeyLocal(Ki, IR, this.config.name, buffer, this.depth + 1, this.fprint)
    }
  }
  async deriveIndex(index : number) {
    return this.derive(Buff.num(index), false)
  }
  async deriveHardIndex(index : number) {
    // typeforce(Uint31, index)
    // Only derives hardened private keys by default
    return this.derive(Buff.num(index + Utils.HIGHEST_BIT), true)
  }
  async deriveHash(index : Uint8Array) {
    return this.derive(index, false)
  }
  async deriveHardHash(index : Uint8Array) {
    return this.derive(index, true)
  }
  async derivePath(path : string) {
    // typeforce(BIP32Path, path)
    let splitPath = path.split('/')
    if (splitPath[0] === 'm') {
      if (this.fprint) {
        throw new TypeError('Expected master, got child')
      }
      splitPath = splitPath.slice(1)
    }

    let self : KeyRing = this

    for (const path of splitPath) {
      if (path.slice(-1) === `#`) {
        // Parse a hashed path. 
        if (path.slice(-2) === `'`) {
          let buffer = Buff.hex(path.slice(0, -2))
          self = await self.deriveHardHash(buffer)
        } else {
          let buffer = Buff.hex(path.slice(0, -1))
          self = await self.deriveHash(buffer)
        }
      }
      else if (path.slice(-1) === `'`) {
        // Parse a hardened path.
        let index = parseInt(path.slice(0, -1), 10)
        self = await self.deriveHardIndex(index)
      }
      else {
        // Parse a non-hardened path.
        let index = parseInt(path, 10)
        self = await self.deriveIndex(index)
      }
    }
    return self
  }
  tweak(t : Uint8Array) : KeyRing {
    if (this.privateKey)
      return this.tweakFromPrivateKey(t)
    return this.tweakFromPublicKey(t)
  }
  tweakFromPublicKey(t : Uint8Array) : KeyRing {
    const xOnlyPubKey = Utils.toXOnly(this.publicKey)
    const tweakedPublicKey = ecc.xOnlyPointAddTweak(xOnlyPubKey, t)
    if (!tweakedPublicKey || tweakedPublicKey.xOnlyPubkey === null) {
      // The tweak value produces an invalid result (point at infinity).
      throw new Error('Cannot tweak public key!')
    }
    const parityByte = tweakedPublicKey.parity === 0 
      ? 0x02
      : 0x03
    const tweakedPublicKeyCompresed = Uint8Array.of(
      parityByte, 
      ...tweakedPublicKey.xOnlyPubkey
    )
    return new KeyRing(null, tweakedPublicKeyCompresed, this.chaincode, this.config.name, this.index, this.depth, this.fprint)
  }
  tweakFromPrivateKey(t : Uint8Array) : KeyRing {
    if (!this.privateKey) {
      throw TypeError('Private key is undefined!')
    }
    const hasOddY = this.publicKey[0] === 3 || (this.publicKey[0] === 4 && (this.publicKey[64] & 1) === 1)
    const privateKey = (hasOddY)
      ? ecc.privateNegate(this.privateKey)
      : this.privateKey
    const tweakedPrivateKey = ecc.privateAdd(privateKey, t)
    if (!tweakedPrivateKey) {
      throw new Error('Invalid tweaked private key!')
    }
    return new KeyRing(tweakedPrivateKey, null, this.chaincode, this.config.name, this.index, this.depth, this.fprint)
  }
}

function incrementBuffer(buffer : Uint8Array) {
  for (let i = buffer.length; i > 0; i--) {
    console.log(buffer)
    if (buffer[i] < 255) {
      buffer.set([buffer[i] + 1], i)
      return buffer
    }
  }
  throw TypeError('Unable to increment buffer: ' + buffer.toString())
}
