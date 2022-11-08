import * as ecc   from 'tiny-secp256k1'
import { Buff, Stream } from '@cmdcode/bytes-utils'
import { Hash }   from '@cmdcode/crypto-utils'
import KeySign    from './signer.js'
import * as Utils from './utils.js'
import { KeyConfig, getConfig } from './config.js'

const ec = new TextEncoder()

const DEFAULT_TYPE = 'bitcoin'

export default class KeyRing extends KeySign {

  private readonly __chain  : Uint8Array
  private readonly __index  : Uint8Array
  private readonly __depth  : number
  private readonly __fprint : number
  private readonly config   : KeyConfig

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

  get chaincode() : Uint8Array {
    return this.__chain
  }

  get depth() : number {
    return this.__depth
  }

  get index() : Uint8Array {
    return this.__index
  }

  get fprint() : number {
    return this.__fprint
  }

  get isPrivate() : boolean {
    return this.privateKey !== null
  }

  async identifier() : Promise<Uint8Array> {
    return Hash.hash160(this.publicKey)
  }

  async fingerprint() : Promise<number> {
    const fprint = await this.identifier()
    return Buff.buff(fprint.slice(0, 4)).toNum()
  }

  copy(neutered : boolean = false) : KeyRing {
    return new KeyRing(
      neutered 
        ? null 
        : this.privateKey, 
      this.publicKey, 
      this.chaincode, 
      this.config.name, 
      this.index, 
      this.depth, 
      this.fprint
    )
  }

  neutered() : KeyRing {
    return this.copy(true)
  }

  async toBase58() : Promise<string> {
    const version = (this.isPrivate)
      ? this.config.version.private
      : this.config.version.public
    const buffer = Buff.buff(new ArrayBuffer(78))
    // 4 bytes = version
    buffer.write(Buff.num(version, 4).reverse(), 0)
    // 1 byte = depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
    buffer.write(Buff.num(this.depth, 1), 4)
    // 4 bytes = parentFp: fingerprint of the parent's key (0x00000000 if master key)
    buffer.write(Buff.num(this.fprint, 4), 5)
    // 4 bytes = index: child index number (i) in xi = xpar/i, with xi the key being serialized.
    // This is encoded in big endian. (0x00000000 if master key)
    buffer.write(this.index, 9)
    // 32 bytes = chainCode: the chain code
    buffer.write(this.chaincode, 13)
    // 33 bytes: the public key or private key data
    if (this.privateKey !== null) {
      // 0x00 + k for private keys
      buffer.write(Buff.num(0), 45)
      buffer.write(this.privateKey, 46)
    }
    else {
      // 33 bytes: the public key
      // X9.62 encoding for public keys
      buffer.write(this.publicKey, 45)
    }
    const checksum = (await Hash.hash256(buffer)).slice(0, 4)
    return buffer.append(checksum).toBase58()
  }

  async toWIF() : Promise<string> {
    if (this.privateKey === null) {
      throw new TypeError('Missing private key')
    }
    const buffer = Buff.buff(new ArrayBuffer(34))
    // Write WIF version byte: 1 byte.
    buffer.write(Buff.num(this.config.wif), 0)
    // Write private key: 32 bytes.
    buffer.write(this.privateKey, 1)
    // Write compression flag: 1 byte.
    buffer.write(Buff.num(0x01), 33)
    // Write hash256 checksum: 4 bytes.
    const checksum = (await Hash.hash256(buffer)).slice(0, 4)
    return buffer.append(checksum).toBase58()
  }

  async derive(
    buffer : Uint8Array, 
    isPrivate = false
  ) : Promise<KeyRing> {
    const data = Buff.buff(new ArrayBuffer(33 + buffer.length))

    // TODO: Add better checks for proper 
    // formatting of private/public keys.

    if (isPrivate) {
      if (this.privateKey === null) {
        throw TypeError('Missing private key for hardened child key')
      }
      if (buffer[0] < 0x80) {
        buffer.set([ buffer[0] + 0x80 ])
      }
      data.write(new Uint8Array([0x00]), 0)
      data.write(this.privateKey, 1)
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

    const fprint = await this.fingerprint()

    // Private parent key -> private child key
    if (this.privateKey !== null) {
        // ki = parse256(IL) + kpar (mod n)
        const ki = ecc.privateAdd(this.privateKey, IL)
        // If ki == 0, then use the next index value.
        if (ki == null) {
          return this.derive(incrementBuffer(buffer))
        }
        return KeyRing.fromPrivateKeyLocal(ki, IR, this.config.name, buffer, this.depth + 1, fprint)
        // Public parent key -> public child key
    }
    else {
        // Ki = point(parse256(IL)) + Kpar
        //    = G*IL + Kpar
        const Ki = ecc.pointAddScalar(this.publicKey, IL, true)
        // In case Ki is the point at infinity, proceed with the next value for i
        if (Ki === null) {
          return this.derive(incrementBuffer(buffer))
        }
        return KeyRing.fromPublicKeyLocal(Ki, IR, this.config.name, buffer, this.depth + 1, fprint)
    }
  }

  async deriveIndex(index : number) : Promise<KeyRing> {
    return this.derive(Buff.num(index).reverse(), false)
  }

  async deriveHardIndex(index : number) : Promise<KeyRing> {
    // typeforce(Uint31, index)
    // Only derives hardened private keys by default
    return this.derive(Buff.num(index + Utils.HIGHEST_BIT).reverse(), true)
  }

  async deriveHash(index : Uint8Array) : Promise<KeyRing> {
    return this.derive(index, false)
  }

  async deriveHardHash(index : Uint8Array) : Promise<KeyRing> {
    return this.derive(index, true)
  }

  async derivePath(path : string) : Promise<KeyRing> {
    // typeforce(BIP32Path, path)
    let splitPath = path.split('/')
    if (splitPath[0] === 'm') {
      if (this.fprint !== 0x00000000) {
        throw new TypeError('Expected master, got child')
      }
      splitPath = splitPath.slice(1)
    }

    let self : KeyRing = this.copy()

    for (const path of splitPath) {
      if (path.slice(-1) === `#`) {
        // Parse a hashed path. 
        if (path.slice(-2) === `'`) {
          const buffer = Buff.hex(path.slice(0, -2))
          self = await self.deriveHardHash(buffer)
        } else {
          const buffer = Buff.hex(path.slice(0, -1))
          self = await self.deriveHash(buffer)
        }
      }
      else if (path.slice(-1) === `'`) {
        // Parse a hardened path.
        const index = parseInt(path.slice(0, -1), 10)
        self = await self.deriveHardIndex(index)
      }
      else {
        // Parse a non-hardened path.
        const index = parseInt(path, 10)
        self = await self.deriveIndex(index)
      }
    }
    return self
  }

  tweak(t : Uint8Array) : KeyRing {
    if (this.privateKey !== null)
      return this.tweakFromPrivateKey(t)
    return this.tweakFromPublicKey(t)
  }

  tweakFromPublicKey(t : Uint8Array) : KeyRing {
    const xOnlyPubKey = Utils.toXOnly(this.publicKey)
    const tweakedPublicKey = ecc.xOnlyPointAddTweak(xOnlyPubKey, t)
    if (tweakedPublicKey === null || tweakedPublicKey.xOnlyPubkey === null) {
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
    if (this.privateKey === null) {
      throw TypeError('Private key is undefined!')
    }
    const hasOddY = this.publicKey[0] === 3 || (this.publicKey[0] === 4 && (this.publicKey[64] & 1) === 1)
    const privateKey = (hasOddY)
      ? ecc.privateNegate(this.privateKey)
      : this.privateKey
    const tweakedPrivateKey = ecc.privateAdd(privateKey, t)
    if (tweakedPrivateKey === null) {
      throw new Error('Invalid tweaked private key!')
    }
    return new KeyRing(tweakedPrivateKey, null, this.chaincode, this.config.name, this.index, this.depth, this.fprint)
  }

  static fromBase58(
    b58string : string,
    keytype = DEFAULT_TYPE
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
      return KeyRing.fromPrivateKeyLocal(key, chaincode, keytype, index, depth, fprint)
      // 33 bytes: public key data (0x02 + X or 0x03 + X)
    }
    else {
      if (![0x02, 0x03].includes(buffer.peek(1).toNum())) {
        throw new TypeError('Public key must start with: 0x02 || 0x03')
      }
      const key = buffer.read(33)
      return KeyRing.fromPublicKeyLocal(key, chaincode, keytype, index, depth, fprint)
    }
  }

  static fromPrivateKey(
    privateKey : Uint8Array,
    chaincode  : Uint8Array,
    keytype    : string
  ) : KeyRing {
    return KeyRing.fromPrivateKeyLocal(privateKey, chaincode, keytype)
  }

  static fromPrivateKeyLocal(
    privateKey : Uint8Array,
    chaincode  : Uint8Array,
    keytype    : string,
    index?     : Uint8Array,
    depth?     : number,
    fprint?    : number
  ) : KeyRing {
    if (!ecc.isPrivate(privateKey)) {
      throw new TypeError('Private key not in range [1, n)')
    }
    return new KeyRing(privateKey, null, chaincode, keytype, index, depth, fprint)
  }

  static fromPublicKey(
    publicKey : Uint8Array,
    chaincode : Uint8Array, 
    keytype   : string
  ) : KeyRing {
    return KeyRing.fromPublicKeyLocal(publicKey, chaincode, keytype)
  }

  static fromPublicKeyLocal(
    publicKey : Uint8Array,
    chaincode : Uint8Array,
    keytype   : string,
    index?    : Uint8Array,
    depth?    : number,
    fprint?   : number
  ) : KeyRing {
    if (!ecc.isPoint(publicKey)) {
      throw new TypeError('Point is not on the curve')
    }
    return new KeyRing(null, publicKey, chaincode, keytype, index, depth, fprint)
  }

  static async fromSeed(
    seed   : Uint8Array,
    config = DEFAULT_TYPE
  ) : Promise<KeyRing> {
    if (seed.length < 16 || seed.length > 64) {
      throw new TypeError('Seed should be at least 128 bits, and at most 512 bits.')
    }
    const I = await Hash.hmac512(ec.encode('Bitcoin seed'), seed)
    const IL = I.slice(0, 32)
    const IR = I.slice(32)
    return KeyRing.fromPrivateKey(IL, IR, config)
  }
}

function incrementBuffer(buffer : Uint8Array) : Uint8Array {
  for (let i = buffer.length - 1; i >= 0; i--) {
    if (buffer[i] < 255) {
      buffer.set([buffer[i] + 1], i)
      return buffer
    }
  }
  throw TypeError('Unable to increment buffer: ' + buffer.toString())
}
