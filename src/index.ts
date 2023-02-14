import { Buff, Stream } from '@cmdcode/buff-utils'

import * as Check  from './check.js'
import * as Config from './config.js'
import * as Crypto from './crypto.js'
import KeySign     from './signer.js'
import * as Utils  from './utils.js'

type LinkMeta = [
  type?    : string,
  index?   : Uint8Array,
  depth?   : number,
  refcode? : number,
  chainKey?: string
]

const ec = new TextEncoder()

export default class KeyLink extends KeySign {
  public readonly config     : Config.LinkConfig
  private readonly __chain   : Uint8Array
  private readonly __index   : Uint8Array
  private readonly __depth   : number
  private readonly __refcode : number
  private readonly __label   : string | undefined

  static DEFAULT_TYPE = 'bitcoin'

  constructor (
    prvKey  : Uint8Array | null,
    pubKey  : Uint8Array | null,
    chain   : Uint8Array,
    ...meta : LinkMeta
  ) {
    super(prvKey, pubKey)
    this.config = Config.getConfig(meta[0] ?? KeyLink.DEFAULT_TYPE)

    const { defaults: Default } = this.config

    this.__chain   = chain
    this.__index   = meta[1] ?? Buff.num(Default.index, 4)
    this.__depth   = meta[2] ?? Default.depth
    this.__refcode = meta[3] ?? Default.refcode
    this.__label   = meta[4]
  }

  get chaincode () : Uint8Array {
    // Return current chaincode in raw format.
    return this.__chain
  }

  get rawindex () : Uint8Array {
    // Return current index in raw format.
    return this.__index
  }

  get index () : number | string {
    // Return an integer or string format
    // of the current index.
    return Utils.decodeIndex(this.rawindex)
  }

  get depth () : number {
    // Return current path depth in raw format.
    return this.__depth
  }

  get refcode () : number {
    // Return the parent refcode in raw format.
    return this.__refcode
  }

  get label () : string | undefined {
    // Return the current label (if any).
    return this.__label ?? ''
  }

  get isPrivate () : boolean {
    return this.privateKey !== null
  }

  get isHardened () : boolean {
    return Check.isHardIndex(this.rawindex, this.config)
  }

  inspect () : string {
    return JSON.stringify({
      prvKey: this.privateKey !== null
        ? Buff.buff(this.privateKey).toHex()
        : null,
      pubKey : Buff.buff(this.publicKey).toHex(),
      chain  : Buff.buff(this.chaincode).toHex(),
      meta   : `i: ${this.index} d: ${this.depth} r: ${this.refcode} l: ${this.label ?? ''}`
    }, null, 2)
  }

  async getPubkeyHash () : Promise<Uint8Array> {
    // BIP32 definition of key identifier.
    return Crypto.hash160(this.publicKey)
  }

  async getAddress () : Promise<string> {
    // bech32 format of the public key hash.
    const { prefix: Prefix } = this.config
    const pkh = await this.getPubkeyHash()
    return Buff.buff(pkh).toBech32(Prefix.address, 0)
  }

  async getRef () : Promise<number> {
    // BIP32 definition of parent fingerprint.
    const kid = await this.getPubkeyHash(),
          ref = kid.slice(0, 4)
    return Buff.buff(ref.reverse()).toNum()
  }

  exportMeta () : LinkMeta {
    // Return a duplicate copy of
    // the current KeyLink object.
    return [
      this.config.name,
      this.rawindex,
      this.depth,
      this.refcode,
      this.label
    ]
  }

  copy (isPublic = false) : KeyLink {
    // Return a copy of the current KeyLink object.
    return (!isPublic && this.privateKey !== null)
      ? KeyLink.fromPrivateLink(this.privateKey, this.chaincode, ...this.exportMeta())
      : KeyLink.fromPublicLink(this.publicKey, this.chaincode, ...this.exportMeta())
  }

  toPrivateLink () : KeyLink {
    // Return a private (signing) copy
    // of the current KeyLink object.
    return this.copy()
  }

  toPublicLink () : KeyLink {
    // Return a public (non-signing) copy
    // of the current KeyLink object.
    return this.copy(true)
  }

  toShareLink () : KeyLink {
    return this
  }

  async toBase58 () : Promise<string> {
    /* Export the current KeyLink object into a
     * BIP32 (extended) format Base58 string.
     */
    const { prefix: Prefix } = this.config
    const version = (this.isPrivate)
      // Select private key first, fall-back to
      // public key if private key is null.
      ? Prefix.private
      : Prefix.public

    // Initiate a buffer for writing the prefix data.
    let buffer = Buff.buff(new ArrayBuffer(9))
    // Write the version number in BE.                   [4 bytes]
    buffer.write(Buff.num(version, 4), 0)
    // Write the current path depth (0-255).             [1 bytes]
    buffer.write(Buff.num(this.depth, 1), 4)
    // Write the refcode of the parent key in BE.        [4 bytes]
    buffer.write(Buff.num(this.refcode, 4).reverse(), 5)
    // Append the index array to the buffer.             [4 or varint bytes]
    buffer = buffer.append(this.rawindex)
    // Append the chaincode array to the buffer.         [32 bytes]
    buffer = buffer.append(this.chaincode)
    // Append the selected key array to the buffer.      [33 bytes]
    buffer = (this.privateKey !== null)
      ? buffer.append(Uint8Array.of(0x00, ...this.privateKey))
      : buffer.append(this.publicKey)
    // Append a hash256 checksum to the buffer.          [4 bytes]
    const checksum = (await Crypto.hash256(buffer)).slice(0, 4)
    // Return the buffer as a base58 encoded string.
    return buffer.append(checksum).toBase58()
  }

  async toWIF () : Promise<string> {
    /* Export the current private key
     * as a WIF encoded Base58 string.
     */
    const { prefix: Prefix } = this.config
    // Enforce that private key exists for export.
    const privateKey = Check.catchEmptyBuffer(this.privateKey)
    // Initiate a buffer for writing the data.
    const buffer = Buff.buff(new ArrayBuffer(34))
    // Write the WIF version number.              [1 byte]
    buffer.write(Buff.num(Prefix.export), 0)
    // Write the current private key.             [32 bytes]
    buffer.write(privateKey, 1)
    // Write the compression flag.                [1 byte]
    buffer.write(Buff.num(0x01), 33)
   // Append a hash256 checksum to the buffer.    [4 bytes]
    const checksum = (await Crypto.hash256(buffer)).slice(0, 4)
    // Return the buffer as a base58 encoded string.
    return buffer.append(checksum).toBase58()
  }

  async derive (
    pathData  : Uint8Array,
    isHardened = false
  ) : Promise<KeyLink> {
    /* Calculate a new key and chain code from the
     * current KeyLink, using the encoded path data,
     */
    // Enforce that private key exists for hardened paths.
    Check.privateKeyRequired(isHardened, this.isPrivate)
    // Get the label of the current key configuration.
    const { name } = this.config
    // Calculate a refcode from the current KeyLink.
    const refcode = await this.getRef()
    // Select a key to load into the buffer.
    const buffer = (isHardened && this.privateKey !== null)
      ? Uint8Array.of(0x00, ...this.privateKey, ...pathData)
      : Uint8Array.of(...this.publicKey, ...pathData)
    // Apply the buffer and derive a new tweak and chaincode.
    const [ IL, IR ] = await Utils.tweakChain(this.chaincode, buffer)
    // Check if private key exists.
    if (this.privateKey !== null) {
      // If private key exists, perform a scalar addition
      // operation to derive the child private key.
      const ki = Crypto.fieldAdd(this.privateKey, IL)
      if (ki === null) {
        // If derived key is null, then increment the
        // buffer by one bit and try again.
        return this.derive(Utils.incrementBuffer(buffer))
      }
      // Return a new KeyLink object with the derived private key.
      return KeyLink.fromPrivateLink(ki, IR, name, pathData, this.depth + 1, refcode)
    } else {
      // Else public key exists, perform a point addition
      // operation to derive the child public key.
      const Ki = Crypto.pointAddScalar(this.publicKey, IL)
      if (Ki === null) {
        // If derived point is null (infinity), increment
        // the buffer by one bit and try again.
        return this.derive(Utils.incrementBuffer(buffer))
      }
      // Return a new KeyLink object with the derived public key.
      return KeyLink.fromPublicLink(Ki, IR, name, pathData, this.depth + 1, refcode)
  }
}

  async getSoftIndex (index : number) : Promise<KeyLink> {
    /* Derive a path index using an standard number value. */
    const bytes = Buff.num(index, 4)
    // Add a check for low byte.
    return this.derive(bytes, false)
  }

  async getHardIndex (index : number) : Promise<KeyLink> {
    /* Derive a path index using a hardened number value. */
    const { index: indexConfig } = this.config
    const hardIndex = index + indexConfig.signMask,
          bytes = Buff.num(hardIndex, 4)
    return this.derive(bytes, true)
  }

  async getSoftMap (
    data : Uint8Array, type = 0) : Promise<KeyLink> {
    /* Derive a path index using a standard byte-array value. */
    const { map: Config } = this.config
    const map = Uint8Array.of(Config.softPrefix, type, ...data)
    return this.derive(map, false)
  }

  async getHardMap (data : Uint8Array, type = 0) : Promise<KeyLink> {
    /* Derive a path index using a hardened byte-array value. */
    const { map: Config } = this.config
    const map = Uint8Array.of(Config.hardPrefix, type, ...data)
    return this.derive(map, true)
  }

  async getKeyIndex (key : string, index : number) : Promise<KeyLink> {
    /* Derive a path index using a key-tweaked number value. */
    const bytes = Buff.num(index, 4)
    const hash  = await Crypto.hmac256(ec.encode(key), bytes.reverse())
    return this.derive(hash, true)
  }

  async getKeyMap (key : string, data : Uint8Array, type = 0) : Promise<KeyLink> {
    /* Derive a path index using a key-tweaked byte-array. */
    const { map: Config } = this.config
    const hash = await Crypto.hmac256(ec.encode(key), data)
    const map  = Uint8Array.of(Config.hardPrefix, type, ...hash)
    return this.derive(map, true)
  }

  async getPath (fullpath : string) : Promise<KeyLink> {
    /* Split a given path string into an array of indices,
     * then parse and derive each child KeyLink in the array.
     */
    const { defaults: Default } = this.config
    // Check if the fullpath is a valid path.
    Check.isValidPath(fullpath)
    // Split the fullpath into an array of substrings.
    let splitPath = fullpath.split('/')
    // Check if path is deriving from the master key.
    if (splitPath[0] === 'm') {
      // Check the refcode of the master key.
      Check.isDefaultRefcode(this.refcode, Default.refcode)
      // Remove the marker from the array.
      splitPath = splitPath.slice(1)
    }
    // Declare path and copy of the current KeyLink.
    let path : string, self : KeyLink = this.copy()
    // Iterate over each index in the path array.
    for (path of splitPath) {
      let isHardened : boolean = false,
          isHexCode  : boolean = false,
          useHmacKey : string | undefined
      // Check if path uses a key for hardening.
      if (path.includes(':')) {
        const [ k, v ] = path.split(':')
        isHardened = true
        useHmacKey = k
        path       = v
      }
      // Check if the path is marked as hexcode.
      if (path.slice(0) === '#') {
        isHexCode = true
        path = path.slice(1)
      }
      // Check if the path is marked as hardened.
      if (path.slice(-1) === '\'') {
        isHardened = true
        path = path.slice(0, -1)
      }
      // Check if the path index is a number.
      if (Check.isValidIndex(path) && !isHexCode) {
        // Handle the index as an integer value.
        const data = parseInt(path, 10)
        self = (isHardened)
          ? (useHmacKey === 'string')
            ? await self.getKeyIndex(useHmacKey, data)
            : await self.getHardIndex(data)
          : await self.getSoftIndex(data)
      } else {
        // Handle the index as an encoded byte-array.
        const type = (isHexCode) ? 0x01 : 0x00
        const data = (isHexCode && Check.isValidHex(path))
          ? Buff.hex(path)
          : ec.encode(path)
        self = (isHardened)
          ? (useHmacKey === 'string')
            ? await self.getKeyMap(useHmacKey, data, type)
            : await self.getHardMap(data, type)
          : await self.getSoftMap(data, type)
      }
    }
    // Return the fully-derived KeyLink object.
    return self
  }

  static fromBase58 (
    b58string : string,
    chainType = KeyLink.DEFAULT_TYPE
  ) : KeyLink {
    /* Import a Base58 formatted string as a
     * BIP32 (extended) KeyLink object.
     */
    const config = Config.getConfig(chainType)
    // Decode the string data into a readable stream.
    const buffer = new Stream(Buff.base58(b58string))
    // Fetch configuration for imported key.
    // Parse version number: 4 bytes.
    const version = buffer.read(4).toNum()
    // Check if version number matches key configuration.
    Check.importKeyVersion(version, config.prefix)
    // Parse depth: 1 byte [0x00] for master nodes, [0x01+] for descendants.
    const depth = buffer.read(1).toNum()
    // Parse parent key refcode: 4 bytes (0x00000000 if master key).
    const refcode = buffer.read(4).toNum()
    // Check if importing master key.
    if (depth === 0) {
      // Check the refcode of the master key.
      Check.isDefaultRefcode(refcode, config.defaults.refcode)
    }

    const index = buffer.read(4)

    Check.noIndexAtDepthZero(depth, index.toNum())

    // Parse chain code: 32 bytes.
    const chaincode = buffer.read(32)
    const parsedKey = buffer.read(33)

    // Parse key data: 33 bytes.
    if (version === config.prefix.private) {
      Check.privateKeyPrefixIsValid(parsedKey[0])
      return KeyLink.fromPrivateLink(parsedKey, chaincode, chainType, index, depth, refcode)
    } else {
      Check.publicKeyPrefixIsValid(parsedKey[0])
      return KeyLink.fromPublicLink(parsedKey, chaincode, chainType, index, depth, refcode)
    }
  }

  static fromPrivateLink (
    privateKey : Uint8Array,
    chaincode  : Uint8Array,
    ...args    : LinkMeta
  ) : KeyLink {
    console.log(privateKey, chaincode, ...args)
    Check.privateKeyinRange(privateKey)
    return new KeyLink(privateKey, null, chaincode, ...args)
  }

  static fromPublicLink (
    publicKey : Uint8Array,
    chaincode : Uint8Array,
    ...args   : LinkMeta
  ) : KeyLink {
    Check.publicKeyOnCurve(publicKey)
    return new KeyLink(null, publicKey, chaincode, ...args)
  }

  static async fromSeed (
    seedData : Uint8Array,
    chainType = KeyLink.DEFAULT_TYPE
  ) : Promise<KeyLink> {
    Check.seedLengthIsValid(seedData.length)
    const config = Config.getConfig(chainType)
    const I = await Crypto.hmac512(ec.encode(config.seed), seedData)
    const IL = I.slice(0, 32)
    const IR = I.slice(32)
    return KeyLink.fromPrivateLink(IL, IR, chainType)
  }
}
