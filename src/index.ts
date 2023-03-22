import { Field, Hash, SecretKey, Point } from '@cmdcode/crypto-utils'
import { Buff, Bytes, Stream } from '@cmdcode/buff-utils'
import { KeyPrefix, Link } from './types.js'
import * as Check from './check.js'
import * as Utils from './utils.js'

const ec = new TextEncoder()

export default class KeyLink {
  readonly _link     : Link
  readonly prefix    : KeyPrefix
  readonly depth     : number
  readonly marker    : number
  readonly index     : number
  readonly chaincode : Uint8Array
  readonly seckey   ?: Uint8Array
  readonly _pubkey  ?: Uint8Array
  readonly label    ?: string

  constructor (link : Link) {
    this._link     = link
    this._pubkey   = link.pubkey
    this.prefix    = Utils.getKeyPrefix(link.format)
    this.depth     = link.depth   ?? 0
    this.marker    = link.marker  ?? 0x00000000
    this.index     = link.index   ?? 0
    this.chaincode = link.code
    this.seckey    = link.seckey
    this.label     = link.label

    if (this.depth === 0) {
      if (this.marker !== 0x00000000) {
        throw new TypeError('Marker should be zero at depth 0!')
      }
      if (this.index !== 0x00000000) {
        throw new TypeError('Index should be zero at depth 0!')
      }
    }

    if (this.seckey !== undefined) {
      Check.privateKeyInRange(this.seckey)
    }

    Check.publicKeyOnCurve(this.pubkey)
  }

  get pubkey () : Uint8Array {
    if (this.seckey === undefined) {
      if (this._pubkey === undefined) {
        throw new TypeError('No keys provided!')
      }
      return this._pubkey
    }
    return new SecretKey(this.seckey).pub.raw
  }

  get isPrivate () : boolean {
    return (this.seckey !== undefined)
  }

  get isHardened () : boolean {
    return this.index > 2 ** 31
  }

  get hasLabel () : boolean {
    return (
      this.index === 0xFFFFFFFF &&
      this.label !== undefined
    )
  }

  getMarker () : number {
    // BIP32 definition of parent fingerprint.
    const pkh = Buff.raw(this.pubkey).toHash('hash160')
    return Buff.raw(pkh.slice(0, 4)).num
  }

  copy () : KeyLink {
    return new KeyLink(this._link)
  }

  export () : Link {
    return this._link
  }

  toPublic () : KeyLink {
    return new KeyLink({ ...this._link, seckey: undefined, pubkey: this.pubkey })
  }

  toBase58 () : string {
    /* Export the current KeyLink object into a
     * BIP32 (extended) format Base58 string.
     */
    const prefix = (this.seckey !== undefined)
      ? this.prefix.prv
      : this.prefix.pub
    const key = (this.seckey !== undefined)
      ? Uint8Array.of(0x00, ...this.seckey)
      : this.pubkey
    const buffer = Buff.of(
      ...Buff.num(prefix,      4),
      ...Buff.num(this.depth,  1),
      ...Buff.num(this.marker, 4),
      ...Buff.num(this.index,  4),
      ...this.chaincode, ...key
    )

    if (this.label !== undefined) {
      buffer.append(Buff.bytes(this.label))
    }

    return buffer.tob58check()
  }

  toWIF (prefix : number = 0x80) : string {
    /* Export the current private key
     * as a WIF encoded Base58 string.
     */
    if (this.seckey !== undefined) {
      return Buff.of(prefix, ...this.seckey, 0x01).tob58check()
    }
    throw new TypeError('Cannot export a public key to WIF.')
  }

  async derive (
    tweak : Uint8Array,
    isHardened = false
  ) : Promise<KeyLink> {
    /* Derive a new key and chain code from the
     * current link, using the encoded path data,
     */

    const marker = this.getMarker()
    const index  = (tweak.length > 4) ? 0xFFFFFFFF : Buff.raw(tweak).num
    const label  = (tweak.length > 4) ? Buff.raw(tweak).hex : undefined

    let { seckey, pubkey } = this

    if (isHardened && seckey === undefined) {
      throw new TypeError('No private key available for hardened path!')
    }

    // Select a key to use in the buffer.
    const buffer = (isHardened && seckey !== undefined)
      ? Uint8Array.of(0x00, ...seckey, ...tweak)
      : Uint8Array.of(...pubkey, ...tweak)

    // Derive a new tweak and chaincode from the buffer.
    const [ scalar, code ] = await Utils.tweakChain(this.chaincode, buffer)

    if (seckey !== undefined) {
      // If private key exists, perform a scalar addition
      // operation to derive the child private key.
      seckey = new Field(seckey).add(scalar)
      // If new key is invalid, increment buffer and ty again.
      if (!Check.privateKeyInRange(seckey)) {
        return this.derive(Utils.incrementBuffer(buffer), isHardened)
      }
    } else {
      // Else public key exists, perform a point addition
      // operation to derive the child public key.
      pubkey = new Point(pubkey).add(scalar).rawX
      // If new key is invalid, increment buffer and ty again.
      if (!Check.publicKeyOnCurve(pubkey)) {
        return this.derive(Utils.incrementBuffer(buffer), isHardened)
      }
  }
  return new KeyLink({ seckey, pubkey, code, index, depth: this.depth + 1, marker, label })
}

  async getPubIndex (index : number) : Promise<KeyLink> {
    /* Derive a path index using an standard number value. */
    Check.indexInRange(index)
    const bytes = Buff.num(index, 4)
    return this.derive(bytes, false)
  }

  async getSecIndex (index : number) : Promise<KeyLink> {
    /* Derive a path index using a hardened number value. */
    Check.indexInRange(index)
    const bytes = Buff.num(index + 0x80000000, 4)
    return this.derive(bytes, true)
  }

  async getPubHash (hash : Bytes) : Promise<KeyLink> {
    /* Derive a path index using a standard byte-array value. */
    const bytes = Buff.bytes(hash)
    return this.derive(Buff.of(0x01, ...bytes), false)
  }

  async getSecHash (hash : Bytes) : Promise<KeyLink> {
    /* Derive a path index using a hardened byte-array value. */
    const bytes = Buff.bytes(hash)
    return this.derive(Buff.of(0x00, ...bytes), true)
  }

  async getPubLabel (label : string) : Promise<KeyLink> {
    /* Derive a path index using a standard byte-array value. */
    const bytes = Buff.str(label).digest
    return this.derive(Buff.of(0x01, ...bytes), false)
  }

  async getSecLabel (label : string) : Promise<KeyLink> {
    /* Derive a path index using a hardened byte-array value. */
    const bytes = Buff.str(label).digest
    return this.derive(Buff.of(0x00, ...bytes), true)
  }

  async getPath (fullpath : string) : Promise<KeyLink> {
    /* Split a given path string into an array of indices,
     * then parse and derive each child KeyLink in the array.
     */
    // Check if the fullpath is a valid path.
    Check.isValidPath(fullpath)
    // Split the fullpath into an array of substrings.
    let splitPath = fullpath.split('/')
    // Check if path is deriving from the master key.
    if (splitPath[0] === 'm') {
      // Check the refcode of the master key.
      Check.isEmptyMarker(this.marker)
      // Remove the marker from the array.
      splitPath = splitPath.slice(1)
    }
    // Declare path and copy of the current KeyLink.
    let path : string, self : KeyLink = this.copy()
    // Iterate over each index in the path array.
    for (path of splitPath) {
      let isHardened : boolean = false,
          isHashed   : boolean = false
      // Check if the path is marked as hardened.
      if (path.slice(-1) === '\'') {
        isHardened = true
        path = path.slice(0, -1)
      }
      if (path.slice(0, 1) === '#') {
        isHashed = true
        path = path.slice(1)
      }
      // Check if the path index is a number.
      if (path.match(/^[0-9]+$/) === null) {
        // Handle the index as an encoded byte-array.
        if (isHashed) Check.isValidHash(path)
        const hash = (isHashed)
          ? Buff.hex(path)
          : Buff.str(path).digest
        self = (isHardened)
          ? await self.getSecHash(hash)
          : await self.getPubHash(hash)
      } else {
        // Handle the index as an integer value.
        Check.isValidIndex(path)
        const index = parseInt(path, 10)
        self = (isHardened)
          ? await self.getSecIndex(index)
          : await self.getPubIndex(index)
      }
    }
    // Return the fully-derived KeyLink object.
    return self
  }

  static fromBase58 (
    b58string : string
  ) : KeyLink {
    /* Import a Base58 formatted string as a
     * BIP32 (extended) KeyLink object.
     */
    const buffer = new Stream(Buff.b58check(b58string))
    const [ format, type ] = Utils.getKeyFormat(buffer.read(4).num)

    const link : Link = {
      format,                         // Format version number.
      depth  : buffer.read(1).num,  // Parse depth ([0x00] for master).
      marker : buffer.read(4).num,  // Parent key reference (0x00000000 for master).
      index  : buffer.read(4).num,  // Key index.
      code   : buffer.read(32)      // Chaincode.
    }

    const key = buffer.read(33)     // Key material.

    if (link.index === 0xFFFFFFFF && buffer.size > 0) {
      link.label = buffer.read(32).str
    }

    if (buffer.size > 0) {
      throw new TypeError('Unparsed data remaining in buffer!')
    }

    // Parse key data: 33 bytes.
    if (key[0] === 0x00 && type === 0) {
      link.seckey = key.raw
    } else if ((key[0] === 0x02 || key[0] === 0x03) && type === 1) {
      link.pubkey = key.raw
    } else {
      throw new TypeError('Invalid key format!')
    }
    return new KeyLink(link)
  }

  static fromPrivateKey (
    seckey : Uint8Array,
    code   : Uint8Array
  ) : KeyLink {
    return new KeyLink({ seckey, code })
  }

  static fromPublicKey (
    pubkey : Uint8Array,
    code   : Uint8Array
  ) : KeyLink {
    return new KeyLink({ pubkey, code })
  }

  static async fromSeed (seed : Uint8Array | string) : Promise<KeyLink> {
    const raw = Buff.normalize(seed)
    const [ seckey, chaincode ] = await generateChain(raw)
    return KeyLink.fromPrivateKey(new Field(seckey).raw, chaincode)
  }
}

async function generateChain (
  key  : Uint8Array,
  seed : Uint8Array = ec.encode('Bitcoin seed')
) : Promise<[ Uint8Array, Uint8Array ]> {
  Check.seedLengthIsValid(key.length)
  const hash = await Hash.hmac512(seed, key)
  return [ hash.slice(0, 32), hash.slice(32) ]
}
