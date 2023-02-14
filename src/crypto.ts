import { Buff } from '@cmdcode/buff-utils'
import { Field, Hash, Noble, Point }  from '@cmdcode/crypto-utils'

// used for generating key refcodes.
export const hash160 = Hash.hash160
// Used for generating base58 checksums.
export const hash256 = Hash.hash256
// Used for key label hardening.
export const hmac256 = Hash.hmac256
// Used for chain-code generation.
export const hmac512 = Hash.hmac512

// Used for private key tweaking.
export function fieldAdd (
  privKey : Uint8Array,
  tweak   : Uint8Array
) : Uint8Array {
  return new Field(privKey).add(tweak)
}

export function fieldNegate (
  privKey : Uint8Array
) : Uint8Array {
  return new Field(privKey).negate()
}

export function fieldIsPrivate (
  privKey : Uint8Array
) : boolean {
  return Noble.utils.isValidPrivateKey(privKey)
}

export function pointIsValid (
  pubkey : Uint8Array
) : boolean {
  const hex   = Buff.buff(pubkey).toHex()
  const point = Noble.Point.fromHex(hex)
  return point instanceof Noble.Point
}

// Used for public key tweaking.
export function pointAddScalar (
  privKey : Uint8Array,
  tweak   : Uint8Array
) : Uint8Array {
  return Point.fromXOnly(privKey).add(Point.fromXOnly(tweak)).rawX
}
