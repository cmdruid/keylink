import * as ecc from 'tiny-secp256k1'
import { Buff } from '@cmdcode/bytes-utils'

import * as Crypto from './crypto.js'

export function toXOnly(pubKey : Uint8Array) : Uint8Array {
  return pubKey.length === 32 ? pubKey : pubKey.slice(1, 33)
}

export function hasOddY(pubKey : Uint8Array) : boolean {
  /* Check if pubkey is marked as odd, 
   * or has a Y coordinate that is odd.
   */
  return pubKey[0] === 3 || (pubKey[0] === 4 && (pubKey[64] & 1) === 1)
}

export function tweakPrvKey(
  privKey : Uint8Array | null,
  pubKey  : Uint8Array,
  tweak   : Uint8Array
) : Uint8Array {
  if (privKey === null) {
    throw new TypeError('Private key is null!')
  }
  /* Perform a scalar addition operation on 
   * the private key.
   */
  const privateKey = (hasOddY(pubKey))
    ? ecc.privateNegate(privKey)
    : privKey
  const tweakedKey = ecc.privateAdd(privateKey, tweak)
  if (tweakedKey === null) {
    throw new TypeError('Invalid tweaked private key!')
  }
  return tweakedKey
}

export function tweakPubKey(
  pubKey  : Uint8Array,
  tweak   : Uint8Array
) : Uint8Array {
  /* Perform a point addition operation on 
   * the public key.
   */
  const tweakedKey = ecc.xOnlyPointAddTweak(toXOnly(pubKey), tweak)
  if (tweakedKey === null || tweakedKey.xOnlyPubkey === null) {
    // The tweak value produces an invalid result (point at infinity).
    throw new TypeError('Cannot tweak public key!')
  }
  const parityByte = tweakedKey.parity === 0 ? 0x02 : 0x03
  return Uint8Array.of(parityByte, ...tweakedKey.xOnlyPubkey)
}

export async function tweakChain(
  chain : Uint8Array, 
  data  : Uint8Array
) : Promise<Uint8Array[]> {
  /* Perform a SHA-512 operation on the provided key,
   * then an HMAC signing operation using the chain code.
   */
    const I  = await Crypto.hmac512(chain, data),
          IL = I.slice(0, 32),
          IR = I.slice(32)
    if (!ecc.isPrivate(IL)) {
      // If left I value is >= N, then increase the 
      // buffer value by one digit, and try again.
      return tweakChain(chain, incrementBuffer(data))
    }
    // Return each half of the hashed result in an array.
    return [ IL, IR ]
}

export function incrementBuffer(buffer : Uint8Array) : Uint8Array {
  /* Find the least significant integer value in the
   * data buffer (using LE), then increment it by one.
   */
  let i = buffer.length
  for (i -= 1; i >= 0; i--) {
    if (buffer[i] < 255) {
      buffer.set([buffer[i] + 1], i)
      return buffer
    }
  }
  throw TypeError('Unable to increment buffer: ' + buffer.toString())
}

export function decodeIndex(raw : Uint8Array) : number | string {
  switch (true) {
    case (raw.length === 4):
      return Buff.buff(raw.reverse()).toNum()
    case (raw[1] === 1):
      return Buff.buff(raw).toHex()
    default:
      return Buff.buff(raw).toStr()
  }
}
