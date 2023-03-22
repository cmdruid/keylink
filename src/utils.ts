import { Hash } from '@cmdcode/crypto-utils'
import { KeyPrefix } from './types.js'

const KEY_TYPES = {
  legacy  : { prv: 0x0488ade4, pub: 0x0488b21e },
  taproot : { prv: 0x04358394, pub: 0x043587cf }
}

export async function tweakChain (
  chain : Uint8Array,
  data  : Uint8Array
) : Promise<Uint8Array[]> {
  /* Perform a SHA-512 operation on the provided key,
   * then an HMAC signing operation using the chain code.
   */
    const I  = await Hash.hmac512(chain, data),
          IL = I.slice(0, 32),
          IR = I.slice(32)
    // Return each half of the hashed result in an array.
    return [ IL, IR ]
}

export function incrementBuffer (buffer : Uint8Array) : Uint8Array {
  /* Find the least significant integer value in the
   * data buffer (using LE), then increment it by one.
   */
  let i = buffer.length
  for (i -= 1; i >= 0; i--) {
    if (buffer[i] < 255) {
      buffer.set([ buffer[i] + 1 ], i)
      return buffer
    }
  }
  throw TypeError('Unable to increment buffer: ' + buffer.toString())
}

export function getKeyFormat (
  ver : number
) : [ string, number ] {
  let key : keyof typeof KEY_TYPES
  for (key in KEY_TYPES) {
    if (KEY_TYPES[key].prv === ver) {
      return [ key, 0 ]
    } else if (KEY_TYPES[key].pub === ver) {
      return [ key, 1 ]
    }
  }
  throw new TypeError('Invalid key version:' + String(ver))
}

export function getKeyPrefix (
  label ?: string
) : KeyPrefix {
  if (label === undefined) label = 'legacy'

  if (!Object.keys(KEY_TYPES).includes(label)) {
    throw new TypeError('Invalid key type:' + label)
  }
  return KEY_TYPES[label as keyof typeof KEY_TYPES]
}
