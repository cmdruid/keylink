import { Hash } from '@cmdcode/buff-utils'

export function tweakChain (
  chain : Uint8Array,
  data  : Uint8Array
) : Uint8Array[] {
  /* Perform a SHA-512 operation on the provided key,
   * then an HMAC signing operation using the chain code.
   */
    const I  = Hash.hmac512(chain, data),
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
