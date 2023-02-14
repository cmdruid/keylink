import { Noble } from '@cmdcode/crypto-utils'

export default class KeySign {
  private readonly __privateKey : Uint8Array | null
  private readonly __publicKey  : Uint8Array

  constructor (
    prvKey  : Uint8Array | null,
    pubKey  : Uint8Array | null
  ) {
    if (pubKey === null) {
      pubKey = getPubkey(prvKey)
    }

    this.__privateKey = prvKey
    this.__publicKey  = pubKey
  }

  get publicKey () : Uint8Array {
    return this.__publicKey
  }

  get privateKey () : Uint8Array | null {
    return this.__privateKey
  }

  sign    = Noble.sign
  verify  = Noble.verify
  schnorr = Noble.schnorr
}

function getPubkey (
  prvKey : Uint8Array | null
) : Uint8Array {
  if (prvKey === null) {
    // If private key is null, throw error.
    throw TypeError('Missing private key!')
  }

  // Derive public key from private key.
  const pubKey = Noble.getPublicKey(prvKey, true)

  if (pubKey === null) {
    // If returned pubkey is null, throw error.
    throw TypeError('Invalid public key!')
  }
  // Return pubkey.
  return pubKey
}
