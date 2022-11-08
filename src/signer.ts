import * as ecc  from 'tiny-secp256k1'

export default class KeySign {

  private readonly lowR : boolean
  private readonly __privateKey : Uint8Array | null
  private readonly __publicKey  : Uint8Array

  constructor(
    prvKey  : Uint8Array | null,
    pubKey  : Uint8Array | null,
    lowR = false
  ) {

    if (pubKey === null) {
      pubKey = getPubkey(prvKey)
    }

    this.__privateKey = prvKey
    this.__publicKey  = pubKey
    this.lowR = lowR
  }

  get publicKey() : Uint8Array {
    return this.__publicKey
  }

  get privateKey() : Uint8Array | null {
    return this.__privateKey
  }

  signECDSA(
    hash  : Uint8Array,
    lowR? : boolean
  ) : Uint8Array {
    if (this.privateKey === null) {
      throw new Error('Missing private key')
    }

    if (lowR === undefined) {
      lowR = this.lowR
    }


    if (!lowR) {
      return ecc.sign(hash, this.privateKey)
    }

    else {
      const padding = new Uint8Array(32).fill(0)
      let sig = ecc.sign(hash, this.privateKey)
      let counter = 0
        // if first try is lowR, skip the loop
        // for second try and on, add extra entropy counting up
      while (sig[0] > 0x7f) {
        counter += 1
        const filler = new Uint8Array(6).fill(counter)
        padding.set(filler, 0)
        sig = ecc.sign(hash, this.privateKey, padding)
      }
      return sig
    }
  }

  signSchnorr(
    hash : Uint8Array
  ) : Uint8Array {
    if (this.privateKey === null) {
      throw new Error('Missing private key')
    }
    if (typeof ecc.signSchnorr !== 'function') {
      throw new Error('signSchnorr not supported by ecc library')
    }
    return ecc.signSchnorr(hash, this.privateKey)
  }

  verifyECDSA(
    hash : Uint8Array,
    sig  : Uint8Array
  ) : boolean {
      if (this.publicKey === null) {
        return false
      }
    return ecc.verify(hash, this.publicKey, sig)
  }

  verifySchnorr(
    hash : Uint8Array,
    sig  : Uint8Array
  ) : boolean {
    if (typeof ecc.verifySchnorr !== 'function') {
      throw new Error('verifySchnorr not supported by ecc library')
    }
    if (this.publicKey === null) {
      return false
    }
    return ecc.verifySchnorr(hash, this.publicKey.slice(1, 33), sig)
  }
}


function getPubkey(
  prvKey : Uint8Array | null
) : Uint8Array {
  if (prvKey === null) {
    // If private key is null, throw error.
    throw TypeError('Missing private key!')
  }

  // Derive public key from private key.
  const pubKey = ecc.pointFromScalar(prvKey, true)
  
  if (pubKey === null) {
    // If returned pubkey is null, throw error.
    throw TypeError('Invalid public key!')
  }
  // Return pubkey.
  return pubKey
}