import * as ecc  from 'tiny-secp256k1'

export default class KeySign {

  private __privateKey : Uint8Array | null
  private __publicKey  : Uint8Array | null
  private lowR : boolean

  constructor(
    prvKey  : Uint8Array | null,
    pubKey  : Uint8Array | null,
    lowR = false
  ) {
    this.__privateKey = prvKey
    this.__publicKey  = pubKey
    this.lowR = lowR
  }

  get publicKey() {
    if (this.__privateKey && !this.__publicKey) {
      this.__publicKey = ecc.pointFromScalar(this.__privateKey, true)
    }
    if (!this.__publicKey) {
      throw TypeError('Public key is invalid!')
    }
    return this.__publicKey
  }

  get privateKey() {
    return this.__privateKey
  }

  signECDSA(
    hash  : Uint8Array,
    lowR? : boolean
  ) : Uint8Array {
    if (!this.privateKey) {
      throw new Error('Missing private key')
    }

    if (lowR === undefined) {
      lowR = this.lowR
    }


    if (lowR === false) {
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
    if (!this.privateKey) {
      throw new Error('Missing private key')
    }
    if (!ecc.signSchnorr) {
      throw new Error('signSchnorr not supported by ecc library')
    }
    return ecc.signSchnorr(hash, this.privateKey)
  }

  verifyECDSA(
    hash : Uint8Array, 
    sig  : Uint8Array
  ) : boolean {
      if (!this.publicKey) {
        return false
      }
    return ecc.verify(hash, this.publicKey, sig)
  }

  verifySchnorr(
    hash : Uint8Array, 
    sig  : Uint8Array
  ) : boolean {
    if (!ecc.verifySchnorr) {
      throw new Error('verifySchnorr not supported by ecc library')
    }
    if (!this.publicKey) {
      return false
    }
    return ecc.verifySchnorr(hash, this.publicKey.slice(1, 33), sig)
  }
}