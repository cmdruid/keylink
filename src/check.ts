import { Buff } from '@cmdcode/bytes-utils'
import * as ecc from 'tiny-secp256k1'
import { type LinkConfig } from './config'

export function isValidPath(path : string) : boolean { 
  return path.match(/^(m\/)?((\w+:)?\w+'?#?\/)*(\w+:)?\w+'?#?$/) !== null
}

export function isValidHex(hex : string) : boolean {
  return hex.match(/^[0-9a-fA-F]$/) !== null
}

export function isValidIndex(index : string) : boolean {
  return index.match(/^[0-9]{1,10}$/) !== null
}

export function isDefaultRefcode(
  current : number, 
  config  : number
) : boolean {
  if (current !== config) {
    throw new TypeError('Master key refcode must be default.')
  }
  return true
}

export function privateKeyRequired(
  required  : boolean, 
  keyExists : boolean
  ) : boolean {
  if (required && !keyExists) {
    throw new TypeError('Private key is required.')
  }
  return true
}

export function catchEmptyBuffer(
  data : Uint8Array | null | undefined
) : Uint8Array {
  if (data === null || data === undefined || data.every((e) => e === 0 )) {
    throw new TypeError('Data buffer cannot be empty!')
  }
  return data
}

export function importKeyVersion(
  version : number,
  config  : { private: number, public: number }
) : boolean {
  const { private: prv, public: pub } = config
  if (version !== prv && version !== pub) {
    throw new TypeError('Key version number does not match configuration.')
  }
  return true
}

export function noIndexAtDepthZero(
  depth : number, 
  index : number
) : boolean {
  if (depth === 0 && index !== 0) {
    throw new TypeError('Starting index must be zero at depth zero.')
  }
  return true
}

export function privateKeyPrefixIsValid(prefix : number) : boolean {
  if (prefix !== 0x00) {
    throw new TypeError('Private key must start with zero byte.')
  }
  return true
}

export function publicKeyPrefixIsValid(prefix : number) : boolean {
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new TypeError('Public key must start with a valid byte.')
  }
  return true
}

export function privateKeyinRange(privKey : Uint8Array) : boolean {
  if (!ecc.isPrivate(privKey)) {
    throw new TypeError('Private key invalid. Not within range of N!')
  }
  return true
}

export function publicKeyOnCurve(pubKey : Uint8Array) : boolean {
  if (!ecc.isPoint(pubKey)) {
    throw new TypeError('Public key invalid. Point is not on the curve!')
  }
  return true
}

export function seedLengthIsValid(length : number) : boolean {
  if (length < 16 || length > 64) {
    throw new TypeError('Seed length should be between 128 bits and 512 bits.')
  }
  return true
}

export function isHardIndex(
  index  : Uint8Array, 
  config : LinkConfig
) : boolean {
  if (index.length === 4) {
    const indexVal = new Buff(index.reverse()).toNum()
    return indexVal > config.index.maxIndex
  }
  return (index[0] === config.map.hardPrefix)
}