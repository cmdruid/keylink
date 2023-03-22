import { Buff } from '@cmdcode/buff-utils'
import { Field, Point } from '@cmdcode/crypto-utils'

export function isValidPath (path : string) : void {
  const regex = /^(m\/)?(#?\w+'?\/)*#?\w+'?$/
  if (path.match(regex) === null) {
    throw new Error('Provided path string is invalid: ' + path)
  }
}

export function isValidHash (hash : string) : void {
  const regex = /^[0-9a-fA-F]{64}$/
  if (hash.match(regex) === null) {
    throw new Error('Provided hash string is invalid: ' + hash)
  }
}

export function isValidIndex (index : string) : void {
  const regex = /^[0-9]+$/
  if (index.match(regex) === null) {
    throw new Error('Provided index string is invalid: ' + index)
  }
  indexInRange(parseInt(index))
}

export function isEmptyMarker (
  marker : number,
  defaults = 0x00000000
) : boolean {
  if (marker !== defaults) {
    throw new TypeError('Master key marker must be zeroed out.')
  }
  return true
}

export function indexInRange (
  index : number
) : void {
  if (index > 0x80000000) {
    throw new TypeError('Index value must not exceed 31 bits.')
  }
}

export function noIndexAtDepthZero (
  depth : number,
  index : number
) : boolean {
  if (depth === 0 && index !== 0) {
    throw new TypeError('Starting index must be zero at depth zero.')
  }
  return true
}

export function privateKeyInRange (seckey : Uint8Array) : boolean {
  const big = Buff.raw(seckey).big
  if (big === 0n || big >= Field.N) {
    throw new TypeError('Private key value is out of range!')
  }
  return true
}

export function publicKeyOnCurve (pubkey : Uint8Array) : boolean {
  if (!Point.validate(pubkey)) {
    throw new TypeError('Public key invalid. Point is not on the curve!')
  }
  return true
}

export function seedLengthIsValid (length : number) : boolean {
  if (length < 16 || length > 64) {
    throw new TypeError('Seed length should be between 128 bits and 512 bits.')
  }
  return true
}
