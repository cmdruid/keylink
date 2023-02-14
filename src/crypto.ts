import * as ecc  from 'tiny-secp256k1'
import { Hash }  from '@cmdcode/crypto-utils'

// used for generating key refcodes.
export const hash160 = Hash.hash160
// Used for generating base58 checksums.
export const hash256 = Hash.hash256
// Used for key label hardening.
export const hmac256 = Hash.hmac256
// Used for chain-code generation.
export const hmac512 = Hash.hmac512
// Used for private key tweaking.
export const fieldAdd = ecc.privateAdd
export const fieldNegate = ecc.privateNegate
export const fieldIsPrivate = ecc.isPrivate
// Used for public key tweaking.
export const pointAddScalar = ecc.pointAddScalar
// export const xPointAddTweak = ecc.xOnlyPointAddTweak
export const signECDSA     = null
export const verifyECDSA   = null
export const signSchnorr   = null
export const verifySchnorr = null
