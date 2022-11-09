import { Hash } from '@cmdcode/crypto-utils'

// used for generating key refcodes.
export const hash160 = Hash.hash160
// Used for generating base58 checksums.
export const hash256 = Hash.hash256
// Used for key label hardening.
export const hmac256 = Hash.hmac256
// Used for chain-code generation.
export const hmac512 = Hash.hmac512
