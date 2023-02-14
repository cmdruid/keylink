import { Buff } from '@cmdcode/bytes-utils'
import { webcrypto as crypto } from 'crypto'
import * as ecc from 'tiny-secp256k1'
import * as secp from '@noble/secp256k1'
import * as Crypto from '@cmdcode/crypto-utils'
import KeyLink from '../src/index.js'
import * as Utils from '../src/utils.js'

import tape from 'tape'

const ec = new TextEncoder()

const { ECC, Hash } = Crypto
const { Field, Point, Noble } = ECC

const seed = Buff.hex('3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678')
const bigSeed = BigInt('0x3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678')

const root   = await KeyLink.fromSeed(seed)
const child1 = await root.getSoftIndex(0)
const child2 = await root.getSoftIndex(1)

if (
  root.privateKey === null
  || root.publicKey === null
  || child1.privateKey === null
  || child1.publicKey === null
  || child2.privateKey === null
  || child2.publicKey === null
  ) {
  throw TypeError()
}

const m1 = new Uint8Array(32)
const m2 = new Uint8Array(32)
m1.set(ec.encode('test message a'))
m2.set(ec.encode('test message b'))


// Schnorr Signature.
const a = new Field(root.privateKey)
const A = Point.fromX(root.publicKey)
const k = new Field(child1.privateKey)
const R1 = Point.fromX(child1.publicKey)
const k2 = new Field(child2.privateKey)
const R2 = Point.fromX(child2.publicKey)
const hm1R = await Hash.sha256(Uint8Array.of(...m1, ...R1.rawX))
const hm2R = await Hash.sha256(Uint8Array.of(...m2, ...R1.rawX))

const sg1 = k1.sub(a.mul(hm1R)) //.point.rawX
const sG1 = R1.sub(A.mul(hm1R)).rawX

const sg2 = k1.sub(a.mul(hm2R)) // .point.rawX
const sG2 = R2.sub(A.mul(hm2R)).rawX

console.log('sig 1 matches: ', sg1.toString() === sG1.toString())
console.log('sig 2 matches: ', sg2.toString() === sG2.toString())

const sP = sg1.sub(sg2)
const hP = new Field(hm2R).sub(hm1R)

const c = sP.div(hP)

console.log(a.num)
console.log(c.num)

// const valid = await verify(Buff.buff(sig).toHex(), hex, Buff.buff(A.mul(m.reverse()).rawX).toHex())

// console.log('sig is valid:', valid)

// const b = a.mul(m).point
// const B = A.p.multiply(m)

// console.log(b, B, b.eq(b))


// // Sign
// const s1 = k.sub(a.mul(m))
// console.log('s1', s1, new Field(s1).point.rawX)

// const sT = root.signSchnorr(m)
// console.log('sT', sT)

// // Verify
// const sG = R.sub(A.mul(await h(m, R.rawX)))
// console.log('sG', sG.rawX)



