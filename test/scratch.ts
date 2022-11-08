import { Buff } from '@cmdcode/bytes-utils'
import KeyRing from '../src/index.js'

const root = await KeyRing.fromSeed(Buff.hex('000102030405060708090a0b0c0d0e0f'))

const child = await root.deriveHardIndex(0)

console.log(await child.toBase58())