import { Buff } from '@cmdcode/bytes-utils'
import KeyLink from '../src/index.js'
import { webcrypto as crypto } from 'crypto'


const randHash = (size = 32) => crypto.getRandomValues(new Uint8Array(size))
const convertToHex = (data) => Buff.buff(data).toHex()

const root = await KeyLink.fromSeed(randHash())

console.log(root)

const path = `m/0'/${convertToHex(randHash())}'/1/test:1000000/${convertToHex(randHash())}#/1`

const child = await root.getPath(path)

console.log(child)

/** TODO:
 * Write test vectors for extended key tweaking.
 * 
 * - test vectors for key leakage.
 * - leakage is also an implicit validation of proper tweaking? 
 */