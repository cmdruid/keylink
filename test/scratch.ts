import { Buff }               from '@cmdcode/bytes-utils'
import { Hash, Field, Point } from '@cmdcode/crypto-utils'
import HDWallet               from '../src/index.js'

const ec   = new TextEncoder()
const root = HDWallet.fromBase58('tpubDCMvBvR79bHQMYnYCZJzwD8SRvYf287A5soUXot1ESGSJERdXQ8PsEB4tcAqa3B5nzNHKST9VxaEdAv6MvVNtzKWRwsfMrbdPjtRD4p3maM')
const node = await root.getPath('1/0')
const pub  = Buff.buff(node.publicKey.slice(1))

async function taproot_tweak_pubkey(
  pubkey : Uint8Array,
  tweak ?: Uint8Array
) : Promise<[ Uint8Array, boolean ]> {
  const t = await getTweak("TapTweak", pubkey, tweak)
  const P = Point.fromXOnly(pubkey)
  const Q = P.add(new Field(t).point)
  return [ Q.rawX.slice(1), Q.hasOddY ]
}

async function getTag(tag : string) {
  const raw  = ec.encode(tag)
  return Uint8Array.of(...await Hash.sha256(raw), ...await Hash.sha256(raw))
}

async function getTweak(
  tag    : string,
  pubkey : Uint8Array,
  tweak ?: Uint8Array
) : Promise<Uint8Array> {
  let buff = Uint8Array.of(...await getTag(tag), ...pubkey)
  if (tweak !== undefined) buff = Uint8Array.of(...buff, ...tweak)
  return Hash.sha256(buff)
}

const [ tweakedPub ] = await taproot_tweak_pubkey(pub)

console.log('Tweaked Pub Hex:', Buff.buff(tweakedPub).toHex())