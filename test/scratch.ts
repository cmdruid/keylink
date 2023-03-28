import KeyLink  from '../src/index.js'
import { Buff } from '@cmdcode/buff-utils'

const tprv = 'tprv8ZgxMBicQKsPemtEKyRCoJDmRb8XK6zJoSRyDDFztCgAkQhhKemP8HTKrJzTLYsfeGgAjUBufwLUc7JRUUsChqoVFxCMco1xbGzYDkqbrET'

const key = KeyLink.fromBase58(tprv)

const link = await key.getPath("/84'/1'/0'/0/10")

console.log(link.pubkey.hex)