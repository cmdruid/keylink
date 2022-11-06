import tape from 'tape'
import { Buff } from '@cmdcode/bytes-utils'
import KeyRing from '../src/index.js'

tape('Test vectors', async t => {
  t.test(`Testing: Vectors 1-4`, async t => {
    for (let i = 1; i < 5; i++) {
      const { title, seed, vectors } = await import(`vectors/vector-0${i}.json`)

      t.test(title, async t => {
        t.plan(vectors.length * 2)
    
        const root = KeyImport.fromSeed(Buff.hex(seed).toBytes())
    
        vectors.forEach(([ path, xprvTarget, xpubTarget ]) => {
          const xprv = root.derivePath(path)
          const xpub = xprv.neutered()
          t.equal(xprvTarget, xprv)
          t.equal(xpubTarget, xpub)
        })
      })
    }
  })
})
