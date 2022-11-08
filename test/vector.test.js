import { Buff } from '@cmdcode/bytes-utils'
import KeyRing from '../src/index.js'

export default async function (t) {
  for (let i = 1; i < 2; i++) {
    const vector = await import(`./vectors/vector-0${i}.json`, { assert: { type: "json" }})

    const { title, seed, vectors } = vector.default

    t.test(title, async t => {
      const root = await KeyRing.fromSeed(Buff.hex(seed))
      // console.log(root)
      for (let j = 0; j < vectors.length; j++) {
        const [ path, xprvTarget, xpubTarget ] = vectors[j]
        t.test(`Vector ${i}.${j+1}`, async t => {
          const xprv = await root.derivePath(path)
          // console.log(xprv)
          const xpub = xprv.neutered()
          // console.log(xpub)
          t.plan(2)
          t.equal(await xprv.toBase58(), xprvTarget, `Test vector ${i}.${j+1}: xprv`)
          t.equal(await xpub.toBase58(), xpubTarget, `Test vector ${i}.${j+1}: xpub`)
        })
      }
    })
  }
}
