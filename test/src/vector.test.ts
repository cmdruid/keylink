import { Buff }  from '@cmdcode/buff-utils'
import { Test }  from 'tape'
import KeyLink   from '../../src/index.js'

export default async function (t : Test) {
  for (let i = 1; i < 5; i++) {
    const vector = await import(`./vectors/vector-0${i}.json`, { assert: { type: "json" }})

    const { title, seed, vectors } = vector.default

    t.test(title, async t => {
      const root = await KeyLink.fromSeed(Buff.hex(seed))
      t.plan(vectors.length * 2)
      for (let j = 0; j < vectors.length; j++) {
        const [ path, xprvTarget, xpubTarget ] = vectors[j]
        const xprv = await root.getPath(path)
        const xpub = xprv.toPublic()

        t.equal(xprv.toBase58(), xprvTarget, `Test vector ${i}.${j+1}: xprv`)
        t.equal(xpub.toBase58(), xpubTarget, `Test vector ${i}.${j+1}: xpub`)
      }
    })
  }
}
