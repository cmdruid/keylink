import KeyLink from '../src/index.js'

export default async function (t) {

  const vector = await import(`./vectors/vector-05.json`, { assert: { type: "json" }})
  const { title, seed, vectors } = vector.default

  t.plan(16)
  
  for (const [ key, errMsg ] of vectors) {
    t.throws(() => {
      KeyLink.fromBase58(key)
    }, /TypeError/, errMsg)
  }
}
