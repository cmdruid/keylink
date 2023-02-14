import KeyLink from '../src/index.js'

export default async function (t) {

  const vector = await import(`./vectors/vector-05.json`, { assert: { type: "json" }})
  const { vectors } = vector.default

  t.plan(16)
  
  for (const [ key, errMsg ] of vectors) {
    t.throws(() => {
      KeyLink.fromBase58(key)
    }, /Error/, errMsg)
  }
}
