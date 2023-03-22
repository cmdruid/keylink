import { Test } from 'tape'
import KeyLink  from '../../src/index.js'

export default async function (t : Test) {

  const vector = await import('./vectors/vector-05.json', { assert: { type: "json" }})
  const { vectors } = vector.default

  t.test('Import tests', t => {
    t.plan(vectors.length)
    for (const [ key, errMsg ] of vectors) {
      try {
        KeyLink.fromBase58(key)
        t.fail(errMsg)
      } catch(err) {
        console.log(err.message)
        t.pass(errMsg)
      }
    }
  })
}
