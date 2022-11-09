import tape from 'tape'
import APICrawler  from './api.test.js'
import vectorTests from './vector.test.js'
import importTests from './import.test.js'

tape('Test Suite', t => {
  t.test('Vectors tests', async t => {
    await vectorTests(t)
  })
  t.test('Import tests', async t => {
    await importTests(t)
  })
  // t.test('API tests', async t => {
  //   await APICrawler(t)
  // })
})
