import tape from 'tape'

import vectorTests from './src/vector.test.js'
import importTests from './src/import.test.js'

tape('Test Suite', async t => {
  await vectorTests(t)
  await importTests(t)
})
