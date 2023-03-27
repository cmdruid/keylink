import KeyLink from '../src/index.js'


const tpub = 'tpubDDSv5UhCKz7Ud3yBHDxdqK6FKqbZTYZ2UxGNYy4aWWPDqVbJXNHkYgyyGn6wF8zNsn5wmm1K1YM4DMcVGzY2gKm7c7tBfGGzsiPHsNVQegd'

const key = KeyLink.fromBase58(tpub)

console.log(key)