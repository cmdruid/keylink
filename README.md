# Keylink

Navigate through key-tweaks like you would the world wide web!

Expands the BIP32 wallet spec to support extra key-tweaking features.

Features include:
 * Specify UTF8 strings as a derivation path!
 * Specify hex-encoded strings as a derivation path!
 * Indexes can be as long as you like!
 * Hardening support for all path lengths and types!
 * Use key-based hardening (/key:index) as well as classic hardening (/0').
 * More to come!

## How to Install
Using the browser:
```html
<script src="https://unpkg.com/@cmdcode/keylink.min.js">
```
Using nodejs:
```js
// Using CommonJS imports.
const KeyLink = require('@cmdcode/keylink')
// Using ES6 imports.
import KeyLink from '@cmdcode/keylink'
```

## How to Use
```ts
// List of Import formats.
KeyLink
  .fromSeed()        // Create from raw bytes or BIP39 seed phrase.
  .fromBase58()      // Create from standard base58check format.
  .fromPrivateLink() // Create a private KeyLink from arguments.
  .fromPublicLink()  // Create a public KeyLink from arguments.

// List of Export formats.
KeyLink
  .toWIF()           // Export as Wallet Import Format for Bitcoin Core.
  .toBase58()        // Export as standard base58check format.
  .toPrivateLink()   // Export a private (signing) copy of current link.
  .toPublicLink()    // Export a public (non-signing) copy of current link.

// Create a link by providing a chaincode and
// the matching private key or public key.
const link = new KeyLink(
  privateKey  : Uint8Array | null,
  publicKey   : Uint8Array | null,
  chaincode   : Uint8Array,
  // You can also provide an 
  // optional array of metadata.
  ...metaData : [
    type?    : string,
    index?   : Uint8Array,
    depth?   : number,
    refcode? : number,
    label?   : string
  ]
)

// BIP44 paths still behave like normal.
link.getPath("m/44'/0'/0'/0/1") => new KeyLink

// The API has been simplified for better usage and
// understanding of hardened / non-hardened key spaces.
link.getHardIndex(index : number) => new KeyLink
link.getSoftIndex(index : number) => new KeyLink

// You can now specify any length character string,
// and it will be parsed as Uint8Array bytes.
link.getPath("0'/thisisatotallyvalidpath/0/1")

// Hardening also works on strings.
link.getPath("0'/thispathwillbehardened'/0/1")

// If you want to parse a string as hex (either
// hardened or not), prepend a hashtag character.
link.getPath("#aabbccddeeff00112233445566778899'/0/1")

// This feature takes advantage of a new API format
// that allows passing byte-arrays for key derivation.
link.getHardMap(data : Uint8Array) => new KeyLink
link.getSoftMap(data : Uint8Array) => new KeyLink

// You can now use HMAC signing to harden key paths.
// Simply prefix a colon-separated string as the HMAC key:
link.getPath("main:0/sub:0/1")
link.getPath("site:stacker.news/pub")
link.getPath("contracts:#aabbccddeeff/id:0011002200330044")

// This feature uses a new derviation operation
// that applies HMAC256 as a hardening tweak.
link.getKeyIndex(key : string, index : number)  => new KeyLink
link.getKeyMap(key : string, data : Uint8Array) => new KeyLink

// Full Path derivation API:
link
  .getHardLink()
  .getSoftLink()
  .getHardIndex()
  .getSoftIndex()
  .getHardMap()
  .getSoftMap()
  .getKeyIndex()
  .getKeyMap()
  .getPath()

// Additional API:
link
  .chaincode => Uint8Array  // The link chaincode.
  .rawindex  => Uint8Array  // The current index (in bytes).
  .index     => string      // The current index (formatted).
  .depth     => number      // The current link depth.
  .refcode   => number      // The parent refcode (fingerprint).
  .label     => string      // The current key label (if any).
  .getPubkeyHash() => string : pubkeyHash
  .getAddress()    => string : address
  .getRef()        => number : refcode
  .copy()          => new KeyLink
```

## Testing
Don't trust, verify!

All BIP32 specified test vectors should pass. Currently in the progress of adding custom vectors for the new derivation types.

All cryptography is done using the `tiny-secp256k1` library, plus the WebCrypto libary. Currently I am using a helper library called `Crypto_Utils` to provide a better WebCrypto interface (and ripemd160), but you can easily import your own library by checking out the `src/crypto.ts` file.

If you have a question or run into any issues, please feel free to open a ticket on the issues page!

## Roadmap

Currently on the roadmap:
 
 * Shared key / link derivation (using ECDH).
 * Discreet Log / Adaptor signature API.

More features to come!

## Contributions
All contributions are welcome!

## Resources

**BIP32 Wiki Page**  
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

**BIP44 Wiki Page**  
https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

**Bytes-Utils**  

**Crypto-Utils**  

