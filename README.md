# Keylink

Derive keys from virtually anything. Navigate through derivation paths like the web!

Expands the BIP32 wallet format to include many additional index types and features.

Features include:
 * Specify UTF8 strings as a derivation path!
 * Specify hex and hashes as a derivation path!
 * Hardening support for all path types!
 * More to come!

## How to Install
Using the browser:
```html
<script src="https://unpkg.com/@cmdcode/keylink">
```
Using nodejs:
```js
// Using CommonJS imports.
const KeyLink = require('@cmdcode/keylink')
// Using ES6 imports.
import KeyLink from '@cmdcode/keylink'
```

## How to Use

You can import and export links in a variety of ways.

```ts
/* List of Import methods. */
KeyLink
  .fromSeed()       // Create a new chain from a raw seed phrase.
  .fromBase58()     // Import a link from standard base58 format.
  .fromPrivateKey() // Import a link from private key and chaincode.
  .fromPublicKey()  // Import a link from public key and chaincode.

/* List of Export methods. */
KeyLink
  .copy()            // Export a a duplicate copy of current link.
  .export()          // Export a JSON object of the current link.
  .toPublic()        // Export a public (non-signing) copy of current link.
  .toWIF()           // Export as Wallet Import Format for Bitcoin Core.
  .toBase58()        // Export as standard base58check format.

/* Create a link by providing a chaincode and
 * the matching private key or public key.
 */
const link = new KeyLink(  
  seckey ?: Uint8Array  // Private Key.
  pubkey ?: Uint8Array  // Public Key.
  code    : Uint8Array  // Chaincode paired with the key.
  format ?: string      // The format version of the key.
  depth  ?: number      // The depth of this link (max 255).
  index  ?: number      // Index value of the provided key.
  label  ?: string      // Hash label of the provided key.
  marker ?: number      // Checksum marker from parent key.
)

// BIP44 paths still behave like normal.
link.getPath("m/44'/0'/0'/0/1") => new KeyLink

// The API has been simplified for better usage and
// understanding of hardened / non-hardened key spaces.
link.getSecIndex(index : number) => new KeyLink
link.getPubIndex(index : number) => new KeyLink

// You can now specify any length character string,
// and it will be parsed as Uint8Array bytes.
link.getPath("0'/thisisatotallyvalidpath/0/1")

// Hardening also works on strings.
link.getPath("0'/thispathwillbehardened'/0/1")

// If you want to parse a string as a hex-encoded
// value, you can prepend it with a hashtag character.
link.getPath("m/84/#aabbccddeeff00112233445566778899'/0/1")

// This feature takes advantage of a new API format
// that allows passing strings and hex for key derivation.
link.getSecLabel (data : string) => new KeyLink
link.getPubLabel (data : string) => new KeyLink
link.getSecHash  (data : string | Uint8Array) => new KeyLink
link.getPubHash  (data : string | Uint8Array) => new KeyLink

// Full Path derivation API:
link
  .getSecIndex()
  .getPubIndex()
  .getSecHash()
  .getPubHash()
  .getSecLabel()
  .getPubLabel()
  .getPath()

// Additional API:
link
  .chaincode => Uint8Array  // The link chaincode.
  .index     => string      // The current index (formatted).
  .depth     => number      // The current link depth.
  .marker    => number      // The parent marker (fingerprint).
  .label     => string      // The current key label (if any).
```

## Testing
Don't trust, verify!

All BIP32 specified test vectors should pass. Currently in the progress of adding custom vectors for the new derivation types.

All cryptography is done using a fork of the `@noble-secp256k1` library, plus the standard WebCrypto API.

If you have a question or run into any issues, please feel free to open a ticket on the issues page!

## Contributions
All contributions are welcome!

## Resources

**BIP32 Wiki Page**  
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

**BIP44 Wiki Page**  
https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

**Buff-Utils**  
https://github.com/cmdruid/buff-utils

**Crypto-Utils**  
https://github.com/cmdruid/crypto-utils
