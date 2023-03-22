export interface Link {
  format ?: string      // The format version of the key.
  depth  ?: number      // The depth of this link (max 255).
  marker ?: number      // Checksum marker from parent key.
  index  ?: number      // Index value of the provided key.
  code    : Uint8Array  // Chaincode paired with the key.
  seckey ?: Uint8Array  // Private Key.
  pubkey ?: Uint8Array  // Public Key.
  label  ?: string      // Key / label metadata.
}

export interface KeyPrefix {
  prv : number
  pub : number
}

export interface Chain {
  readonly prefix    : KeyPrefix
  readonly depth     : number
  readonly marker    : number
  readonly index     : number
  readonly chaincode : Uint8Array
  readonly _seckey  ?: Uint8Array
  readonly _pubkey  ?: Uint8Array
  readonly label    ?: string
}
