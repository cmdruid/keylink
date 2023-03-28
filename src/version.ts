import { VersionData, VersionFilter } from './types.js'

export const KEY_VERSIONS = [
  { type: 'default',           sec_prefix: 0x0488ade4, pub_prefix: 0x0488b21e, purpose: 44, network: 0  },
  { type: 'p2pkh',             sec_prefix: 0x0488ade4, pub_prefix: 0x0488b21e, purpose: 44, network: 0  },
  { type: 'p2wpkh-p2sh',       sec_prefix: 0x049d7878, pub_prefix: 0x049d7cb2, purpose: 49, network: 0  },
  { type: 'p2wpkh',            sec_prefix: 0x04b24746, pub_prefix: 0x04b2430c, purpose: 84, network: 0  },
  { type: 'p2wpkh-p2sh',       sec_prefix: 0x0295b005, pub_prefix: 0x0295b43f, purpose: 49, network: 0  },
  { type: 'p2wpkh-multi',      sec_prefix: 0x02aa7a99, pub_prefix: 0x02aa7ed3, purpose: 48, network: 0  },
  { type: 'p2pkh',             sec_prefix: 0x04358394, pub_prefix: 0x043587cf, purpose: 44, network: 1  },
  { type: 'p2wpkh-p2sh',       sec_prefix: 0x044a4e28, pub_prefix: 0x044a5262, purpose: 49, network: 1  },
  { type: 'p2wpkh',            sec_prefix: 0x045f18bc, pub_prefix: 0x045f1cf6, purpose: 84, network: 1  },
  { type: 'p2wpkh-p2sh-multi', sec_prefix: 0x024285b5, pub_prefix: 0x024289ef, purpose: 49, network: 1  },
  { type: 'p2wpkh-multi',      sec_prefix: 0x02575048, pub_prefix: 0x02575483, purpose: 84, network: 1  }
]

function filterVersion (
  version : VersionData,
  filters  : VersionFilter = {}
) : boolean {
  for (const [ key, val ] of Object.entries(filters)) {
    const k = key as keyof VersionData
    if (version[k] !== val) return false
  }
  return true
}

function sortVersion (
  a : VersionData,
  b : VersionData
) : number {
  if (a.purpose < b.purpose) return 1
  if (a.purpose > b.purpose) return -1
  return 0
}

export function getVersionData (
    filters : VersionFilter = { type: 'default' }
  ) : VersionData {
  const versions = []
  for (const v of KEY_VERSIONS) {
    if (filterVersion(v, filters)) {
      versions.push(v)
    }
  }
  versions.sort(sortVersion)
  if (versions.length < 1) {
    throw new Error('Version not found: ' + JSON.stringify(filters))
  }
  return versions[0]
}
