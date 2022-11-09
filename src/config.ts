export interface LinkConfig {
  name : string
  seed : string
  prefix : {
    public  : number
    private : number
    export  : number
    address : string
  }
  index: {
    signMask : number
    maxIndex : number
  }
  map: {
    hardPrefix : number
    softPrefix : number
  }
  defaults: {
    index   : number
    depth   : number
    refcode : number
  }
}

const LinkConfigs : LinkConfig[] = [
  {
    name : 'bitcoin',
    seed : 'Bitcoin seed',
    prefix : {
      public  : 0x0488b21e,
      private : 0x0488ade4,
      export  : 0x80,
      address : 'bc',
    },
    index: {
      signMask : 0x80000000,
      maxIndex : Math.pow(2, 31) - 1
    },
    map: {
      hardPrefix: 0x80,
      softPrefix: 0x00
    },
    defaults: {
      index   : 0,
      depth   : 0,
      refcode : 0x00000000
    }
  }
]

export function getConfig(configName : string) : LinkConfig {
  const result = Object.values(LinkConfigs).find(({ name }) => name === configName)
  if (result === undefined) {
    throw TypeError('Key configuration does not exist for type: ' + configName)
  }
  return result
}
